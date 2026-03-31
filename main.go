package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	_ "modernc.org/sqlite"
	"gopkg.in/yaml.v3"
)

// VirtualKeyConfig represents a virtual key with a human-readable name.
type VirtualKeyConfig struct {
	Name           string  `yaml:"name" json:"name"`
	Key            string  `yaml:"key" json:"key"`
	BudgetLimitUSD float64 `yaml:"budget_limit_usd,omitempty" json:"budget_limit_usd"`
}

type AdminConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Config struct {
	Port       int             `yaml:"port"`
	Upstream   string          `yaml:"upstream"`
	OAuthToken string          `yaml:"oauth_token"`
	Admin      AdminConfig     `yaml:"admin"`
	SeedKeys   []VirtualKeyConfig `yaml:"virtual_keys"`
}

// UsageRecord stores a single request's usage data with timestamp.
type UsageRecord struct {
	Timestamp                time.Time `json:"timestamp"`
	Model                    string    `json:"model"`
	InputTokens              int64     `json:"input_tokens"`
	OutputTokens             int64     `json:"output_tokens"`
	CacheCreationInputTokens int64     `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int64     `json:"cache_read_input_tokens"`
}

// ModelUsage is aggregated usage for a single model.
type ModelUsage struct {
	InputTokens              int64 `json:"input_tokens"`
	OutputTokens             int64 `json:"output_tokens"`
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
}

// KeyStats is the aggregated stats for a single key within a time range.
type KeyStats struct {
	RequestCount             int64                 `json:"request_count"`
	InputTokens              int64                 `json:"input_tokens"`
	OutputTokens             int64                 `json:"output_tokens"`
	CacheCreationInputTokens int64                 `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int64                 `json:"cache_read_input_tokens"`
	ByModel                  map[string]ModelUsage `json:"by_model"`
	LastActive               time.Time             `json:"last_active,omitempty"`
}

// Store handles all persistent data via SQLite.
type Store struct {
	db  *sql.DB
	log *zerolog.Logger
}

func NewStore(dbPath string, log *zerolog.Logger) (*Store, error) {
	if dbPath == "" {
		dbPath = ":memory:"
	}
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	// Limit connections to 1 for SQLite.
	db.SetMaxOpenConns(1)

	s := &Store{db: db, log: log}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating database: %w", err)
	}
	return s, nil
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS virtual_keys (
			key TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			budget_limit_usd REAL NOT NULL DEFAULT 0
		);
		CREATE TABLE IF NOT EXISTS usage_records (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			virtual_key TEXT NOT NULL,
			timestamp DATETIME NOT NULL DEFAULT (datetime('now')),
			model TEXT NOT NULL DEFAULT '',
			input_tokens INTEGER NOT NULL DEFAULT 0,
			output_tokens INTEGER NOT NULL DEFAULT 0,
			cache_creation_input_tokens INTEGER NOT NULL DEFAULT 0,
			cache_read_input_tokens INTEGER NOT NULL DEFAULT 0
		);
		CREATE INDEX IF NOT EXISTS idx_records_key_ts ON usage_records(virtual_key, timestamp);
		CREATE TABLE IF NOT EXISTS sessions (
			token  TEXT PRIMARY KEY,
			expiry TEXT NOT NULL
		);
	`)
	if err != nil {
		return err
	}
	// Migration: add budget_limit_usd column if missing (for existing databases).
	s.db.Exec("ALTER TABLE virtual_keys ADD COLUMN budget_limit_usd REAL NOT NULL DEFAULT 0")
	return nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// --- Config key-value ---

func (s *Store) GetConfig(key string) (string, error) {
	var val string
	err := s.db.QueryRow("SELECT value FROM config WHERE key = ?", key).Scan(&val)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return val, err
}

func (s *Store) SetConfig(key, value string) error {
	_, err := s.db.Exec(
		"INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		key, value,
	)
	return err
}

// --- Virtual keys ---

func (s *Store) ListKeys() ([]VirtualKeyConfig, error) {
	rows, err := s.db.Query("SELECT key, name, budget_limit_usd FROM virtual_keys ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []VirtualKeyConfig
	for rows.Next() {
		var k VirtualKeyConfig
		if err := rows.Scan(&k.Key, &k.Name, &k.BudgetLimitUSD); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (s *Store) AddKey(name, key string) error {
	_, err := s.db.Exec(
		"INSERT INTO virtual_keys (key, name) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET name = excluded.name",
		key, name,
	)
	return err
}

func (s *Store) RemoveKey(key string) (bool, error) {
	res, err := s.db.Exec("DELETE FROM virtual_keys WHERE key = ?", key)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		// Also delete usage records for this key.
		s.db.Exec("DELETE FROM usage_records WHERE virtual_key = ?", key)
	}
	return n > 0, nil
}

func (s *Store) SetBudget(key string, budgetUSD float64) error {
	_, err := s.db.Exec("UPDATE virtual_keys SET budget_limit_usd = ? WHERE key = ?", budgetUSD, key)
	return err
}

func (s *Store) GetBudget(key string) float64 {
	var budget float64
	s.db.QueryRow("SELECT budget_limit_usd FROM virtual_keys WHERE key = ?", key).Scan(&budget)
	return budget
}

// QueryKeyCost calculates the total estimated cost for a key (all time).
func (s *Store) QueryKeyCost(key string) (float64, error) {
	rows, err := s.db.Query(
		`SELECT model,
			SUM(input_tokens), SUM(output_tokens),
			SUM(cache_creation_input_tokens), SUM(cache_read_input_tokens)
		 FROM usage_records
		 WHERE virtual_key = ?
		 GROUP BY model`, key)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var totalCost float64
	for rows.Next() {
		var model string
		var inTok, outTok, cw, cr int64
		if err := rows.Scan(&model, &inTok, &outTok, &cw, &cr); err != nil {
			return 0, err
		}
		totalCost += calcModelCost(model, inTok, outTok, cw, cr)
	}
	return totalCost, rows.Err()
}

func (s *Store) IsValidKey(key string) bool {
	var n int
	s.db.QueryRow("SELECT 1 FROM virtual_keys WHERE key = ?", key).Scan(&n)
	return n == 1
}

// SeedKeys adds keys from config if they don't already exist in the database.
func (s *Store) SeedKeys(keys []VirtualKeyConfig) error {
	for _, k := range keys {
		_, err := s.db.Exec(
			"INSERT OR IGNORE INTO virtual_keys (key, name) VALUES (?, ?)",
			k.Key, k.Name,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

// --- Usage records ---

func (s *Store) AddRecord(virtualKey string, rec UsageRecord) error {
	_, err := s.db.Exec(
		`INSERT INTO usage_records (virtual_key, timestamp, model, input_tokens, output_tokens, cache_creation_input_tokens, cache_read_input_tokens)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		virtualKey, rec.Timestamp.UTC().Format(time.RFC3339Nano), rec.Model,
		rec.InputTokens, rec.OutputTokens, rec.CacheCreationInputTokens, rec.CacheReadInputTokens,
	)
	return err
}

func (s *Store) QueryAll(since time.Time) (map[string]KeyStats, error) {
	sinceStr := ""
	if !since.IsZero() {
		sinceStr = since.UTC().Format(time.RFC3339Nano)
	}

	var rows *sql.Rows
	var err error
	if sinceStr == "" {
		rows, err = s.db.Query(
			`SELECT virtual_key, model,
				COUNT(*) as cnt,
				SUM(input_tokens), SUM(output_tokens),
				SUM(cache_creation_input_tokens), SUM(cache_read_input_tokens),
				MAX(timestamp)
			 FROM usage_records
			 GROUP BY virtual_key, model`)
	} else {
		rows, err = s.db.Query(
			`SELECT virtual_key, model,
				COUNT(*) as cnt,
				SUM(input_tokens), SUM(output_tokens),
				SUM(cache_creation_input_tokens), SUM(cache_read_input_tokens),
				MAX(timestamp)
			 FROM usage_records
			 WHERE timestamp >= ?
			 GROUP BY virtual_key, model`, sinceStr)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]KeyStats)
	for rows.Next() {
		var vk, model string
		var cnt, inTok, outTok, cacheCreate, cacheRead int64
		var lastActiveStr *string
		if err := rows.Scan(&vk, &model, &cnt, &inTok, &outTok, &cacheCreate, &cacheRead, &lastActiveStr); err != nil {
			return nil, err
		}
		ks := result[vk]
		if ks.ByModel == nil {
			ks.ByModel = make(map[string]ModelUsage)
		}
		ks.RequestCount += cnt
		ks.InputTokens += inTok
		ks.OutputTokens += outTok
		ks.CacheCreationInputTokens += cacheCreate
		ks.CacheReadInputTokens += cacheRead
		if lastActiveStr != nil {
			if t, err := time.Parse(time.RFC3339Nano, *lastActiveStr); err == nil {
				if t.After(ks.LastActive) {
					ks.LastActive = t
				}
			}
		}
		if model != "" {
			m := ks.ByModel[model]
			m.InputTokens += inTok
			m.OutputTokens += outTok
			m.CacheCreationInputTokens += cacheCreate
			m.CacheReadInputTokens += cacheRead
			ks.ByModel[model] = m
		}
		result[vk] = ks
	}
	return result, rows.Err()
}

// PurgeOlderThan deletes records older than the given duration.
func (s *Store) PurgeOlderThan(d time.Duration) (int64, error) {
	cutoff := time.Now().Add(-d).UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec("DELETE FROM usage_records WHERE timestamp < ?", cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

type keyInfo struct {
	name           string
	budgetLimitUSD float64
}

// KeyManager provides a fast in-memory cache for key validation.
type KeyManager struct {
	mu    sync.RWMutex
	keys  map[string]keyInfo // key -> info
	store *Store
}

func NewKeyManager(store *Store) (*KeyManager, error) {
	m := &KeyManager{keys: make(map[string]keyInfo), store: store}
	if err := m.reload(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *KeyManager) reload() error {
	keys, err := m.store.ListKeys()
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys = make(map[string]keyInfo, len(keys))
	for _, k := range keys {
		m.keys[k.Key] = keyInfo{name: k.Name, budgetLimitUSD: k.BudgetLimitUSD}
	}
	return nil
}

func (m *KeyManager) IsValid(key string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.keys[key]
	return ok
}

func (m *KeyManager) GetBudget(key string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.keys[key].budgetLimitUSD
}

func (m *KeyManager) SetBudget(key string, budget float64) error {
	if err := m.store.SetBudget(key, budget); err != nil {
		return err
	}
	m.mu.Lock()
	if info, ok := m.keys[key]; ok {
		info.budgetLimitUSD = budget
		m.keys[key] = info
	}
	m.mu.Unlock()
	return nil
}

func (m *KeyManager) Add(name, key string) error {
	if err := m.store.AddKey(name, key); err != nil {
		return err
	}
	m.mu.Lock()
	m.keys[key] = keyInfo{name: name}
	m.mu.Unlock()
	return nil
}

func (m *KeyManager) Remove(key string) (bool, error) {
	ok, err := m.store.RemoveKey(key)
	if err != nil {
		return false, err
	}
	if ok {
		m.mu.Lock()
		delete(m.keys, key)
		m.mu.Unlock()
	}
	return ok, nil
}

func (m *KeyManager) List() []VirtualKeyConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]VirtualKeyConfig, 0, len(m.keys))
	for k, info := range m.keys {
		result = append(result, VirtualKeyConfig{Name: info.name, Key: k, BudgetLimitUSD: info.budgetLimitUSD})
	}
	return result
}

// SessionStore manages admin login sessions via SQLite.
type SessionStore struct {
	store *Store
}

func NewSessionStore(store *Store) *SessionStore {
	// Clean up expired sessions on startup.
	store.db.Exec("DELETE FROM sessions WHERE expiry < ?", time.Now().UTC().Format(time.RFC3339))
	return &SessionStore{store: store}
}

func (s *SessionStore) Create() string {
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)
	expiry := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	s.store.db.Exec("INSERT INTO sessions (token, expiry) VALUES (?, ?)", token, expiry)
	return token
}

func (s *SessionStore) Valid(token string) bool {
	var expiry string
	err := s.store.db.QueryRow("SELECT expiry FROM sessions WHERE token = ?", token).Scan(&expiry)
	if err != nil {
		return false
	}
	t, err := time.Parse(time.RFC3339, expiry)
	if err != nil {
		return false
	}
	if time.Now().After(t) {
		s.store.db.Exec("DELETE FROM sessions WHERE token = ?", token)
		return false
	}
	return true
}

func (s *SessionStore) Delete(token string) {
	s.store.db.Exec("DELETE FROM sessions WHERE token = ?", token)
}

// apiUsage represents the usage field in Anthropic API responses.
type apiUsage struct {
	InputTokens              int64 `json:"input_tokens"`
	OutputTokens             int64 `json:"output_tokens"`
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
}

type apiResponse struct {
	Model string    `json:"model"`
	Usage *apiUsage `json:"usage"`
}

func extractFromBody(body []byte) (model string, inputTokens, outputTokens, cacheCreation, cacheRead int64) {
	var resp apiResponse
	if err := json.Unmarshal(body, &resp); err == nil && resp.Usage != nil {
		return resp.Model, resp.Usage.InputTokens, resp.Usage.OutputTokens,
			resp.Usage.CacheCreationInputTokens, resp.Usage.CacheReadInputTokens
	}
	return "", 0, 0, 0, 0
}

// sseUsageReader wraps a streaming response body and extracts usage
// information from SSE events as data flows through to the client.
type sseUsageReader struct {
	reader                   io.ReadCloser
	virtualKey               string
	keyName                  string
	start                    time.Time
	method                   string
	path                     string
	store                    *Store
	log                      *zerolog.Logger
	buf                      []byte
	model                    string
	inputTokens              int64
	outputTokens             int64
	cacheCreationInputTokens int64
	cacheReadInputTokens     int64
	closed                   bool
}

func (r *sseUsageReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.buf = append(r.buf, p[:n]...)
		r.scanBuffer()
	}
	if err == io.EOF && !r.closed {
		r.closed = true
		r.recordUsage()
	}
	return n, err
}

func (r *sseUsageReader) scanBuffer() {
	for {
		idx := bytes.IndexByte(r.buf, '\n')
		if idx < 0 {
			break
		}
		line := string(r.buf[:idx])
		r.buf = r.buf[idx+1:]

		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")

		var event struct {
			Type    string    `json:"type"`
			Usage   *apiUsage `json:"usage"`
			Message *struct {
				Model string    `json:"model"`
				Usage *apiUsage `json:"usage"`
			} `json:"message"`
		}
		// Use Decoder instead of Unmarshal: stops after valid JSON and ignores
		// trailing whitespace/garbage that Anthropic sometimes appends.
		if err := json.NewDecoder(strings.NewReader(data)).Decode(&event); err != nil {
			continue
		}
		r.log.Debug().Str("type", event.Type).Msg("sse event")
		if event.Type == "message_start" && event.Message != nil {
			if event.Message.Model != "" {
				r.model = event.Message.Model
			}
			if event.Message.Usage != nil {
				r.inputTokens = event.Message.Usage.InputTokens
				r.cacheCreationInputTokens = event.Message.Usage.CacheCreationInputTokens
				r.cacheReadInputTokens = event.Message.Usage.CacheReadInputTokens
			}
		}
		if event.Type == "message_delta" && event.Usage != nil {
			r.outputTokens = event.Usage.OutputTokens
		}
	}
}

func (r *sseUsageReader) recordUsage() {
	rec := UsageRecord{
		Timestamp:                time.Now(),
		Model:                    r.model,
		InputTokens:              r.inputTokens,
		OutputTokens:             r.outputTokens,
		CacheCreationInputTokens: r.cacheCreationInputTokens,
		CacheReadInputTokens:     r.cacheReadInputTokens,
	}
	if err := r.store.AddRecord(r.virtualKey, rec); err != nil {
		r.log.Error().Err(err).Msg("failed to record usage")
	}
	cost := calcModelCost(r.model, r.inputTokens, r.outputTokens, r.cacheCreationInputTokens, r.cacheReadInputTokens)
	r.log.Info().
		Str("key", r.keyName).
		Str("method", r.method).
		Str("path", r.path).
		Dur("duration", time.Since(r.start)).
		Str("model", r.model).
		Int64("input_tokens", r.inputTokens).
		Int64("output_tokens", r.outputTokens).
		Int64("cache_creation", r.cacheCreationInputTokens).
		Int64("cache_read", r.cacheReadInputTokens).
		Float64("cost_usd", math.Round(cost*1000000)/1000000).
		Msg("completed")
}

func (r *sseUsageReader) Close() error {
	if !r.closed {
		r.closed = true
		remaining, _ := io.ReadAll(r.reader)
		if len(remaining) > 0 {
			r.buf = append(r.buf, remaining...)
			r.scanBuffer()
		}
		r.recordUsage()
	}
	return r.reader.Close()
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if cfg.Port == 0 {
		cfg.Port = 4000
	}
	if cfg.Upstream == "" {
		cfg.Upstream = "https://api.anthropic.com"
	}
	return &cfg, nil
}

// Server-side model pricing ($/M tokens) — mirrors the JS pricing in adminHTML.
var modelPricing = map[string][2]float64{
	"claude-opus-4-6":            {15, 75},
	"claude-opus-4-20250514":     {15, 75},
	"claude-opus-4-0":            {15, 75},
	"claude-sonnet-4-6":          {3, 15},
	"claude-sonnet-4-20250514":   {3, 15},
	"claude-sonnet-4-0":          {3, 15},
	"claude-3-5-sonnet-20241022": {3, 15},
	"claude-3-5-sonnet-20240620": {3, 15},
	"claude-haiku-4-5-20251001":  {0.8, 4},
	"claude-3-5-haiku-20241022":  {0.8, 4},
	"claude-3-opus-20240229":     {15, 75},
	"claude-3-sonnet-20240229":   {3, 15},
	"claude-3-haiku-20240307":    {0.25, 1.25},
}

func getModelPricing(model string) (inputPrice, outputPrice float64) {
	if p, ok := modelPricing[model]; ok {
		return p[0], p[1]
	}
	// Fuzzy match by prefix.
	for key, p := range modelPricing {
		prefix := strings.Split(key, "-2")[0] // e.g. "claude-opus-4" from "claude-opus-4-20250514"
		if model != "" && strings.HasPrefix(model, prefix) {
			return p[0], p[1]
		}
	}
	return 3, 15 // default
}

func calcModelCost(model string, inputTokens, outputTokens, cacheWrite, cacheRead int64) float64 {
	inp, out := getModelPricing(model)
	return (float64(inputTokens)*inp +
		float64(outputTokens)*out +
		float64(cacheWrite)*inp*1.25 +
		float64(cacheRead)*inp*0.1) / 1_000_000
}

type ctxStartKey struct{}

func maskToken(t string) string {
	if len(t) <= 16 {
		return "***"
	}
	return t[:12] + "..." + t[len(t)-6:]
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	dataPath := flag.String("data", "", "path to SQLite database (e.g. /data/maxmux.db)")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, error")
	retention := flag.Int("retention", 30, "data retention in days (0 = keep forever)")
	flag.Parse()

	level, err := zerolog.ParseLevel(*logLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.DateTime}).
		With().Timestamp().Logger().Level(level)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
	}

	if cfg.OAuthToken == "" {
		log.Fatal().Msg("oauth_token is required in config")
	}
	if cfg.Admin.Username == "" || cfg.Admin.Password == "" {
		log.Fatal().Msg("admin username and password are required in config")
	}

	store, err := NewStore(*dataPath, &log)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open store")
	}
	defer store.Close()

	// Seed keys from config (only inserts if not already present).
	if len(cfg.SeedKeys) > 0 {
		if err := store.SeedKeys(cfg.SeedKeys); err != nil {
			log.Fatal().Err(err).Msg("failed to seed keys")
		}
	}

	// Purge old records on startup.
	if *retention > 0 {
		purged, err := store.PurgeOlderThan(time.Duration(*retention) * 24 * time.Hour)
		if err != nil {
			log.Error().Err(err).Msg("failed to purge old records")
		} else if purged > 0 {
			log.Info().Int64("purged", purged).Int("retention_days", *retention).Msg("purged old records")
		}
	}

	keyMgr, err := NewKeyManager(store)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load keys")
	}
	sessions := NewSessionStore(store)

	// Load or initialize OAuth token.
	var oauthToken atomic.Value
	savedToken, _ := store.GetConfig("oauth_token")
	if savedToken != "" {
		oauthToken.Store(savedToken)
	} else {
		oauthToken.Store(cfg.OAuthToken)
		store.SetConfig("oauth_token", cfg.OAuthToken)
	}

	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		log.Fatal().Err(err).Str("upstream", cfg.Upstream).Msg("invalid upstream URL")
	}
	log.Info().
		Int("port", cfg.Port).
		Str("upstream", cfg.Upstream).
		Str("oauth_token", maskToken(oauthToken.Load().(string))).
		Msg("starting maxmux")

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			token := oauthToken.Load().(string)
			req.URL.Scheme = upstream.Scheme
			req.URL.Host = upstream.Host
			req.Host = upstream.Host

			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Del("X-Api-Key")
			// Prevent gzip so the SSE reader sees plain text bytes.
			req.Header.Del("Accept-Encoding")

			if existing := req.Header.Get("Anthropic-Beta"); existing != "" {
				req.Header.Set("Anthropic-Beta", existing+",oauth-2025-04-20")
			} else {
				req.Header.Set("Anthropic-Beta", "oauth-2025-04-20")
			}
			req.Header.Set("Anthropic-Dangerous-Direct-Browser-Access", "true")

			log.Debug().
				Str("authorization", "Bearer "+maskToken(token)).
				Str("anthropic-beta", req.Header.Get("Anthropic-Beta")).
				Msg("injected oauth headers")
		},
		ModifyResponse: func(resp *http.Response) error {
			virtualKey := resp.Request.Header.Get("X-Maxmux-Virtual-Key")
			resp.Request.Header.Del("X-Maxmux-Virtual-Key")

			if virtualKey == "" {
				return nil
			}

			// Resolve key name for logging.
			resolvedName := maskToken(virtualKey)
			for _, k := range keyMgr.List() {
				if k.Key == virtualKey {
					resolvedName = k.Name
					break
				}
			}

			contentType := resp.Header.Get("Content-Type")
			isStreaming := strings.Contains(contentType, "text/event-stream")

			if isStreaming {
				resp.Body = &sseUsageReader{
					reader:     resp.Body,
					virtualKey: virtualKey,
					keyName:    resolvedName,
					start:      resp.Request.Context().Value(ctxStartKey{}).(time.Time),
					method:     resp.Request.Method,
					path:       resp.Request.URL.Path,
					store:      store,
					log:        &log,
				}
			} else {
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					return err
				}

				model, inputTokens, outputTokens, cacheCreation, cacheRead := extractFromBody(body)
				reqStart, _ := resp.Request.Context().Value(ctxStartKey{}).(time.Time)
				if resp.StatusCode == http.StatusTooManyRequests {
					// Strip retry headers so the SDK does not back-off and retry endlessly.
					resp.Header.Del("Retry-After")
					resp.Header.Del("X-Ratelimit-Reset-Requests")
					resp.Header.Del("X-Ratelimit-Reset-Tokens")
				}
				if resp.StatusCode >= 400 {
					// Error response — log as warning, no usage to record.
					log.Error().
						Str("key", resolvedName).
						Str("method", resp.Request.Method).
						Str("path", resp.Request.URL.Path).
						Dur("duration", time.Since(reqStart)).
						Int("status", resp.StatusCode).
						Str("error", string(body[:min(200, len(body))])).
						Msg("upstream error response")
				} else {
					rec := UsageRecord{
						Timestamp:                time.Now(),
						Model:                    model,
						InputTokens:              inputTokens,
						OutputTokens:             outputTokens,
						CacheCreationInputTokens: cacheCreation,
						CacheReadInputTokens:     cacheRead,
					}
					if err := store.AddRecord(virtualKey, rec); err != nil {
						log.Error().Err(err).Msg("failed to record usage")
					}
					cost := calcModelCost(model, inputTokens, outputTokens, cacheCreation, cacheRead)
					log.Info().
						Str("key", resolvedName).
						Str("method", resp.Request.Method).
						Str("path", resp.Request.URL.Path).
						Dur("duration", time.Since(reqStart)).
						Str("model", model).
						Int64("input_tokens", inputTokens).
						Int64("output_tokens", outputTokens).
						Int64("cache_creation", cacheCreation).
						Int64("cache_read", cacheRead).
						Float64("cost_usd", math.Round(cost*1000000)/1000000).
						Msg("completed")
				}

				resp.Body = io.NopCloser(bytes.NewReader(body))
				resp.ContentLength = int64(len(body))
			}

			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Error().Err(err).Str("method", r.Method).Str("path", r.URL.Path).Msg("upstream error")
			http.Error(w, `{"error":{"message":"upstream error","type":"proxy_error"}}`, http.StatusBadGateway)
		},
	}

	requireAdmin := func(w http.ResponseWriter, r *http.Request) bool {
		cookie, err := r.Cookie("session")
		if err != nil || !sessions.Valid(cookie.Value) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return false
		}
		return true
	}

	// parseSince parses the "since" query param as minutes ago. 0 means all time.
	parseSince := func(r *http.Request) time.Time {
		s := r.URL.Query().Get("since")
		if s == "" {
			return time.Time{}
		}
		mins, err := strconv.ParseInt(s, 10, 64)
		if err != nil || mins <= 0 {
			return time.Time{}
		}
		return time.Now().Add(-time.Duration(mins) * time.Minute)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// --- Admin UI & API routes ---

		if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(adminHTML))
			return
		}

		if r.URL.Path == "/admin/api/login" && r.Method == http.MethodPost {
			var req struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
				return
			}
			if req.Username != cfg.Admin.Username || req.Password != cfg.Admin.Password {
				log.Warn().Str("username", req.Username).Str("remote", r.RemoteAddr).Msg("admin login failed")
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
				return
			}
			token := sessions.Create()
			http.SetCookie(w, &http.Cookie{
				Name:     "session",
				Value:    token,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   86400,
			})
			log.Info().Str("username", req.Username).Msg("admin login success")
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}

		if r.URL.Path == "/admin/api/logout" && r.Method == http.MethodPost {
			if cookie, err := r.Cookie("session"); err == nil {
				sessions.Delete(cookie.Value)
			}
			http.SetCookie(w, &http.Cookie{
				Name:   "session",
				Value:  "",
				Path:   "/",
				MaxAge: -1,
			})
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}

		if r.URL.Path == "/admin/api/keys" && r.Method == http.MethodGet {
			if !requireAdmin(w, r) {
				return
			}
			since := parseSince(r)
			type modelUsageJSON struct {
				InputTokens              int64 `json:"input_tokens"`
				OutputTokens             int64 `json:"output_tokens"`
				CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
				CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
			}
			type keyWithUsage struct {
				Name                     string                    `json:"name"`
				Key                      string                    `json:"key"`
				MaskedKey                string                    `json:"masked_key"`
				RequestCount             int64                     `json:"request_count"`
				InputTokens              int64                     `json:"input_tokens"`
				OutputTokens             int64                     `json:"output_tokens"`
				CacheCreationInputTokens int64                     `json:"cache_creation_input_tokens"`
				CacheReadInputTokens     int64                     `json:"cache_read_input_tokens"`
				ByModel                  map[string]modelUsageJSON `json:"by_model"`
				BudgetLimitUSD           float64                   `json:"budget_limit_usd"`
				LastActive               *time.Time                `json:"last_active,omitempty"`
			}
			keys := keyMgr.List()
			allUsage, err := store.QueryAll(since)
			if err != nil {
				log.Error().Err(err).Msg("failed to query usage")
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
				return
			}
			result := make([]keyWithUsage, 0, len(keys))
			for _, k := range keys {
				u := allUsage[k.Key]
				bm := make(map[string]modelUsageJSON, len(u.ByModel))
				for model, mu := range u.ByModel {
					bm[model] = modelUsageJSON{
						InputTokens:              mu.InputTokens,
						OutputTokens:             mu.OutputTokens,
						CacheCreationInputTokens: mu.CacheCreationInputTokens,
						CacheReadInputTokens:     mu.CacheReadInputTokens,
					}
				}
				entry := keyWithUsage{
					Name:                     k.Name,
					Key:                      k.Key,
					MaskedKey:                maskToken(k.Key),
					RequestCount:             u.RequestCount,
					InputTokens:              u.InputTokens,
					OutputTokens:             u.OutputTokens,
					CacheCreationInputTokens: u.CacheCreationInputTokens,
					CacheReadInputTokens:     u.CacheReadInputTokens,
					ByModel:                  bm,
					BudgetLimitUSD:           k.BudgetLimitUSD,
				}
				if !u.LastActive.IsZero() {
					t := u.LastActive
					entry.LastActive = &t
				}
				result = append(result, entry)
			}
			writeJSON(w, http.StatusOK, result)
			return
		}

		if r.URL.Path == "/admin/api/keys" && r.Method == http.MethodPost {
			if !requireAdmin(w, r) {
				return
			}
			var req struct {
				Name string `json:"name"`
				Key  string `json:"key"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
				return
			}
			if req.Name == "" || req.Key == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and key are required"})
				return
			}
			if err := keyMgr.Add(req.Name, req.Key); err != nil {
				log.Error().Err(err).Msg("failed to add key")
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
				return
			}
			log.Info().Str("name", req.Name).Str("key", maskToken(req.Key)).Msg("virtual key added")
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}

		if r.URL.Path == "/admin/api/keys" && r.Method == http.MethodDelete {
			if !requireAdmin(w, r) {
				return
			}
			var req struct {
				Key string `json:"key"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
				return
			}
			ok, err := keyMgr.Remove(req.Key)
			if err != nil {
				log.Error().Err(err).Msg("failed to remove key")
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
				return
			}
			if !ok {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "key not found"})
				return
			}
			log.Info().Str("key", maskToken(req.Key)).Msg("virtual key removed")
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}

		if r.URL.Path == "/admin/api/session" && r.Method == http.MethodGet {
			cookie, err := r.Cookie("session")
			if err != nil || !sessions.Valid(cookie.Value) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}

		// Get current OAuth token (masked).
		if r.URL.Path == "/admin/api/token" && r.Method == http.MethodGet {
			if !requireAdmin(w, r) {
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"masked_token": maskToken(oauthToken.Load().(string))})
			return
		}

		// Update OAuth token.
		if r.URL.Path == "/admin/api/token" && r.Method == http.MethodPut {
			if !requireAdmin(w, r) {
				return
			}
			var req struct {
				Token string `json:"token"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
				return
			}
			if req.Token == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token is required"})
				return
			}
			oauthToken.Store(req.Token)
			if err := store.SetConfig("oauth_token", req.Token); err != nil {
				log.Error().Err(err).Msg("failed to save token")
			}
			log.Info().Str("token", maskToken(req.Token)).Msg("oauth token updated")
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "masked_token": maskToken(req.Token)})
			return
		}

		// Set budget for a key.
		if r.URL.Path == "/admin/api/budget" && r.Method == http.MethodPut {
			if !requireAdmin(w, r) {
				return
			}
			var req struct {
				Key            string  `json:"key"`
				BudgetLimitUSD float64 `json:"budget_limit_usd"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
				return
			}
			if req.Key == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key is required"})
				return
			}
			if req.BudgetLimitUSD < 0 {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "budget must be >= 0"})
				return
			}
			if err := keyMgr.SetBudget(req.Key, req.BudgetLimitUSD); err != nil {
				log.Error().Err(err).Msg("failed to set budget")
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
				return
			}
			log.Info().Str("key", maskToken(req.Key)).Float64("budget", req.BudgetLimitUSD).Msg("budget updated")
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}

		// --- Balance API (for cc-switch etc.) ---
		if r.URL.Path == "/user/balance" && r.Method == http.MethodGet {
			var vk string
			if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				vk = strings.TrimPrefix(auth, "Bearer ")
			}
			if !keyMgr.IsValid(vk) {
				writeJSON(w, http.StatusOK, map[string]any{
					"is_active":      false,
					"invalidMessage": "invalid virtual key",
				})
				return
			}
			budget := keyMgr.GetBudget(vk)
			cost, _ := store.QueryKeyCost(vk)

			resp := map[string]any{
				"is_active": true,
				"used":      math.Round(cost*10000) / 10000,
				"unit":      "USD",
			}

			// Find key name for planName.
			for _, k := range keyMgr.List() {
				if k.Key == vk {
					resp["planName"] = k.Name
					break
				}
			}

			if budget > 0 {
				remaining := budget - cost
				if remaining < 0 {
					remaining = 0
				}
				resp["total"] = budget
				resp["remaining"] = math.Round(remaining*10000) / 10000
				if cost >= budget {
					resp["is_active"] = false
					resp["invalidMessage"] = "budget limit exceeded"
				}
			} else {
				resp["remaining"] = -1
				resp["extra"] = "unlimited budget"
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}

		// --- Proxy routes ---

		// Health check: respond to HEAD / without auth.
		if r.Method == http.MethodHead && r.URL.Path == "/" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Ignore common browser noise that should not require a virtual key.
		if r.URL.Path == "/favicon.ico" {
			http.NotFound(w, r)
			return
		}

		start := time.Now()

		var virtualKey string
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			virtualKey = strings.TrimPrefix(auth, "Bearer ")
		}

		if !keyMgr.IsValid(virtualKey) {
			log.Warn().
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Str("remote", r.RemoteAddr).
				Msg("rejected — invalid virtual key")
			http.Error(w, `{"error":{"message":"invalid virtual key","type":"authentication_error"}}`, http.StatusUnauthorized)
			return
		}

		// Check budget limit.
		if budget := keyMgr.GetBudget(virtualKey); budget > 0 {
			cost, err := store.QueryKeyCost(virtualKey)
			if err != nil {
				log.Error().Err(err).Msg("failed to query key cost")
			} else if cost >= budget {
				log.Warn().
					Str("key", maskToken(virtualKey)).
					Float64("cost", cost).
					Float64("budget", budget).
					Msg("rejected — budget exceeded")
				http.Error(w, `{"error":{"message":"budget limit exceeded","type":"rate_limit_error"}}`, http.StatusTooManyRequests)
				return
			}
		}

		for name, values := range r.Header {
			for _, v := range values {
				if strings.EqualFold(name, "Authorization") {
					log.Debug().Str("header", name).Str("value", maskToken(v)).Msg("request header")
				} else {
					log.Debug().Str("header", name).Str("value", v).Msg("request header")
				}
			}
		}

		r.Header.Set("X-Maxmux-Virtual-Key", virtualKey)

		// Inject start time into context so ModifyResponse can compute duration.
		ctx := context.WithValue(r.Context(), ctxStartKey{}, start)
		proxy.ServeHTTP(w, r.WithContext(ctx))
	})

	addr := fmt.Sprintf(":%d", cfg.Port)
	log.Info().Str("addr", addr).Msg("listening")
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatal().Err(err).Msg("server error")
	}
}

const adminHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Maxmux Admin</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0f2f5; color: #1a1a1a; min-height: 100vh; }

  .login-container { display: flex; justify-content: center; align-items: center; min-height: 100vh; }
  .login-box { background: #fff; padding: 40px; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.08); width: 360px; }
  .login-box h1 { font-size: 24px; margin-bottom: 8px; }
  .login-box p { color: #666; margin-bottom: 24px; font-size: 14px; }
  .form-group { margin-bottom: 16px; }
  .form-group label { display: block; font-size: 13px; font-weight: 500; margin-bottom: 6px; color: #444; }
  .form-group input { width: 100%; padding: 10px 12px; border: 1px solid #d9d9d9; border-radius: 8px; font-size: 14px; outline: none; transition: border-color 0.2s; }
  .form-group input:focus { border-color: #4f46e5; }
  .btn { padding: 10px 20px; border: none; border-radius: 8px; font-size: 14px; font-weight: 500; cursor: pointer; transition: all 0.2s; }
  .btn-primary { background: #4f46e5; color: #fff; width: 100%; }
  .btn-primary:hover { background: #4338ca; }
  .btn-danger { background: #ef4444; color: #fff; }
  .btn-danger:hover { background: #dc2626; }
  .btn-sm { padding: 6px 12px; font-size: 12px; }
  .error-msg { color: #ef4444; font-size: 13px; margin-top: 12px; display: none; }

  .dashboard { display: none; }
  .header { background: #fff; border-bottom: 1px solid #e5e7eb; padding: 16px 32px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }
  .header h1 { font-size: 20px; }
  .header-right { display: flex; align-items: center; gap: 12px; }
  .header .btn { background: #f3f4f6; color: #374151; width: auto; }
  .header .btn:hover { background: #e5e7eb; }
  .content { max-width: 1100px; margin: 32px auto; padding: 0 24px; }

  .time-filter { display: flex; gap: 6px; flex-wrap: wrap; }
  .time-filter button { padding: 5px 12px; border: 1px solid #d1d5db; border-radius: 6px; background: #fff; font-size: 13px; cursor: pointer; color: #374151; transition: all 0.15s; }
  .time-filter button:hover { background: #f3f4f6; }
  .time-filter button.active { background: #4f46e5; color: #fff; border-color: #4f46e5; }

  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }
  .stat-card { background: #fff; padding: 20px; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.06); }
  .stat-card .label { font-size: 13px; color: #6b7280; margin-bottom: 4px; }
  .stat-card .value { font-size: 28px; font-weight: 600; }
  .stat-card .value.cost { color: #059669; }

  .section { background: #fff; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.06); padding: 24px; margin-bottom: 24px; }
  .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
  .section-header h2 { font-size: 16px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 12px 16px; border-bottom: 1px solid #f3f4f6; font-size: 14px; }
  th { font-weight: 500; color: #6b7280; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
  tr:last-child td { border-bottom: none; }
  .mono { font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 13px; color: #6b7280; }
  .cost-cell { color: #059669; font-weight: 500; }

  .model-detail { font-size: 12px; color: #9ca3af; margin-top: 4px; }
  .model-detail span { margin-right: 12px; }

  .modal-overlay { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.4); z-index: 100; justify-content: center; align-items: center; }
  .modal-overlay.active { display: flex; }
  .modal { background: #fff; padding: 32px; border-radius: 12px; width: 420px; box-shadow: 0 8px 32px rgba(0,0,0,0.12); }
  .modal h2 { margin-bottom: 20px; font-size: 18px; }
  .modal .form-group:last-of-type { margin-bottom: 24px; }
  .modal-actions { display: flex; gap: 12px; justify-content: flex-end; }
  .btn-secondary { background: #f3f4f6; color: #374151; }
  .btn-secondary:hover { background: #e5e7eb; }

  .token-num { font-variant-numeric: tabular-nums; }

  @media (max-width: 768px) {
    .stats { grid-template-columns: repeat(2, 1fr); }
    .content { padding: 0 16px; }
    .header { padding: 16px; }
    table { font-size: 13px; }
    th, td { padding: 8px 10px; }
  }
  @media (max-width: 480px) {
    .stats { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>

<div class="login-container" id="loginPage">
  <div class="login-box">
    <h1>Maxmux</h1>
    <p>Sign in to the admin dashboard</p>
    <div class="form-group">
      <label>Username</label>
      <input type="text" id="username" autocomplete="username">
    </div>
    <div class="form-group">
      <label>Password</label>
      <input type="password" id="password" autocomplete="current-password">
    </div>
    <button class="btn btn-primary" onclick="login()">Sign In</button>
    <div class="error-msg" id="loginError">Invalid username or password</div>
  </div>
</div>

<div class="dashboard" id="dashboard">
  <div class="header">
    <h1>Maxmux Dashboard</h1>
    <div class="header-right">
      <div class="time-filter" id="timeFilter">
        <button data-since="1" onclick="setTimeRange(this)">1m</button>
        <button data-since="5" onclick="setTimeRange(this)">5m</button>
        <button data-since="30" onclick="setTimeRange(this)">30m</button>
        <button data-since="60" onclick="setTimeRange(this)">1h</button>
        <button data-since="360" onclick="setTimeRange(this)">6h</button>
        <button data-since="1440" onclick="setTimeRange(this)">1d</button>
        <button data-since="10080" onclick="setTimeRange(this)">7d</button>
        <button data-since="43200" onclick="setTimeRange(this)">30d</button>
        <button data-since="0" class="active" onclick="setTimeRange(this)">All</button>
      </div>
      <button class="btn" onclick="logout()">Sign Out</button>
    </div>
  </div>
  <div class="content">
    <div class="stats">
      <div class="stat-card">
        <div class="label">Total Requests</div>
        <div class="value token-num" id="totalRequests">0</div>
      </div>
      <div class="stat-card">
        <div class="label">Total Input Tokens</div>
        <div class="value token-num" id="totalInput">0</div>
      </div>
      <div class="stat-card">
        <div class="label">Total Output Tokens</div>
        <div class="value token-num" id="totalOutput">0</div>
      </div>
      <div class="stat-card">
        <div class="label">Est. Cost (API Pricing)</div>
        <div class="value cost token-num" id="totalCost">$0.00</div>
      </div>
    </div>
    <div class="stats" style="margin-top:-16px">
      <div class="stat-card">
        <div class="label">Cache Write Tokens</div>
        <div class="value token-num" id="totalCacheWrite">0</div>
      </div>
      <div class="stat-card">
        <div class="label">Cache Read Tokens</div>
        <div class="value token-num" id="totalCacheRead">0</div>
      </div>
      <div class="stat-card">
        <div class="label">Cache Hit Rate</div>
        <div class="value token-num" id="cacheHitRate">-</div>
      </div>
      <div class="stat-card">
        <div class="label">Est. Savings from Cache</div>
        <div class="value cost token-num" id="cacheSavings">$0.00</div>
      </div>
    </div>
    <div class="section">
      <div class="section-header">
        <h2>Virtual Keys</h2>
        <label class="btn btn-secondary btn-sm" style="cursor:pointer;margin-right:6px">Import CSV<input type="file" accept=".csv,.txt" style="display:none" onchange="importCSV(this)"></label>
        <button class="btn btn-primary btn-sm" onclick="showAddModal()">+ Add Key</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Key</th>
            <th>Requests</th>
            <th>Input Tokens</th>
            <th>Output Tokens</th>
            <th>Cache Write</th>
            <th>Cache Read</th>
            <th>Est. Cost</th>
            <th>Budget</th>
            <th>Last Active</th>
            <th></th>
          </tr>
        </thead>
        <tbody id="keysTable"></tbody>
      </table>
    </div>
    <div class="section">
      <div class="section-header">
        <h2>Settings</h2>
      </div>
      <div style="display:flex;gap:12px;align-items:flex-end">
        <div class="form-group" style="flex:1;margin-bottom:0">
          <label>OAuth Token</label>
          <div style="display:flex;gap:8px">
            <input type="password" id="tokenInput" placeholder="Current token" style="flex:1;padding:10px 12px;border:1px solid #d9d9d9;border-radius:8px;font-size:14px;font-family:monospace">
            <button class="btn btn-secondary" style="width:auto;white-space:nowrap" onclick="toggleTokenVisibility()">Show</button>
            <button class="btn btn-primary" style="width:auto;white-space:nowrap" onclick="updateToken()">Save</button>
          </div>
          <div style="font-size:12px;color:#9ca3af;margin-top:6px">Current: <span id="currentToken" class="mono">-</span></div>
        </div>
      </div>
    </div>
  </div>
</div>

<div class="modal-overlay" id="addModal">
  <div class="modal">
    <h2>Add Virtual Key</h2>
    <div class="form-group">
      <label>Name</label>
      <input type="text" id="newName" placeholder="e.g. Alice">
    </div>
    <div class="form-group">
      <label>Key</label>
      <input type="text" id="newKey" placeholder="e.g. sk-proxy-alice-001">
    </div>
    <div class="modal-actions">
      <button class="btn btn-secondary" onclick="hideAddModal()">Cancel</button>
      <button class="btn btn-primary" onclick="addKey()">Add</button>
    </div>
  </div>
</div>

<script>
const API = '/admin/api';
let refreshTimer;
let currentSince = 0; // 0 = all time, otherwise minutes

const MODEL_PRICING = {
  'claude-opus-4-6':              { input: 15, output: 75 },
  'claude-opus-4-20250514':       { input: 15, output: 75 },
  'claude-opus-4-0':              { input: 15, output: 75 },
  'claude-sonnet-4-6':            { input: 3,  output: 15 },
  'claude-sonnet-4-20250514':     { input: 3,  output: 15 },
  'claude-sonnet-4-0':            { input: 3,  output: 15 },
  'claude-3-5-sonnet-20241022':   { input: 3,  output: 15 },
  'claude-3-5-sonnet-20240620':   { input: 3,  output: 15 },
  'claude-haiku-4-5-20251001':    { input: 0.8, output: 4 },
  'claude-3-5-haiku-20241022':    { input: 0.8, output: 4 },
  'claude-3-opus-20240229':       { input: 15, output: 75 },
  'claude-3-sonnet-20240229':     { input: 3,  output: 15 },
  'claude-3-haiku-20240307':      { input: 0.25, output: 1.25 },
};
const DEFAULT_PRICING = { input: 3, output: 15 };

function getPricing(model) {
  if (MODEL_PRICING[model]) return MODEL_PRICING[model];
  for (const [key, val] of Object.entries(MODEL_PRICING)) {
    if (model && model.startsWith(key.split('-2')[0])) return val;
  }
  return DEFAULT_PRICING;
}

function calcCost(byModel) {
  let total = 0;
  if (!byModel) return total;
  for (const [model, usage] of Object.entries(byModel)) {
    const p = getPricing(model);
    total += (usage.input_tokens * p.input
            + usage.output_tokens * p.output
            + (usage.cache_creation_input_tokens || 0) * p.input * 1.25
            + (usage.cache_read_input_tokens || 0) * p.input * 0.1) / 1_000_000;
  }
  return total;
}

function calcCacheSavings(byModel) {
  let savings = 0;
  if (!byModel) return savings;
  for (const [model, usage] of Object.entries(byModel)) {
    const p = getPricing(model);
    savings += ((usage.cache_read_input_tokens || 0) * p.input * 0.9) / 1_000_000;
  }
  return savings;
}

function formatCost(cost) {
  if (cost < 0.01) return '$' + cost.toFixed(4);
  return '$' + cost.toFixed(2);
}

function formatNumber(n) {
  return n.toLocaleString();
}

function formatRelTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  const diff = Math.floor((Date.now() - d.getTime()) / 1000);
  if (diff < 60) return diff + 's ago';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
  return Math.floor(diff / 86400) + 'd ago';
}

function setTimeRange(el) {
  document.querySelectorAll('.time-filter button').forEach(b => b.classList.remove('active'));
  el.classList.add('active');
  currentSince = parseInt(el.dataset.since, 10);
  loadKeys();
}

async function login() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const res = await fetch(API + '/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  if (res.ok) {
    showDashboard();
  } else {
    const el = document.getElementById('loginError');
    el.style.display = 'block';
    setTimeout(() => el.style.display = 'none', 3000);
  }
}

document.getElementById('password').addEventListener('keydown', e => { if (e.key === 'Enter') login(); });
document.getElementById('username').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('password').focus(); });

async function logout() {
  await fetch(API + '/logout', { method: 'POST' });
  document.getElementById('dashboard').style.display = 'none';
  document.getElementById('loginPage').style.display = 'flex';
  clearInterval(refreshTimer);
}

async function checkSession() {
  for (let i = 0; i < 3; i++) {
    try {
      const res = await fetch(API + '/session');
      if (res.ok) { showDashboard(); return; }
      if (res.status === 401) return; // definitively not logged in
    } catch(e) { /* network error, retry */ }
    await new Promise(r => setTimeout(r, 500));
  }
}

function showDashboard() {
  if (refreshTimer) clearInterval(refreshTimer);
  document.getElementById('loginPage').style.display = 'none';
  document.getElementById('dashboard').style.display = 'block';
  loadKeys();
  loadToken();
  refreshTimer = setInterval(loadKeys, 30000);
}

async function loadKeys() {
  const url = currentSince > 0 ? API + '/keys?since=' + currentSince : API + '/keys';
  let res;
  try { res = await fetch(url); } catch(e) { return; }
  if (!res.ok) {
    // Background polling failures (including 401) are silently ignored.
    // The user will only be logged out when they explicitly trigger an action
    // and the server confirms the session is invalid via /admin/api/session.
    return;
  }
  const keys = await res.json();
  const tbody = document.getElementById('keysTable');

  let totalReq = 0, totalIn = 0, totalOut = 0, totalCostVal = 0;
  let totalCacheW = 0, totalCacheR = 0, totalSavingsVal = 0;
  let html = '';
  for (const k of keys) {
    totalReq += k.request_count;
    totalIn += k.input_tokens;
    totalOut += k.output_tokens;
    totalCacheW += k.cache_creation_input_tokens || 0;
    totalCacheR += k.cache_read_input_tokens || 0;
    const keyCost = calcCost(k.by_model);
    totalCostVal += keyCost;
    totalSavingsVal += calcCacheSavings(k.by_model);

    let modelDetail = '';
    if (k.by_model && Object.keys(k.by_model).length > 0) {
      const parts = [];
      for (const [model, usage] of Object.entries(k.by_model)) {
        const shortName = model.replace('claude-', '').replace(/-\d{8}$/, '');
        parts.push('<span>' + escHtml(shortName) + ': ' + formatNumber(usage.input_tokens) + '/' + formatNumber(usage.output_tokens) + '</span>');
      }
      modelDetail = '<div class="model-detail">' + parts.join('') + '</div>';
    }

    const budgetLimit = k.budget_limit_usd || 0;
    let budgetCell;
    if (budgetLimit > 0) {
      const pct = Math.min(keyCost / budgetLimit * 100, 100);
      const color = pct >= 100 ? '#ef4444' : pct >= 80 ? '#f59e0b' : '#059669';
      budgetCell = '<td class="token-num" style="white-space:nowrap">' +
        '<div style="font-size:13px;color:' + color + '">' + formatCost(keyCost) + ' / ' + formatCost(budgetLimit) + '</div>' +
        '<div style="background:#e5e7eb;border-radius:4px;height:4px;margin-top:4px"><div style="background:' + color + ';border-radius:4px;height:4px;width:' + pct.toFixed(1) + '%"></div></div>' +
        '<a href="#" style="font-size:11px;color:#6b7280" onclick="event.preventDefault();setBudget(\'' + escAttr(k.key) + '\',' + budgetLimit + ')">edit</a>' +
        '</td>';
    } else {
      budgetCell = '<td class="token-num"><a href="#" style="font-size:12px;color:#9ca3af" onclick="event.preventDefault();setBudget(\'' + escAttr(k.key) + '\',0)">set limit</a></td>';
    }

    const lastActiveStr = k.last_active ? formatRelTime(k.last_active) : '<span style="color:#9ca3af">—</span>';
    html += '<tr>' +
      '<td><strong>' + escHtml(k.name) + '</strong></td>' +
      '<td class="mono" style="white-space:nowrap">' + escHtml(k.masked_key) + ' <a href="#" style="font-size:11px;color:#6b7280;text-decoration:none" onclick="event.preventDefault();copyKey(\'' + escAttr(k.key) + '\',this)">copy</a></td>' +
      '<td class="token-num">' + formatNumber(k.request_count) + '</td>' +
      '<td class="token-num">' + formatNumber(k.input_tokens) + modelDetail + '</td>' +
      '<td class="token-num">' + formatNumber(k.output_tokens) + '</td>' +
      '<td class="token-num">' + formatNumber(k.cache_creation_input_tokens || 0) + '</td>' +
      '<td class="token-num">' + formatNumber(k.cache_read_input_tokens || 0) + '</td>' +
      '<td class="cost-cell token-num">' + formatCost(keyCost) + '</td>' +
      budgetCell +
      '<td style="white-space:nowrap;font-size:12px;color:#6b7280">' + lastActiveStr + '</td>' +
      '<td><button class="btn btn-danger btn-sm" onclick="removeKey(\'' + escAttr(k.key) + '\',\'' + escAttr(k.name) + '\')">Delete</button></td>' +
      '</tr>';
  }
  if (keys.length === 0) {
    html = '<tr><td colspan="11" style="text-align:center;color:#9ca3af;padding:32px">No virtual keys configured</td></tr>';
  }
  tbody.innerHTML = html;

  document.getElementById('totalRequests').textContent = formatNumber(totalReq);
  document.getElementById('totalInput').textContent = formatNumber(totalIn);
  document.getElementById('totalOutput').textContent = formatNumber(totalOut);
  document.getElementById('totalCost').textContent = formatCost(totalCostVal);
  document.getElementById('totalCacheWrite').textContent = formatNumber(totalCacheW);
  document.getElementById('totalCacheRead').textContent = formatNumber(totalCacheR);
  document.getElementById('cacheSavings').textContent = formatCost(totalSavingsVal);
  const totalAllInput = totalIn + totalCacheR + totalCacheW;
  document.getElementById('cacheHitRate').textContent = totalAllInput > 0
    ? (totalCacheR / totalAllInput * 100).toFixed(1) + '%'
    : '-';
}

function showAddModal() {
  document.getElementById('newName').value = '';
  document.getElementById('newKey').value = '';
  document.getElementById('addModal').classList.add('active');
  document.getElementById('newName').focus();
}

function hideAddModal() {
  document.getElementById('addModal').classList.remove('active');
}

async function addKey() {
  const name = document.getElementById('newName').value.trim();
  const key = document.getElementById('newKey').value.trim();
  if (!name || !key) return;
  await fetch(API + '/keys', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, key })
  });
  hideAddModal();
  loadKeys();
}

async function removeKey(key, name) {
  if (!confirm('Delete key "' + name + '"?')) return;
  await fetch(API + '/keys', {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key })
  });
  loadKeys();
}

function escHtml(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function escAttr(s) {
  return s.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '\\"');
}

async function loadToken() {
  const res = await fetch(API + '/token');
  if (res.ok) {
    const data = await res.json();
    document.getElementById('currentToken').textContent = data.masked_token;
  }
}

function toggleTokenVisibility() {
  const input = document.getElementById('tokenInput');
  const btn = input.nextElementSibling;
  if (input.type === 'password') {
    input.type = 'text';
    btn.textContent = 'Hide';
  } else {
    input.type = 'password';
    btn.textContent = 'Show';
  }
}

async function updateToken() {
  const token = document.getElementById('tokenInput').value.trim();
  if (!token) return;
  const res = await fetch(API + '/token', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token })
  });
  if (res.ok) {
    const data = await res.json();
    document.getElementById('currentToken').textContent = data.masked_token;
    document.getElementById('tokenInput').value = '';
    document.getElementById('tokenInput').type = 'password';
    document.getElementById('tokenInput').nextElementSibling.textContent = 'Show';
  }
}

async function importCSV(input) {
  const file = input.files[0];
  if (!file) return;
  const text = await file.text();
  const lines = text.trim().split('\n').filter(l => l.trim() && !l.startsWith('#'));
  let added = 0, errors = 0;
  for (const line of lines) {
    const parts = line.split(',').map(s => s.trim());
    if (parts.length < 2 || !parts[0] || !parts[1]) { errors++; continue; }
    const [name, key] = parts;
    const res = await fetch(API + '/keys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, key })
    });
    if (res.ok) added++; else errors++;
  }
  input.value = '';
  alert('Imported ' + added + ' key(s)' + (errors > 0 ? ', ' + errors + ' failed' : ''));
  loadKeys();
}

async function copyKey(key, el) {
  try {
    await navigator.clipboard.writeText(key);
    const orig = el.textContent;
    el.textContent = 'copied!';
    setTimeout(() => el.textContent = orig, 1500);
  } catch(e) {
    prompt('Copy this key:', key);
  }
}

async function setBudget(key, current) {
  const val = prompt('Set budget limit in USD (0 = unlimited):', current || '');
  if (val === null) return;
  const budget = parseFloat(val);
  if (isNaN(budget) || budget < 0) { alert('Invalid amount'); return; }
  await fetch(API + '/budget', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key, budget_limit_usd: budget })
  });
  loadKeys();
}

checkSession();
</script>
</body>
</html>`
