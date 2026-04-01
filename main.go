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
	Name            string  `yaml:"name" json:"name"`
	Key             string  `yaml:"key" json:"key"`
	BudgetLimitUSD  float64 `yaml:"budget_limit_usd,omitempty" json:"budget_limit_usd"`
	DailyLimitUSD   float64 `yaml:"daily_limit_usd,omitempty" json:"daily_limit_usd"`
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

// StatsBucket is one time-series data point returned by /admin/api/stats.
type StatsBucket struct {
	Time         string  `json:"time"`
	Requests     int64   `json:"requests"`
	CostUSD      float64 `json:"cost_usd"`
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
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
	// Migration: add columns if missing (for existing databases).
	s.db.Exec("ALTER TABLE virtual_keys ADD COLUMN budget_limit_usd REAL NOT NULL DEFAULT 0")
	s.db.Exec("ALTER TABLE virtual_keys ADD COLUMN daily_limit_usd REAL NOT NULL DEFAULT 0")
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
	rows, err := s.db.Query("SELECT key, name, budget_limit_usd, daily_limit_usd FROM virtual_keys ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []VirtualKeyConfig
	for rows.Next() {
		var k VirtualKeyConfig
		if err := rows.Scan(&k.Key, &k.Name, &k.BudgetLimitUSD, &k.DailyLimitUSD); err != nil {
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

func (s *Store) SetDailyLimit(key string, dailyUSD float64) error {
	_, err := s.db.Exec("UPDATE virtual_keys SET daily_limit_usd = ? WHERE key = ?", dailyUSD, key)
	return err
}

func (s *Store) GetDailyLimit(key string) float64 {
	var limit float64
	s.db.QueryRow("SELECT daily_limit_usd FROM virtual_keys WHERE key = ?", key).Scan(&limit)
	return limit
}

// QueryKeyCostToday calculates the estimated cost for a key since midnight UTC today.
func (s *Store) QueryKeyCostToday(key string) (float64, error) {
	todayUTC := time.Now().UTC().Truncate(24 * time.Hour).Format(time.RFC3339)
	rows, err := s.db.Query(
		`SELECT model,
			SUM(input_tokens), SUM(output_tokens),
			SUM(cache_creation_input_tokens), SUM(cache_read_input_tokens)
		 FROM usage_records
		 WHERE virtual_key = ? AND timestamp >= ?
		 GROUP BY model`, key, todayUTC)
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

// timeRangeWhere builds a SQL WHERE clause for an optional from/to time range.
func timeRangeWhere(from, to time.Time) (clause string, args []any) {
	var parts []string
	if !from.IsZero() {
		parts = append(parts, "timestamp >= ?")
		args = append(args, from.UTC().Format(time.RFC3339Nano))
	}
	if !to.IsZero() {
		parts = append(parts, "timestamp <= ?")
		args = append(args, to.UTC().Format(time.RFC3339Nano))
	}
	if len(parts) > 0 {
		clause = "WHERE " + strings.Join(parts, " AND ")
	}
	return
}

func (s *Store) QueryAll(from, to time.Time) (map[string]KeyStats, error) {
	where, args := timeRangeWhere(from, to)
	q := fmt.Sprintf(`SELECT virtual_key, model,
		COUNT(*) as cnt,
		SUM(input_tokens), SUM(output_tokens),
		SUM(cache_creation_input_tokens), SUM(cache_read_input_tokens),
		MAX(timestamp)
	 FROM usage_records %s
	 GROUP BY virtual_key, model`, where)
	rows, err := s.db.Query(q, args...)
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

func (s *Store) QueryStats(from, to time.Time, key string) ([]StatsBucket, error) {
	// Choose bucket granularity based on range duration.
	var bucketExpr string
	if !from.IsZero() && !to.IsZero() {
		d := to.Sub(from)
		switch {
		case d < 2*24*time.Hour:
			bucketExpr = "strftime('%Y-%m-%dT%H:00:00Z', timestamp)"
		case d < 60*24*time.Hour:
			bucketExpr = "strftime('%Y-%m-%dT00:00:00Z', timestamp)"
		default:
			bucketExpr = "strftime('%Y-%m-%dT00:00:00Z', date(timestamp, 'weekday 0', '-6 days'))"
		}
	} else if !from.IsZero() {
		d := time.Since(from)
		switch {
		case d < 2*24*time.Hour:
			bucketExpr = "strftime('%Y-%m-%dT%H:00:00Z', timestamp)"
		case d < 60*24*time.Hour:
			bucketExpr = "strftime('%Y-%m-%dT00:00:00Z', timestamp)"
		default:
			bucketExpr = "strftime('%Y-%m-%dT00:00:00Z', date(timestamp, 'weekday 0', '-6 days'))"
		}
	} else {
		// No range specified — default to daily buckets.
		bucketExpr = "strftime('%Y-%m-%dT00:00:00Z', timestamp)"
	}

	where, args := timeRangeWhere(from, to)
	if key != "" {
		if where == "" {
			where = "WHERE virtual_key = ?"
		} else {
			where += " AND virtual_key = ?"
		}
		args = append(args, key)
	}

	q := fmt.Sprintf(`SELECT %s as bucket,
		COUNT(*),
		SUM(input_tokens), SUM(output_tokens),
		SUM(cache_creation_input_tokens), SUM(cache_read_input_tokens)
	 FROM usage_records %s
	 GROUP BY bucket
	 ORDER BY bucket`, bucketExpr, where)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var buckets []StatsBucket
	for rows.Next() {
		var b StatsBucket
		var cw, cr int64
		if err := rows.Scan(&b.Time, &b.Requests, &b.InputTokens, &b.OutputTokens, &cw, &cr); err != nil {
			return nil, err
		}
		b.CostUSD = math.Round(calcModelCost("", b.InputTokens, b.OutputTokens, cw, cr)*1000000) / 1000000
		buckets = append(buckets, b)
	}
	return buckets, rows.Err()
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
	dailyLimitUSD  float64
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
		m.keys[k.Key] = keyInfo{name: k.Name, budgetLimitUSD: k.BudgetLimitUSD, dailyLimitUSD: k.DailyLimitUSD}
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

func (m *KeyManager) GetDailyLimit(key string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.keys[key].dailyLimitUSD
}

func (m *KeyManager) SetDailyLimit(key string, daily float64) error {
	if err := m.store.SetDailyLimit(key, daily); err != nil {
		return err
	}
	m.mu.Lock()
	if info, ok := m.keys[key]; ok {
		info.dailyLimitUSD = daily
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
		result = append(result, VirtualKeyConfig{Name: info.name, Key: k, BudgetLimitUSD: info.budgetLimitUSD, DailyLimitUSD: info.dailyLimitUSD})
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
	"claude-opus-4-6":            {5, 25},
	"claude-opus-4-5":            {5, 25},
	"claude-opus-4-1":            {5, 25},
	"claude-opus-4-20250514":     {5, 25},
	"claude-opus-4-0":            {5, 25},
	"claude-sonnet-4-6":          {3, 15},
	"claude-sonnet-4-5":          {3, 15},
	"claude-sonnet-4-20250514":   {3, 15},
	"claude-sonnet-4-0":          {3, 15},
	"claude-3-7-sonnet-20250219": {3, 15},
	"claude-3-5-sonnet-20241022": {3, 15},
	"claude-3-5-sonnet-20240620": {3, 15},
	"claude-haiku-4-5-20251001":  {1, 5},
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

	// parseTimeRange parses from=/to= (ISO8601) or falls back to since=<minutes>.
	parseTimeRange := func(r *http.Request) (from, to time.Time) {
		q := r.URL.Query()
		if fs := q.Get("from"); fs != "" {
			if t, err := time.Parse(time.RFC3339, fs); err == nil {
				from = t.UTC()
			}
		}
		if ts := q.Get("to"); ts != "" {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				to = t.UTC()
			}
		}
		// Fall back to since= (minutes ago) only if from not set.
		if from.IsZero() {
			if s := q.Get("since"); s != "" {
				if mins, err := strconv.ParseInt(s, 10, 64); err == nil && mins > 0 {
					from = time.Now().Add(-time.Duration(mins) * time.Minute).UTC()
				}
			}
		}
		return
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
			from, to := parseTimeRange(r)
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
				CostUSD                  float64                   `json:"cost_usd"`
				CacheSavingsUSD          float64                   `json:"cache_savings_usd"`
				BudgetLimitUSD           float64                   `json:"budget_limit_usd"`
				DailyLimitUSD            float64                   `json:"daily_limit_usd"`
				CostTodayUSD             float64                   `json:"cost_today_usd"`
				LastActive               *time.Time                `json:"last_active,omitempty"`
			}
			keys := keyMgr.List()
			allUsage, err := store.QueryAll(from, to)
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
				// Compute cost and cache savings server-side.
				var totalCost, totalSavings float64
				for model, mu := range u.ByModel {
					inp, out := getModelPricing(model)
					totalCost += (float64(mu.InputTokens)*inp +
						float64(mu.OutputTokens)*out +
						float64(mu.CacheCreationInputTokens)*inp*1.25 +
						float64(mu.CacheReadInputTokens)*inp*0.1) / 1_000_000
					// Savings: cache reads cost 0.1x vs full input price; cache writes cost 1.25x.
					// Savings from reads = (1 - 0.1) * cacheRead * inp / 1e6
					totalSavings += float64(mu.CacheReadInputTokens) * inp * 0.9 / 1_000_000
				}
				costToday, _ := store.QueryKeyCostToday(k.Key)
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
					CostUSD:                  math.Round(totalCost*1000000) / 1000000,
					CacheSavingsUSD:          math.Round(totalSavings*1000000) / 1000000,
					BudgetLimitUSD:           k.BudgetLimitUSD,
					DailyLimitUSD:            k.DailyLimitUSD,
					CostTodayUSD:             math.Round(costToday*1000000) / 1000000,
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

		if r.URL.Path == "/admin/api/stats" && r.Method == http.MethodGet {
			if !requireAdmin(w, r) {
				return
			}
			from, to := parseTimeRange(r)
			key := r.URL.Query().Get("key")
			buckets, err := store.QueryStats(from, to, key)
			if err != nil {
				log.Error().Err(err).Msg("failed to query stats")
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
				return
			}
			if buckets == nil {
				buckets = []StatsBucket{}
			}
			writeJSON(w, http.StatusOK, buckets)
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
				DailyLimitUSD  float64 `json:"daily_limit_usd"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
				return
			}
			if req.Key == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key is required"})
				return
			}
			if req.BudgetLimitUSD < 0 || req.DailyLimitUSD < 0 {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limits must be >= 0"})
				return
			}
			if err := keyMgr.SetBudget(req.Key, req.BudgetLimitUSD); err != nil {
				log.Error().Err(err).Msg("failed to set budget")
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
				return
			}
			if err := keyMgr.SetDailyLimit(req.Key, req.DailyLimitUSD); err != nil {
				log.Error().Err(err).Msg("failed to set daily limit")
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
				return
			}
			log.Info().Str("key", maskToken(req.Key)).Float64("budget", req.BudgetLimitUSD).Float64("daily", req.DailyLimitUSD).Msg("limits updated")
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
		if daily := keyMgr.GetDailyLimit(virtualKey); daily > 0 {
			costToday, err := store.QueryKeyCostToday(virtualKey)
			if err != nil {
				log.Error().Err(err).Msg("failed to query daily cost")
			} else if costToday >= daily {
				log.Warn().
					Str("key", maskToken(virtualKey)).
					Float64("cost_today", costToday).
					Float64("daily_limit", daily).
					Msg("rejected — daily limit exceeded")
				http.Error(w, `{"error":{"message":"daily budget limit exceeded","type":"rate_limit_error"}}`, http.StatusTooManyRequests)
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
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600&family=Fira+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Fira Sans', -apple-system, BlinkMacSystemFont, sans-serif; background: #0d1117; color: #e6edf3; min-height: 100vh; font-size: 14px; }

  /* ── Login ── */
  .login-container { display: flex; justify-content: center; align-items: center; min-height: 100vh; background: #0d1117; }
  .login-box { background: #161b22; border: 1px solid #30363d; padding: 40px; border-radius: 12px; width: 360px; }
  .login-logo { font-family: 'Fira Code', monospace; font-size: 22px; font-weight: 600; color: #58a6ff; margin-bottom: 6px; letter-spacing: -0.5px; }
  .login-sub { color: #8b949e; margin-bottom: 28px; font-size: 13px; }
  .form-group { margin-bottom: 16px; }
  .form-group label { display: block; font-size: 12px; font-weight: 500; margin-bottom: 6px; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; }
  .form-group input { width: 100%; padding: 9px 12px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; font-size: 14px; color: #e6edf3; outline: none; transition: border-color 0.15s; font-family: inherit; }
  .form-group input:focus { border-color: #58a6ff; box-shadow: 0 0 0 3px rgba(88,166,255,0.1); }
  .btn { padding: 8px 16px; border: none; border-radius: 6px; font-size: 13px; font-weight: 500; cursor: pointer; transition: all 0.15s; font-family: inherit; white-space: nowrap; }
  .btn-primary { background: #238636; color: #fff; }
  .btn-primary:hover { background: #2ea043; }
  .btn-blue { background: #1f6feb; color: #fff; }
  .btn-blue:hover { background: #388bfd; }
  .btn-danger { background: #da3633; color: #fff; }
  .btn-danger:hover { background: #f85149; }
  .btn-secondary { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; }
  .btn-secondary:hover { background: #30363d; }
  .btn-sm { padding: 5px 10px; font-size: 12px; }
  .btn-login { width: 100%; padding: 10px; font-size: 14px; margin-top: 4px; }
  .error-msg { color: #f85149; font-size: 12px; margin-top: 10px; display: none; background: rgba(248,81,73,0.1); padding: 8px 12px; border-radius: 6px; border: 1px solid rgba(248,81,73,0.2); }

  /* ── Layout ── */
  .dashboard { display: none; }
  .header { background: #161b22; border-bottom: 1px solid #21262d; padding: 12px 24px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; position: sticky; top: 0; z-index: 50; }
  .header-left { display: flex; align-items: center; gap: 16px; }
  .header-logo { font-family: 'Fira Code', monospace; font-size: 16px; font-weight: 600; color: #58a6ff; letter-spacing: -0.5px; }
  .header-right { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .content { max-width: 1280px; margin: 24px auto; padding: 0 24px; }

  /* ── Time filter ── */
  .time-filter { display: flex; gap: 4px; align-items: center; flex-wrap: wrap; }
  .time-filter button { padding: 4px 10px; border: 1px solid #30363d; border-radius: 6px; background: transparent; font-size: 12px; cursor: pointer; color: #8b949e; transition: all 0.15s; font-family: 'Fira Code', monospace; }
  .time-filter button:hover { background: #21262d; color: #e6edf3; border-color: #58a6ff; }
  .time-filter button.active { background: #1f6feb; color: #fff; border-color: #1f6feb; }
  .datetime-range { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin-top: 6px; }
  .datetime-range label { font-size: 11px; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; }
  .datetime-range input[type="datetime-local"] { padding: 4px 8px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; font-size: 12px; color: #e6edf3; font-family: 'Fira Code', monospace; outline: none; color-scheme: dark; }
  .datetime-range input[type="datetime-local"]:focus { border-color: #58a6ff; }

  /* ── Charts ── */
  .charts-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
  .chart-card { background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 20px; }
  .chart-card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
  .chart-card-header h3 { font-size: 13px; font-weight: 600; color: #e6edf3; }
  .chart-select { padding: 4px 8px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; font-size: 12px; color: #e6edf3; font-family: inherit; outline: none; cursor: pointer; }
  .chart-select:focus { border-color: #58a6ff; }
  .chart-canvas { width: 100%; height: 200px; display: block; }
  .chart-legend { display: flex; gap: 12px; margin-top: 8px; flex-wrap: wrap; }
  .legend-item { display: flex; align-items: center; gap: 4px; font-size: 11px; color: #8b949e; }
  .legend-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; flex-shrink: 0; }

  /* ── Stats ── */
  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 16px; }
  .stat-card { background: #161b22; border: 1px solid #21262d; padding: 16px 20px; border-radius: 8px; }
  .stat-card .label { font-size: 11px; color: #8b949e; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.05em; }
  .stat-card .value { font-size: 24px; font-weight: 600; font-family: 'Fira Code', monospace; color: #e6edf3; }
  .stat-card .value.cost { color: #3fb950; }
  .stat-card .value.savings { color: #58a6ff; }

  /* ── Section / Table ── */
  .section { background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 20px; margin-bottom: 16px; }
  .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
  .section-header h2 { font-size: 14px; font-weight: 600; color: #e6edf3; }
  .section-actions { display: flex; gap: 8px; align-items: center; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 8px 12px; font-size: 11px; font-weight: 500; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid #21262d; }
  td { padding: 12px 12px; border-bottom: 1px solid #161b22; font-size: 13px; vertical-align: middle; }
  tr:hover td { background: #1c2128; }
  tr:last-child td { border-bottom: none; }
  .mono { font-family: 'Fira Code', monospace; font-size: 12px; color: #8b949e; }
  .cost-cell { color: #3fb950; font-weight: 500; font-family: 'Fira Code', monospace; }
  .name-cell { font-weight: 500; color: #e6edf3; }
  .model-detail { font-size: 11px; color: #6e7681; margin-top: 3px; }
  .model-detail span { margin-right: 8px; }

  /* ── Budget bar ── */
  .budget-wrap { min-width: 120px; }
  .budget-nums { font-size: 12px; font-family: 'Fira Code', monospace; margin-bottom: 4px; display: flex; justify-content: space-between; align-items: baseline; gap: 6px; }
  .budget-bar-bg { background: #21262d; border-radius: 3px; height: 4px; overflow: hidden; }
  .budget-bar-fill { height: 4px; border-radius: 3px; transition: width 0.3s; }
  .budget-label { font-size: 11px; color: #6e7681; margin-top: 3px; }
  .limit-edit { font-size: 11px; color: #58a6ff; text-decoration: none; cursor: pointer; background: none; border: none; padding: 0; font-family: inherit; }
  .limit-edit:hover { text-decoration: underline; }

  /* ── Tag / badge ── */
  .tag { display: inline-block; padding: 2px 7px; border-radius: 4px; font-size: 11px; font-weight: 500; }
  .tag-green { background: rgba(63,185,80,0.15); color: #3fb950; }
  .tag-yellow { background: rgba(210,153,34,0.15); color: #d29922; }
  .tag-red { background: rgba(248,81,73,0.15); color: #f85149; }
  .tag-gray { background: rgba(110,118,129,0.15); color: #6e7681; }

  /* ── Modal ── */
  .modal-overlay { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.6); z-index: 200; justify-content: center; align-items: center; }
  .modal-overlay.active { display: flex; }
  .modal { background: #161b22; border: 1px solid #30363d; padding: 28px; border-radius: 10px; width: 420px; box-shadow: 0 16px 48px rgba(0,0,0,0.5); }
  .modal h2 { margin-bottom: 20px; font-size: 16px; color: #e6edf3; }
  .modal .form-group { margin-bottom: 14px; }
  .modal .form-group:last-of-type { margin-bottom: 20px; }
  .modal-actions { display: flex; gap: 8px; justify-content: flex-end; }
  .modal-hint { font-size: 12px; color: #6e7681; margin-top: 5px; }
  .input-row { display: flex; gap: 8px; }
  .input-row input { flex: 1; }

  /* ── Settings ── */
  .settings-row { display: flex; gap: 8px; align-items: center; }
  .settings-row input { flex: 1; padding: 8px 12px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; font-size: 13px; color: #e6edf3; font-family: 'Fira Code', monospace; outline: none; }
  .settings-row input:focus { border-color: #58a6ff; }
  .token-current { font-size: 12px; color: #6e7681; margin-top: 6px; }
  .token-current span { color: #8b949e; font-family: 'Fira Code', monospace; }

  /* ── Toast ── */
  .toast { position: fixed; bottom: 24px; right: 24px; background: #1f2937; border: 1px solid #374151; color: #e6edf3; padding: 10px 16px; border-radius: 8px; font-size: 13px; z-index: 999; opacity: 0; transform: translateY(8px); transition: all 0.2s; pointer-events: none; }
  .toast.show { opacity: 1; transform: translateY(0); }

  .token-num { font-variant-numeric: tabular-nums; }

  @media (max-width: 900px) {
    .stats { grid-template-columns: repeat(2, 1fr); }
    .charts-grid { grid-template-columns: 1fr; }
    .content { padding: 0 16px; }
    th, td { padding: 8px; font-size: 12px; }
  }
  @media (max-width: 500px) {
    .stats { grid-template-columns: 1fr 1fr; }
    .modal { width: calc(100vw - 32px); }
  }
</style>
</head>
<body>

<div class="login-container" id="loginPage">
  <div class="login-box">
    <div class="login-logo">maxmux</div>
    <div class="login-sub">Admin Dashboard</div>
    <div class="form-group">
      <label>Username</label>
      <input type="text" id="username" autocomplete="username">
    </div>
    <div class="form-group">
      <label>Password</label>
      <input type="password" id="password" autocomplete="current-password">
    </div>
    <button class="btn btn-blue btn-login" onclick="login()">Sign In</button>
    <div class="error-msg" id="loginError">Invalid username or password</div>
  </div>
</div>

<div class="dashboard" id="dashboard">
  <div class="header">
    <div class="header-left">
      <span class="header-logo">maxmux</span>
      <div class="time-filter" id="timeFilter">
        <button data-preset="5m" onclick="setPreset(this)">5m</button>
        <button data-preset="1h" onclick="setPreset(this)">1h</button>
        <button data-preset="1d" onclick="setPreset(this)">1d</button>
        <button data-preset="7d" onclick="setPreset(this)">7d</button>
        <button data-preset="30d" onclick="setPreset(this)">30d</button>
        <button data-preset="all" class="active" onclick="setPreset(this)">All</button>
      </div>
      <div class="datetime-range">
        <label>From</label>
        <input type="datetime-local" id="dtFrom" onchange="applyDateRange()">
        <label>To</label>
        <input type="datetime-local" id="dtTo" onchange="applyDateRange()">
      </div>
    </div>
    <div class="header-right">
      <button class="btn btn-secondary btn-sm" onclick="logout()">Sign Out</button>
    </div>
  </div>
  <div class="content">
    <div class="stats">
      <div class="stat-card">
        <div class="label">Requests</div>
        <div class="value token-num" id="totalRequests">0</div>
      </div>
      <div class="stat-card">
        <div class="label">Input Tokens</div>
        <div class="value token-num" id="totalInput">0</div>
      </div>
      <div class="stat-card">
        <div class="label">Output Tokens</div>
        <div class="value token-num" id="totalOutput">0</div>
      </div>
      <div class="stat-card">
        <div class="label">Est. Cost</div>
        <div class="value cost token-num" id="totalCost">$0.00</div>
      </div>
    </div>
    <div class="stats">
      <div class="stat-card">
        <div class="label">Cache Write</div>
        <div class="value token-num" id="totalCacheWrite">0</div>
      </div>
      <div class="stat-card">
        <div class="label">Cache Read</div>
        <div class="value token-num" id="totalCacheRead">0</div>
      </div>
      <div class="stat-card">
        <div class="label">Cache Hit Rate</div>
        <div class="value token-num" id="cacheHitRate">—</div>
      </div>
      <div class="stat-card">
        <div class="label">Cache Savings</div>
        <div class="value savings token-num" id="cacheSavings">$0.00</div>
      </div>
    </div>
    <div class="charts-grid">
      <div class="chart-card">
        <div class="chart-card-header">
          <span>Requests &amp; Cost Over Time</span>
          <select class="chart-select" id="keyFilter" onchange="loadStats()">
            <option value="">All Keys</option>
          </select>
        </div>
        <canvas class="chart-canvas" id="timeseriesChart"></canvas>
      </div>
      <div class="chart-card">
        <div class="chart-card-header">
          <span>Cost by Key</span>
        </div>
        <canvas class="chart-canvas" id="distributionChart"></canvas>
        <div class="chart-legend" id="distributionLegend"></div>
      </div>
    </div>
    <div class="section">
      <div class="section-header">
        <h2>Virtual Keys</h2>
        <div class="section-actions">
          <label class="btn btn-secondary btn-sm" style="cursor:pointer">Import CSV<input type="file" accept=".csv,.txt" style="display:none" onchange="importCSV(this)"></label>
          <button class="btn btn-blue btn-sm" onclick="showAddModal()">+ Add Key</button>
        </div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Key</th>
            <th>Requests</th>
            <th>Input</th>
            <th>Output</th>
            <th>Est. Cost</th>
            <th>Total Budget</th>
            <th>Daily Budget</th>
            <th>Last Active</th>
            <th></th>
          </tr>
        </thead>
        <tbody id="keysTable"></tbody>
      </table>
    </div>
    <div class="section">
      <div class="section-header"><h2>Settings</h2></div>
      <div class="form-group" style="max-width:480px">
        <label>OAuth Token</label>
        <div class="settings-row">
          <input type="password" id="tokenInput" placeholder="Paste new token">
          <button class="btn btn-secondary btn-sm" onclick="toggleTokenVisibility()">Show</button>
          <button class="btn btn-blue btn-sm" onclick="updateToken()">Save</button>
        </div>
        <div class="token-current">Current: <span id="currentToken">—</span></div>
      </div>
    </div>
  </div>
</div>

<!-- Add Key Modal -->
<div class="modal-overlay" id="addModal">
  <div class="modal">
    <h2>Add Virtual Key</h2>
    <div class="form-group">
      <label>Name</label>
      <input type="text" id="newName" placeholder="e.g. Alice">
    </div>
    <div class="form-group">
      <label>Key</label>
      <input type="text" id="newKey" placeholder="e.g. sk-ant-...">
    </div>
    <div class="modal-actions">
      <button class="btn btn-secondary" onclick="hideAddModal()">Cancel</button>
      <button class="btn btn-blue" onclick="addKey()">Add Key</button>
    </div>
  </div>
</div>

<!-- Budget Modal -->
<div class="modal-overlay" id="budgetModal">
  <div class="modal">
    <h2 id="budgetModalTitle">Set Limits</h2>
    <input type="hidden" id="budgetKey">
    <div class="form-group">
      <label>Total Budget (USD)</label>
      <input type="number" id="budgetTotal" placeholder="0 = unlimited" min="0" step="0.01">
      <div class="modal-hint">Cumulative all-time spending cap. 0 = no limit.</div>
    </div>
    <div class="form-group">
      <label>Daily Limit (USD)</label>
      <input type="number" id="budgetDaily" placeholder="0 = unlimited" min="0" step="0.01">
      <div class="modal-hint">Resets at midnight UTC each day. 0 = no limit.</div>
    </div>
    <div class="modal-actions">
      <button class="btn btn-secondary" onclick="hideBudgetModal()">Cancel</button>
      <button class="btn btn-blue" onclick="saveBudget()">Save</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const API = '/admin/api';
let refreshTimer;
let currentFrom = ''; // ISO string or ''
let currentTo = '';   // ISO string or ''


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

function toDatetimeLocal(d) {
  // Convert Date to datetime-local string (local time, no seconds)
  const pad = n => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + pad(d.getMonth()+1) + '-' + pad(d.getDate()) +
         'T' + pad(d.getHours()) + ':' + pad(d.getMinutes());
}

function fromDatetimeLocal(s) {
  return s ? new Date(s).toISOString() : '';
}

function buildRangeParams() {
  const p = new URLSearchParams();
  if (currentFrom) p.set('from', currentFrom);
  if (currentTo) p.set('to', currentTo);
  return p.toString() ? '?' + p.toString() : '';
}

function setPreset(el) {
  document.querySelectorAll('.time-filter button[data-preset]').forEach(b => b.classList.remove('active'));
  el.classList.add('active');
  const preset = el.dataset.preset;
  const now = new Date();
  let from = null;
  if (preset === '5m')  from = new Date(now - 5*60*1000);
  else if (preset === '1h')  from = new Date(now - 60*60*1000);
  else if (preset === '1d')  from = new Date(now - 24*60*60*1000);
  else if (preset === '7d')  from = new Date(now - 7*24*60*60*1000);
  else if (preset === '30d') from = new Date(now - 30*24*60*60*1000);
  // 'all' => from = null
  currentFrom = from ? from.toISOString() : '';
  currentTo = '';
  document.getElementById('dtFrom').value = from ? toDatetimeLocal(from) : '';
  document.getElementById('dtTo').value = '';
  loadAll();
}

function applyDateRange() {
  const fromStr = document.getElementById('dtFrom').value;
  const toStr = document.getElementById('dtTo').value;
  currentFrom = fromDatetimeLocal(fromStr);
  currentTo = fromDatetimeLocal(toStr);
  // Deselect preset buttons
  document.querySelectorAll('.time-filter button[data-preset]').forEach(b => b.classList.remove('active'));
  loadAll();
}

function loadAll() {
  loadKeys();
  loadStats();
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
  loadAll();
  loadToken();
  refreshTimer = setInterval(loadAll, 30000);
}

async function loadKeys() {
  const url = API + '/keys' + buildRangeParams();
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
    const keyCost = k.cost_usd || 0;
    totalCostVal += keyCost;
    totalSavingsVal += k.cache_savings_usd || 0;

    let modelDetail = '';
    if (k.by_model && Object.keys(k.by_model).length > 0) {
      const parts = [];
      for (const [model, usage] of Object.entries(k.by_model)) {
        const shortName = model.replace('claude-', '').replace(/-\d{8}$/, '');
        parts.push('<span>' + escHtml(shortName) + ': ' + formatNumber(usage.input_tokens) + '/' + formatNumber(usage.output_tokens) + '</span>');
      }
      modelDetail = '<div class="model-detail">' + parts.join('') + '</div>';
    }

    // Total budget cell
    const budgetLimit = k.budget_limit_usd || 0;
    let totalBudgetCell;
    if (budgetLimit > 0) {
      const pct = Math.min(keyCost / budgetLimit * 100, 100);
      const barColor = pct >= 100 ? '#f85149' : pct >= 80 ? '#d29922' : '#3fb950';
      totalBudgetCell = '<td><div class="budget-wrap">' +
        '<div class="budget-nums"><span style="color:' + barColor + '">' + formatCost(keyCost) + '</span><span style="color:#6e7681">/ ' + formatCost(budgetLimit) + '</span></div>' +
        '<div class="budget-bar-bg"><div class="budget-bar-fill" style="width:' + pct.toFixed(1) + '%;background:' + barColor + '"></div></div>' +
        '<button class="limit-edit" onclick="showBudgetModal(\'' + escAttr(k.key) + '\',\'' + escAttr(k.name) + '\',' + budgetLimit + ',' + (k.daily_limit_usd||0) + ')">edit</button>' +
        '</div></td>';
    } else {
      totalBudgetCell = '<td><button class="limit-edit" onclick="showBudgetModal(\'' + escAttr(k.key) + '\',\'' + escAttr(k.name) + '\',0,' + (k.daily_limit_usd||0) + ')">set limit</button></td>';
    }

    // Daily budget cell
    const dailyLimit = k.daily_limit_usd || 0;
    const costToday = k.cost_today_usd || 0;
    let dailyBudgetCell;
    if (dailyLimit > 0) {
      const dpct = Math.min(costToday / dailyLimit * 100, 100);
      const dcolor = dpct >= 100 ? '#f85149' : dpct >= 80 ? '#d29922' : '#58a6ff';
      dailyBudgetCell = '<td><div class="budget-wrap">' +
        '<div class="budget-nums"><span style="color:' + dcolor + '">' + formatCost(costToday) + '</span><span style="color:#6e7681">/ ' + formatCost(dailyLimit) + '</span></div>' +
        '<div class="budget-bar-bg"><div class="budget-bar-fill" style="width:' + dpct.toFixed(1) + '%;background:' + dcolor + '"></div></div>' +
        '<button class="limit-edit" onclick="showBudgetModal(\'' + escAttr(k.key) + '\',\'' + escAttr(k.name) + '\',' + budgetLimit + ',' + dailyLimit + ')">edit</button>' +
        '</div></td>';
    } else {
      dailyBudgetCell = '<td><button class="limit-edit" onclick="showBudgetModal(\'' + escAttr(k.key) + '\',\'' + escAttr(k.name) + '\',' + budgetLimit + ',0)">set limit</button></td>';
    }

    const lastActiveStr = k.last_active ? formatRelTime(k.last_active) : '<span style="color:#6e7681">—</span>';
    html += '<tr>' +
      '<td class="name-cell">' + escHtml(k.name) + '</td>' +
      '<td class="mono" style="white-space:nowrap">' + escHtml(k.masked_key) + ' <button class="limit-edit" onclick="copyKey(\'' + escAttr(k.key) + '\',this)">copy</button></td>' +
      '<td class="token-num">' + formatNumber(k.request_count) + '</td>' +
      '<td class="token-num">' + formatNumber(k.input_tokens) + modelDetail + '</td>' +
      '<td class="token-num">' + formatNumber(k.output_tokens) + '</td>' +
      '<td class="cost-cell token-num">' + formatCost(keyCost) + '</td>' +
      totalBudgetCell +
      dailyBudgetCell +
      '<td style="white-space:nowrap;font-size:12px;color:#6e7681">' + lastActiveStr + '</td>' +
      '<td><button class="btn btn-danger btn-sm" onclick="removeKey(\'' + escAttr(k.key) + '\',\'' + escAttr(k.name) + '\')">Delete</button></td>' +
      '</tr>';
  }
  if (keys.length === 0) {
    html = '<tr><td colspan="10" style="text-align:center;color:#6e7681;padding:40px">No virtual keys configured</td></tr>';
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
  // Also refresh key filter dropdown while keeping current selection.
  populateKeyFilter(keys);
}

let _lastKeys = [];
function populateKeyFilter(keys) {
  _lastKeys = keys;
  const sel = document.getElementById('keyFilter');
  const prev = sel.value;
  sel.innerHTML = '<option value="">All Keys</option>';
  for (const k of keys) {
    const opt = document.createElement('option');
    opt.value = k.key;
    opt.textContent = k.name;
    sel.appendChild(opt);
  }
  if ([...sel.options].some(o => o.value === prev)) sel.value = prev;
}

async function loadStats() {
  const p = new URLSearchParams();
  if (currentFrom) p.set('from', currentFrom);
  if (currentTo) p.set('to', currentTo);
  const keyFilter = document.getElementById('keyFilter');
  if (keyFilter && keyFilter.value) p.set('key', keyFilter.value);
  const qs = p.toString() ? '?' + p.toString() : '';
  let res;
  try { res = await fetch(API + '/stats' + qs); } catch(e) { return; }
  if (!res.ok) return;
  const buckets = await res.json();
  renderTimeseriesChart(buckets);
  renderDistributionChart(_lastKeys, keyFilter ? keyFilter.value : '');
}

function formatBucketLabel(isoStr) {
  const d = new Date(isoStr);
  // Detect granularity from string: contains 'T' and non-zero hour → hourly
  if (isoStr.includes('T') && isoStr.slice(11, 13) !== '00') {
    return (d.getMonth()+1) + '/' + d.getDate() + ' ' + String(d.getHours()).padStart(2,'0') + ':00';
  }
  return (d.getMonth()+1) + '/' + d.getDate();
}

function renderTimeseriesChart(buckets) {
  const canvas = document.getElementById('timeseriesChart');
  if (!canvas) return;
  canvas._lastBuckets = buckets;
  const dpr = window.devicePixelRatio || 1;
  const W = canvas.offsetWidth || 400;
  const H = canvas.offsetHeight || 200;
  canvas.width = W * dpr;
  canvas.height = H * dpr;
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);

  const PAD = { top: 20, right: 55, bottom: 36, left: 55 };
  const cw = W - PAD.left - PAD.right;
  const ch = H - PAD.top - PAD.bottom;

  ctx.clearRect(0, 0, W, H);

  if (!buckets || buckets.length === 0) {
    ctx.fillStyle = '#6e7681';
    ctx.font = '13px "Fira Code", monospace';
    ctx.textAlign = 'center';
    ctx.fillText('No data for selected range', W/2, H/2);
    return;
  }

  const maxReq = Math.max(...buckets.map(b => b.requests), 1);
  const maxCost = Math.max(...buckets.map(b => b.cost_usd), 0.000001);
  const n = buckets.length;

  // Grid lines
  ctx.strokeStyle = '#21262d';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = PAD.top + (ch / 4) * i;
    ctx.beginPath(); ctx.moveTo(PAD.left, y); ctx.lineTo(PAD.left + cw, y); ctx.stroke();
  }

  // Left axis labels (requests, blue)
  ctx.fillStyle = '#58a6ff';
  ctx.font = '10px "Fira Code", monospace';
  ctx.textAlign = 'right';
  for (let i = 0; i <= 4; i++) {
    const val = Math.round(maxReq * (1 - i/4));
    ctx.fillText(val, PAD.left - 4, PAD.top + (ch/4)*i + 4);
  }

  // Right axis labels (cost, green)
  ctx.fillStyle = '#3fb950';
  ctx.textAlign = 'left';
  for (let i = 0; i <= 4; i++) {
    const val = (maxCost * (1 - i/4));
    const label = val < 0.01 ? '$' + val.toFixed(4) : '$' + val.toFixed(2);
    ctx.fillText(label, PAD.left + cw + 4, PAD.top + (ch/4)*i + 4);
  }

  function xPos(i) { return PAD.left + (n === 1 ? cw/2 : (i / (n-1)) * cw); }

  // Requests line (blue)
  ctx.strokeStyle = '#58a6ff';
  ctx.lineWidth = 2;
  ctx.beginPath();
  buckets.forEach((b, i) => {
    const x = xPos(i);
    const y = PAD.top + ch * (1 - b.requests / maxReq);
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.stroke();

  // Cost line (green)
  ctx.strokeStyle = '#3fb950';
  ctx.lineWidth = 2;
  ctx.beginPath();
  buckets.forEach((b, i) => {
    const x = xPos(i);
    const y = PAD.top + ch * (1 - b.cost_usd / maxCost);
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.stroke();

  // X axis labels (sparse, max 8)
  ctx.fillStyle = '#8b949e';
  ctx.textAlign = 'center';
  ctx.font = '10px "Fira Code", monospace';
  const step = Math.ceil(n / 8);
  for (let i = 0; i < n; i += step) {
    const x = xPos(i);
    ctx.fillText(formatBucketLabel(buckets[i].time), x, PAD.top + ch + 18);
  }
  // Always label last bucket
  if ((n-1) % step !== 0) {
    ctx.fillText(formatBucketLabel(buckets[n-1].time), xPos(n-1), PAD.top + ch + 18);
  }
}

function renderDistributionChart(keys, filterKey) {
  const canvas = document.getElementById('distributionChart');
  const legend = document.getElementById('distributionLegend');
  if (!canvas) return;

  const data = filterKey
    ? keys.filter(k => k.key === filterKey)
    : keys.filter(k => (k.cost_usd || 0) > 0);

  const dpr = window.devicePixelRatio || 1;
  const W = canvas.offsetWidth || 400;
  const H = canvas.offsetHeight || 160;
  canvas.width = W * dpr;
  canvas.height = H * dpr;
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, W, H);

  if (data.length === 0) {
    ctx.fillStyle = '#6e7681';
    ctx.font = '13px "Fira Code", monospace';
    ctx.textAlign = 'center';
    ctx.fillText('No cost data', W/2, H/2);
    if (legend) legend.innerHTML = '';
    return;
  }

  const BAR_COLORS = ['#58a6ff','#3fb950','#d29922','#f85149','#bc8cff','#79c0ff','#56d364','#ffa657'];
  const PAD = { top: 12, right: 12, bottom: 28, left: 48 };
  const cw = W - PAD.left - PAD.right;
  const ch = H - PAD.top - PAD.bottom;
  const maxCost = Math.max(...data.map(k => k.cost_usd || 0), 0.000001);
  const barW = Math.max(4, cw / data.length * 0.6);
  const gap = cw / data.length;

  // Grid
  ctx.strokeStyle = '#21262d';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 3; i++) {
    const y = PAD.top + (ch/3)*i;
    ctx.beginPath(); ctx.moveTo(PAD.left, y); ctx.lineTo(PAD.left+cw, y); ctx.stroke();
  }

  // Left axis
  ctx.fillStyle = '#8b949e';
  ctx.font = '10px "Fira Code", monospace';
  ctx.textAlign = 'right';
  for (let i = 0; i <= 3; i++) {
    const val = maxCost * (1 - i/3);
    ctx.fillText(val < 0.01 ? '$'+val.toFixed(4) : '$'+val.toFixed(2), PAD.left-4, PAD.top+(ch/3)*i+4);
  }

  // Bars
  data.forEach((k, i) => {
    const cost = k.cost_usd || 0;
    const barH = ch * (cost / maxCost);
    const x = PAD.left + gap * (i + 0.5) - barW/2;
    const y = PAD.top + ch - barH;
    ctx.fillStyle = BAR_COLORS[i % BAR_COLORS.length];
    ctx.beginPath();
    ctx.roundRect ? ctx.roundRect(x, y, barW, barH, [3,3,0,0]) : ctx.rect(x, y, barW, barH);
    ctx.fill();
    // X label
    ctx.fillStyle = '#8b949e';
    ctx.textAlign = 'center';
    ctx.font = '10px "Fira Code", monospace';
    const label = k.name.length > 8 ? k.name.slice(0, 7) + '…' : k.name;
    ctx.fillText(label, PAD.left + gap*(i+0.5), PAD.top+ch+16);
  });

  // Legend
  if (legend) {
    legend.innerHTML = data.map((k, i) =>
      '<span class="legend-item"><span class="legend-dot" style="background:' + BAR_COLORS[i%BAR_COLORS.length] + '"></span>' +
      escHtml(k.name) + ': ' + formatCost(k.cost_usd||0) + '</span>'
    ).join('');
  }
}

// Redraw charts on container resize
if (window.ResizeObserver) {
  const ro = new ResizeObserver(() => {
    const el = document.getElementById('timeseriesChart');
    if (el && el._lastBuckets) renderTimeseriesChart(el._lastBuckets);
    renderDistributionChart(_lastKeys, document.getElementById('keyFilter')?.value || '');
  });
  document.querySelectorAll('.chart-card').forEach(c => ro.observe(c));
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
  if (!confirm('Delete key "' + name + '"? This will also delete all usage history.')) return;
  await fetch(API + '/keys', {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key })
  });
  showToast('Key "' + name + '" deleted');
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
    showToast('Copy failed — check clipboard permissions');
  }
}

function showBudgetModal(key, name, currentTotal, currentDaily) {
  document.getElementById('budgetKey').value = key;
  document.getElementById('budgetModalTitle').textContent = 'Limits — ' + name;
  document.getElementById('budgetTotal').value = currentTotal > 0 ? currentTotal : '';
  document.getElementById('budgetDaily').value = currentDaily > 0 ? currentDaily : '';
  document.getElementById('budgetModal').classList.add('active');
  document.getElementById('budgetTotal').focus();
}

function hideBudgetModal() {
  document.getElementById('budgetModal').classList.remove('active');
}

async function saveBudget() {
  const key = document.getElementById('budgetKey').value;
  const totalVal = document.getElementById('budgetTotal').value;
  const dailyVal = document.getElementById('budgetDaily').value;
  const budget = totalVal === '' ? 0 : parseFloat(totalVal);
  const daily = dailyVal === '' ? 0 : parseFloat(dailyVal);
  if (isNaN(budget) || budget < 0 || isNaN(daily) || daily < 0) {
    showToast('Invalid amount — must be 0 or positive');
    return;
  }
  await fetch(API + '/budget', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key, budget_limit_usd: budget, daily_limit_usd: daily })
  });
  hideBudgetModal();
  showToast('Limits saved');
  loadKeys();
}

let toastTimer;
function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 3000);
}

// Close modals on overlay click
document.getElementById('addModal').addEventListener('click', e => { if (e.target === e.currentTarget) hideAddModal(); });
document.getElementById('budgetModal').addEventListener('click', e => { if (e.target === e.currentTarget) hideBudgetModal(); });

// Enter key in budget modal
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') { hideAddModal(); hideBudgetModal(); }
});

checkSession();
</script>
</body>
</html>`
