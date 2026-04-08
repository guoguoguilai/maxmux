package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	_ "embed"
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
	Disabled        bool    `yaml:"disabled,omitempty" json:"disabled"`
}

type AdminConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Config struct {
	Port           int                `yaml:"port"`
	Upstream       string             `yaml:"upstream"`
	OAuthToken     string             `yaml:"oauth_token"`
	OAuthTokens    []string           `yaml:"oauth_tokens"`
	Admin          AdminConfig        `yaml:"admin"`
	SeedKeys       []VirtualKeyConfig `yaml:"virtual_keys"`
	FeishuWebhook  string             `yaml:"feishu_webhook"`
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
	s.db.Exec("ALTER TABLE virtual_keys ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0")

	// OAuth tokens table for multi-token support.
	_, err2 := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS oauth_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			token TEXT NOT NULL UNIQUE,
			name TEXT NOT NULL DEFAULT '',
			disabled INTEGER NOT NULL DEFAULT 0,
			sort_order INTEGER NOT NULL DEFAULT 0
		)
	`)
	if err2 != nil {
		return err2
	}
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
	rows, err := s.db.Query("SELECT key, name, budget_limit_usd, daily_limit_usd, disabled FROM virtual_keys ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []VirtualKeyConfig
	for rows.Next() {
		var k VirtualKeyConfig
		var disabled int
		if err := rows.Scan(&k.Key, &k.Name, &k.BudgetLimitUSD, &k.DailyLimitUSD, &disabled); err != nil {
			return nil, err
		}
		k.Disabled = disabled != 0
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

func (s *Store) SetDisabled(key string, disabled bool) error {
	v := 0
	if disabled {
		v = 1
	}
	_, err := s.db.Exec("UPDATE virtual_keys SET disabled = ? WHERE key = ?", v, key)
	return err
}

// --- OAuth tokens ---

type OAuthTokenEntry struct {
	ID        int    `json:"id"`
	Token     string `json:"token"`
	Name      string `json:"name"`
	Disabled  bool   `json:"disabled"`
	SortOrder int    `json:"sort_order"`
}

func (s *Store) ListOAuthTokens() ([]OAuthTokenEntry, error) {
	rows, err := s.db.Query("SELECT id, token, name, disabled, sort_order FROM oauth_tokens ORDER BY sort_order, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []OAuthTokenEntry
	for rows.Next() {
		var t OAuthTokenEntry
		var disabled int
		if err := rows.Scan(&t.ID, &t.Token, &t.Name, &disabled, &t.SortOrder); err != nil {
			return nil, err
		}
		t.Disabled = disabled != 0
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

func (s *Store) AddOAuthToken(token, name string) error {
	var maxOrder int
	s.db.QueryRow("SELECT COALESCE(MAX(sort_order), 0) FROM oauth_tokens").Scan(&maxOrder)
	_, err := s.db.Exec(
		"INSERT INTO oauth_tokens (token, name, sort_order) VALUES (?, ?, ?) ON CONFLICT(token) DO UPDATE SET name = excluded.name",
		token, name, maxOrder+1,
	)
	return err
}

func (s *Store) RemoveOAuthToken(id int) error {
	_, err := s.db.Exec("DELETE FROM oauth_tokens WHERE id = ?", id)
	return err
}

func (s *Store) SetOAuthTokenDisabled(id int, disabled bool) error {
	v := 0
	if disabled {
		v = 1
	}
	_, err := s.db.Exec("UPDATE oauth_tokens SET disabled = ? WHERE id = ?", v, id)
	return err
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

func (s *Store) QueryStats(from, to time.Time, keys []string) ([]StatsBucket, error) {
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
	if len(keys) > 0 {
		placeholders := make([]string, len(keys))
		for i, k := range keys {
			placeholders[i] = "?"
			args = append(args, k)
		}
		inClause := "virtual_key IN (" + strings.Join(placeholders, ",") + ")"
		if where == "" {
			where = "WHERE " + inClause
		} else {
			where += " AND " + inClause
		}
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
	disabled       bool
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
		m.keys[k.Key] = keyInfo{name: k.Name, budgetLimitUSD: k.BudgetLimitUSD, dailyLimitUSD: k.DailyLimitUSD, disabled: k.Disabled}
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

func (m *KeyManager) IsDisabled(key string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.keys[key].disabled
}

func (m *KeyManager) SetDisabled(key string, disabled bool) error {
	if err := m.store.SetDisabled(key, disabled); err != nil {
		return err
	}
	m.mu.Lock()
	if info, ok := m.keys[key]; ok {
		info.disabled = disabled
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
		result = append(result, VirtualKeyConfig{Name: info.name, Key: k, BudgetLimitUSD: info.budgetLimitUSD, DailyLimitUSD: info.dailyLimitUSD, Disabled: info.disabled})
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

// TokenPool manages multiple OAuth tokens with automatic failover.
// Uses the first enabled token by default; rotates to the next on 429/529 errors.
type TokenPool struct {
	mu      sync.RWMutex
	tokens  []OAuthTokenEntry
	current int // index into tokens
	store   *Store
	log     *zerolog.Logger
}

func NewTokenPool(store *Store, log *zerolog.Logger) *TokenPool {
	tp := &TokenPool{store: store, log: log}
	tp.Reload()
	return tp
}

func (tp *TokenPool) Reload() {
	tokens, err := tp.store.ListOAuthTokens()
	if err != nil {
		tp.log.Error().Err(err).Msg("failed to reload oauth tokens")
		return
	}
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.tokens = tokens
	// Reset current to first enabled token.
	tp.current = -1
	for i, t := range tp.tokens {
		if !t.Disabled {
			tp.current = i
			break
		}
	}
}

// Current returns the current active OAuth token string.
func (tp *TokenPool) Current() string {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	if tp.current >= 0 && tp.current < len(tp.tokens) {
		return tp.tokens[tp.current].Token
	}
	return ""
}

// Rotate advances to the next enabled token. Returns true if a different token is now active.
func (tp *TokenPool) Rotate() bool {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	if len(tp.tokens) <= 1 {
		return false
	}
	start := tp.current
	for i := 1; i < len(tp.tokens); i++ {
		idx := (start + i) % len(tp.tokens)
		if !tp.tokens[idx].Disabled {
			tp.current = idx
			tp.log.Warn().
				Str("from", maskToken(tp.tokens[start].Token)).
				Str("to", maskToken(tp.tokens[idx].Token)).
				Str("name", tp.tokens[idx].Name).
				Msg("rotated to next oauth token")
			return true
		}
	}
	return false // no other enabled token found
}

// Count returns total and enabled token counts.
func (tp *TokenPool) Count() (total, enabled int) {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	total = len(tp.tokens)
	for _, t := range tp.tokens {
		if !t.Disabled {
			enabled++
		}
	}
	return
}

// SetCurrent switches the active token to the one with the given ID.
func (tp *TokenPool) SetCurrent(id int) bool {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	for i, t := range tp.tokens {
		if t.ID == id {
			tp.current = i
			tp.log.Info().Int("id", id).Str("name", t.Name).Str("token", maskToken(t.Token)).Msg("manually switched active token")
			return true
		}
	}
	return false
}

type ctxStartKey struct{}

func formatTokenCount(n int64) string {
	if n >= 1_000_000 {
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	}
	if n >= 1_000 {
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	}
	return fmt.Sprintf("%d", n)
}

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

var version = "dev"

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

	// Initialize OAuth token pool.
	// Seed tokens from config into the oauth_tokens table.
	allConfigTokens := cfg.OAuthTokens
	if cfg.OAuthToken != "" {
		// Prepend the single token if not already in the list.
		found := false
		for _, t := range allConfigTokens {
			if t == cfg.OAuthToken {
				found = true
				break
			}
		}
		if !found {
			allConfigTokens = append([]string{cfg.OAuthToken}, allConfigTokens...)
		}
	}
	for i, t := range allConfigTokens {
		name := fmt.Sprintf("Token %d", i+1)
		store.AddOAuthToken(t, name)
	}
	// Migrate legacy single token from config table into oauth_tokens.
	if legacyToken, _ := store.GetConfig("oauth_token"); legacyToken != "" {
		existing, _ := store.ListOAuthTokens()
		found := false
		for _, e := range existing {
			if e.Token == legacyToken {
				found = true
				break
			}
		}
		if !found {
			store.AddOAuthToken(legacyToken, "Legacy Token")
		}
	}
	tokenPool := NewTokenPool(store, &log)
	// Also keep atomic value for backward compat with single-token GET/PUT endpoints.
	var oauthToken atomic.Value
	if cur := tokenPool.Current(); cur != "" {
		oauthToken.Store(cur)
	} else if cfg.OAuthToken != "" {
		oauthToken.Store(cfg.OAuthToken)
	} else {
		oauthToken.Store("")
	}

	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		log.Fatal().Err(err).Str("upstream", cfg.Upstream).Msg("invalid upstream URL")
	}
	totalTokens, enabledTokens := tokenPool.Count()
	currentToken := tokenPool.Current()
	if currentToken == "" {
		currentToken = oauthToken.Load().(string)
	}
	if currentToken == "" && totalTokens == 0 {
		log.Warn().Msg("no oauth tokens configured — add tokens via admin UI or config file")
	}
	log.Info().
		Int("port", cfg.Port).
		Str("upstream", cfg.Upstream).
		Int("oauth_tokens_total", totalTokens).
		Int("oauth_tokens_enabled", enabledTokens).
		Str("active_token", maskToken(currentToken)).
		Msg("starting maxmux")

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			token := tokenPool.Current()
			if token == "" {
				token = oauthToken.Load().(string)
			}
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
				if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == 529 {
					// Try rotating to the next OAuth token.
					if tokenPool.Rotate() {
						log.Warn().Int("status", resp.StatusCode).Msg("upstream rate limited — rotated to next token")
					}
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
				Disabled                 bool                      `json:"disabled"`
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
					Disabled:                 k.Disabled,
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
			keys := r.URL.Query()["keys"]
			buckets, err := store.QueryStats(from, to, keys)
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
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": version})
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

		// Update OAuth token (legacy single-token endpoint — adds to pool).
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
			// Also add to token pool.
			store.AddOAuthToken(req.Token, "Token (via settings)")
			tokenPool.Reload()
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

		// Disable/enable a key.
		if r.URL.Path == "/admin/api/keys/disable" && r.Method == http.MethodPut {
			if !requireAdmin(w, r) {
				return
			}
			var req struct {
				Key      string `json:"key"`
				Disabled bool   `json:"disabled"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
				return
			}
			if req.Key == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key is required"})
				return
			}
			if err := keyMgr.SetDisabled(req.Key, req.Disabled); err != nil {
				log.Error().Err(err).Msg("failed to set disabled")
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
				return
			}
			action := "enabled"
			if req.Disabled {
				action = "disabled"
			}
			log.Info().Str("key", maskToken(req.Key)).Str("action", action).Msg("key status changed")
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}

		// --- OAuth tokens management ---
		if r.URL.Path == "/admin/api/tokens" && r.Method == http.MethodGet {
			if !requireAdmin(w, r) {
				return
			}
			tokens, err := store.ListOAuthTokens()
			if err != nil {
				log.Error().Err(err).Msg("failed to list tokens")
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
				return
			}
			// Mask token values in response.
			type maskedToken struct {
				ID        int    `json:"id"`
				Name      string `json:"name"`
				Masked    string `json:"masked_token"`
				Disabled  bool   `json:"disabled"`
				SortOrder int    `json:"sort_order"`
				Active    bool   `json:"active"`
			}
			activeToken := tokenPool.Current()
			result := make([]maskedToken, len(tokens))
			for i, t := range tokens {
				result[i] = maskedToken{
					ID:        t.ID,
					Name:      t.Name,
					Masked:    maskToken(t.Token),
					Disabled:  t.Disabled,
					SortOrder: t.SortOrder,
					Active:    t.Token == activeToken,
				}
			}
			writeJSON(w, http.StatusOK, result)
			return
		}

		if r.URL.Path == "/admin/api/tokens" && r.Method == http.MethodPost {
			if !requireAdmin(w, r) {
				return
			}
			var req struct {
				Token string `json:"token"`
				Name  string `json:"name"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
				return
			}
			if req.Token == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token is required"})
				return
			}
			if req.Name == "" {
				req.Name = maskToken(req.Token)
			}
			if err := store.AddOAuthToken(req.Token, req.Name); err != nil {
				log.Error().Err(err).Msg("failed to add token")
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
				return
			}
			tokenPool.Reload()
			log.Info().Str("name", req.Name).Str("token", maskToken(req.Token)).Msg("oauth token added")
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}

		if r.URL.Path == "/admin/api/tokens" && r.Method == http.MethodDelete {
			if !requireAdmin(w, r) {
				return
			}
			var req struct {
				ID int `json:"id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
				return
			}
			if err := store.RemoveOAuthToken(req.ID); err != nil {
				log.Error().Err(err).Msg("failed to remove token")
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
				return
			}
			tokenPool.Reload()
			log.Info().Int("id", req.ID).Msg("oauth token removed")
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}

		if r.URL.Path == "/admin/api/tokens/disable" && r.Method == http.MethodPut {
			if !requireAdmin(w, r) {
				return
			}
			var req struct {
				ID       int  `json:"id"`
				Disabled bool `json:"disabled"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
				return
			}
			if err := store.SetOAuthTokenDisabled(req.ID, req.Disabled); err != nil {
				log.Error().Err(err).Msg("failed to set token disabled")
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
				return
			}
			tokenPool.Reload()
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}

		// Manually switch active token.
		if r.URL.Path == "/admin/api/tokens/switch" && r.Method == http.MethodPut {
			if !requireAdmin(w, r) {
				return
			}
			var req struct {
				ID int `json:"id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
				return
			}
			if !tokenPool.SetCurrent(req.ID) {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "token not found"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}

		// --- Feishu Webhook ---
		if r.URL.Path == "/admin/api/feishu" && r.Method == http.MethodPost {
			if !requireAdmin(w, r) {
				return
			}
			if cfg.FeishuWebhook == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "feishu_webhook not configured in config.yaml"})
				return
			}
			var req struct {
				Keys []string `json:"keys"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
				return
			}

			// Gather usage data for all keys, then filter.
			allUsage, err := store.QueryAll(time.Time{}, time.Now())
			if err != nil {
				log.Error().Err(err).Msg("feishu: failed to query usage")
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to query usage"})
				return
			}
			keys := keyMgr.List()
			wantAll := len(req.Keys) == 0
			wantSet := make(map[string]bool, len(req.Keys))
			for _, k := range req.Keys {
				wantSet[k] = true
			}

			type keyRow struct {
				Name      string
				Requests  int64
				Input     int64
				Output    int64
				Cost      float64
				CostToday float64
			}
			var rows []keyRow
			var totalCost float64
			for _, k := range keys {
				if !wantAll && !wantSet[k.Key] {
					continue
				}
				u := allUsage[k.Key]
				var cost float64
				for model, mu := range u.ByModel {
					inp, out := getModelPricing(model)
					cost += (float64(mu.InputTokens)*inp +
						float64(mu.OutputTokens)*out +
						float64(mu.CacheCreationInputTokens)*inp*1.25 +
						float64(mu.CacheReadInputTokens)*inp*0.1) / 1_000_000
				}
				costToday, _ := store.QueryKeyCostToday(k.Key)
				rows = append(rows, keyRow{
					Name:      k.Name,
					Requests:  u.RequestCount,
					Input:     u.InputTokens,
					Output:    u.OutputTokens,
					Cost:      math.Round(cost*10000) / 10000,
					CostToday: math.Round(costToday*10000) / 10000,
				})
				totalCost += cost
			}

			// Build Feishu interactive card using column_set for clean table layout.
			now := time.Now().UTC().Add(8 * time.Hour) // China time
			title := fmt.Sprintf("Maxmux Usage Report — %s", now.Format("2006-01-02 15:04"))

			// Helper to build a column_set row.
			makeRow := func(bgStyle string, vals [6]string, bold bool) map[string]any {
				cols := make([]any, 6)
				weights := [6]int{2, 1, 2, 2, 2, 2}
				for i, v := range vals {
					content := v
					if bold {
						content = "**" + v + "**"
					}
					cols[i] = map[string]any{
						"tag":    "column",
						"width":  "weighted",
						"weight": weights[i],
						"elements": []any{
							map[string]any{
								"tag":     "markdown",
								"content": content,
							},
						},
					}
				}
				return map[string]any{
					"tag":              "column_set",
					"flex_mode":        "none",
					"background_style": bgStyle,
					"columns":          cols,
				}
			}

			elements := []any{
				makeRow("grey", [6]string{"Name", "Reqs", "Input", "Output", "Total", "Today"}, true),
			}
			for _, r := range rows {
				costStr := fmt.Sprintf("$%.2f", r.Cost)
				if r.Cost < 0.01 {
					costStr = fmt.Sprintf("$%.4f", r.Cost)
				}
				todayStr := fmt.Sprintf("$%.2f", r.CostToday)
				if r.CostToday < 0.01 {
					todayStr = fmt.Sprintf("$%.4f", r.CostToday)
				}
				elements = append(elements, makeRow("default", [6]string{
					r.Name,
					fmt.Sprintf("%d", r.Requests),
					formatTokenCount(r.Input),
					formatTokenCount(r.Output),
					costStr,
					todayStr,
				}, false))
			}
			// Divider + total
			elements = append(elements,
				map[string]any{"tag": "hr"},
				map[string]any{
					"tag":     "markdown",
					"content": fmt.Sprintf("**Total Cost: $%.4f**", totalCost),
				},
			)

			card := map[string]any{
				"msg_type": "interactive",
				"card": map[string]any{
					"header": map[string]any{
						"title": map[string]any{
							"tag":     "plain_text",
							"content": title,
						},
						"template": "blue",
					},
					"elements": elements,
				},
			}

			cardJSON, _ := json.Marshal(card)
			resp, err := http.Post(cfg.FeishuWebhook, "application/json", bytes.NewReader(cardJSON))
			if err != nil {
				log.Error().Err(err).Msg("feishu: failed to send webhook")
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": "failed to send to feishu: " + err.Error()})
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				log.Error().Int("status", resp.StatusCode).Str("body", string(body)).Msg("feishu: webhook returned error")
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": "feishu returned " + resp.Status})
				return
			}
			log.Info().Int("keys", len(rows)).Msg("feishu: usage report sent")
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
			if keyMgr.IsDisabled(vk) {
				writeJSON(w, http.StatusOK, map[string]any{
					"is_active":      false,
					"invalidMessage": "this key has been disabled by the administrator",
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

		if keyMgr.IsDisabled(virtualKey) {
			log.Warn().
				Str("key", maskToken(virtualKey)).
				Msg("rejected — key is disabled")
			http.Error(w, `{"error":{"message":"this key has been disabled by the administrator","type":"authentication_error"}}`, http.StatusForbidden)
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


//go:embed static/index.html
var adminHTML string
