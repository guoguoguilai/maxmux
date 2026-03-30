package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
	"gopkg.in/yaml.v3"
)

// VirtualKeyConfig represents a virtual key with a human-readable name.
type VirtualKeyConfig struct {
	Name string `yaml:"name" json:"name"`
	Key  string `yaml:"key" json:"key"`
}

type AdminConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Config struct {
	Port        int                `yaml:"port"`
	Upstream    string             `yaml:"upstream"`
	OAuthToken  string             `yaml:"oauth_token"`
	Admin       AdminConfig        `yaml:"admin"`
	VirtualKeys []VirtualKeyConfig `yaml:"virtual_keys"`
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

// UsageTracker stores per-key usage records with timestamps.
type UsageTracker struct {
	mu      sync.RWMutex
	records map[string][]UsageRecord // key -> records
	dirty   bool
}

func NewUsageTracker() *UsageTracker {
	return &UsageTracker{records: make(map[string][]UsageRecord)}
}

func (t *UsageTracker) Add(key string, rec UsageRecord) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.records[key] = append(t.records[key], rec)
	t.dirty = true
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
}

func (t *UsageTracker) Query(key string, since time.Time) KeyStats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var s KeyStats
	s.ByModel = make(map[string]ModelUsage)
	for _, r := range t.records[key] {
		if r.Timestamp.Before(since) {
			continue
		}
		s.RequestCount++
		s.InputTokens += r.InputTokens
		s.OutputTokens += r.OutputTokens
		s.CacheCreationInputTokens += r.CacheCreationInputTokens
		s.CacheReadInputTokens += r.CacheReadInputTokens
		if r.Model != "" {
			m := s.ByModel[r.Model]
			m.InputTokens += r.InputTokens
			m.OutputTokens += r.OutputTokens
			m.CacheCreationInputTokens += r.CacheCreationInputTokens
			m.CacheReadInputTokens += r.CacheReadInputTokens
			s.ByModel[r.Model] = m
		}
	}
	return s
}

func (t *UsageTracker) QueryAll(since time.Time) map[string]KeyStats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make(map[string]KeyStats, len(t.records))
	for key, recs := range t.records {
		var s KeyStats
		s.ByModel = make(map[string]ModelUsage)
		for _, r := range recs {
			if r.Timestamp.Before(since) {
				continue
			}
			s.RequestCount++
			s.InputTokens += r.InputTokens
			s.OutputTokens += r.OutputTokens
			s.CacheCreationInputTokens += r.CacheCreationInputTokens
			s.CacheReadInputTokens += r.CacheReadInputTokens
			if r.Model != "" {
				m := s.ByModel[r.Model]
				m.InputTokens += r.InputTokens
				m.OutputTokens += r.OutputTokens
				m.CacheCreationInputTokens += r.CacheCreationInputTokens
				m.CacheReadInputTokens += r.CacheReadInputTokens
				s.ByModel[r.Model] = m
			}
		}
		result[key] = s
	}
	return result
}

func (t *UsageTracker) Delete(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.records, key)
	t.dirty = true
}

// KeyManager manages virtual keys with thread safety.
type KeyManager struct {
	mu    sync.RWMutex
	keys  map[string]string // key -> name
	dirty bool
}

func NewKeyManager(keys []VirtualKeyConfig) *KeyManager {
	m := &KeyManager{keys: make(map[string]string, len(keys))}
	for _, k := range keys {
		m.keys[k.Key] = k.Name
	}
	return m
}

func (m *KeyManager) IsValid(key string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.keys[key]
	return ok
}

func (m *KeyManager) Add(name, key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[key] = name
	m.dirty = true
}

func (m *KeyManager) Remove(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keys[key]; !ok {
		return false
	}
	delete(m.keys, key)
	m.dirty = true
	return true
}

func (m *KeyManager) List() []VirtualKeyConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]VirtualKeyConfig, 0, len(m.keys))
	for k, name := range m.keys {
		result = append(result, VirtualKeyConfig{Name: name, Key: k})
	}
	return result
}

// StoreData is the on-disk persistence format.
type StoreData struct {
	OAuthToken string                      `json:"oauth_token,omitempty"`
	Keys       []VirtualKeyConfig          `json:"keys"`
	Records    map[string][]UsageRecord    `json:"records"`
}

// Store handles loading and saving persistent data.
type Store struct {
	path       string
	keyMgr     *KeyManager
	tracker    *UsageTracker
	oauthToken *atomic.Value
	log        *zerolog.Logger
}

func NewStore(path string, keyMgr *KeyManager, tracker *UsageTracker, oauthToken *atomic.Value, log *zerolog.Logger) *Store {
	return &Store{path: path, keyMgr: keyMgr, tracker: tracker, oauthToken: oauthToken, log: log}
}

func (s *Store) Load() error {
	if s.path == "" {
		return nil
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading store: %w", err)
	}
	var sd StoreData
	if err := json.Unmarshal(data, &sd); err != nil {
		return fmt.Errorf("parsing store: %w", err)
	}
	// Restore oauth token if saved.
	if sd.OAuthToken != "" {
		s.oauthToken.Store(sd.OAuthToken)
	}

	// Merge keys from disk (disk keys supplement config keys, not replace).
	s.keyMgr.mu.Lock()
	for _, k := range sd.Keys {
		if _, exists := s.keyMgr.keys[k.Key]; !exists {
			s.keyMgr.keys[k.Key] = k.Name
		}
	}
	s.keyMgr.dirty = false
	s.keyMgr.mu.Unlock()

	// Load records.
	s.tracker.mu.Lock()
	s.tracker.records = sd.Records
	if s.tracker.records == nil {
		s.tracker.records = make(map[string][]UsageRecord)
	}
	s.tracker.dirty = false
	s.tracker.mu.Unlock()

	s.log.Info().Str("path", s.path).Int("keys", len(sd.Keys)).Msg("loaded store")
	return nil
}

func (s *Store) Save() error {
	return s.save(false)
}

func (s *Store) SaveForce() error {
	return s.save(true)
}

func (s *Store) save(force bool) error {
	if s.path == "" {
		return nil
	}
	if !force {
		// Check if anything changed.
		s.keyMgr.mu.RLock()
		keysDirty := s.keyMgr.dirty
		s.keyMgr.mu.RUnlock()
		s.tracker.mu.RLock()
		recDirty := s.tracker.dirty
		s.tracker.mu.RUnlock()
		if !keysDirty && !recDirty {
			return nil
		}
	}

	// Snapshot data under locks.
	s.keyMgr.mu.Lock()
	keys := make([]VirtualKeyConfig, 0, len(s.keyMgr.keys))
	for k, name := range s.keyMgr.keys {
		keys = append(keys, VirtualKeyConfig{Name: name, Key: k})
	}
	s.keyMgr.dirty = false
	s.keyMgr.mu.Unlock()

	s.tracker.mu.Lock()
	records := make(map[string][]UsageRecord, len(s.tracker.records))
	for k, v := range s.tracker.records {
		cp := make([]UsageRecord, len(v))
		copy(cp, v)
		records[k] = cp
	}
	s.tracker.dirty = false
	s.tracker.mu.Unlock()

	sd := StoreData{OAuthToken: s.oauthToken.Load().(string), Keys: keys, Records: records}
	data, err := json.Marshal(sd)
	if err != nil {
		return fmt.Errorf("marshaling store: %w", err)
	}
	// Atomic write: write to temp file then rename.
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("writing store: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("renaming store: %w", err)
	}
	return nil
}

// RunAutoSave periodically saves data to disk.
func (s *Store) RunAutoSave(interval time.Duration) {
	if s.path == "" {
		return
	}
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			if err := s.Save(); err != nil {
				s.log.Error().Err(err).Msg("auto-save failed")
			}
		}
	}()
}

// SessionStore manages admin login sessions.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]time.Time
}

func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[string]time.Time)}
}

func (s *SessionStore) Create() string {
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[token] = time.Now().Add(24 * time.Hour)
	return token
}

func (s *SessionStore) Valid(token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	expiry, ok := s.sessions[token]
	return ok && time.Now().Before(expiry)
}

func (s *SessionStore) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
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
	tracker                  *UsageTracker
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
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue
		}
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
	r.tracker.Add(r.virtualKey, rec)
	if r.inputTokens > 0 || r.outputTokens > 0 || r.cacheCreationInputTokens > 0 || r.cacheReadInputTokens > 0 {
		r.log.Info().
			Str("key", maskToken(r.virtualKey)).
			Str("model", r.model).
			Int64("input_tokens", r.inputTokens).
			Int64("output_tokens", r.outputTokens).
			Int64("cache_creation", r.cacheCreationInputTokens).
			Int64("cache_read", r.cacheReadInputTokens).
			Msg("usage recorded")
	}
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
	dataPath := flag.String("data", "", "path to data file for persistence (e.g. /data/maxmux.json)")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, error")
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

	keyMgr := NewKeyManager(cfg.VirtualKeys)
	sessions := NewSessionStore()
	tracker := NewUsageTracker()

	var oauthToken atomic.Value
	oauthToken.Store(cfg.OAuthToken)

	store := NewStore(*dataPath, keyMgr, tracker, &oauthToken, &log)
	if err := store.Load(); err != nil {
		log.Fatal().Err(err).Msg("failed to load store")
	}
	store.RunAutoSave(30 * time.Second)

	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		log.Fatal().Err(err).Str("upstream", cfg.Upstream).Msg("invalid upstream URL")
	}
	log.Info().
		Int("port", cfg.Port).
		Str("upstream", cfg.Upstream).
		Int("virtual_keys", len(cfg.VirtualKeys)).
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

			contentType := resp.Header.Get("Content-Type")
			isStreaming := strings.Contains(contentType, "text/event-stream")

			if isStreaming {
				resp.Body = &sseUsageReader{
					reader:     resp.Body,
					virtualKey: virtualKey,
					tracker:    tracker,
					log:        &log,
				}
			} else {
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					return err
				}

				model, inputTokens, outputTokens, cacheCreation, cacheRead := extractFromBody(body)
				rec := UsageRecord{
					Timestamp:                time.Now(),
					Model:                    model,
					InputTokens:              inputTokens,
					OutputTokens:             outputTokens,
					CacheCreationInputTokens: cacheCreation,
					CacheReadInputTokens:     cacheRead,
				}
				tracker.Add(virtualKey, rec)
				if inputTokens > 0 || outputTokens > 0 || cacheCreation > 0 || cacheRead > 0 {
					log.Info().
						Str("key", maskToken(virtualKey)).
						Str("model", model).
						Int64("input_tokens", inputTokens).
						Int64("output_tokens", outputTokens).
						Int64("cache_creation", cacheCreation).
						Int64("cache_read", cacheRead).
						Msg("usage recorded")
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
				SameSite: http.SameSiteStrictMode,
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
			}
			keys := keyMgr.List()
			allUsage := tracker.QueryAll(since)
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
				result = append(result, keyWithUsage{
					Name:                     k.Name,
					Key:                      k.Key,
					MaskedKey:                maskToken(k.Key),
					RequestCount:             u.RequestCount,
					InputTokens:              u.InputTokens,
					OutputTokens:             u.OutputTokens,
					CacheCreationInputTokens: u.CacheCreationInputTokens,
					CacheReadInputTokens:     u.CacheReadInputTokens,
					ByModel:                  bm,
				})
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
			keyMgr.Add(req.Name, req.Key)
			store.Save()
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
			if !keyMgr.Remove(req.Key) {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "key not found"})
				return
			}
			tracker.Delete(req.Key)
			store.Save()
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
			store.SaveForce()
			log.Info().Str("token", maskToken(req.Token)).Msg("oauth token updated")
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "masked_token": maskToken(req.Token)})
			return
		}

		// --- Proxy routes ---

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

		log.Info().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Msg("forwarding")

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

		proxy.ServeHTTP(w, r)

		log.Info().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Dur("duration", time.Since(start)).
			Msg("completed")
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
  'claude-opus-4-20250514':       { input: 15, output: 75 },
  'claude-opus-4-0':              { input: 15, output: 75 },
  'claude-sonnet-4-20250514':     { input: 3,  output: 15 },
  'claude-sonnet-4-0':            { input: 3,  output: 15 },
  'claude-3-5-sonnet-20241022':   { input: 3,  output: 15 },
  'claude-3-5-sonnet-20240620':   { input: 3,  output: 15 },
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
  const res = await fetch(API + '/session');
  if (res.ok) showDashboard();
}

function showDashboard() {
  document.getElementById('loginPage').style.display = 'none';
  document.getElementById('dashboard').style.display = 'block';
  loadKeys();
  loadToken();
  refreshTimer = setInterval(loadKeys, 10000);
}

async function loadKeys() {
  const url = currentSince > 0 ? API + '/keys?since=' + currentSince : API + '/keys';
  const res = await fetch(url);
  if (!res.ok) {
    if (res.status === 401) { logout(); }
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

    html += '<tr>' +
      '<td><strong>' + escHtml(k.name) + '</strong></td>' +
      '<td class="mono">' + escHtml(k.masked_key) + '</td>' +
      '<td class="token-num">' + formatNumber(k.request_count) + '</td>' +
      '<td class="token-num">' + formatNumber(k.input_tokens) + modelDetail + '</td>' +
      '<td class="token-num">' + formatNumber(k.output_tokens) + '</td>' +
      '<td class="token-num">' + formatNumber(k.cache_creation_input_tokens || 0) + '</td>' +
      '<td class="token-num">' + formatNumber(k.cache_read_input_tokens || 0) + '</td>' +
      '<td class="cost-cell token-num">' + formatCost(keyCost) + '</td>' +
      '<td><button class="btn btn-danger btn-sm" onclick="removeKey(\'' + escAttr(k.key) + '\',\'' + escAttr(k.name) + '\')">Delete</button></td>' +
      '</tr>';
  }
  if (keys.length === 0) {
    html = '<tr><td colspan="9" style="text-align:center;color:#9ca3af;padding:32px">No virtual keys configured</td></tr>';
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

checkSession();
</script>
</body>
</html>`
