package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/intel/enrich"
	"github.com/networkshard/shardlure/internal/settings"
)

// This file backs the dashboard Settings panel: a masked GET snapshot, a
// whitelisted save/clear, a per-provider connection test, and dashboard-token
// rotation. Every route is registered under s.guard (auth), and NO handler ever
// returns or logs a raw secret value — the snapshot only reveals a masked hint
// and a set/unset source.

// settingKind classifies a setting for the snapshot: secrets are masked, knobs
// are returned in full.
type settingKind int

const (
	kindSecret settingKind = iota // API keys, dashboard token — never returned raw
	kindText                      // free text (comment, city…)
	kindBool                      // "1"/"0"-ish flags
	kindInt                       // numeric knobs
	kindFloat                     // lat/lon
	kindIntCSV                    // categories "18,22"
)

// settingMeta describes one operator-editable setting. testProvider names the
// enrich provider (or "bazaar"/"ipapi") a Test button exercises, "" when none.
type settingMeta struct {
	Key         string
	Kind        settingKind
	Label       string
	Testable    string // provider id for the Test button, or ""
	MinInt      int    // for kindInt validation (inclusive)
	MaxInt      int
	HasIntRange bool
}

// settingsRegistry is the single source of truth for what the panel exposes.
// Order here is the render order in the UI. Adding a provider is one row.
var settingsRegistry = []settingMeta{
	// --- provider API keys (secrets) ---
	{Key: settings.KeyAbuseIPDB, Kind: kindSecret, Label: "AbuseIPDB", Testable: enrich.ProviderAbuseIPDB},
	{Key: settings.KeyVT, Kind: kindSecret, Label: "VirusTotal", Testable: enrich.ProviderVirusTotal},
	{Key: settings.KeyGreyNoise, Kind: kindSecret, Label: "GreyNoise (optional)", Testable: enrich.ProviderGreyNoise},
	{Key: settings.KeyOTX, Kind: kindSecret, Label: "AlienVault OTX", Testable: enrich.ProviderOTX},
	{Key: settings.KeyIPQS, Kind: kindSecret, Label: "IPQualityScore", Testable: enrich.ProviderIPQS},
	{Key: settings.KeyIPinfo, Kind: kindSecret, Label: "IPinfo", Testable: enrich.ProviderIPinfo},
	{Key: settings.KeyBazaar, Kind: kindSecret, Label: "MalwareBazaar", Testable: "bazaar"},
	{Key: settings.KeyIPAPI, Kind: kindSecret, Label: "ip-api (geo)", Testable: "ipapi"},

	// --- AbuseIPDB reporting knobs (non-secret) ---
	{Key: settings.KeyAbuseReportEnabled, Kind: kindBool, Label: "Reporting enabled"},
	{Key: settings.KeyAbuseMinProbe, Kind: kindInt, Label: "Min probe score", MinInt: 0, MaxInt: 100, HasIntRange: true},
	{Key: settings.KeyAbuseRewindowHours, Kind: kindInt, Label: "Re-report window (h)", MinInt: 0, MaxInt: 8760, HasIntRange: true},
	{Key: settings.KeyAbuseCategories, Kind: kindIntCSV, Label: "Categories"},
	{Key: settings.KeyAbuseComment, Kind: kindText, Label: "Report comment"},

	// --- geolocation (non-secret) ---
	// Only the geo-HTTP toggles are exposed here: they meaningfully enable /
	// disable outbound attacker-IP geolocation. The globe's home origin
	// (lat/lon/city/country) stays in shardlure.yaml — it's set once at deploy
	// and editing it here duplicated config while barely affecting the globe.
	{Key: settings.KeyGeoHTTP, Kind: kindBool, Label: "Geo lookups enabled"},
	{Key: settings.KeyGeoInsecure, Kind: kindBool, Label: "Allow insecure geo HTTP"},
}

// metaFor looks up a setting's metadata; ok=false means the key is not on the
// whitelist and must be rejected.
func metaFor(key string) (settingMeta, bool) {
	for _, m := range settingsRegistry {
		if m.Key == key {
			return m, true
		}
	}
	return settingMeta{}, false
}

// maskSecret renders a non-revealing hint: the last 4 chars when the value is
// long enough to make that safe, else a fixed dot run. Never the full value.
func maskSecret(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if len(v) >= 8 {
		return "····" + v[len(v)-4:]
	}
	return "········"
}

type settingRow struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Kind     string `json:"kind"`
	Testable string `json:"testable,omitempty"`
	// Secret rows: set + hint + source only. Non-secret rows: value.
	Set    bool   `json:"set"`
	Hint   string `json:"hint,omitempty"`
	Source string `json:"source"` // db | env | unset
	Value  string `json:"value,omitempty"`
}

var settingKindNames = map[settingKind]string{
	kindSecret: "secret", kindText: "text", kindBool: "bool",
	kindInt: "int", kindFloat: "float", kindIntCSV: "intcsv",
}

// handleSettings returns the masked settings snapshot. Secrets never leave the
// process in the clear — only a hint + set/unset source.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	rows := make([]settingRow, 0, len(settingsRegistry))
	for _, m := range settingsRegistry {
		row := settingRow{
			Key:      m.Key,
			Label:    m.Label,
			Kind:     settingKindNames[m.Kind],
			Testable: m.Testable,
			Set:      s.keys.Has(m.Key),
			Source:   string(s.keys.SourceOf(m.Key)),
		}
		if m.Kind == kindSecret {
			row.Hint = maskSecret(s.keys.Get(m.Key))
		} else {
			// Non-secret knobs are safe to echo so the form can prefill.
			row.Value = s.keys.Get(m.Key)
		}
		rows = append(rows, row)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"generatedAt": time.Now().UTC().Format(time.RFC3339),
		"settings":    rows,
	})
}

type saveRequest struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Action string `json:"action"` // "clear" to remove; otherwise save Value
}

// handleSettingsSave persists or clears one whitelisted setting. An empty value
// on a SECRET is treated as no-change (so re-submitting the masked form can't
// wipe a key); clearing requires action:"clear". Never logs the value.
func (s *Server) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req saveRequest
	if err := decodeJSONBody(r, &req, 1<<16); err != nil {
		writeSettingsError(w, http.StatusBadRequest, err.Error())
		return
	}
	meta, ok := metaFor(req.Key)
	if !ok {
		writeSettingsError(w, http.StatusBadRequest, "unknown setting key")
		return
	}

	if req.Action == "clear" {
		if err := s.keys.Clear(req.Key); err != nil {
			httpError(w, "settings_save", err, http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
		return
	}

	val := strings.TrimSpace(req.Value)
	// Empty secret submission = no-op (the UI shows a mask, not the real value).
	if val == "" {
		if meta.Kind == kindSecret {
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "unchanged"})
			return
		}
		// For non-secret knobs, an empty value means "clear / revert to default".
		if err := s.keys.Clear(req.Key); err != nil {
			httpError(w, "settings_save", err, http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
		return
	}

	if msg := validateSetting(meta, val); msg != "" {
		writeSettingsError(w, http.StatusBadRequest, msg)
		return
	}
	if err := s.keys.Set(req.Key, val); err != nil {
		httpError(w, "settings_save", err, http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
}

// validateSetting enforces per-kind constraints, mirroring config.Validate.
// Returns "" when valid, else a human-readable reason (never echoing secrets).
func validateSetting(m settingMeta, val string) string {
	switch m.Kind {
	case kindInt:
		n, err := strconv.Atoi(val)
		if err != nil {
			return "value must be an integer"
		}
		if m.HasIntRange && (n < m.MinInt || n > m.MaxInt) {
			return fmt.Sprintf("value must be in %d-%d", m.MinInt, m.MaxInt)
		}
	case kindFloat:
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return "value must be a number"
		}
		// Coordinate sanity for the home point.
		if m.Key == settings.KeyHomeLat && (f < -90 || f > 90) {
			return "latitude must be in -90..90"
		}
		if m.Key == settings.KeyHomeLon && (f < -180 || f > 180) {
			return "longitude must be in -180..180"
		}
	case kindBool:
		switch strings.ToLower(val) {
		case "1", "0", "true", "false", "yes", "no", "on", "off":
		default:
			return "value must be a boolean"
		}
	case kindIntCSV:
		for _, part := range strings.Split(val, ",") {
			if _, err := strconv.Atoi(strings.TrimSpace(part)); err != nil {
				return "categories must be comma-separated integers"
			}
		}
	}
	return ""
}

type testRequest struct {
	Provider string `json:"provider"`
}

// handleSettingsTest exercises one provider's live liveness/key-validity using
// the currently-effective key (so it validates a just-saved value). It never
// echoes the key. Enrichment providers reuse enrich.TestProvider; bazaar/ipapi
// use a lightweight read-only probe.
func (s *Server) handleSettingsTest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req testRequest
	if err := decodeJSONBody(r, &req, 1<<12); err != nil {
		writeSettingsError(w, http.StatusBadRequest, err.Error())
		return
	}
	const testIP = "1.1.1.1"
	ctx := r.Context()

	var ok bool
	var msg string
	switch req.Provider {
	case "bazaar":
		ok, msg = s.testBazaar(ctx)
	case "ipapi":
		ok, msg = s.testIPAPI(ctx, testIP)
	default:
		// Enrichment providers (abuseipdb, virustotal, greynoise, otx, ipqs, ipinfo).
		ok, msg = enrich.TestProvider(ctx, nil, s.keys, req.Provider, testIP)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": ok, "message": msg})
}

// testBazaar does a read-only MalwareBazaar liveness check: a get_info query
// with a dummy hash. A JSON response (any query_status) means the API is
// reachable and, for an authed key, accepted. Never uploads.
func (s *Server) testBazaar(ctx context.Context) (bool, string) {
	key := s.bazaarKeyLive()
	if key == "" {
		return false, "no API key configured"
	}
	endpoint := s.bazaarEndpoint
	if endpoint == "" {
		endpoint = "https://mb-api.abuse.ch/api/v1/"
	}
	form := strings.NewReader("query=get_info&hash=" +
		"0000000000000000000000000000000000000000000000000000000000000000")
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, form)
	if err != nil {
		return false, "request build failed"
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Auth-Key", key)
	client := &http.Client{Timeout: 6 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return false, "unreachable: " + err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var parsed struct {
		QueryStatus string `json:"query_status"`
	}
	_ = json.Unmarshal(body, &parsed)
	switch parsed.QueryStatus {
	case "":
		return false, fmt.Sprintf("unexpected response (HTTP %d)", resp.StatusCode)
	case "unauthenticated", "unauthorized", "invalid_auth_key":
		return false, "key rejected by MalwareBazaar"
	default:
		// "hash_not_found"/"no_results"/"ok" all prove the key was accepted.
		return true, "key accepted; MalwareBazaar reachable"
	}
}

// testIPAPI hits the geo lookup URL for a test IP and checks status:success.
func (s *Server) testIPAPI(ctx context.Context, ip string) (bool, string) {
	url := geoLookupURL(ip, geoConfig{}, s.keys)
	if url == "" {
		return false, "geo lookups not enabled (need ip-api key or insecure-http)"
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, "request build failed"
	}
	client := &http.Client{Timeout: 6 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return false, "unreachable: " + err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var parsed struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(body, &parsed)
	if parsed.Status == "success" {
		return true, "geo lookup succeeded"
	}
	return false, "geo lookup did not succeed (check key/plan)"
}

// providerArm describes whether one provider is ready to use, for the health
// strip's armed/idle dots. Keyless providers are always armed.
type providerArm struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Armed   bool   `json:"armed"`
	Keyless bool   `json:"keyless,omitempty"`
}

// handleSettingsStatus returns read-only observability for the Settings tab:
// a live-health strip (uptime, ingest freshness, counts, which providers are
// armed, whether the dashboard token is set) plus AbuseIPDB reporting stats and
// the recent report history. Everything here already exists elsewhere; this is
// a single convenience aggregate so the panel needs one fetch.
func (s *Server) handleSettingsStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	events, _ := s.st.EventCount()
	actors, _ := s.st.ActorCount()
	ips, _ := s.st.UniqueIPCount()
	lastEvent, _ := s.st.LatestEventTime()

	// Provider armed-state: a keyed provider is armed when Has() is true; the
	// two keyless ones (Shodan, GreyNoise-community) are always armed.
	armed := []providerArm{
		{Key: settings.KeyAbuseIPDB, Label: "AbuseIPDB", Armed: s.keys.Has(settings.KeyAbuseIPDB)},
		{Key: settings.KeyVT, Label: "VirusTotal", Armed: s.keys.Has(settings.KeyVT)},
		{Key: settings.KeyGreyNoise, Label: "GreyNoise", Armed: true, Keyless: true},
		{Key: "shodan", Label: "Shodan", Armed: true, Keyless: true},
		{Key: settings.KeyOTX, Label: "OTX", Armed: s.keys.Has(settings.KeyOTX)},
		{Key: settings.KeyIPQS, Label: "IPQualityScore", Armed: s.keys.Has(settings.KeyIPQS)},
		{Key: settings.KeyIPinfo, Label: "IPinfo", Armed: s.keys.Has(settings.KeyIPinfo)},
		{Key: settings.KeyBazaar, Label: "MalwareBazaar", Armed: s.bazaarKeyLive() != ""},
	}

	stats, _ := s.st.AbuseReportStats()
	reports, _ := s.st.ListAbuseReports(25)
	type reportRow struct {
		IP         string `json:"ip"`
		ReportedAt string `json:"reportedAt"`
		Status     string `json:"status"`
		Score      int    `json:"score"`
		Categories []int  `json:"categories"`
	}
	rows := make([]reportRow, 0, len(reports))
	for _, rp := range reports {
		rows = append(rows, reportRow{
			IP:         rp.IP,
			ReportedAt: rp.ReportedAt.UTC().Format(time.RFC3339),
			Status:     rp.Status,
			Score:      rp.AbuseScore,
			Categories: rp.Categories,
		})
	}

	lastEventStr := ""
	if !lastEvent.IsZero() {
		lastEventStr = lastEvent.UTC().Format(time.RFC3339)
	}
	lastReportStr := ""
	if !stats.LastReportAt.IsZero() {
		lastReportStr = stats.LastReportAt.UTC().Format(time.RFC3339)
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"generatedAt":   time.Now().UTC().Format(time.RFC3339),
		"startedAt":     s.startedAt.UTC().Format(time.RFC3339),
		"uptimeSeconds": int64(time.Since(s.startedAt).Seconds()),
		"events":        events,
		"actors":        actors,
		"uniqueIps":     ips,
		"lastEvent":     lastEventStr,
		"tokenSet":      s.dashboardToken() != "",
		"reportEnabled": s.abuseEnabledLive(),
		"providers":     armed,
		"abuse": map[string]any{
			"totalReported": stats.TotalReported,
			"lastReportAt":  lastReportStr,
			"reports":       rows,
		},
	})
}

// handleTokenRotate mints a fresh dashboard token, persists it, and returns it
// ONCE so the calling session can keep working (the JS swaps it immediately).
// Auth-gated by s.guard, so the caller has already proven it holds the old
// token. Other open tabs will 401 until re-authed with the new token.
func (s *Server) handleTokenRotate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	tok, err := newRandomToken()
	if err != nil {
		httpError(w, "token_rotate", err, http.StatusInternalServerError)
		return
	}
	if err := s.keys.Set(settings.KeyDashToken, tok); err != nil {
		httpError(w, "token_rotate", err, http.StatusInternalServerError)
		return
	}
	// This is the one place a token value is returned — to the authenticated
	// operator who just rotated it, so their session survives.
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "rotated", "token": tok})
}

// newRandomToken returns a 32-byte URL-safe random token.
func newRandomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// decodeJSONBody reads a capped request body into v.
func decodeJSONBody(r *http.Request, v any, max int64) error {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, max))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if len(body) == 0 {
		return fmt.Errorf("empty body")
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("invalid JSON")
	}
	return nil
}

func writeSettingsError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": msg})
}
