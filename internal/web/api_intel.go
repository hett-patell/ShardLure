package web

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/actor"
	"github.com/networkshard/shardlure/internal/intel/enrich"
	"github.com/networkshard/shardlure/internal/intel/ioc"
	"github.com/networkshard/shardlure/internal/intel/mitre"
)

// ==== /api/intel/mitre ============================================

type mitreResponse struct {
	GeneratedAt string             `json:"generatedAt"`
	WindowHours int                `json:"windowHours"`
	TotalEvents int                `json:"totalEvents"`
	Hits        []mitreHit         `json:"hits"`
	Grid        []mitre.GridTactic `json:"grid"`
}

type mitreHit struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Tactic     string         `json:"tactic"`
	URL        string         `json:"url,omitempty"`
	Count      int            `json:"count"`
	ActorCount int            `json:"actorCount"`
	TopActors  []mitreTopActor `json:"topActors,omitempty"`
}

type mitreTopActor struct {
	ID    string `json:"id"`    // stripped of "journal:" / "cowrie:"
	Count int    `json:"count"`
}

// handleIntelMitre runs the MITRE classifier over the requested time
// window and returns both the ranked hit list (for the "techniques
// observed" panel) and the full coverage grid (for the heat-grid
// widget). The grid intentionally includes every catalogued technique
// with count=0 for techniques we haven't observed — that empty pattern
// is the value of a coverage view.
func (s *Server) handleIntelMitre(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	windowHours := windowHoursFromQuery(r.URL.Query().Get("window"), 24)
	since := time.Now().Add(-time.Duration(windowHours) * time.Hour)
	events, err := s.st.EventsSince(since, 20000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	hits := mitre.Classify(events)
	resp := mitreResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		WindowHours: windowHours,
		TotalEvents: len(events),
		Grid:        mitre.CoverageGrid(hits),
	}
	for _, h := range hits {
		mh := mitreHit{
			ID:         h.Technique.ID,
			Name:       h.Technique.Name,
			Tactic:     string(h.Technique.Tactic),
			URL:        h.Technique.URL,
			Count:      h.Count,
			ActorCount: len(h.ActorCounts),
		}
		// Top 5 actors per technique, sorted by count desc then id
		// asc so refreshes don't flip the order on ties.
		actors := make([]mitreTopActor, 0, len(h.ActorCounts))
		for id, c := range h.ActorCounts {
			actors = append(actors, mitreTopActor{ID: actor.TrimActorPrefix(id), Count: c})
		}
		sort.Slice(actors, func(i, j int) bool {
			if actors[i].Count != actors[j].Count {
				return actors[i].Count > actors[j].Count
			}
			return actors[i].ID < actors[j].ID
		})
		if len(actors) > 5 {
			actors = actors[:5]
		}
		mh.TopActors = actors
		resp.Hits = append(resp.Hits, mh)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// ==== /api/intel/sessions and /api/intel/session =================

type sessionsResponse struct {
	GeneratedAt string             `json:"generatedAt"`
	WindowHours int                `json:"windowHours"`
	Sessions    []sessionRow       `json:"sessions"`
}

type sessionRow struct {
	ID        string `json:"id"`
	IP        string `json:"ip"`
	User      string `json:"user,omitempty"`
	HASSH     string `json:"hassh,omitempty"`
	Client    string `json:"client,omitempty"`
	Actor     string `json:"actor,omitempty"`
	Start     string `json:"start"`
	End       string `json:"end"`
	DurMillis int64  `json:"durMs"`
	Events    int    `json:"events"`
	Commands  int    `json:"commands"`
}

func (s *Server) handleIntelSessions(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	windowHours := windowHoursFromQuery(r.URL.Query().Get("window"), 24)
	since := time.Now().Add(-time.Duration(windowHours) * time.Hour)
	sessions, err := s.st.ListSessions(since, 200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp := sessionsResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		WindowHours: windowHours,
	}
	for _, sm := range sessions {
		dur := sm.EndTS.Sub(sm.StartTS).Milliseconds()
		if dur < 0 {
			dur = 0
		}
		resp.Sessions = append(resp.Sessions, sessionRow{
			ID:        sm.ID,
			IP:        sm.SrcIP,
			User:      sm.Username,
			HASSH:     sm.HASSH,
			Client:    sm.SSHClient,
			Actor:     actor.TrimActorPrefix(sm.ActorID),
			Start:     sm.StartTS.UTC().Format(time.RFC3339),
			End:       sm.EndTS.UTC().Format(time.RFC3339),
			DurMillis: dur,
			Events:    sm.EventCount,
			Commands:  sm.CmdCount,
		})
	}
	_ = json.NewEncoder(w).Encode(resp)
}

type sessionDetailResponse struct {
	ID    string             `json:"id"`
	IP    string             `json:"ip"`
	User  string             `json:"user,omitempty"`
	Start string             `json:"start"`
	End   string             `json:"end"`
	Lines []sessionEventRow  `json:"lines"`
}

type sessionEventRow struct {
	TS       string   `json:"ts"`
	OffsetMs int64    `json:"offsetMs"`
	Kind     string   `json:"kind"`
	User     string   `json:"user,omitempty"`
	Command  string   `json:"command,omitempty"`
	SHA256   string   `json:"sha256,omitempty"`
	Filename string   `json:"filename,omitempty"`
	Techs    []string `json:"techs,omitempty"`
}

func (s *Server) handleIntelSession(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	events, err := s.st.SessionEvents(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(events) == 0 {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	resp := sessionDetailResponse{
		ID:    id,
		IP:    events[0].SrcIP,
		User:  events[len(events)-1].Username,
		Start: events[0].TS.UTC().Format(time.RFC3339),
		End:   events[len(events)-1].TS.UTC().Format(time.RFC3339),
	}
	t0 := events[0].TS
	for _, e := range events {
		row := sessionEventRow{
			TS:       e.TS.UTC().Format(time.RFC3339),
			OffsetMs: e.TS.Sub(t0).Milliseconds(),
			Kind:     string(e.Kind),
			User:     e.Username,
			Command:  e.Command,
			SHA256:   e.SHA256,
			Filename: e.Filename,
			Techs:    mitre.ClassifyOne(e),
		}
		resp.Lines = append(resp.Lines, row)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// windowHoursFromQuery accepts UI chip values (1h/24h/7d/30d) or a
// bare integer hours value. Defaults to fallback on parse failure so
// the endpoint never 400s on a stray query string.
func windowHoursFromQuery(v string, fallback int) int {
	v = strings.TrimSpace(strings.ToLower(v))
	switch v {
	case "", "0":
		return fallback
	case "1h":
		return 1
	case "24h":
		return 24
	case "7d":
		return 24 * 7
	case "30d":
		return 24 * 30
	}
	if strings.HasSuffix(v, "h") {
		if n, err := strconv.Atoi(strings.TrimSuffix(v, "h")); err == nil && n > 0 {
			return n
		}
	}
	if strings.HasSuffix(v, "d") {
		if n, err := strconv.Atoi(strings.TrimSuffix(v, "d")); err == nil && n > 0 {
			return n * 24
		}
	}
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		return n
	}
	return fallback
}

// ==== /api/intel/enrich ===========================================

type enrichResponse struct {
	GeneratedAt string           `json:"generatedAt"`
	IP          string           `json:"ip"`
	Results     []enrich.Result  `json:"results"`
}

func (s *Server) handleIntelEnrich(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		http.Error(w, "missing ip", http.StatusBadRequest)
		return
	}
	// Basic IPv4 sanity check; nothing fancy, just keep the API from
	// being a generic outbound request relay.
	if !looksLikeIP(ip) {
		http.Error(w, "invalid ip", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	resolver := enrich.NewResolver(s.st)
	results := resolver.LookupAll(r.Context(), ip)

	_ = json.NewEncoder(w).Encode(enrichResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		IP:          ip,
		Results:     results,
	})
}

func looksLikeIP(s string) bool {
	if len(s) < 7 || len(s) > 45 { // covers IPv4 + IPv6 bounds
		return false
	}
	dots := 0
	colons := 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		case r == '.':
			dots++
		case r == ':':
			colons++
		default:
			return false
		}
	}
	return (dots == 3 && colons == 0) || colons >= 2
}

// ==== /api/ioc/list and /api/ioc/{csv,stix} =======================

type iocListResponse struct {
	GeneratedAt string           `json:"generatedAt"`
	WindowHours int              `json:"windowHours"`
	Kind        string           `json:"kind"`
	Total       int              `json:"total"`
	Indicators  []ioc.Indicator  `json:"indicators"`
}

// handleIOCList returns a JSON preview of the IOC set. Optionally
// filtered to a single kind via ?kind=ip|hash|url|user; ?limit caps
// the response so dashboard previews stay snappy.
func (s *Server) handleIOCList(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	windowHours := windowHoursFromQuery(r.URL.Query().Get("window"), 24)
	since := time.Now().Add(-time.Duration(windowHours) * time.Hour)
	events, err := s.st.EventsSince(since, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	kind := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("kind")))
	var kinds []ioc.Kind
	if kind != "" && kind != "all" {
		kinds = []ioc.Kind{ioc.Kind(kind)}
	}
	indicators := ioc.Collect(events, kinds)
	limit := 100
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 5000 {
		limit = n
	}
	total := len(indicators)
	if len(indicators) > limit {
		indicators = indicators[:limit]
	}
	_ = json.NewEncoder(w).Encode(iocListResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		WindowHours: windowHours,
		Kind:        kind,
		Total:       total,
		Indicators:  indicators,
	})
}

// handleIOCCSV streams indicators as RFC4180 CSV with an
// attachment Content-Disposition so the browser saves the file.
// Optionally filtered to a single kind.
func (s *Server) handleIOCCSV(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	windowHours := windowHoursFromQuery(r.URL.Query().Get("window"), 24)
	since := time.Now().Add(-time.Duration(windowHours) * time.Hour)
	events, err := s.st.EventsSince(since, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	kind := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("kind")))
	var kinds []ioc.Kind
	if kind != "" && kind != "all" {
		kinds = []ioc.Kind{ioc.Kind(kind)}
	}
	indicators := ioc.Collect(events, kinds)

	fname := "shardlure-ioc"
	if kind != "" && kind != "all" {
		fname += "-" + kind
	}
	fname += "-" + time.Now().UTC().Format("20060102T150405Z") + ".csv"

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`"`)
	if err := ioc.WriteCSV(w, indicators); err != nil {
		// Best-effort: header already written; nothing useful to surface to
		// the browser, but we still log via the server's default writer.
		_ = err
	}
}

// handleIOCSTIX streams a STIX 2.1 bundle of every indicator kind.
// Filtering by kind is intentionally not exposed for STIX: bundles
// are meant to be holistic snapshots that downstream TIPs can dedupe
// themselves.
func (s *Server) handleIOCSTIX(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	windowHours := windowHoursFromQuery(r.URL.Query().Get("window"), 24)
	since := time.Now().Add(-time.Duration(windowHours) * time.Hour)
	events, err := s.st.EventsSince(since, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	indicators := ioc.Collect(events, nil)

	fname := "shardlure-stix-" + time.Now().UTC().Format("20060102T150405Z") + ".json"
	w.Header().Set("Content-Type", "application/vnd.oasis.stix+json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`"`)
	if err := ioc.WriteSTIX(w, indicators); err != nil {
		_ = err
	}
}

