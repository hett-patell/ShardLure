package web

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/actor"
	"github.com/networkshard/shardlure/internal/intel/enrich"
	"github.com/networkshard/shardlure/internal/intel/ioc"
	"github.com/networkshard/shardlure/internal/intel/mitre"
	"github.com/networkshard/shardlure/internal/intel/payload"
	"github.com/networkshard/shardlure/internal/intel/ttp"
	"github.com/networkshard/shardlure/internal/intel/deobf"
	"github.com/networkshard/shardlure/internal/intel/graph"
	"github.com/networkshard/shardlure/internal/intel/replay"
	"sync"

	"github.com/networkshard/shardlure/internal/intel/bazaar"
	"github.com/networkshard/shardlure/internal/intel/wordlist"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

var (
	classifyMu    sync.Mutex
	classifyCache = make(map[string]bazaar.Classification, 256)
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
	// Default 200; clients can request up to 2000. Values above the
	// ceiling clamp rather than silently fall back so paginators see
	// a predictable maximum.
	limit := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		if n > 2000 {
			n = 2000
		}
		limit = n
	}
	sessions, err := s.st.ListSessions(since, limit)
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
	ID         string            `json:"id"`
	IP         string            `json:"ip"`
	User       string            `json:"user,omitempty"`
	Start      string            `json:"start"`
	End        string            `json:"end"`
	Lines      []sessionEventRow `json:"lines"`
	Transcript *sessionTranscript `json:"transcript,omitempty"`
}

// sessionTranscript is the decoded cowrie ttylog for the session, if
// one was captured. Bytes is the raw artifact size on disk; Text is the
// human-readable transcript (ANSI-stripped). Truncated reports whether
// Text was clipped to keep the JSON payload small.
type sessionTranscript struct {
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes"`
	Text      string `json:"text"`
	Truncated bool   `json:"truncated,omitempty"`
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

	// Pick the most recent non-empty username. The previous code
	// pulled events[len-1].Username, which is almost always a
	// `command` event with Username="" - cowrie only stamps the user
	// on the login/auth events at the start of the session. Walk
	// from newest to oldest so re-auth events (e.g. su) take
	// precedence over the initial login.
	var user string
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Username != "" {
			user = events[i].Username
			break
		}
	}
	resp := sessionDetailResponse{
		ID:    id,
		IP:    events[0].SrcIP,
		User:  user,
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

	// Attach the decoded TTY transcript if cowrie captured one for
	// this session. We cap the inline payload at 256 KiB so a huge
	// transcript can't bloat the JSON response -- the raw file is
	// still on disk for anyone who wants the full session replay.
	if art, err := s.st.CowrieTTYArtifactForSession(id); err == nil && art != nil && art.LocalPath != "" {
		const maxInline = 256 * 1024
		if data, err := os.ReadFile(art.LocalPath + ".txt"); err == nil && len(data) > 0 {
			text := string(data)
			truncated := false
			if len(text) > maxInline {
				text = text[:maxInline]
				truncated = true
			}
			resp.Transcript = &sessionTranscript{
				SHA256:    art.SHA256,
				Bytes:     art.SizeBytes,
				Text:      text,
				Truncated: truncated,
			}
		}
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

// ==== /api/intel/ttp ==============================================

type ttpResponse struct {
	GeneratedAt string    `json:"generatedAt"`
	WindowHours int       `json:"windowHours"`
	Total       int       `json:"total"`
	Rows        []ttp.Row `json:"rows"`
}

func (s *Server) handleIntelTTP(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	windowHours := windowHoursFromQuery(r.URL.Query().Get("window"), 168) // default 7d for TTP
	since := time.Now().Add(-time.Duration(windowHours) * time.Hour)
	events, err := s.st.EventsSince(since, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	limit := 100
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 1000 {
		limit = n
	}
	rows := ttp.Harvest(events, 0)
	total := len(rows)
	if len(rows) > limit {
		rows = rows[:limit]
	}
	_ = json.NewEncoder(w).Encode(ttpResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		WindowHours: windowHours,
		Total:       total,
		Rows:        rows,
	})
}

// ==== /api/intel/deobf ============================================

type deobfRow struct {
	TS       string         `json:"ts"`
	SrcIP    string         `json:"srcIp,omitempty"`
	Session  string         `json:"session,omitempty"`
	Actor    string         `json:"actor,omitempty"`
	Original string         `json:"original"`
	Final    string         `json:"final"`
	Layers   []deobf.Layer  `json:"layers"`
}

type deobfResponse struct {
	GeneratedAt string     `json:"generatedAt"`
	WindowHours int        `json:"windowHours"`
	Scanned     int        `json:"scanned"`
	Matched     int        `json:"matched"`
	Rows        []deobfRow `json:"rows"`
}

func (s *Server) handleIntelDeobf(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}

	// Ad-hoc one-shot mode: POST/GET ?cmd=… decodes a single input.
	if cmd := r.URL.Query().Get("cmd"); cmd != "" {
		res := deobf.Decode(cmd)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(res)
		return
	}

	windowHours := windowHoursFromQuery(r.URL.Query().Get("window"), 168) // 7d default
	since := time.Now().Add(-time.Duration(windowHours) * time.Hour)
	events, err := s.st.EventsSince(since, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := deobfResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		WindowHours: windowHours,
	}
	limit := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 2000 {
		limit = n
	}

	for _, e := range events {
		if e == nil || e.Kind != models.KindCommand {
			continue
		}
		cmd := strings.TrimSpace(e.Command)
		if cmd == "" {
			continue
		}
		resp.Scanned++
		res := deobf.Decode(cmd)
		if len(res.Layers) == 0 {
			continue
		}
		resp.Matched++
		if len(resp.Rows) < limit {
			resp.Rows = append(resp.Rows, deobfRow{
				TS:       e.TS.UTC().Format(time.RFC3339),
				SrcIP:    e.SrcIP,
				Session:  e.SessionID,
				Actor:    actor.TrimActorPrefix(e.ActorID),
				Original: res.Original,
				Final:    res.Final,
				Layers:   res.Layers,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}

// ==== /api/intel/replay ===========================================

func (s *Server) handleIntelReplay(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	sid := strings.TrimSpace(r.URL.Query().Get("session"))
	if sid == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	events, err := s.st.SessionEvents(sid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	opts := replay.Options{
		IncludeSleeps: r.URL.Query().Get("sleeps") != "0",
		DryRun:        r.URL.Query().Get("dryrun") == "1",
	}
	script := replay.Render(sid, events, opts)

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "download" {
		// Sanitise session id for filename use.
		safe := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
				return r
			}
			return '_'
		}, sid)
		fname := "shardlure-replay-" + safe + ".sh"
		w.Header().Set("Content-Type", "application/x-sh; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`"`)
		_, _ = w.Write([]byte(script))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(struct {
		Session string `json:"session"`
		Script  string `json:"script"`
	}{Session: sid, Script: script})
}

// ==== /api/intel/graph ============================================

func (s *Server) handleIntelGraph(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	windowHours := windowHoursFromQuery(r.URL.Query().Get("window"), 168) // 7d default
	topN := 60
	if n, err := strconv.Atoi(r.URL.Query().Get("top")); err == nil && n > 0 && n <= 500 {
		topN = n
	}
	since := time.Now().Add(-time.Duration(windowHours) * time.Hour)
	events, err := s.st.EventsSince(since, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	g := graph.Build(events, topN)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(struct {
		GeneratedAt string        `json:"generatedAt"`
		WindowHours int           `json:"windowHours"`
		Nodes       []graph.Node  `json:"nodes"`
		Edges       []graph.Edge  `json:"edges"`
	}{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		WindowHours: windowHours,
		Nodes:       g.Nodes,
		Edges:       g.Edges,
	})
}

// ==== /api/intel/wordlist =========================================

type wordlistResponse struct {
	GeneratedAt string            `json:"generatedAt"`
	WindowHours int               `json:"windowHours"`
	Kind        string            `json:"kind"`
	Total       int               `json:"total"`
	Entries     []wordlist.Entry  `json:"entries"`
}

func (s *Server) handleIntelWordlist(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	kind := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("kind")))
	if kind == "" {
		kind = "users"
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}

	windowHours := windowHoursFromQuery(r.URL.Query().Get("window"), 720) // 30d default
	since := time.Now().Add(-time.Duration(windowHours) * time.Hour)
	events, err := s.st.EventsSince(since, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var entries []wordlist.Entry
	switch kind {
	case "users", "usernames":
		entries = wordlist.CollectUsernames(events)
	case "passwords":
		entries = wordlist.CollectPasswords(events)
	case "combos":
		entries = wordlist.CollectCombos(events)
	default:
		http.Error(w, "invalid kind (users|passwords|combos)", http.StatusBadRequest)
		return
	}

	// Optional limit for JSON preview; TXT downloads always send the
	// full list since that's the whole point.
	if format == "json" {
		limit := 100
		if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 50000 {
			limit = n
		}
		total := len(entries)
		if len(entries) > limit {
			entries = entries[:limit]
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(wordlistResponse{
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			WindowHours: windowHours,
			Kind:        kind,
			Total:       total,
			Entries:     entries,
		})
		return
	}

	// TXT download path - one entry per line, hashcat/hydra-compatible.
	var fname string
	switch kind {
	case "users", "usernames":
		fname = "shardlure-users-"
	case "passwords":
		fname = "shardlure-passwords-"
	case "combos":
		fname = "shardlure-combos-"
	}
	fname += time.Now().UTC().Format("20060102T150405Z") + ".txt"

	var sb strings.Builder
	switch kind {
	case "users", "usernames":
		wordlist.WriteLines(&sb, entries, func(e wordlist.Entry) string { return e.Username })
	case "passwords":
		wordlist.WriteLines(&sb, entries, func(e wordlist.Entry) string { return e.Password })
	case "combos":
		wordlist.WriteCombos(&sb, entries)
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`"`)
	_, _ = w.Write([]byte(sb.String()))
}

// ==== /api/intel/payloads and /api/intel/payload =================

type payloadsResponse struct {
	GeneratedAt string        `json:"generatedAt"`
	WindowHours int           `json:"windowHours"`
	Total       int           `json:"total"`
	Rows        []payloadRow  `json:"rows"`
}

// payloadRow is one unique payload (grouped by sha256). URL/Actor/
// Session/SrcIP/TS describe the most-recent capture and the *Count
// fields surface delivery breadth across the window.
type payloadRow struct {
	SHA256       string `json:"sha256"`
	Origin       string `json:"origin,omitempty"`
	URL          string `json:"url,omitempty"`           // last-seen URL
	Status       string `json:"status,omitempty"`        // last-seen status
	SizeBytes    int64  `json:"sizeBytes"`
	Actor        string `json:"actor,omitempty"`         // last-seen actor
	Session      string `json:"session,omitempty"`       // last-seen session
	SrcIP        string `json:"srcIp,omitempty"`         // last-seen src IP
	TS           string `json:"ts"`                      // last-seen timestamp
	FirstTS      string `json:"firstTs,omitempty"`       // first-seen timestamp
	Occurrences  int    `json:"occurrences"`             // total captures of this sha
	URLCount     int    `json:"urlCount"`                // distinct URLs
	IPCount      int    `json:"ipCount"`                 // distinct source IPs
	ActorCount   int    `json:"actorCount"`              // distinct actors
	SessionCount int    `json:"sessionCount"`            // distinct sessions
	HasLocal     bool   `json:"hasLocal"`
}

func (s *Server) handleIntelPayloads(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	windowHours := windowHoursFromQuery(r.URL.Query().Get("window"), 168) // 7d default
	since := time.Now().Add(-time.Duration(windowHours) * time.Hour)
	// Default 200, accept 1..1000; values above 1000 clamp to 1000
	// rather than silently falling back to the default.
	limit := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		if n > 1000 {
			n = 1000
		}
		limit = n
	}
	arts, err := s.st.ListArtifactsAggregatedSince(since, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows := make([]payloadRow, 0, len(arts))
	for _, a := range arts {
		rows = append(rows, payloadRow{
			SHA256:       a.SHA256,
			Origin:       a.Origin,
			URL:          a.LastURL,
			Status:       a.Status,
			SizeBytes:    a.SizeBytes,
			Actor:        actor.TrimActorPrefix(a.LastActor),
			Session:      a.LastSession,
			SrcIP:        a.LastSrcIP,
			TS:           a.LastTS.UTC().Format(time.RFC3339),
			FirstTS:      a.FirstTS.UTC().Format(time.RFC3339),
			Occurrences:  a.Occurrences,
			URLCount:     a.URLCount,
			IPCount:      a.IPCount,
			ActorCount:   a.ActorCount,
			SessionCount: a.SessionCount,
			HasLocal:     a.HasLocal,
		})
	}
	_ = json.NewEncoder(w).Encode(payloadsResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		WindowHours: windowHours,
		Total:       len(arts),
		Rows:        rows,
	})
}

type payloadDetailResponse struct {
	SHA256    string             `json:"sha256"`
	URL       string             `json:"url,omitempty"`
	Origin    string             `json:"origin,omitempty"`
	Status    string             `json:"status,omitempty"`
	SizeBytes int64              `json:"sizeBytes"`
	Actor     string             `json:"actor,omitempty"`
	Session   string             `json:"session,omitempty"`
	SrcIP     string             `json:"srcIp,omitempty"`
	TS        string             `json:"ts,omitempty"`
	Inspect   payload.Inspection `json:"inspect"`
}

func (s *Server) handleIntelPayload(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	sha := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sha")))
	if sha == "" {
		http.Error(w, "missing sha", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	a, err := s.st.GetArtifactBySHA(sha)
	if err != nil {
		http.Error(w, "artifact not found: "+err.Error(), http.StatusNotFound)
		return
	}
	resp := payloadDetailResponse{
		SHA256:    a.SHA256,
		URL:       a.URL,
		Origin:    a.Origin,
		Status:    a.Status,
		SizeBytes: a.SizeBytes,
		Actor:     actor.TrimActorPrefix(a.ActorID),
		Session:   a.SessionID,
		SrcIP:     a.SrcIP,
		TS:        a.TS.UTC().Format(time.RFC3339),
		Inspect:   payload.File(a.LocalPath),
	}
	_ = json.NewEncoder(w).Encode(resp)
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

// handleIntelBazaar returns MalwareBazaar sharing stats and recent uploads.
func (s *Server) handleIntelBazaar(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	limit := 50
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 200 {
		limit = v
	}

	stats, err := s.st.BazaarUploadStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	uploads, err := s.st.ListBazaarUploads(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type bazaarUploadRow struct {
		SHA256     string   `json:"sha256"`
		UploadedAt string   `json:"uploadedAt"`
		Status     string   `json:"status"`
		MBURL      string   `json:"mbUrl,omitempty"`
		SizeBytes  int64    `json:"sizeBytes,omitempty"`
		Family     string   `json:"family,omitempty"`
		FileKind   string   `json:"fileKind,omitempty"`
		SrcIP      string   `json:"srcIp,omitempty"`
		Tags       []string `json:"tags,omitempty"`
	}

	rows := make([]bazaarUploadRow, 0, len(uploads))
	for _, u := range uploads {
		row := bazaarUploadRow{
			SHA256:     u.SHA256,
			UploadedAt: u.UploadedAt.UTC().Format(time.RFC3339),
			Status:     u.ResponseStatus,
			MBURL:      u.MBURL,
		}
		if art, err := s.st.GetArtifactBySHA(u.SHA256); err == nil && art != nil {
			row.SizeBytes = art.SizeBytes
			row.SrcIP = art.SrcIP
			classifyMu.Lock()
			cls, cached := classifyCache[u.SHA256]
			classifyMu.Unlock()
			if cached {
				row.Family = cls.Family
				row.FileKind = cls.FileKind
				row.Tags = cls.Tags
			} else if art.LocalPath != "" {
				if _, serr := os.Stat(art.LocalPath); serr == nil {
					if cls, cerr := bazaar.Classify(art.LocalPath); cerr == nil {
						classifyMu.Lock()
						if len(classifyCache) >= 500 {
							for k := range classifyCache { delete(classifyCache, k); break }
						}
						classifyCache[u.SHA256] = cls
						classifyMu.Unlock()
						row.Family = cls.Family
						row.FileKind = cls.FileKind
						row.Tags = cls.Tags
					}
				}
			}
		}
		rows = append(rows, row)
	}

	type statsBlock struct {
		TotalUploaded int    `json:"totalUploaded"`
		Duplicates    int    `json:"duplicates"`
		Pending       int    `json:"pending"`
		LastUploadAt  string `json:"lastUploadAt,omitempty"`
	}
	sb := statsBlock{
		TotalUploaded: stats.TotalUploaded,
		Duplicates:    stats.Duplicates,
		Pending:       stats.Pending,
	}
	if !stats.LastUploadAt.IsZero() {
		sb.LastUploadAt = stats.LastUploadAt.UTC().Format(time.RFC3339)
	}

	resp := struct {
		GeneratedAt string            `json:"generatedAt"`
		Stats       statsBlock        `json:"stats"`
		Uploads     []bazaarUploadRow `json:"uploads"`
	}{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Stats:       sb,
		Uploads:     rows,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// bazaarRecorderAdapter bridges store.BazaarUpload struct to the
// bazaar.UploadRecorder interface.
type bazaarRecorderAdapter struct{ st *store.Store }

func (a *bazaarRecorderAdapter) BazaarUploadRecorded(sha string) (bool, error) {
	return a.st.BazaarUploadRecorded(sha)
}
func (a *bazaarRecorderAdapter) RecordBazaarUpload(sha, status, mbURL string, at time.Time) error {
	return a.st.RecordBazaarUpload(store.BazaarUpload{
		SHA256: sha, UploadedAt: at, ResponseStatus: status, MBURL: mbURL,
	})
}

// handleBazaarUpload triggers a single-payload upload to MalwareBazaar.
func (s *Server) handleBazaarUpload(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	sha := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sha")))
	if sha == "" {
		http.Error(w, "missing sha", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	if s.bazaarKey == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": "bazaar API key not configured"})
		return
	}

	already, _ := s.st.BazaarUploadRecorded(sha)
	if already {
		json.NewEncoder(w).Encode(map[string]string{"status": "already_shared", "mbUrl": "https://bazaar.abuse.ch/sample/" + sha + "/"})
		return
	}

	art, err := s.st.GetArtifactBySHA(sha)
	if err != nil || art == nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": "artifact not found"})
		return
	}

	cand := bazaar.Candidate{
		SHA256: art.SHA256, LocalPath: art.LocalPath, SizeBytes: art.SizeBytes,
		URL: art.URL, SrcIP: art.SrcIP, SessionID: art.SessionID, CreatedAt: art.CreatedAt,
	}
	rec := &bazaarRecorderAdapter{st: s.st}
	var result *bazaar.Result
	opts := bazaar.Options{
		APIKey:    s.bazaarKey,
		Endpoint:  s.bazaarEndpoint,
		ExtraTags: s.bazaarTags,
		MaxBytes:  s.bazaarMaxBytes,
		OnProgress: func(_ bazaar.Candidate, _ bazaar.Classification, r *bazaar.Result, _ error) {
			result = r
		},
	}

	_, _, shareErr := bazaar.Share(r.Context(), rec, []bazaar.Candidate{cand}, opts)

	resp := struct {
		Status string `json:"status"`
		MBURL  string `json:"mbUrl,omitempty"`
		Error  string `json:"error,omitempty"`
	}{}
	if result != nil {
		resp.Status = result.Status
		resp.MBURL = result.SampleURL
	} else if shareErr != nil {
		resp.Status = "error"
		resp.Error = shareErr.Error()
	} else {
		resp.Status = "skipped"
	}
	json.NewEncoder(w).Encode(resp)
}

// handleIntelTimeline returns recent events for the live timeline widget.
func (s *Server) handleIntelTimeline(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	limit := 50
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 200 {
		limit = v
	}
	since := time.Now().Add(-1 * time.Hour)
	events, err := s.st.EventsSince(since, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type timelineEvent struct {
		TS       string `json:"ts"`
		Kind     string `json:"kind"`
		SrcIP    string `json:"srcIp"`
		Username string `json:"username,omitempty"`
		Command  string `json:"command,omitempty"`
		Session  string `json:"session,omitempty"`
		Actor    string `json:"actor,omitempty"`
		Source   string `json:"source"`
	}
	rows := make([]timelineEvent, 0, len(events))
	for _, e := range events {
		if e == nil {
			continue
		}
		rows = append(rows, timelineEvent{
			TS:       e.TS.UTC().Format(time.RFC3339),
			Kind:     string(e.Kind),
			SrcIP:    e.SrcIP,
			Username: e.Username,
			Command:  e.Command,
			Session:  e.SessionID,
			Actor:    actor.TrimActorPrefix(e.ActorID),
			Source:   string(e.Source),
		})
	}
	resp := struct {
		GeneratedAt string          `json:"generatedAt"`
		Events      []timelineEvent `json:"events"`
	}{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Events:      rows,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

