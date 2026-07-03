package web

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/actor"
	"github.com/networkshard/shardlure/internal/store"
)

type intelResponse struct {
	GeneratedAt    string          `json:"generatedAt"`
	StartedAt      string          `json:"startedAt"`     // RFC3339 process start time
	UptimeSeconds  int64           `json:"uptimeSeconds"` // seconds the live process has been running
	Summary        summaryBlock    `json:"summary"`
	TopCountries   []topCountryRow `json:"topCountries"` // true attack geography (all events by country)
	Radar          []radarRow      `json:"radar"`        // top actors by attempts/hour (brute-force radar)
	KindCounts     []labelCountRow `json:"kindCounts"`
	IntentCounts   []labelCountRow `json:"intentCounts"`
	PlaybookCounts []labelCountRow `json:"playbookCounts"`
	SourceCounts   []labelCountRow `json:"sourceCounts"`
	Heatmap        []heatmapCell   `json:"heatmap"`
	Actors         []intelActorRow `json:"actors"`
	RecentCommands []commandRow    `json:"recentCommands"`
}

type labelCountRow struct {
	Label string `json:"label"`
	Hits  int    `json:"hits"`
}

// radarRow is one bar in the Brute-Force Radar: an attacker IP and its
// attempts-per-hour rate.
type radarRow struct {
	IP       string  `json:"ip"`
	RateHour float64 `json:"rateHour"`
}

type heatmapCell struct {
	T    int64  `json:"t"`
	Kind string `json:"kind"`
	N    int    `json:"n"`
}

type intelActorRow struct {
	ID          string       `json:"id"`
	IP          string       `json:"ip"`
	Source      string       `json:"source"`
	Playbook    string       `json:"playbook"`
	Intent      string       `json:"intent"`
	Events      int          `json:"events"`
	UniqueUsers int          `json:"uniqueUsers"`
	RateHour    float64      `json:"rateHour"`
	ProbeScore  int          `json:"probeScore"`
	Confidence  int          `json:"confidence"`
	HASSH       string       `json:"hassh,omitempty"`
	SSHClient   string       `json:"sshClient,omitempty"`
	FirstSeen   string       `json:"firstSeen"`
	LastSeen    string       `json:"lastSeen"`
	Country     string       `json:"country,omitempty"`
	City        string       `json:"city,omitempty"`
	CC          string       `json:"cc,omitempty"`
	TopUsers    []topUserRow `json:"topUsers"`
	LastCommand string       `json:"lastCommand,omitempty"`
}

type commandRow struct {
	TS       string `json:"ts"`
	Kind     string `json:"kind"`
	IP       string `json:"ip"`
	User     string `json:"user"`
	Actor    string `json:"actor"`
	Command  string `json:"command"`
	Session  string `json:"session,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	Filename string `json:"filename,omitempty"`
	Source   string `json:"source"`
}

type actorDetailResponse struct {
	Actor    intelActorRow `json:"actor"`
	Commands []commandRow  `json:"commands"`
	Events   []commandRow  `json:"events"`
}

func (s *Server) handleIntelPage(w http.ResponseWriter, r *http.Request) {
	// Page route: accept ?token= so a browser navigation can load the HTML,
	// whose JS then uses the header for /api calls. See requirePageAuth.
	if !s.requirePageAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(intelHTML))
}

func (s *Server) handleIntel(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	// Whole-table aggregates come from the shared TTL cache: this endpoint
	// is polled every 5s per open tab and each of these was a full-table
	// scan/aggregation.
	stats, err := s.summaryStatsCached()
	if err != nil {
		httpError(w, "intel", err, http.StatusInternalServerError)
		return
	}

	now := time.Now()
	resp := intelResponse{
		GeneratedAt:   now.UTC().Format(time.RFC3339),
		StartedAt:     s.startedAt.UTC().Format(time.RFC3339),
		UptimeSeconds: int64(now.Sub(s.startedAt).Seconds()),
		Summary: summaryBlock{
			EventCount: stats.Events,
			ActorCount: stats.Actors,
			UniqueIPs:  stats.UniqueIPs,
			Countries:  stats.Countries,
		},
	}
	// Attack Geography: true hits-by-country over ALL events (was recomputed
	// client-side over only the recent-N actor slice, so a dominant high-volume
	// IP outside that slice — e.g. 64k hits from Brazil — vanished from the
	// chart). Authoritative SQL aggregation joined to the geo cache, cached and
	// shared with /api/dashboard so it isn't run twice per page load.
	resp.TopCountries = append(resp.TopCountries, s.topCountriesCached()...)
	// Brute-Force Radar: the most aggressive actors by attempts/hour across ALL
	// actors (was derived client-side from the recent-80 actor slice, so it
	// showed ~171/h when the true peak was 3000+/h).
	if rad, err := s.st.TopActorsByRate(8); err == nil {
		for _, a := range rad {
			resp.Radar = append(resp.Radar, radarRow{
				IP:       a.PrimaryIP,
				RateHour: a.AttemptsPerHour,
			})
		}
	}

	for _, k := range stats.KindCounts {
		resp.KindCounts = append(resp.KindCounts, labelCountRow{Label: k.Label, Hits: k.Hits})
	}

	intents, err := s.st.CountsByIntent()
	if err != nil {
		httpError(w, "intel", err, http.StatusInternalServerError)
		return
	}
	for _, k := range intents {
		resp.IntentCounts = append(resp.IntentCounts, labelCountRow{Label: k.Label, Hits: k.Hits})
	}

	playbooks, err := s.st.CountsByPlaybook()
	if err != nil {
		httpError(w, "intel", err, http.StatusInternalServerError)
		return
	}
	for _, k := range playbooks {
		resp.PlaybookCounts = append(resp.PlaybookCounts, labelCountRow{Label: k.Label, Hits: k.Hits})
	}

	for _, k := range stats.SourceCounts {
		resp.SourceCounts = append(resp.SourceCounts, labelCountRow{Label: k.Label, Hits: k.Hits})
	}

	cells, err := s.st.HourlyEventCountsByKind(72)
	if err != nil {
		httpError(w, "intel", err, http.StatusInternalServerError)
		return
	}
	for _, c := range cells {
		resp.Heatmap = append(resp.Heatmap, heatmapCell{
			T:    c.Hour.Unix(),
			Kind: c.Kind,
			N:    c.Hits,
		})
	}

	actors, err := s.st.ListActors(80)
	if err != nil {
		httpError(w, "intel", err, http.StatusInternalServerError)
		return
	}
	geoIPs := make([]string, 0, len(actors))
	actorIDs := make([]string, 0, len(actors))
	for _, a := range actors {
		geoIPs = append(geoIPs, a.PrimaryIP)
		actorIDs = append(actorIDs, a.ID)
	}
	// Fire-and-forget: both frontends render "resolving…" for missing geo,
	// so blocking this 5s-polled handler on outbound lookups (up to the
	// whole poll interval during an attack wave) buys nothing. prefetch
	// dedupes in-flight lookups, so overlapping polls are safe.
	go s.geo.prefetch(geoIPs, 5*time.Second)

	// One window-function query for all actors' top users instead of one
	// point query per actor (was ~80 queries per poll).
	usersByActor, err := s.st.ActorUsersForActors(actorIDs, 8)
	if err != nil {
		httpError(w, "intel", err, http.StatusInternalServerError)
		return
	}
	// Last command per actor in one batched query so the actor table's
	// "Last cmd" column is populated (it was permanently blank — handleIntel
	// never set LastCommand, only the detail endpoint did). Best-effort: on
	// error just leave the column empty rather than failing the whole panel.
	lastCmdByActor, _ := s.st.LastCommandsForActors(actorIDs)

	for _, a := range actors {
		row := intelActorRow{
			ID:          a.ID,
			IP:          a.PrimaryIP,
			Source:      string(a.Source),
			Playbook:    a.Playbook,
			Intent:      a.Intent,
			Events:      a.EventCount,
			UniqueUsers: a.UniqueUsers,
			RateHour:    a.AttemptsPerHour,
			ProbeScore:  a.ProbeScore,
			Confidence:  a.Confidence,
			HASSH:       a.HASSH,
			SSHClient:   a.SSHClient,
			FirstSeen:   a.FirstSeen.UTC().Format(time.RFC3339),
			LastSeen:    a.LastSeen.UTC().Format(time.RFC3339),
		}
		if !isPrivateIP(a.PrimaryIP) {
			g := s.geo.cached(a.PrimaryIP)
			if g.OK {
				row.Country = g.Country
				row.City = g.City
				row.CC = g.CC
			}
		}
		for _, u := range usersByActor[a.ID] {
			row.TopUsers = append(row.TopUsers, topUserRow{User: u.Username, Hits: u.Count})
		}
		row.LastCommand = lastCmdByActor[a.ID]
		resp.Actors = append(resp.Actors, row)
	}

	cmds, err := s.st.RecentCommands(120)
	if err != nil {
		httpError(w, "intel", err, http.StatusInternalServerError)
		return
	}
	for _, c := range cmds {
		resp.RecentCommands = append(resp.RecentCommands, commandRowFromEvent(c))
	}

	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleActorDetail(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	a, err := s.st.GetActor(id)
	if err != nil {
		httpError(w, "intel", err, http.StatusNotFound)
		return
	}

	row := intelActorRow{
		ID:          a.ID,
		IP:          a.PrimaryIP,
		Source:      string(a.Source),
		Playbook:    a.Playbook,
		Intent:      a.Intent,
		Events:      a.EventCount,
		UniqueUsers: a.UniqueUsers,
		RateHour:    a.AttemptsPerHour,
		ProbeScore:  a.ProbeScore,
		Confidence:  a.Confidence,
		HASSH:       a.HASSH,
		SSHClient:   a.SSHClient,
		FirstSeen:   a.FirstSeen.UTC().Format(time.RFC3339),
		LastSeen:    a.LastSeen.UTC().Format(time.RFC3339),
	}
	if !isPrivateIP(a.PrimaryIP) {
		g := s.geo.cached(a.PrimaryIP)
		if g.OK {
			row.Country = g.Country
			row.City = g.City
			row.CC = g.CC
		}
	}
	users, err := s.st.ActorUsersLimit(id, 20)
	if err != nil {
		httpError(w, "intel", err, http.StatusInternalServerError)
		return
	}
	for _, u := range users {
		row.TopUsers = append(row.TopUsers, topUserRow{User: u.Username, Hits: u.Count})
	}
	if cmd, err := s.st.LastCommandByActor(id); err == nil {
		row.LastCommand = cmd
	} else if !errors.Is(err, sql.ErrNoRows) {
		httpError(w, "intel", err, http.StatusInternalServerError)
		return
	}

	events, err := s.st.EventsByActor(id, 150)
	if err != nil {
		httpError(w, "intel", err, http.StatusInternalServerError)
		return
	}
	var cmds []commandRow
	var all []commandRow
	for _, e := range events {
		cr := commandRowFromEvent(e)
		all = append(all, cr)
		if e.Command != "" {
			cmds = append(cmds, cr)
		}
	}
	sort.Slice(cmds, func(i, j int) bool { return cmds[i].TS > cmds[j].TS })

	_ = json.NewEncoder(w).Encode(actorDetailResponse{
		Actor:    row,
		Commands: cmds,
		Events:   all,
	})
}

func commandRowFromEvent(e store.CommandEvent) commandRow {
	return commandRow{
		TS:       e.TS.UTC().Format(time.RFC3339),
		Kind:     string(e.Kind),
		IP:       e.SrcIP,
		User:     e.Username,
		Actor:    actor.TrimActorPrefix(e.ActorID),
		Command:  e.Command,
		Session:  e.SessionID,
		SHA256:   e.SHA256,
		Filename: e.Filename,
		Source:   string(e.Source),
	}
}
