package web

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/store"
)

type intelResponse struct {
	GeneratedAt    string            `json:"generatedAt"`
	Summary        summaryBlock      `json:"summary"`
	KindCounts     []labelCountRow   `json:"kindCounts"`
	IntentCounts   []labelCountRow   `json:"intentCounts"`
	PlaybookCounts []labelCountRow   `json:"playbookCounts"`
	SourceCounts   []labelCountRow   `json:"sourceCounts"`
	Heatmap        []heatmapCell     `json:"heatmap"`
	Actors         []intelActorRow   `json:"actors"`
	RecentCommands []commandRow      `json:"recentCommands"`
}

type labelCountRow struct {
	Label string `json:"label"`
	Hits  int    `json:"hits"`
}

type heatmapCell struct {
	T    int64  `json:"t"`
	Kind string `json:"kind"`
	N    int    `json:"n"`
}

type intelActorRow struct {
	ID            string        `json:"id"`
	IP            string        `json:"ip"`
	Source        string        `json:"source"`
	Playbook      string        `json:"playbook"`
	Intent        string        `json:"intent"`
	Events        int           `json:"events"`
	UniqueUsers   int           `json:"uniqueUsers"`
	RateHour      float64       `json:"rateHour"`
	ProbeScore    int           `json:"probeScore"`
	Confidence    int           `json:"confidence"`
	HASSH         string        `json:"hassh,omitempty"`
	SSHClient     string        `json:"sshClient,omitempty"`
	FirstSeen     string        `json:"firstSeen"`
	LastSeen      string        `json:"lastSeen"`
	Country       string        `json:"country,omitempty"`
	City          string        `json:"city,omitempty"`
	CC            string        `json:"cc,omitempty"`
	TopUsers      []topUserRow  `json:"topUsers"`
	LastCommand   string        `json:"lastCommand,omitempty"`
}

type commandRow struct {
	TS        string `json:"ts"`
	Kind      string `json:"kind"`
	IP        string `json:"ip"`
	User      string `json:"user"`
	Actor     string `json:"actor"`
	Command   string `json:"command"`
	Session   string `json:"session,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	Filename  string `json:"filename,omitempty"`
	Source    string `json:"source"`
}

type actorDetailResponse struct {
	Actor    intelActorRow `json:"actor"`
	Commands []commandRow  `json:"commands"`
	Events   []commandRow  `json:"events"`
}

func (s *Server) handleIntelPage(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
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

	ec, _ := s.st.EventCount()
	ac, _ := s.st.ActorCount()
	uniqueIPs, _ := s.st.UniqueIPCount()

	resp := intelResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Summary: summaryBlock{
			EventCount: ec,
			ActorCount: ac,
			UniqueIPs:  uniqueIPs,
		},
	}

	kinds, _ := s.st.CountsByKind()
	for _, k := range kinds {
		resp.KindCounts = append(resp.KindCounts, labelCountRow{Label: k.Label, Hits: k.Hits})
	}
	intents, _ := s.st.CountsByIntent()
	for _, k := range intents {
		resp.IntentCounts = append(resp.IntentCounts, labelCountRow{Label: k.Label, Hits: k.Hits})
	}
	playbooks, _ := s.st.CountsByPlaybook()
	for _, k := range playbooks {
		resp.PlaybookCounts = append(resp.PlaybookCounts, labelCountRow{Label: k.Label, Hits: k.Hits})
	}
	sources, _ := s.st.CountsBySource()
	for _, k := range sources {
		resp.SourceCounts = append(resp.SourceCounts, labelCountRow{Label: k.Label, Hits: k.Hits})
	}

	cells, _ := s.st.HourlyEventCountsByKind(72)
	for _, c := range cells {
		resp.Heatmap = append(resp.Heatmap, heatmapCell{
			T:    c.Hour.Unix(),
			Kind: c.Kind,
			N:    c.Hits,
		})
	}

	actors, _ := s.st.ListActors(80)
	geoIPs := make([]string, 0, len(actors))
	for _, a := range actors {
		geoIPs = append(geoIPs, a.PrimaryIP)
	}
	s.geo.prefetch(geoIPs, 3*time.Second)

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
		users, _ := s.st.ActorUsersLimit(a.ID, 8)
		for _, u := range users {
			row.TopUsers = append(row.TopUsers, topUserRow{User: u.Username, Hits: u.Count})
		}
		resp.Actors = append(resp.Actors, row)
	}

	cmds, _ := s.st.RecentCommands(120)
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
		http.Error(w, err.Error(), http.StatusNotFound)
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
	users, _ := s.st.ActorUsersLimit(id, 20)
	for _, u := range users {
		row.TopUsers = append(row.TopUsers, topUserRow{User: u.Username, Hits: u.Count})
	}
	if cmd, err := s.st.LastCommandByActor(id); err == nil {
		row.LastCommand = cmd
	}

	events, _ := s.st.EventsByActor(id, 150)
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
	actor := e.ActorID
	if strings.HasPrefix(actor, "journal:") {
		actor = strings.TrimPrefix(actor, "journal:")
	} else if strings.HasPrefix(actor, "cowrie:") {
		actor = strings.TrimPrefix(actor, "cowrie:")
	}
	return commandRow{
		TS:       e.TS.UTC().Format(time.RFC3339),
		Kind:     string(e.Kind),
		IP:       e.SrcIP,
		User:     e.Username,
		Actor:    actor,
		Command:  e.Command,
		Session:  e.SessionID,
		SHA256:   e.SHA256,
		Filename: e.Filename,
		Source:   string(e.Source),
	}
}
