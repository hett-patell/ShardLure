package web

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/actor"
	"github.com/networkshard/shardlure/internal/store"
)

type Server struct {
	st            *store.Store
	addr          string
	geo           *geoResolver
	dashboardAuth string
	home          homePoint
	bazaarKey     string
	bazaarEndpoint string
	bazaarTags    []string
	bazaarMaxBytes int64
	// startedAt marks when this Server was constructed; surfaced as the
	// dashboard "uptime" so the operator can tell at a glance how long the
	// live process has been running (and spot an unexpected restart).
	startedAt time.Time
}

type Options struct {
	HomeLat        float64
	HomeLon        float64
	HomeCity       string
	HomeCountry    string
	HomeCC         string
	GeoEnabled     bool
	GeoInsecureHTTP bool
	BazaarAPIKey   string
	BazaarEndpoint string
	BazaarTags     []string
	BazaarMaxBytes int64
}

func New(st *store.Store, addr string, opts ...Options) *Server {
	if addr == "" {
		addr = ":8080"
	}
	home := defaultHomePoint()
	if len(opts) > 0 {
		if opts[0].HomeLat != 0 || opts[0].HomeLon != 0 {
			home.Lat = opts[0].HomeLat
			home.Lon = opts[0].HomeLon
		}
		if opts[0].HomeCity != "" {
			home.City = opts[0].HomeCity
		}
		if opts[0].HomeCountry != "" {
			home.Country = opts[0].HomeCountry
		}
		if opts[0].HomeCC != "" {
			home.CC = opts[0].HomeCC
		}
	}
	var firstOpt Options
	if len(opts) > 0 {
		firstOpt = opts[0]
	}
	bzKey := strings.TrimSpace(os.Getenv("SHARDLURE_BAZAAR_KEY"))
	if bzKey == "" {
		bzKey = strings.TrimSpace(os.Getenv("SHARDLURE_BAZAAR_API_KEY"))
	}
	if bzKey == "" {
		bzKey = firstOpt.BazaarAPIKey
	}
	bzEndpoint := firstOpt.BazaarEndpoint
	if bzEndpoint == "" {
		bzEndpoint = "https://mb-api.abuse.ch/api/v1/"
	}
	bzTags := firstOpt.BazaarTags
	if len(bzTags) == 0 {
		bzTags = []string{"shardlure", "honeypot"}
	}
	bzMax := firstOpt.BazaarMaxBytes
	if bzMax <= 0 {
		bzMax = 33 << 20
	}
	return &Server{
		st:             st,
		addr:           addr,
		geo:            newGeoResolver(geoOpts(len(opts) > 0, firstOpt), st),
		dashboardAuth:  strings.TrimSpace(os.Getenv("SHARDLURE_DASH_TOKEN")),
		home:           home,
		bazaarKey:      bzKey,
		bazaarEndpoint: bzEndpoint,
		bazaarTags:     bzTags,
		bazaarMaxBytes: bzMax,
		startedAt:      time.Now(),
	}
}

func (s *Server) Run() error {
	return s.RunContext(context.Background())
}

// RunContext runs the HTTP server and gracefully shuts it down when ctx is canceled.
func (s *Server) RunContext(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/intel", s.handleIntelPage)
	mux.HandleFunc("/api/intel", s.handleIntel)
	mux.HandleFunc("/api/intel/mitre", s.handleIntelMitre)
	mux.HandleFunc("/api/intel/sessions", s.handleIntelSessions)
	mux.HandleFunc("/api/intel/session", s.handleIntelSession)
	mux.HandleFunc("/api/intel/enrich", s.handleIntelEnrich)
	mux.HandleFunc("/api/intel/ttp", s.handleIntelTTP)
	mux.HandleFunc("/api/intel/payloads", s.handleIntelPayloads)
	mux.HandleFunc("/api/intel/payload", s.handleIntelPayload)
	mux.HandleFunc("/api/intel/wordlist", s.handleIntelWordlist)
	mux.HandleFunc("/api/intel/graph", s.handleIntelGraph)
	mux.HandleFunc("/api/intel/replay", s.handleIntelReplay)
	mux.HandleFunc("/api/intel/deobf", s.handleIntelDeobf)
	mux.HandleFunc("/api/intel/bazaar", s.handleIntelBazaar)
	mux.HandleFunc("/api/intel/bazaar/upload", s.handleBazaarUpload)
	mux.HandleFunc("/api/intel/timeline", s.handleIntelTimeline)
	mux.HandleFunc("/vendor/vis-network.min.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
		_, _ = w.Write(visNetworkJS)
	})
	mux.HandleFunc("/api/ioc/list", s.handleIOCList)
	mux.HandleFunc("/api/ioc/csv", s.handleIOCCSV)
	mux.HandleFunc("/api/ioc/stix", s.handleIOCSTIX)
	mux.HandleFunc("/api/actor", s.handleActorDetail)
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/dashboard", s.handleDashboard)
	mux.HandleFunc("/api/capture", s.handleCapture)

	// Diagnostic endpoints: net/http/pprof + a small RSS/cache
	// stats handler. All gated behind the same dashboard token used
	// by the rest of /api/* so the profile data isn't world-readable.
	// pprof imports register on http.DefaultServeMux as a side
	// effect; we re-register the handlers explicitly on our own mux
	// to avoid leaking them on the unauthenticated path.
	mux.HandleFunc("/debug/pprof/", s.guard(pprof.Index))
	mux.HandleFunc("/debug/pprof/cmdline", s.guard(pprof.Cmdline))
	mux.HandleFunc("/debug/pprof/profile", s.guard(pprof.Profile))
	mux.HandleFunc("/debug/pprof/symbol", s.guard(pprof.Symbol))
	mux.HandleFunc("/debug/pprof/trace", s.guard(pprof.Trace))
	mux.HandleFunc("/debug/runtime", s.guard(s.handleRuntimeStats))

	// Loud warning when the dashboard runs without a token: with
	// SHARDLURE_DASH_TOKEN unset, every endpoint is open — including the
	// credential/password wordlist export and /debug/pprof/*. The dashboard is
	// meant to live on Tailscale/loopback, but operators who bind it wider
	// should know it's wide open. (We warn rather than refuse, to preserve the
	// documented "token is optional defense-in-depth" behavior.)
	if s.dashboardAuth == "" {
		fmt.Fprintln(os.Stderr,
			"shardlure: WARNING dashboard is UNAUTHENTICATED (SHARDLURE_DASH_TOKEN unset) — "+
				"credential exports and pprof are world-readable to anyone who can reach this port. "+
				"Keep it on Tailscale/loopback or set SHARDLURE_DASH_TOKEN.")
	}

	srv := &http.Server{
		Addr:        s.addr,
		Handler:     mux,
		ReadTimeout: 10 * time.Second,
		// 60s rather than 20s so /debug/pprof/profile?seconds=30 can
		// complete. No handler is supposed to take longer than a few
		// seconds; if one does, the longer timeout means we can use
		// pprof to find out why instead of just getting a generic
		// upstream truncation.
		WriteTimeout: 60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		<-errCh
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

func (s *Server) requireDashboardAuth(w http.ResponseWriter, r *http.Request) bool {
	if s.dashboardAuth == "" {
		return true
	}
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if token == "" {
		token = strings.TrimSpace(r.Header.Get("X-ShardLure-Token"))
	}
	if token == "" {
		token = strings.TrimSpace(r.URL.Query().Get("token"))
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.dashboardAuth)) == 1 {
		return true
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="shardlure-dashboard"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

type dashboardResponse struct {
	GeneratedAt  string          `json:"generatedAt"`
	Summary      summaryBlock    `json:"summary"`
	Actors       []actorCard     `json:"actors"`
	Recent       []recentRecord  `json:"recent"`
	Sessions     []shellSessionRow `json:"sessions"`
	TopIPs       []topIPRow      `json:"topIps"`
	TopUsers     []topUserRow    `json:"topUsers"`
	TopCommands  []topCommandRow `json:"topCommands"`
	TopCountries []topCountryRow `json:"topCountries"`
	Hourly       []hourPoint     `json:"hourly"`
	Home         homePoint       `json:"home"`
}

// shellSessionRow is a flattened cowrie session for the "Recent shell
// sessions" dashboard panel. Only sessions that produced at least one
// cowrie.command.input event are surfaced -- a bare connect / login
// attempt is not worth a row of attention. Distinct from the intel API's
// sessionRow which serves the broader timeline view.
type shellSessionRow struct {
	ID         string  `json:"id"`
	IP         string  `json:"ip"`
	Username   string  `json:"username,omitempty"`
	StartTS    string  `json:"startTs"`
	EndTS      string  `json:"endTs"`
	CmdCount   int     `json:"cmdCount"`
	EventCount int     `json:"eventCount"`
	Sample     string  `json:"sample,omitempty"`
	Country    string  `json:"country,omitempty"`
	CC         string  `json:"cc,omitempty"`
	City       string  `json:"city,omitempty"`
	Lat        float64 `json:"lat,omitempty"`
	Lon        float64 `json:"lon,omitempty"`
}

type summaryBlock struct {
	EventCount int `json:"eventCount"`
	ActorCount int `json:"actorCount"`
	UniqueIPs  int `json:"uniqueIps"`
	Countries  int `json:"countries"`
}

type actorCard struct {
	ID       string  `json:"id"`
	IP       string  `json:"ip"`
	Playbook string  `json:"playbook"`
	Events   int     `json:"events"`
	RateHour float64 `json:"rateHour"`
	LastSeen string  `json:"lastSeen"`
	Conf     int     `json:"conf"`
	Lat      float64 `json:"lat,omitempty"`
	Lon      float64 `json:"lon,omitempty"`
	Country  string  `json:"country,omitempty"`
	CC       string  `json:"cc,omitempty"`
}

type recentRecord struct {
	TS      string `json:"ts"`
	Kind    string `json:"kind"`
	IP      string `json:"ip"`
	User    string `json:"user"`
	Actor   string `json:"actor"`
	Command string `json:"command,omitempty"`
}

type topIPRow struct {
	IP      string `json:"ip"`
	Hits    int    `json:"hits"`
	CC      string `json:"cc,omitempty"`
	Country string `json:"country,omitempty"`
	City    string `json:"city,omitempty"`
}

type topUserRow struct {
	User string `json:"user"`
	Hits int    `json:"hits"`
}

type topCommandRow struct {
	Command string `json:"command"`
	Hits    int    `json:"hits"`
}

type topCountryRow struct {
	CC      string `json:"cc"`
	Country string `json:"country"`
	Hits    int    `json:"hits"`
}

type hourPoint struct {
	T int64 `json:"t"`
	N int   `json:"n"`
}

type homePoint struct {
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	Country string  `json:"country"`
	City    string  `json:"city"`
	CC      string  `json:"cc"`
}

func geoOpts(has bool, o Options) geoConfig {
	if !has {
		return geoConfig{}
	}
	return geoConfig{Enabled: o.GeoEnabled, InsecureHTTP: o.GeoInsecureHTTP}
}

func defaultHomePoint() homePoint {
	return homePoint{
		Lat:     19.0760,
		Lon:     72.8777,
		City:    "Mumbai",
		Country: "India",
		CC:      "IN",
	}
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	actors, err := s.st.ListActors(100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	events, err := s.st.RecentEvents(120)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	topIPs, err := s.st.TopSourceIPs(25)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	topUsers, err := s.st.TopUsernames(20)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	topCommands, err := s.st.TopCommands(20)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hourly, err := s.st.HourlyEventCounts(72)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	shellSessions, err := s.st.RecentShellSessions(time.Now().UTC().Add(-24*time.Hour), 30)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	uniqueIPs, _ := s.st.UniqueIPCount()
	ec, _ := s.st.EventCount()
	ac, _ := s.st.ActorCount()

	resp := dashboardResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Summary: summaryBlock{
			EventCount: ec,
			ActorCount: ac,
		},
		Home: s.home,
	}

	countryStats := map[string]*topCountryRow{}

	geoIPs := make([]string, 0, len(actors)+len(topIPs))
	for _, a := range actors {
		geoIPs = append(geoIPs, a.PrimaryIP)
	}
	for _, row := range topIPs {
		geoIPs = append(geoIPs, row.Key)
	}
	s.geo.prefetch(geoIPs, 5*time.Second)

	for _, a := range actors {
		card := actorCard{
			ID:       a.ID,
			IP:       a.PrimaryIP,
			Playbook: a.Playbook,
			Events:   a.EventCount,
			RateHour: a.AttemptsPerHour,
			LastSeen: a.LastSeen.UTC().Format(time.RFC3339),
			Conf:     a.Confidence,
		}
		if !isPrivateIP(a.PrimaryIP) {
			g := s.geo.cached(a.PrimaryIP)
			if g.OK {
				card.Lat = g.Lat
				card.Lon = g.Lon
				card.Country = g.Country
				card.CC = g.CC
			}
		}
		resp.Actors = append(resp.Actors, card)
	}

	for _, row := range topIPs {
		var cc, country, city string
		if !isPrivateIP(row.Key) {
			g := s.geo.cached(row.Key)
			if g.OK {
				cc = g.CC
				country = g.Country
				city = g.City
			}
		}
		resp.TopIPs = append(resp.TopIPs, topIPRow{
			IP:      row.Key,
			Hits:    row.Hits,
			CC:      cc,
			Country: country,
			City:    city,
		})
		// Aggregate into the country chart. If geo hasn't resolved yet (a brand-
		// new high-volume attacker IP whose lookup didn't make the prefetch
		// budget, and isn't in the persistent cache), bucket its hits under
		// "Unknown" rather than DROPPING them — otherwise Attack Geography
		// silently disagrees with Top source IPs (e.g. a 64k-hit IP showing in
		// the IP list but missing from the country totals). Private/admin IPs
		// are excluded entirely.
		key, label := cc, country
		if isPrivateIP(row.Key) {
			continue
		}
		if key == "" {
			key, label = "??", "Unknown"
		}
		countryRow, ok := countryStats[key]
		if !ok {
			countryRow = &topCountryRow{CC: key, Country: label}
			countryStats[key] = countryRow
		}
		countryRow.Hits += row.Hits
	}

	for _, row := range topUsers {
		resp.TopUsers = append(resp.TopUsers, topUserRow{User: row.Key, Hits: row.Hits})
	}
	for _, row := range topCommands {
		resp.TopCommands = append(resp.TopCommands, topCommandRow{Command: row.Key, Hits: row.Hits})
	}

	// Prefer the authoritative all-events hits-by-country aggregation so the
	// globe's "By country" matches the intel page's Attack Geography and isn't
	// limited to the top-25 IPs. Fall back to the top-25-derived countryStats
	// if the geo-join query fails.
	if cph, err := s.st.TopCountriesByHits(12); err == nil && len(cph) > 0 {
		resp.TopCountries = resp.TopCountries[:0]
		for _, c := range cph {
			resp.TopCountries = append(resp.TopCountries, topCountryRow{CC: c.CC, Country: c.Country, Hits: c.Hits})
		}
	} else {
		for _, c := range countryStats {
			resp.TopCountries = append(resp.TopCountries, *c)
		}
		sort.Slice(resp.TopCountries, func(i, j int) bool { return resp.TopCountries[i].Hits > resp.TopCountries[j].Hits })
		if len(resp.TopCountries) > 12 {
			resp.TopCountries = resp.TopCountries[:12]
		}
	}
	resp.Summary.UniqueIPs = uniqueIPs
	// Countries: count distinct CCs across the WHOLE geo cache, not just the
	// top-25 IPs that feed the topCountries chart — otherwise a 2600-IP dataset
	// spanning 20+ countries reported ~7. Fall back to the top-25-derived count
	// (minus the "??" Unknown bucket) if the geo-cache query fails.
	if cc, err := s.st.DistinctGeoCountryCount(); err == nil && cc > 0 {
		resp.Summary.Countries = cc
	} else {
		resp.Summary.Countries = len(countryStats)
		if _, hasUnknown := countryStats["??"]; hasUnknown {
			resp.Summary.Countries--
		}
	}

	for _, row := range hourly {
		resp.Hourly = append(resp.Hourly, hourPoint{T: row.Hour.Unix(), N: row.Hits})
	}

	for _, e := range events {
		resp.Recent = append(resp.Recent, recentRecord{
			TS:      e.TS.UTC().Format(time.RFC3339),
			Kind:    string(e.Kind),
			IP:      e.SrcIP,
			User:    e.Username,
			Actor:   actor.TrimActorPrefix(e.ActorID),
			Command: strings.TrimSpace(e.Command),
		})
	}

	for _, sess := range shellSessions {
		row := shellSessionRow{
			ID:         sess.ID,
			IP:         sess.SrcIP,
			Username:   sess.Username,
			StartTS:    sess.StartTS.UTC().Format(time.RFC3339),
			EndTS:      sess.EndTS.UTC().Format(time.RFC3339),
			CmdCount:   sess.CmdCount,
			EventCount: sess.EventCount,
			Sample:     strings.TrimSpace(sess.FirstCommand),
		}
		if !isPrivateIP(sess.SrcIP) {
			g := s.geo.cached(sess.SrcIP)
			if g.OK {
				row.Country = g.Country
				row.CC = g.CC
				row.City = g.City
				row.Lat = g.Lat
				row.Lon = g.Lon
			}
		}
		resp.Sessions = append(resp.Sessions, row)
	}

	_ = json.NewEncoder(w).Encode(resp)
}

// guard wraps an HTTP handler with the dashboard auth check. Used
// for diagnostic endpoints (pprof, runtime stats) so they share the
// exact same token check as /api/* without each handler having to
// re-implement the auth boilerplate.
func (s *Server) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.requireDashboardAuth(w, r) {
			return
		}
		h(w, r)
	}
}

// handleRuntimeStats returns a tiny JSON snapshot of process memory
// and bounded-cache sizes. Useful for "is the leak fix actually
// holding?" smoke checks without grabbing a full pprof heap dump.
//
// Fields:
//   - heapAlloc / heapInuse / sys: from runtime.MemStats. heapAlloc
//     is live objects; heapInuse is the resident heap span; sys is
//     total OS-reserved bytes (≈ RSS modulo unmapping).
//   - numGoroutines / numGC: classic Go runtime counters.
//   - liveJournalCollectorIPs / liveJournalCollectorLRU: the size of
//     the bounded journal collector. Should plateau near the cap on
//     a busy host; previously this grew without bound.
//   - geoCacheEntries / geoCacheLRU / geoCacheMax: same for the IP
//     geo cache. Reads geoResolver.cache via its mutex so the
//     snapshot is consistent.
func (s *Server) handleRuntimeStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	geoEntries, geoLRU, geoMax := 0, 0, 0
	if s.geo != nil {
		s.geo.mu.Lock()
		geoEntries = len(s.geo.cache)
		if s.geo.lru != nil {
			geoLRU = s.geo.lru.Len()
		}
		geoMax = s.geo.maxSize
		s.geo.mu.Unlock()
	}

	liveIPs, liveLRU, liveMax, liveUsersCap := actor.LiveJournalCollectorStats()

	resp := map[string]any{
		"generatedAt":               time.Now().UTC().Format(time.RFC3339Nano),
		"heapAlloc":                 ms.HeapAlloc,
		"heapInuse":                 ms.HeapInuse,
		"sys":                       ms.Sys,
		"numGoroutines":             runtime.NumGoroutine(),
		"numGC":                     ms.NumGC,
		"pauseTotalNs":              ms.PauseTotalNs,
		"liveJournalCollectorIPs":   liveIPs,
		"liveJournalCollectorLRU":   liveLRU,
		"liveJournalCollectorMax":   liveMax,
		"liveJournalUsersPerIPMax":  liveUsersCap,
		"geoCacheEntries":           geoEntries,
		"geoCacheLRU":               geoLRU,
		"geoCacheMax":               geoMax,
	}
	_ = json.NewEncoder(w).Encode(resp)
}
