package web

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/networkshard/shardlure/internal/actor"
	"github.com/networkshard/shardlure/internal/netmatch"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

// httpError logs the real (possibly DB-internal) error server-side and returns
// a generic message to the client, so store/SQL internals aren't exposed over
// HTTP. All these endpoints are auth-gated, but leaking schema/error detail is
// still poor hygiene. `where` is a short handler tag for the server log.
func httpError(w http.ResponseWriter, where string, err error, code int) {
	log.Printf("web: %s: %v", where, err)
	http.Error(w, http.StatusText(code), code)
}

type Server struct {
	st             *store.Store
	addr           string
	geo            *geoResolver
	dashboardAuth  string
	home           homePoint
	bazaarKey      string
	bazaarEndpoint string
	bazaarTags     []string
	bazaarMaxBytes int64

	// AbuseIPDB reporting (opt-in, off unless abuseReportEnabled AND
	// abuseKey present). abuseAdmin hard-rejects admin IPs in Vet; the rest
	// mirror the config knobs. Reporting is the only outbound WRITE surface
	// the dashboard exposes beyond bazaar, so it carries the same throttle.
	abuseKey        string
	abuseEndpoint   string
	abuseEnabled    bool
	abuseCategories []int
	abuseMinProbe   int
	abuseRewindow   time.Duration
	abuseComment    string
	abuseAdmin      *netmatch.Set
	// startedAt marks when this Server was constructed; surfaced as the
	// dashboard "uptime" so the operator can tell at a glance how long the
	// live process has been running (and spot an unexpected restart).
	startedAt time.Time

	// bazaarMu + lastBazaarAt throttle actual MalwareBazaar submissions
	// process-wide. The frontend paces "Upload All" at 2.5s, but that's UX
	// only and bypassable (curl the endpoint in a loop); this server-side
	// floor guarantees we never machine-gun the MB API regardless of client.
	bazaarMu     sync.Mutex
	lastBazaarAt time.Time

	// abuseReportMu + lastAbuseReportAt throttle AbuseIPDB /report POSTs
	// process-wide, the same defense as bazaar: the per-actor button is
	// bypassable, so a server-side floor guarantees we never spam the API.
	abuseReportMu     sync.Mutex
	lastAbuseReportAt time.Time

	// countriesCache memoizes the (relatively expensive) full-table
	// hits-by-country aggregation, which both /api/dashboard and /api/intel
	// render on every poll. The result changes slowly, so a few-second TTL
	// removes the duplicate per-page full scans without staleness anyone notices.
	countriesMu     sync.Mutex
	countriesCached []topCountryRow
	countriesAt     time.Time

	// eventsCache memoizes the full windowed event slice that the intel
	// endpoints (mitre/ttp/deobf/graph/wordlist/ioc) each load on every poll.
	// Materializing a 7–30d window over a multi-million-row table costs a full
	// scan and a multi-GB allocation; without this, several of those widgets
	// firing together on one tab open ran that work concurrently, an OOM/IO
	// storm. Keyed by window-hours; computed under the lock so concurrent
	// pollers of the same window collapse onto one scan.
	eventsMu    sync.Mutex
	eventsCache map[int]windowedEvents

	// statsCache memoizes the whole-table aggregates both /api/dashboard and
	// /api/intel recompute on every 5s poll per open tab: COUNT(*) over
	// events, COUNT(DISTINCT src_ip), and the unbounded kind/source GROUP
	// BYs. On a multi-million-row DB these were the dominant recurring
	// load; the data only changes on the 5s ingest tick, so a short TTL is
	// invisible to the operator.
	statsMu     sync.Mutex
	statsCached *summaryStats
	statsAt     time.Time
}

type summaryStats struct {
	Events       int
	Actors       int
	UniqueIPs    int
	Countries    int
	KindCounts   []store.LabelCount
	SourceCounts []store.LabelCount
}

const statsTTL = 10 * time.Second

// summaryStatsCached returns the memoized whole-table aggregates,
// recomputing at most once per statsTTL.
func (s *Server) summaryStatsCached() (*summaryStats, error) {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	if s.statsCached != nil && time.Since(s.statsAt) < statsTTL {
		return s.statsCached, nil
	}
	ec, err := s.st.EventCount()
	if err != nil {
		return s.statsCached, err
	}
	ac, err := s.st.ActorCount()
	if err != nil {
		return s.statsCached, err
	}
	ips, err := s.st.UniqueIPCount()
	if err != nil {
		return s.statsCached, err
	}
	// Best-effort; 0 on error keeps the panel alive.
	countries, _ := s.st.DistinctGeoCountryCount()
	kinds, err := s.st.CountsByKind()
	if err != nil {
		return s.statsCached, err
	}
	sources, err := s.st.CountsBySource()
	if err != nil {
		return s.statsCached, err
	}
	s.statsCached = &summaryStats{
		Events:       ec,
		Actors:       ac,
		UniqueIPs:    ips,
		Countries:    countries,
		KindCounts:   kinds,
		SourceCounts: sources,
	}
	s.statsAt = time.Now()
	return s.statsCached, nil
}

type windowedEvents struct {
	events []*models.Event
	at     time.Time
}

// eventsWindowTTL bounds staleness of the cached window. Data only changes on
// the 5s ingest tick, so a few seconds is invisible to the operator.
const eventsWindowTTL = 15 * time.Second

// maxWindowHours clamps the queried window so a stray ?window=99999d can't pin
// an enormous slice in cache. Retention caps the data well below this anyway.
const maxWindowHours = 24 * 366

// eventsForWindowCached returns the events with TS within the last windowHours,
// memoized per window for eventsWindowTTL. The returned slice is shared and
// MUST be treated read-only by callers (the intel collectors only read).
func (s *Server) eventsForWindowCached(windowHours int) ([]*models.Event, error) {
	if windowHours <= 0 {
		windowHours = 24
	}
	if windowHours > maxWindowHours {
		windowHours = maxWindowHours
	}
	s.eventsMu.Lock()
	defer s.eventsMu.Unlock()
	if e, ok := s.eventsCache[windowHours]; ok && time.Since(e.at) < eventsWindowTTL {
		return e.events, nil
	}
	since := time.Now().Add(-time.Duration(windowHours) * time.Hour)
	ev, err := s.st.EventsSinceAll(since)
	if err != nil {
		if e, ok := s.eventsCache[windowHours]; ok {
			return e.events, nil // serve last-good on transient error
		}
		return nil, err
	}
	if s.eventsCache == nil {
		s.eventsCache = make(map[int]windowedEvents, 4)
	}
	// Evict stale entries so the map can't accumulate slices for windows that
	// are no longer being polled.
	for k, e := range s.eventsCache {
		if time.Since(e.at) >= eventsWindowTTL {
			delete(s.eventsCache, k)
		}
	}
	s.eventsCache[windowHours] = windowedEvents{events: ev, at: time.Now()}
	return ev, nil
}

// topCountriesCached returns the hits-by-country aggregation, recomputing at
// most once per countriesTTL. Shared by the dashboard and intel handlers.
const countriesTTL = 10 * time.Second

func (s *Server) topCountriesCached() []topCountryRow {
	s.countriesMu.Lock()
	defer s.countriesMu.Unlock()
	if s.countriesCached != nil && time.Since(s.countriesAt) < countriesTTL {
		return s.countriesCached
	}
	cph, err := s.st.TopCountriesByHits(12)
	if err != nil {
		return s.countriesCached // serve last-good (possibly nil) on error
	}
	rows := make([]topCountryRow, 0, len(cph))
	for _, c := range cph {
		rows = append(rows, topCountryRow{CC: c.CC, Country: c.Country, Hits: c.Hits})
	}
	s.countriesCached = rows
	s.countriesAt = time.Now()
	return rows
}

type Options struct {
	HomeLat         float64
	HomeLon         float64
	HomeCity        string
	HomeCountry     string
	HomeCC          string
	GeoEnabled      bool
	GeoInsecureHTTP bool
	BazaarAPIKey    string
	BazaarEndpoint  string
	BazaarTags      []string
	BazaarMaxBytes  int64

	// AbuseIPDB opt-in reporting. AbuseReportEnabled + a key (from
	// SHARDLURE_ABUSEIPDB_KEY, reused from enrichment) are both required to
	// arm the dashboard "Report" button. AdminIPs feed the Vet hard-reject.
	AbuseReportEnabled bool
	AbuseEndpoint      string
	AbuseCategories    []int
	AbuseMinProbe      int
	AbuseRewindowHours int
	AbuseComment       string
	AdminIPs           []string
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

	// AbuseIPDB reporting: reuse the same env key as enrichment /check. Off
	// unless the operator both enabled it in config AND provided a key.
	abuseKey := strings.TrimSpace(os.Getenv("SHARDLURE_ABUSEIPDB_KEY"))
	abuseEndpoint := firstOpt.AbuseEndpoint
	if abuseEndpoint == "" {
		abuseEndpoint = "https://api.abuseipdb.com/api/v2/report"
	}
	abuseCats := firstOpt.AbuseCategories
	if len(abuseCats) == 0 {
		abuseCats = []int{18, 22}
	}
	abuseRewindow := time.Duration(firstOpt.AbuseRewindowHours) * time.Hour
	if abuseRewindow <= 0 {
		abuseRewindow = 24 * time.Hour
	}
	return &Server{
		st:              st,
		addr:            addr,
		geo:             newGeoResolver(geoOpts(len(opts) > 0, firstOpt), st),
		dashboardAuth:   strings.TrimSpace(os.Getenv("SHARDLURE_DASH_TOKEN")),
		home:            home,
		bazaarKey:       bzKey,
		bazaarEndpoint:  bzEndpoint,
		bazaarTags:      bzTags,
		bazaarMaxBytes:  bzMax,
		abuseKey:        abuseKey,
		abuseEndpoint:   abuseEndpoint,
		abuseEnabled:    firstOpt.AbuseReportEnabled,
		abuseCategories: abuseCats,
		abuseMinProbe:   firstOpt.AbuseMinProbe,
		abuseRewindow:   abuseRewindow,
		abuseComment:    firstOpt.AbuseComment,
		abuseAdmin:      netmatch.New(firstOpt.AdminIPs),
		startedAt:       time.Now(),
	}
}

// RunContext runs the HTTP server and gracefully shuts it down when ctx is canceled.
func (s *Server) RunContext(ctx context.Context) error {
	mux := http.NewServeMux()
	// Every /api/* route is registered through s.guard so the auth check
	// lives in ONE place — a new handler cannot forget it. Handlers keep
	// their own inner requireDashboardAuth calls harmlessly (it's
	// idempotent), but the guard is what enforces.
	mux.HandleFunc("/intel", s.handleIntelPage) // page route: token-in-query allowed, see requirePageAuth
	mux.HandleFunc("/api/intel", s.guard(s.handleIntel))
	mux.HandleFunc("/api/intel/mitre", s.guard(s.handleIntelMitre))
	mux.HandleFunc("/api/intel/sessions", s.guard(s.handleIntelSessions))
	mux.HandleFunc("/api/intel/session", s.guard(s.handleIntelSession))
	mux.HandleFunc("/api/intel/enrich", s.guard(s.handleIntelEnrich))
	mux.HandleFunc("/api/intel/ttp", s.guard(s.handleIntelTTP))
	mux.HandleFunc("/api/intel/payloads", s.guard(s.handleIntelPayloads))
	mux.HandleFunc("/api/intel/payload", s.guard(s.handleIntelPayload))
	mux.HandleFunc("/api/intel/wordlist", s.guard(s.handleIntelWordlist))
	mux.HandleFunc("/api/intel/graph", s.guard(s.handleIntelGraph))
	mux.HandleFunc("/api/intel/replay", s.guard(s.handleIntelReplay))
	mux.HandleFunc("/api/intel/deobf", s.guard(s.handleIntelDeobf))
	mux.HandleFunc("/api/intel/bazaar", s.guard(s.handleIntelBazaar))
	mux.HandleFunc("/api/intel/bazaar/upload", s.guard(s.handleBazaarUpload))
	mux.HandleFunc("/api/intel/abuseipdb/report", s.guard(s.handleAbuseIPDBReport))
	mux.HandleFunc("/api/intel/tunnels", s.guard(s.handleIntelTunnels))
	mux.HandleFunc("/api/intel/timeline", s.guard(s.handleIntelTimeline))
	mux.HandleFunc("/vendor/vis-network.min.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
		_, _ = w.Write(visNetworkJS)
	})
	mux.HandleFunc("/api/ioc/list", s.guard(s.handleIOCList))
	mux.HandleFunc("/api/ioc/csv", s.guard(s.handleIOCCSV))
	mux.HandleFunc("/api/ioc/stix", s.guard(s.handleIOCSTIX))
	mux.HandleFunc("/api/actor", s.guard(s.handleActorDetail))
	mux.HandleFunc("/", s.handleIndex) // page route
	mux.HandleFunc("/api/dashboard", s.guard(s.handleDashboard))
	mux.HandleFunc("/api/capture", s.guard(s.handleCapture))

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

	// With SHARDLURE_DASH_TOKEN unset every endpoint is open — including the
	// credential/password wordlist export and /debug/pprof/*. The dashboard is
	// meant to live on Tailscale/loopback.
	//
	// Fail CLOSED for the one config that's almost certainly a mistake: an
	// unauthenticated bind to a public, routable address (exposing credential
	// exports to the internet). Loopback / private / CGNAT (Tailscale) / and
	// the bare ":port" / 0.0.0.0 "behind a firewall" case stay a warning, to
	// preserve the documented "token is optional defense-in-depth" behavior.
	if s.dashboardAuth == "" {
		if host := listenHostIP(s.addr); host != nil && isPublicIP(host) {
			return fmt.Errorf("refusing to start: dashboard would bind a PUBLIC address (%s) with no "+
				"SHARDLURE_DASH_TOKEN set — credential exports and pprof would be world-readable. "+
				"Set a token, or bind to loopback/Tailscale", s.addr)
		}
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
		// Bound idle keep-alive connections so a slow/slowloris client can't
		// hold sockets open indefinitely.
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
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
	if !s.requirePageAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

// tokenMatches is the constant-time token comparison shared by the API
// (header-only) and page (header or ?token=) auth gates.
func (s *Server) tokenMatches(token string) bool {
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(token)), []byte(s.dashboardAuth)) == 1
}

// listenHostIP returns the parsed IP a listen address binds to, or nil when the
// host is empty (":8080"), a wildcard ("0.0.0.0"/"::"), or a hostname — i.e.
// the "behind a firewall / Tailscale" cases we only warn about, not the
// explicit public-IP bind we refuse.
func listenHostIP(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr // addr may be a bare host with no port
	}
	if host == "" {
		return nil // ":8080" — wildcard, can't tell if public; warn only
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		return nil // hostname or 0.0.0.0/:: — warn only
	}
	return ip
}

// isPublicIP reports whether ip is a globally-routable address: not loopback,
// private, CGNAT/Tailscale (100.64/10), link-local, multicast, or unspecified.
func isPublicIP(ip net.IP) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	// 100.64.0.0/10 CGNAT — Tailscale's range; documented bind target, allow it.
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return false
	}
	return true
}

// requireDashboardAuth gates /api/* and debug routes. Header-only by design:
// the token must never travel in an /api URL, where it would leak into access
// logs, Referer headers, and proxy logs. The dashboard's fetch wrapper always
// sets the Authorization header, so these routes need nothing else.
func (s *Server) requireDashboardAuth(w http.ResponseWriter, r *http.Request) bool {
	if s.dashboardAuth == "" {
		return true
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if strings.TrimSpace(token) == "" {
		token = r.Header.Get("X-ShardLure-Token")
	}
	if s.tokenMatches(token) {
		return true
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="shardlure-dashboard"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

// requirePageAuth gates the two HTML page routes (/ and /intel). Unlike the API
// gate it ALSO accepts a ?token= query param: a browser navigating to the
// dashboard URL can't set a header, so the page must load first for its JS to
// stash the token and set the header on every subsequent /api call. Without
// this, a configured SHARDLURE_DASH_TOKEN made the dashboard unreachable in a
// browser (the page 401'd before any JS ran). Token-in-URL exposure is confined
// to these two GETs; all data endpoints stay header-only above.
func (s *Server) requirePageAuth(w http.ResponseWriter, r *http.Request) bool {
	if s.dashboardAuth == "" {
		return true
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if strings.TrimSpace(token) == "" {
		token = r.Header.Get("X-ShardLure-Token")
	}
	if strings.TrimSpace(token) == "" {
		token = r.URL.Query().Get("token")
	}
	if s.tokenMatches(token) {
		return true
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="shardlure-dashboard"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

type dashboardResponse struct {
	GeneratedAt  string            `json:"generatedAt"`
	Summary      summaryBlock      `json:"summary"`
	Actors       []actorCard       `json:"actors"`    // recent actors (drives globe points/arcs)
	TopActors    []actorCard       `json:"topActors"` // actors by event volume (the "Top actors" widget)
	Recent       []recentRecord    `json:"recent"`
	Sessions     []shellSessionRow `json:"sessions"`
	TopIPs       []topIPRow        `json:"topIps"`
	TopUsers     []topUserRow      `json:"topUsers"`
	TopCommands  []topCommandRow   `json:"topCommands"`
	TopCountries []topCountryRow   `json:"topCountries"`
	Hourly       []hourPoint       `json:"hourly"`
	Home         homePoint         `json:"home"`
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
		httpError(w, "server", err, http.StatusInternalServerError)
		return
	}
	events, err := s.st.RecentEvents(120)
	if err != nil {
		httpError(w, "server", err, http.StatusInternalServerError)
		return
	}
	topIPs, err := s.st.TopSourceIPs(25)
	if err != nil {
		httpError(w, "server", err, http.StatusInternalServerError)
		return
	}
	topUsers, err := s.st.TopUsernames(20)
	if err != nil {
		httpError(w, "server", err, http.StatusInternalServerError)
		return
	}
	topCommands, err := s.st.TopCommands(20)
	if err != nil {
		httpError(w, "server", err, http.StatusInternalServerError)
		return
	}
	hourly, err := s.st.HourlyEventCounts(72)
	if err != nil {
		httpError(w, "server", err, http.StatusInternalServerError)
		return
	}
	shellSessions, err := s.st.RecentShellSessions(time.Now().UTC().Add(-24*time.Hour), 30)
	if err != nil {
		httpError(w, "server", err, http.StatusInternalServerError)
		return
	}
	var ec, ac, uniqueIPs int
	if stats, err := s.summaryStatsCached(); err == nil {
		ec, ac, uniqueIPs = stats.Events, stats.Actors, stats.UniqueIPs
	}

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
	// Fire-and-forget: blocking this 5s-polled handler on outbound geo
	// lookups stalled the response up to the whole poll interval when a
	// batch of new IPs appeared. The frontend renders "resolving…" for
	// missing geo and the next poll picks up the cached result; prefetch
	// dedupes in-flight lookups so overlapping polls are safe.
	go s.geo.prefetch(geoIPs, 5*time.Second)

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

	// Top actors by event VOLUME for the "Top actors" widget. resp.Actors is
	// ordered by last_seen (for the live globe), so the widget — slicing that —
	// showed recent actors, not the highest-volume ones (the 64k-event top
	// attacker was missing). This is a separate, volume-ordered list.
	if topActors, err := s.st.TopActorsByEvents(14); err == nil {
		for _, a := range topActors {
			tc := actorCard{
				ID:       a.ID,
				IP:       a.PrimaryIP,
				Playbook: a.Playbook,
				Events:   a.EventCount,
				RateHour: a.AttemptsPerHour,
				LastSeen: a.LastSeen.UTC().Format(time.RFC3339),
				Conf:     a.Confidence,
			}
			if !isPrivateIP(a.PrimaryIP) {
				if g := s.geo.cached(a.PrimaryIP); g.OK {
					tc.Lat, tc.Lon, tc.Country, tc.CC = g.Lat, g.Lon, g.Country, g.CC
				}
			}
			resp.TopActors = append(resp.TopActors, tc)
		}
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

	// Prefer the authoritative all-events hits-by-country aggregation (cached,
	// shared with /api/intel) so the globe's "By country" matches the intel
	// page's Attack Geography and isn't limited to the top-25 IPs. Fall back to
	// the top-25-derived countryStats if the cache/query yielded nothing.
	if cached := s.topCountriesCached(); len(cached) > 0 {
		resp.TopCountries = append(resp.TopCountries[:0], cached...)
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
		"generatedAt":              time.Now().UTC().Format(time.RFC3339Nano),
		"heapAlloc":                ms.HeapAlloc,
		"heapInuse":                ms.HeapInuse,
		"sys":                      ms.Sys,
		"numGoroutines":            runtime.NumGoroutine(),
		"numGC":                    ms.NumGC,
		"pauseTotalNs":             ms.PauseTotalNs,
		"liveJournalCollectorIPs":  liveIPs,
		"liveJournalCollectorLRU":  liveLRU,
		"liveJournalCollectorMax":  liveMax,
		"liveJournalUsersPerIPMax": liveUsersCap,
		"geoCacheEntries":          geoEntries,
		"geoCacheLRU":              geoLRU,
		"geoCacheMax":              geoMax,
	}
	_ = json.NewEncoder(w).Encode(resp)
}
