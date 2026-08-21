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
	"github.com/networkshard/shardlure/internal/hostsvc"
	"github.com/networkshard/shardlure/internal/intel/vt"
	"github.com/networkshard/shardlure/internal/netmatch"
	"github.com/networkshard/shardlure/internal/settings"
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
	st   *store.Store
	addr string
	geo  *geoResolver
	// keys is the live runtime keystore. Secrets (dashboard token, bazaar +
	// abuseipdb API keys) and the tunable knobs below are read THROUGH it at
	// request time so a value saved from the Settings panel takes effect
	// without a restart. The *Default fields hold the startup-resolved
	// fallbacks (config/Options/env) used when the keystore has no value.
	keys *settings.Keystore
	// vt resolves captured payload hashes on VirusTotal. Built lazily (see
	// vtResolver) because it reads the API key through the keystore at request
	// time. vtEndpoint is a test seam.
	vtOnce                 sync.Once
	vt                     *vt.Resolver
	vtEndpoint             string
	homeDefault            homePoint
	bazaarKeyDefault       string // config intel.bazaar.api_key fallback (env/DB win)
	bazaarEndpointDefault  string
	bazaarTagsDefault      []string
	bazaarMaxBytesDefault  int64
	bazaarFreshnessDefault int

	// AbuseIPDB reporting (opt-in, off unless report-enabled AND a key is
	// present). abuseAdmin hard-rejects admin IPs in Vet. The report knobs
	// (enabled/min-probe/rewindow/categories/comment) are read live from the
	// keystore via the accessors below; the *Default fields are the startup
	// fallbacks. Reporting is the only outbound WRITE surface the dashboard
	// exposes beyond bazaar, so it carries the same throttle.
	abuseEndpoint          string
	abuseEnabledDefault    bool
	abuseCategoriesDefault []int
	abuseMinProbeDefault   int
	abuseRewindowDefault   time.Duration
	abuseCommentDefault    string
	abuseAdmin             *netmatch.Set
	// cowrieUnit names the sibling systemd unit running the honeypot. Used only
	// to read its uptime for the dashboard; never to control it.
	cowrieUnit string
	// tailscaleMode mirrors Options.TailscaleMode so RunContext can relax
	// the wildcard-bind security check when Tailscale is the access control.
	tailscaleMode bool
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
	// abuseReportBatchMu serializes batch report-all runs. Separate from
	// abuseReportMu so single-IP reports aren't blocked for the duration
	// of a multi-minute batch. TryLock returns "already in progress" to
	// concurrent callers instead of queueing.
	abuseReportBatchMu sync.Mutex

	// urlhausBatchMu serializes URLhaus submit batches. Without it a
	// double-clicked "Submit All" could race the dedup ledger and publish the
	// same URL twice to a public dataset.
	urlhausBatchMu sync.Mutex
	// threatfoxBatchMu serializes ThreatFox submit batches — same reason.
	threatfoxBatchMu sync.Mutex
	// URLhaus startup defaults (config), overridden live by the keystore.
	urlhausEndpointDefault   string
	urlhausTagsDefault       []string
	urlhausActiveDaysDefault int
	urlhausAnonymousDefault  bool

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

	// dashExtraCache memoizes the two remaining full-window scans that
	// /api/dashboard ran UNCACHED on every 5s poll: the 72h hourly-by-kind
	// GROUP BY (substr(ts) grouping, whole-window sort) and RecentShellSessions
	// (GROUP BY session_id + a ROW_NUMBER() CTE over the 24h cowrie window).
	// Same cadence and staleness profile as statsCache — data only moves on
	// the 5s ingest tick — so they share its TTL.
	dashExtraMu     sync.Mutex
	dashExtraCached *dashExtra
	dashExtraAt     time.Time

	// Threat-gauge window aggregate. Same reasoning as the caches above: one
	// indexed pass over the 24h window (~16ms cold on 670k rows), memoized so a
	// 5s poll from several open tabs does not repeat it.
	threatMu     sync.Mutex
	threatCached *threatBlock
	threatAt     time.Time

	// Windowed per-actor attack rates; see report_candidate.go.
	ratesMu     sync.Mutex
	ratesCached map[string]float64
	ratesAt     time.Time

	// Per-actor primary-IP last-seen for the report staleness gate; see
	// report_candidate.go for why this is not actors.last_seen.
	ipSeenMu     sync.Mutex
	ipSeenCached map[string]time.Time
	ipSeenAt     time.Time
}

// threatBlockCached returns the memoized windowed threat score.
//
// On error it returns the previous value rather than a zero block: a transient
// query failure should leave the gauge showing its last reading, not drop it to
// 0/LOW, which would read as "the attack stopped".
func (s *Server) threatBlockCached() (*threatBlock, error) {
	s.threatMu.Lock()
	defer s.threatMu.Unlock()
	if s.threatCached != nil && time.Since(s.threatAt) < statsTTL {
		return s.threatCached, nil
	}
	act, err := s.st.WindowActivitySince(time.Now().Add(-threatWindow))
	if err != nil {
		return s.threatCached, err
	}
	b := buildThreatBlock(act, threatWindow)
	s.threatCached = &b
	s.threatAt = time.Now()
	return s.threatCached, nil
}

type dashExtra struct {
	Hourly        []store.HourCount
	ShellSessions []store.ShellSessionSummary
}

type summaryStats struct {
	Events       int
	Actors       int
	UniqueIPs    int
	Countries    int
	KindCounts   []store.LabelCount
	SourceCounts []store.LabelCount
	// Top-N whole-table GROUP BYs. These share the stats cache because they
	// have the same cadence and cost profile (an O(all-rows) index scan) and
	// were previously recomputed on every 5s dashboard poll, uncached.
	TopIPs      []store.CountRow
	TopUsers    []store.CountRow
	TopCommands []store.CountRow
	// Intel-tab aggregates, likewise recomputed every 5s poll before caching:
	// the two actors GROUP BYs and the 72h hourly-by-kind heatmap scan.
	IntentCounts   []store.LabelCount
	PlaybookCounts []store.LabelCount
	HourlyByKind   []store.HourlyKindCell
	// Fingerprinted / FingerprintTotal are the EVENT-weighted identity-over-IP
	// coverage numbers from store.HASSHCoverage: cowrie events carrying a HASSH,
	// out of all cowrie events. Event-weighted rather than actor-weighted on
	// purpose — see the HASSHCoverage doc comment for why counting actor rows
	// inverted the result. Queried uncached on every 5s poll originally; folded
	// in here so it shares the same statsTTL memoization as the other aggregates.
	Fingerprinted    int
	FingerprintTotal int
	// CowrieUptime is how long the sibling Cowrie unit has been active, and
	// CowrieUp reports whether that could be determined at all (false on a
	// non-systemd host, or if the unit has never started). Cached with the rest
	// so the systemctl exec happens at most once per statsTTL, never per poll.
	CowrieUptime time.Duration
	CowrieUp     bool
	// Sessions is the ALL-TIME distinct cowrie session count, for the Summary
	// tile. Deliberately not len(RecentShellSessions): that slice is LIMITed to
	// 30, so the tile would freeze at "30". Cached here rather than queried in
	// handleDashboard to keep the 5s landing path fully memoized.
	Sessions int
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
	topIPs, err := s.st.TopSourceIPs(25)
	if err != nil {
		return s.statsCached, err
	}
	topUsers, err := s.st.TopUsernames(20)
	if err != nil {
		return s.statsCached, err
	}
	topCommands, err := s.st.TopCommands(20)
	if err != nil {
		return s.statsCached, err
	}
	intents, err := s.st.CountsByIntent()
	if err != nil {
		return s.statsCached, err
	}
	playbooks, err := s.st.CountsByPlaybook()
	if err != nil {
		return s.statsCached, err
	}
	hourlyByKind, err := s.st.HourlyEventCountsByKind(72)
	if err != nil {
		return s.statsCached, err
	}
	// Best-effort, like countries above: a transient error just leaves the
	// fingerprinted count at 0 rather than failing the whole cache refresh.
	fingerprinted, fingerprintTotal, _ := s.st.HASSHCoverage()
	// Best-effort like the others: 0 on error keeps the panel alive.
	sessionCount, _ := s.st.CountSessions()
	// Read-only liveness of the sibling honeypot unit. Best-effort: an unknown
	// value simply hides the readout rather than failing the cache refresh.
	//
	// context.Background() is deliberate, NOT an oversight: this populates a
	// shared 10s cache, so binding it to whichever request happened to trigger
	// the refresh would let one client disconnecting abort the refresh for
	// everyone. StartedAt applies its own 2s timeout, so nothing can hang.
	cowrieUptime, cowrieUp := hostsvc.Uptime(context.Background(), s.cowrieUnit, time.Now())
	s.statsCached = &summaryStats{
		Events:           ec,
		Actors:           ac,
		UniqueIPs:        ips,
		Countries:        countries,
		KindCounts:       kinds,
		SourceCounts:     sources,
		TopIPs:           topIPs,
		TopUsers:         topUsers,
		TopCommands:      topCommands,
		IntentCounts:     intents,
		PlaybookCounts:   playbooks,
		HourlyByKind:     hourlyByKind,
		Fingerprinted:    fingerprinted,
		FingerprintTotal: fingerprintTotal,
		Sessions:         sessionCount,
		CowrieUptime:     cowrieUptime,
		CowrieUp:         cowrieUp,
	}
	s.statsAt = time.Now()
	return s.statsCached, nil
}

// dashExtraCachedValues returns the memoized 72h hourly counts and recent shell
// sessions, recomputing at most once per statsTTL. These two ran uncached on
// every 5s /api/dashboard poll; they share statsTTL because they change on the
// same 5s ingest tick. On a recompute error the last-good value is served (nil
// on first call), keeping the landing dashboard alive through a transient error.
func (s *Server) dashExtraCachedValues() ([]store.HourCount, []store.ShellSessionSummary) {
	s.dashExtraMu.Lock()
	defer s.dashExtraMu.Unlock()
	if s.dashExtraCached != nil && time.Since(s.dashExtraAt) < statsTTL {
		return s.dashExtraCached.Hourly, s.dashExtraCached.ShellSessions
	}
	hourly, err := s.st.HourlyEventCounts(72)
	if err != nil {
		if s.dashExtraCached != nil {
			return s.dashExtraCached.Hourly, s.dashExtraCached.ShellSessions
		}
		return nil, nil
	}
	shell, err := s.st.RecentShellSessions(time.Now().UTC().Add(-24*time.Hour), 30)
	if err != nil {
		if s.dashExtraCached != nil {
			return s.dashExtraCached.Hourly, s.dashExtraCached.ShellSessions
		}
		return hourly, nil
	}
	s.dashExtraCached = &dashExtra{Hourly: hourly, ShellSessions: shell}
	s.dashExtraAt = time.Now()
	return hourly, shell
}

type windowedEvents struct {
	events []*models.Event
	total  int // true window size; > len(events) when the cap truncated
	at     time.Time
}

// eventsWindowTTL bounds staleness of the cached window. Data only changes on
// the 5s ingest tick, so a few seconds is invisible to the operator.
const eventsWindowTTL = 15 * time.Second

// maxWindowHours clamps the queried window so a stray ?window=99999d can't pin
// an enormous slice in cache. Retention caps the data well below this anyway.
const maxWindowHours = 24 * 366

// eventsForWindowCached returns up to defaultWindowEventCap events (newest
// first) with TS within the last windowHours, plus the TRUE total number of
// events in that window (which may exceed len(events) when the cap truncated).
// Memoized per window for eventsWindowTTL. The returned slice is shared and
// MUST be treated read-only by callers (the intel collectors only read).
//
// The cap is what keeps this bounded: a 30d window over a multi-million-row DB
// no longer materializes the whole thing into a cached slice. Callers disclose
// total vs len(events) so the truncation is honest, not silent (the old
// uncapped EventsSinceAll here was the process's largest single allocation).
func (s *Server) eventsForWindowCached(windowHours int) ([]*models.Event, int, error) {
	if windowHours <= 0 {
		windowHours = 24
	}
	if windowHours > maxWindowHours {
		windowHours = maxWindowHours
	}
	s.eventsMu.Lock()
	defer s.eventsMu.Unlock()
	if e, ok := s.eventsCache[windowHours]; ok && time.Since(e.at) < eventsWindowTTL {
		return e.events, e.total, nil
	}
	since := time.Now().Add(-time.Duration(windowHours) * time.Hour)
	ev, total, err := s.st.EventsSinceCapped(since, 0)
	if err != nil {
		if e, ok := s.eventsCache[windowHours]; ok {
			return e.events, e.total, nil // serve last-good on transient error
		}
		return nil, 0, err
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
	s.eventsCache[windowHours] = windowedEvents{events: ev, total: total, at: time.Now()}
	return ev, total, nil
}

// discloseWindowTruncation sets an advisory response header when the windowed
// event cap truncated the analysis, so every intel endpoint discloses it
// uniformly (returned/total) regardless of its own JSON shape. No-op when the
// full window fit under the cap. Header, not body, so it can't break any
// existing endpoint's JSON contract.
func discloseWindowTruncation(w http.ResponseWriter, returned, total int) {
	if total > returned {
		w.Header().Set("X-ShardLure-Window-Truncated", fmt.Sprintf("%d/%d", returned, total))
	}
}

// windowSample is the SAME disclosure carried in the response body.
//
// The header alone was not enough: no panel reads response headers, so a
// truncated analysis rendered as though it described the whole window. Measured
// on a 30-day window of 533,647 events, the analysis ran over 200,000 of them
// and said nothing about it. The header stays for API consumers; this is what
// the dashboard can actually show.
type windowSample struct {
	Analyzed int `json:"analyzed"`
	Total    int `json:"total"`
}

// sampledWindow returns nil when the whole window fit under the cap, so the
// field is omitted entirely rather than claiming a full analysis is a sample.
func sampledWindow(returned, total int) *windowSample {
	if total <= returned {
		return nil
	}
	return &windowSample{Analyzed: returned, Total: total}
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
	// GeoMMDB is the path to a MaxMind GeoLite2/GeoIP2 City database. When
	// set, geolocation is resolved locally with no outbound HTTP.
	GeoMMDB string
	// CowrieUnit is the systemd unit running Cowrie, read ONLY to report the
	// honeypot's uptime on the dashboard. Empty falls back to "cowrie"; a host
	// without systemd simply reports uptime as unknown.
	CowrieUnit     string
	BazaarAPIKey   string
	BazaarEndpoint string
	BazaarTags     []string
	// URLhaus knobs. There is no URLhausAPIKey: abuse.ch issues one Auth-Key
	// per account, so BazaarAPIKey arms URLhaus too (see abuseCHKeyLive).
	URLhausEndpoint     string
	URLhausTags         []string
	URLhausActiveDays   int
	URLhausAnonymous    bool
	BazaarMaxBytes      int64
	BazaarFreshnessDays int

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
	// TailscaleMode is set when the operator explicitly passes --tailscale.
	// Tailscale itself provides network-level access control, so wildcard
	// binds (0.0.0.0:port) are allowed without a dashboard token.
	TailscaleMode bool
}

func New(st *store.Store, keys *settings.Keystore, addr string, opts ...Options) *Server {
	if addr == "" {
		addr = "127.0.0.1:8080"
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
	cowrieUnit := firstOpt.CowrieUnit
	if cowrieUnit == "" {
		cowrieUnit = "cowrie"
	}
	// Secrets (bazaar/abuseipdb keys, dashboard token) are NOT resolved here
	// anymore — they're read live from the keystore at each use site, which
	// already layers DB-over-env. main.go seeds the keystore from config/env
	// so existing systemd deployments behave identically. Non-secret endpoints
	// and defaults are still resolved once below.
	bzEndpoint := firstOpt.BazaarEndpoint
	if bzEndpoint == "" {
		bzEndpoint = "https://mb-api.abuse.ch/api/v1/"
	}
	bzTags := firstOpt.BazaarTags
	if len(bzTags) == 0 {
		bzTags = []string{"shardlure", "honeypot"}
	}
	uhEndpoint := firstOpt.URLhausEndpoint
	if uhEndpoint == "" {
		uhEndpoint = "https://urlhaus.abuse.ch/api/"
	}
	uhTags := firstOpt.URLhausTags
	if len(uhTags) == 0 {
		uhTags = []string{"shardlure", "honeypot"}
	}
	uhActive := firstOpt.URLhausActiveDays
	if uhActive < 1 || uhActive > 3 {
		uhActive = 3
	}
	bzMax := firstOpt.BazaarMaxBytes
	if bzMax <= 0 {
		bzMax = 33 << 20
	}
	bzFresh := firstOpt.BazaarFreshnessDays
	if bzFresh <= 0 {
		bzFresh = 10
	}

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
		st:                    st,
		addr:                  addr,
		keys:                  keys,
		geo:                   newGeoResolver(geoOpts(len(opts) > 0, firstOpt), st, keys),
		homeDefault:           home,
		bazaarKeyDefault:      firstOpt.BazaarAPIKey,
		bazaarEndpointDefault: bzEndpoint,
		bazaarTagsDefault:     bzTags,
		// URLhaus shares bazaarKeyDefault (one abuse.ch Auth-Key); only the
		// non-secret knobs are separate.
		urlhausEndpointDefault:   uhEndpoint,
		urlhausTagsDefault:       uhTags,
		urlhausActiveDaysDefault: uhActive,
		urlhausAnonymousDefault:  firstOpt.URLhausAnonymous,
		bazaarMaxBytesDefault:    bzMax,
		bazaarFreshnessDefault:   bzFresh,
		abuseEndpoint:            abuseEndpoint,
		abuseEnabledDefault:      firstOpt.AbuseReportEnabled,
		abuseCategoriesDefault:   abuseCats,
		abuseMinProbeDefault:     firstOpt.AbuseMinProbe,
		abuseRewindowDefault:     abuseRewindow,
		abuseCommentDefault:      firstOpt.AbuseComment,
		abuseAdmin:               netmatch.New(firstOpt.AdminIPs),
		cowrieUnit:               cowrieUnit,
		tailscaleMode:            firstOpt.TailscaleMode,
		startedAt:                time.Now(),
	}
}

// ---- live setting accessors ---------------------------------------------
// Each reads the keystore (DB-over-env) and falls back to the startup default
// resolved in New(). These are the single read path for every secret/knob the
// Settings panel can change, so a save takes effect on the next request.

// abuseCHKeyLive resolves THE abuse.ch Auth-Key. abuse.ch issues exactly one
// key per account (https://auth.abuse.ch/) and it authenticates every abuse.ch
// service we talk to — MalwareBazaar sample uploads AND URLhaus URL
// submissions. Both surfaces resolve the key through this single function so
// they can never disagree about whether sharing is configured: setting the key
// once in Settings arms both.
//
// Precedence is the project-wide DB > env > config (the keystore Get already
// does DB-then-env; bazaarKeyDefault is the startup-resolved config value).
func (s *Server) abuseCHKeyLive() string {
	if k := s.keys.Get(settings.KeyBazaar); k != "" {
		return k
	}
	if k := s.keys.Get(settings.KeyBazaarAlt); k != "" {
		return k
	}
	return s.bazaarKeyDefault
}

// bazaarKeyLive is the MalwareBazaar-facing name for the shared abuse.ch key.
// Kept as a thin alias so existing call sites read naturally at the point of
// use while there remains exactly ONE resolution path.
func (s *Server) bazaarKeyLive() string { return s.abuseCHKeyLive() }

func (s *Server) bazaarEndpointLive() string {
	return s.keys.GetOr(settings.KeyBazaarEndpoint, s.bazaarEndpointDefault)
}

func (s *Server) bazaarTagsLive() []string {
	return s.keys.GetStringCSV(settings.KeyBazaarTags, s.bazaarTagsDefault)
}

// ---- URLhaus live knobs (the Auth-Key comes from abuseCHKeyLive) ----------

func (s *Server) urlhausEndpointLive() string {
	return s.keys.GetOr(settings.KeyURLhausEndpoint, s.urlhausEndpointDefault)
}

func (s *Server) urlhausTagsLive() []string {
	return s.keys.GetStringCSV(settings.KeyURLhausTags, s.urlhausTagsDefault)
}

// urlhausActiveDaysLive clamps to 1..3. Larger values must not loosen the
// liveness window — urlhaus.Vet enforces the same ceiling, this just keeps the
// UI and the gate telling the same story.
func (s *Server) urlhausActiveDaysLive() int {
	v := s.keys.GetInt(settings.KeyURLhausActiveDays, s.urlhausActiveDaysDefault)
	if v < 1 || v > 3 {
		return 3
	}
	return v
}

func (s *Server) urlhausAnonymousLive() bool {
	return s.keys.GetBool(settings.KeyURLhausAnonymous, s.urlhausAnonymousDefault)
}

func (s *Server) bazaarMaxBytesLive() int64 {
	if v := s.keys.GetInt(settings.KeyBazaarMaxBytes, 0); v > 0 {
		return int64(v)
	}
	return s.bazaarMaxBytesDefault
}

func (s *Server) bazaarFreshnessDaysLive() int {
	if v := s.keys.GetInt(settings.KeyBazaarFreshnessDays, 0); v > 0 {
		return v
	}
	return s.bazaarFreshnessDefault
}

func (s *Server) abuseKeyLive() string { return s.keys.Get(settings.KeyAbuseIPDB) }

func (s *Server) dashboardToken() string { return s.keys.Get(settings.KeyDashToken) }

func (s *Server) abuseEnabledLive() bool {
	return s.keys.GetBool(settings.KeyAbuseReportEnabled, s.abuseEnabledDefault)
}

func (s *Server) abuseMinProbeLive() int {
	return s.keys.GetInt(settings.KeyAbuseMinProbe, s.abuseMinProbeDefault)
}

func (s *Server) abuseRewindowLive() time.Duration {
	if h := s.keys.GetInt(settings.KeyAbuseRewindowHours, 0); h > 0 {
		return time.Duration(h) * time.Hour
	}
	return s.abuseRewindowDefault
}

func (s *Server) abuseCommentLive() string {
	return s.keys.GetOr(settings.KeyAbuseComment, s.abuseCommentDefault)
}

func (s *Server) abuseCategoriesLive() []int {
	return s.keys.GetIntCSV(settings.KeyAbuseCategories, s.abuseCategoriesDefault)
}

// homeLive builds the globe origin from the keystore, falling back per-field to
// the startup default so a partial override still renders a coherent point.
func (s *Server) homeLive() homePoint {
	h := s.homeDefault
	if v := s.keys.GetFloat(settings.KeyHomeLat, 0); v != 0 {
		h.Lat = v
	}
	if v := s.keys.GetFloat(settings.KeyHomeLon, 0); v != 0 {
		h.Lon = v
	}
	if v := s.keys.Get(settings.KeyHomeCity); v != "" {
		h.City = v
	}
	if v := s.keys.Get(settings.KeyHomeCountry); v != "" {
		h.Country = v
	}
	if v := s.keys.Get(settings.KeyHomeCC); v != "" {
		h.CC = v
	}
	return h
}

// RunContext runs the HTTP server and gracefully shuts it down when ctx is canceled.
func (s *Server) RunContext(ctx context.Context) error {
	mux := http.NewServeMux()
	// Every /api/* route is registered through s.guard so the auth check
	// lives in ONE place — a new handler cannot forget it. Handlers keep
	// their own inner requireDashboardAuth calls harmlessly (it's
	// idempotent), but the guard is what enforces.
	mux.HandleFunc("/intel", s.handleIntelPage) // page route: token-in-query allowed, see requirePageAuth
	mux.HandleFunc("/api/intel", s.guardRead(s.handleIntel))
	mux.HandleFunc("/api/intel/mitre", s.guardRead(s.handleIntelMitre))
	mux.HandleFunc("/api/intel/sessions", s.guardRead(s.handleIntelSessions))
	mux.HandleFunc("/api/intel/session", s.guardRead(s.handleIntelSession))
	mux.HandleFunc("/api/intel/enrich", s.guardRead(s.handleIntelEnrich))
	mux.HandleFunc("/api/intel/ttp", s.guardRead(s.handleIntelTTP))
	mux.HandleFunc("/api/intel/payloads", s.guardRead(s.handleIntelPayloads))
	mux.HandleFunc("/api/intel/payload", s.guardRead(s.handleIntelPayload))
	mux.HandleFunc("/api/intel/wordlist", s.guardRead(s.handleIntelWordlist))
	mux.HandleFunc("/api/intel/graph", s.guardRead(s.handleIntelGraph))
	mux.HandleFunc("/api/intel/replay", s.guardRead(s.handleIntelReplay))
	mux.HandleFunc("/api/intel/deobf", s.guardRead(s.handleIntelDeobf))
	mux.HandleFunc("/api/intel/bazaar", s.guardRead(s.handleIntelBazaar))
	mux.HandleFunc("/api/intel/bazaar/upload", s.guard(s.handleBazaarUpload))
	// VirusTotal payload-hash lookups. /vt is ON DEMAND (one hash, spends
	// quota); /vt/cached is a cache-only bulk decorator safe to call from a
	// list render. See api_vt.go for why the split exists.
	mux.HandleFunc("/api/intel/payload/vt", s.guard(s.handleIntelPayloadVT))
	mux.HandleFunc("/api/intel/payloads/vt/cached", s.guardRead(s.handleIntelPayloadsVTCached))
	mux.HandleFunc("/api/intel/urlhaus", s.guardRead(s.handleIntelURLhaus))
	mux.HandleFunc("/api/intel/urlhaus/submit", s.guard(s.handleURLhausSubmit))
	mux.HandleFunc("/api/intel/threatfox", s.guardRead(s.handleIntelThreatFox))
	mux.HandleFunc("/api/intel/threatfox/submit", s.guard(s.handleThreatFoxSubmit))
	mux.HandleFunc("/api/intel/abuseipdb/report", s.guard(s.handleAbuseIPDBReport))
	mux.HandleFunc("/api/intel/abuseipdb/report-all", s.guard(s.handleAbuseIPDBReportAll))
	mux.HandleFunc("/api/intel/abuseipdb/suggestions", s.guardRead(s.handleAbuseIPDBSuggestions))
	mux.HandleFunc("/api/intel/tunnels", s.guardRead(s.handleIntelTunnels))
	mux.HandleFunc("/api/intel/timeline", s.guardRead(s.handleIntelTimeline))
	// Settings panel: read masked snapshot, save/clear one setting, test a
	// provider key, rotate the dashboard token. Guarded like every other /api.
	mux.HandleFunc("/api/settings", s.guardRead(s.handleSettings))
	mux.HandleFunc("/api/settings/status", s.guardRead(s.handleSettingsStatus))
	mux.HandleFunc("/api/settings/save", s.guard(s.handleSettingsSave))
	mux.HandleFunc("/api/settings/test", s.guard(s.handleSettingsTest))
	mux.HandleFunc("/api/settings/token/rotate", s.guard(s.handleTokenRotate))
	mux.HandleFunc("/vendor/vis-network.min.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
		_, _ = w.Write(visNetworkJS)
	})
	mux.HandleFunc("/vendor/cobe.esm.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
		_, _ = w.Write(cobeESMJS)
	})
	mux.HandleFunc("/themes.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(themesCSS)
	})
	// Brand assets. Unauthenticated like the other static files: a favicon is
	// requested by the browser before any token is available, and the mark
	// carries no telemetry. Long cache — these change only on release.
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(faviconICO)
	})
	mux.HandleFunc("/logo.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(logoSVG)
	})
	mux.HandleFunc("/logo-180.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(logo180PNG)
	})
	mux.HandleFunc("/cobe-globe.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(cobeGlobeJS)
	})
	mux.HandleFunc("/cobe-boot.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(cobeBootJS)
	})
	mux.HandleFunc("/api/ioc/list", s.guardRead(s.handleIOCList))
	mux.HandleFunc("/api/ioc/csv", s.guardRead(s.handleIOCCSV))
	mux.HandleFunc("/api/ioc/stix", s.guardRead(s.handleIOCSTIX))
	mux.HandleFunc("/api/actor", s.guardRead(s.handleActorDetail))
	// Unmatched /api/* — guarded like every other API route so a 404 can only
	// be observed by an authorised caller (no route enumeration).
	mux.HandleFunc("/api/", s.guardRead(s.handleAPINotFound))
	mux.HandleFunc("/", s.handleIndex) // page route (also the 404 catch-all)
	mux.HandleFunc("/api/dashboard", s.guardRead(s.handleDashboard))
	mux.HandleFunc("/api/capture", s.guardRead(s.handleCapture))

	// Diagnostic endpoints: net/http/pprof + a small RSS/cache
	// stats handler. All gated behind the same dashboard token used
	// by the rest of /api/* so the profile data isn't world-readable.
	// pprof imports register on http.DefaultServeMux as a side
	// effect; we re-register the handlers explicitly on our own mux
	// to avoid leaking them on the unauthenticated path.
	// guardDebug, not guard: unlike /api/* (which is deliberately open in
	// token-less Tailscale/loopback mode), the profiling endpoints get NO
	// open mode on non-loopback peers. pprof heap/goroutine/cmdline dumps
	// leak file paths, flag values, and memory contents — with an empty
	// token they are reachable by anything on the tailnet/LAN, and the UI
	// never calls them, so there is no usability cost to failing closed.
	mux.HandleFunc("/debug/pprof/", s.guardDebug(pprof.Index))
	mux.HandleFunc("/debug/pprof/cmdline", s.guardDebug(pprof.Cmdline))
	mux.HandleFunc("/debug/pprof/profile", s.guardDebug(pprof.Profile))
	mux.HandleFunc("/debug/pprof/symbol", s.guardDebug(pprof.Symbol))
	mux.HandleFunc("/debug/pprof/trace", s.guardDebug(pprof.Trace))
	mux.HandleFunc("/debug/runtime", s.guardDebug(s.handleRuntimeStats))

	// With SHARDLURE_DASH_TOKEN unset every /api/* endpoint is open —
	// including the credential/password wordlist export. (/debug/* is the
	// exception: guardDebug still requires a loopback peer in open mode.)
	// The dashboard is meant to live on Tailscale/loopback.
	//
	// Fail CLOSED for the one config that's almost certainly a mistake: an
	// unauthenticated bind to a public, routable address (exposing credential
	// exports to the internet). Loopback / private / CGNAT (Tailscale) / and
	// the bare ":port" / 0.0.0.0 "behind a firewall" case stay a warning, to
	// preserve the documented "token is optional defense-in-depth" behavior.
	if s.dashboardToken() == "" {
		if host := listenHostIP(s.addr); host != nil && isPublicIP(host) {
			return fmt.Errorf("refusing to start: dashboard would bind a PUBLIC address (%s) with no "+
				"SHARDLURE_DASH_TOKEN set - credential exports would be world-readable. "+
				"Set a token, or bind to loopback/Tailscale", s.addr)
		}
		// Also fail for wildcard / unresolved addresses without a token.
		if listenHostIP(s.addr) == nil && !s.tailscaleMode {
			return fmt.Errorf("refusing to start: dashboard would bind a WILDCARD address (%s) with no "+
				"SHARDLURE_DASH_TOKEN set - credential exports would be world-readable. "+
				"Set a token, or bind to an explicit loopback address", s.addr)
		}
		// Note: /debug/* is NOT part of this exposure — guardDebug restricts it
		// to loopback peers whenever the token is unset, so the warning
		// deliberately no longer claims pprof is world-readable.
		fmt.Fprintln(os.Stderr,
			"shardlure: WARNING dashboard is UNAUTHENTICATED (SHARDLURE_DASH_TOKEN unset) — "+
				"credential exports are world-readable to anyone who can reach this port "+
				"(/debug/* stays loopback-only). "+
				"Keep it on Tailscale/loopback or set SHARDLURE_DASH_TOKEN.")
	}

	srv := &http.Server{
		Addr:        s.addr,
		Handler:     securityHeaders(mux),
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
		// Close the geo mmdb handle on the way out. One long-lived fd is
		// harmless in practice, but the resolver has a lifecycle method and
		// shutdown is the one place it belongs.
		if s.geo != nil {
			s.geo.mmdb.close()
		}
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	// "/" is a catch-all in net/http's ServeMux, so without this every typo
	// (/dashbaord, /favicon.png, a scanner probing /wp-admin) returned 200 with
	// the whole dashboard HTML. Auth is still checked first so an unauthorised
	// caller cannot enumerate which paths exist by comparing 401 vs 404.
	if !s.requirePageAuth(w, r) {
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

// handleAPINotFound answers unmatched /api/* paths. Registered as the "/api/"
// subtree so it catches typos and probes that would otherwise fall through to
// "/" and receive the dashboard HTML — an API client asking for JSON should
// get JSON, and an unknown /api path should not be answered by the page-auth
// gate (which accepts ?token=) instead of the header-only API gate.
//
// Exact patterns like "/api/dashboard" still win: ServeMux prefers the longest
// matching pattern, and non-slash-terminated patterns match exactly.
func (s *Server) handleAPINotFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "no such endpoint"})
}

// tokenMatches is the constant-time token comparison shared by the API
// (header-only) and page (header or ?token=) auth gates.
func (s *Server) tokenMatches(token string) bool {
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(token)), []byte(s.dashboardToken())) == 1
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
	if s.dashboardToken() == "" {
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

// securityHeaders adds defence-in-depth HTTP headers to every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// CSP: all SCRIPTS are embedded (vis-network + the vendored Cobe globe
		// engine under /vendor/), so script-src and connect-src are 'self' only
		// — no CDN in the supply chain of an authenticated page, and the globe
		// works on air-gapped networks. Fonts remain on Google Fonts because
		// they degrade gracefully (system fallback) when unreachable.
		// unsafe-inline is required for the inline <script> blocks in
		// index.html / intel.html and Cobe's dynamic style injection.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// requirePageAuth gates the two HTML page routes (/ and /intel). Unlike the API
// gate it ALSO accepts a ?token= query param and a shardlure_session cookie.
//
// Cookie bootstrap: a valid ?token= on a page GET sets an HttpOnly,
// SameSite=Strict session cookie and 302-redirects to the same path without
// the token, so the bearer never persists in browser history, referrer
// headers, or server access logs. Subsequent page loads authenticate via
// the cookie alone.
//
// All /api endpoints remain header-only (Authorization / X-ShardLure-Token);
// the cookie is only used by the two HTML page routes.
func (s *Server) requirePageAuth(w http.ResponseWriter, r *http.Request) bool {
	if s.dashboardToken() == "" {
		return true
	}

	// 1. Check Bearer / X-ShardLure-Token header (preferred).
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if strings.TrimSpace(token) == "" {
		token = r.Header.Get("X-ShardLure-Token")
	}
	if s.tokenMatches(token) {
		return true
	}

	// 2. Check the HttpOnly session cookie.
	if ck, err := r.Cookie("shardlure_session"); err == nil && s.tokenMatches(ck.Value) {
		return true
	}

	// 3. Check ?token= query param (bootstrap only). On success, set cookie
	//    and redirect to the same URL without the token so it leaves history.
	if qt := r.URL.Query().Get("token"); s.tokenMatches(qt) {
		http.SetCookie(w, &http.Cookie{
			Name:     "shardlure_session",
			Value:    qt,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   r.TLS != nil,
			MaxAge:   0, // session cookie - expires when the browser closes
		})
		// Strip token from the URL and redirect.
		clean := *r.URL
		q := clean.Query()
		q.Del("token")
		clean.RawQuery = q.Encode()
		http.Redirect(w, r, clean.String(), http.StatusFound)
		return false // redirect; don't serve the page
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
	IntentCounts []labelCountRow   `json:"intentCounts"`
	KindCounts   []labelCountRow   `json:"kindCounts"`
	Home         homePoint         `json:"home"`
	// Threat is the SAME server-scored block /api/intel serves, from the same
	// 10s cache. Both dashboards render a Threat Level panel, and they used to
	// each compute it in their own template - so the fix for the frozen gauge
	// landed in one page and left the other reading a stale formula.
	Threat *threatBlock `json:"threat,omitempty"`
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
	// Fingerprinted / FingerprintTotal are EVENT-weighted over cowrie telemetry
	// (see store.HASSHCoverage): how much of what we observed carries a client
	// fingerprint. The UI shows this as a percentage; the total is the cowrie
	// event count, NOT actorCount — dividing by actors inverted the result,
	// because clustering collapses many IPs into one actor row.
	Fingerprinted    int `json:"fingerprinted"`
	FingerprintTotal int `json:"fingerprintTotal"`
	// SessionCount is all-time distinct cowrie sessions (see summaryStats.Sessions
	// for why this is not the length of the capped `sessions` slice below).
	SessionCount int `json:"sessionCount"`
	// CowrieUptimeSeconds is how long the sibling Cowrie systemd unit has been
	// active. -1 means "unknown" (no systemd, or the unit never started), which
	// the UI renders as a dash rather than inventing a zero.
	CowrieUptimeSeconds int64 `json:"cowrieUptimeSeconds"`
}

type actorCard struct {
	ID       string  `json:"id"`
	IP       string  `json:"ip"`
	Playbook string  `json:"playbook"`
	Intent   string  `json:"intent"`
	Probe    int     `json:"probe"`
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
	return geoConfig{Enabled: o.GeoEnabled, InsecureHTTP: o.GeoInsecureHTTP, MMDB: o.GeoMMDB}
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
	// Both the 72h hourly scan and the 24h shell-session GROUP BY were full-window
	// queries on the 5s poll path; served from a statsTTL cache now (see
	// dashExtraCachedValues). They no longer fail the request — a transient DB
	// error serves last-good rather than 500ing the whole dashboard.
	hourly, shellSessions := s.dashExtraCachedValues()
	var ec, ac, uniqueIPs, countries, fingerprinted, fingerprintTotal, sessionCount int
	cowrieUptime := int64(-1) // -1 = unknown; never silently render 0
	var topIPs, topUsers, topCommands []store.CountRow
	var intentCounts, kindCounts []labelCountRow
	// Shares /api/intel's cache entry, so serving both dashboards costs one
	// query per 10s regardless of how many tabs are open.
	var threat *threatBlock
	if tb, err := s.threatBlockCached(); err == nil {
		threat = tb
	}
	if stats, err := s.summaryStatsCached(); err == nil {
		ec, ac, uniqueIPs, countries = stats.Events, stats.Actors, stats.UniqueIPs, stats.Countries
		topIPs, topUsers, topCommands = stats.TopIPs, stats.TopUsers, stats.TopCommands
		fingerprinted, fingerprintTotal = stats.Fingerprinted, stats.FingerprintTotal
		sessionCount = stats.Sessions
		if stats.CowrieUp {
			cowrieUptime = int64(stats.CowrieUptime.Seconds())
		}
		// Already computed and cached by summaryStatsCached — no extra query.
		// These drive the intent/kind bar charts. They no longer feed the threat
		// gauge: it is scored server-side over a window (see threat.go).
		for _, k := range stats.IntentCounts {
			intentCounts = append(intentCounts, labelCountRow{Label: k.Label, Hits: k.Hits})
		}
		for _, k := range stats.KindCounts {
			kindCounts = append(kindCounts, labelCountRow{Label: k.Label, Hits: k.Hits})
		}
	}

	resp := dashboardResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Summary: summaryBlock{
			EventCount: ec,
			ActorCount: ac,
		},
		IntentCounts: intentCounts,
		KindCounts:   kindCounts,
		Threat:       threat,
		Home:         s.homeLive(),
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

	// Windowed rates for the globe cards: the Meridian/Signal chips print this as
	// "N/h", so it has to mean current intensity rather than a lifetime mean.
	cardRates := s.recentRatesCached()
	for _, a := range actors {
		card := actorCard{
			ID:       a.ID,
			IP:       a.PrimaryIP,
			Playbook: a.Playbook,
			Intent:   a.Intent,
			Probe:    a.ProbeScore,
			Events:   a.EventCount,
			RateHour: cardRates[a.ID],
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
				Intent:   a.Intent,
				Probe:    a.ProbeScore,
				Events:   a.EventCount,
				RateHour: cardRates[a.ID],
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
	// Identity-over-IP coverage: actors keyed by HASSH vs. all actors. Read
	// from the shared stats cache (summaryStatsCached already ran
	// HASSHCoverage) rather than querying directly — this was the last
	// uncached full scan (SCAN actors) on the 5s dashboard poll path.
	resp.Summary.Fingerprinted = fingerprinted
	resp.Summary.FingerprintTotal = fingerprintTotal
	resp.Summary.SessionCount = sessionCount
	resp.Summary.CowrieUptimeSeconds = cowrieUptime
	// Countries: distinct CCs across the WHOLE geo cache, not just the top-25
	// IPs that feed the topCountries chart — otherwise a 2600-IP dataset
	// spanning 20+ countries reported ~7. This value comes from the shared
	// stats cache (summaryStatsCached already ran DistinctGeoCountryCount), so
	// we don't re-run that whole-geo-cache JSON scan a second time per poll.
	// Fall back to the top-25-derived count (minus the "??" bucket) if it was 0.
	if countries > 0 {
		resp.Summary.Countries = countries
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
// guardRead is guard for endpoints that only ever read. It rejects anything but
// GET/HEAD.
//
// Not a CSRF fix - requireDashboardAuth reads the token from headers only, never
// a cookie or query param, so a cross-site POST cannot authenticate in the first
// place. It is method hygiene: a read endpoint answering POST 200 invites a
// caller to believe the verb carries meaning, and every write endpoint here
// already rejects the wrong verb, so the two halves of the API should agree.
func (s *Server) guardRead(h http.HandlerFunc) http.HandlerFunc {
	return s.guard(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	})
}

func (s *Server) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.requireDashboardAuth(w, r) {
			return
		}
		h(w, r)
	}
}

// guardDebug wraps the /debug/* endpoints. With a token configured it behaves
// exactly like guard. With NO token (open mode) it additionally requires the
// TCP peer to be loopback — profiling data is operator-only and must not ride
// along with the "dashboard is open on Tailscale" convenience mode.
func (s *Server) guardDebug(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.dashboardToken() == "" && !isLoopbackPeer(r.RemoteAddr) {
			http.Error(w, "debug endpoints require a dashboard token or a loopback connection", http.StatusForbidden)
			return
		}
		if !s.requireDashboardAuth(w, r) {
			return
		}
		h(w, r)
	}
}

// isLoopbackPeer reports whether the request's direct TCP peer is a loopback
// address. RemoteAddr is set by net/http from the accepted connection (not
// from any spoofable header), so this is a trustworthy check for "the caller
// is on this host".
func isLoopbackPeer(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
