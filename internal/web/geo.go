package web

import (
	"container/list"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/networkshard/shardlure/internal/store"
)

// geoCacheMaxEntries caps the IP→geo cache. The previous map was
// unbounded; on a long-running honeypot every distinct attacker IP
// ever rendered on the dashboard pinned an entry forever, even after
// its 24h expiry. A few thousand entries is plenty for the live
// "what's hot right now" use case and the eviction policy (oldest
// touched first) naturally prefers IPs the dashboard isn't currently
// showing. Override at startup with SHARDLURE_GEO_CACHE_MAX if you
// expect to display far more than this concurrently.
var geoCacheMaxEntries = func() int {
	if v := strings.TrimSpace(os.Getenv("SHARDLURE_GEO_CACHE_MAX")); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return 4096
}()

type geoEntry struct {
	OK      bool
	Lat     float64
	Lon     float64
	Country string
	City    string
	CC      string
	Expiry  time.Time
	elem    *list.Element // back-pointer into geoResolver.lru
}

type geoResolver struct {
	mu       sync.Mutex
	cache    map[string]*geoEntry
	lru      *list.List // front = most recent insert/touch
	inflight map[string]bool
	http     *http.Client
	sem      chan struct{}
	enabled  bool
	cfg      geoConfig
	maxSize  int
	now      func() time.Time // injectable for tests
	st       *store.Store     // persists geo lookups across restarts
}

type geoConfig struct {
	Enabled      bool
	InsecureHTTP bool
}

func geoEnabled(cfg geoConfig) bool {
	if strings.TrimSpace(os.Getenv("SHARDLURE_GEO_HTTP")) == "1" {
		return geoHTTPAllowed(cfg)
	}
	if strings.TrimSpace(os.Getenv("SHARDLURE_GEO_HTTP")) == "0" {
		return false
	}
	return cfg.Enabled && geoHTTPAllowed(cfg)
}

func geoHTTPAllowed(cfg geoConfig) bool {
	if strings.TrimSpace(os.Getenv("SHARDLURE_IPAPI_KEY")) != "" {
		return true
	}
	if strings.TrimSpace(os.Getenv("SHARDLURE_GEO_INSECURE_HTTP")) == "1" {
		return true
	}
	return cfg.InsecureHTTP
}

func geoLookupURL(ip string, cfg geoConfig) string {
	key := strings.TrimSpace(os.Getenv("SHARDLURE_IPAPI_KEY"))
	fields := "status,country,countryCode,city,lat,lon"
	// Escape the IP into the path. Callers already validate it looks like an
	// IP, but escaping is the correct defensive practice so a stray special
	// character can never break out of the path segment.
	esc := url.PathEscape(ip)
	if key != "" {
		return fmt.Sprintf("https://pro.ip-api.com/json/%s?key=%s&fields=%s", esc, url.QueryEscape(key), fields)
	}
	if strings.TrimSpace(os.Getenv("SHARDLURE_GEO_INSECURE_HTTP")) == "1" || cfg.InsecureHTTP {
		return fmt.Sprintf("http://ip-api.com/json/%s?fields=%s", esc, fields)
	}
	return ""
}

func newGeoResolver(cfg geoConfig, st *store.Store) *geoResolver {
	if st != nil {
		_ = st.EnsureEnrichmentTable()
	}
	return &geoResolver{
		cache:    map[string]*geoEntry{},
		lru:      list.New(),
		inflight: map[string]bool{},
		http:     &http.Client{Timeout: 2500 * time.Millisecond},
		sem:      make(chan struct{}, 6),
		enabled:  geoEnabled(cfg),
		cfg:      cfg,
		maxSize:  geoCacheMaxEntries,
		now:      time.Now,
		st:       st,
	}
}

// cached returns geolocation only if already resolved (never blocks
// on HTTP). Expired entries are reported as a miss; they are removed
// lazily on the next put() so the cache size obeys the LRU cap even
// if expiry sweeping never gets to them.
func (g *geoResolver) cached(ip string) geoEntry {
	if !g.enabled || isPrivateIP(ip) {
		return geoEntry{}
	}
	g.mu.Lock()
	if v, ok := g.cache[ip]; ok && g.now().Before(v.Expiry) {
		g.lru.MoveToFront(v.elem)
		g.mu.Unlock()
		return *v
	}
	g.mu.Unlock()

	if g.st != nil {
		if rec, found, _ := g.st.GetEnrichment(ip, "geo"); found && rec.Payload != "" {
			if g.now().Sub(rec.FetchedAt) < 7*24*time.Hour {
				var parsed struct {
					OK      bool    `json:"ok"`
					Lat     float64 `json:"lat"`
					Lon     float64 `json:"lon"`
					Country string  `json:"country"`
					City    string  `json:"city"`
					CC      string  `json:"cc"`
				}
				if json.Unmarshal([]byte(rec.Payload), &parsed) == nil && parsed.OK {
					ent := geoEntry{
						OK: true, Lat: parsed.Lat, Lon: parsed.Lon,
						Country: parsed.Country, City: parsed.City, CC: parsed.CC,
						Expiry: rec.FetchedAt.Add(7 * 24 * time.Hour),
					}
					g.mu.Lock()
					g.putLocked(ip, ent)
					g.mu.Unlock()
					return ent
				}
			}
		}
	}
	g.mu.Lock()
	if existing, ok := g.cache[ip]; !ok || !existing.OK {
		g.putLocked(ip, geoEntry{Expiry: g.now().Add(30 * time.Second)})
	}
	g.mu.Unlock()
	return geoEntry{}
}

// put inserts or updates the cache entry for ip, maintaining the
// LRU and evicting the oldest entry once the cap is reached. Caller
// must hold g.mu.
//
// The 4-step expiry sweep at the bottom is opportunistic — at most
// four expired entries are deleted per put() so a hot insert path
// doesn't pay for an unbounded sweep. The LRU cap is the firm
// upper bound on size; this is only here so a workload that
// constantly churns the same few IPs (re-fetched after expiry) still
// drops stale rows quickly.
func (g *geoResolver) putLocked(ip string, ent geoEntry) {
	if v, ok := g.cache[ip]; ok {
		ent.elem = v.elem
		g.cache[ip] = &ent
		g.lru.MoveToFront(ent.elem)
		return
	}
	ent.elem = g.lru.PushFront(ip)
	g.cache[ip] = &ent
	for g.lru.Len() > g.maxSize {
		e := g.lru.Back()
		if e == nil {
			break
		}
		evict := e.Value.(string)
		g.lru.Remove(e)
		delete(g.cache, evict)
	}
	// Opportunistic expiry sweep from the tail, capped at four
	// entries per call. We stop the moment we hit a still-valid
	// entry because the LRU order is by access time, not expiry,
	// and we don't want to walk the whole list.
	now := g.now()
	for i := 0; i < 4; i++ {
		e := g.lru.Back()
		if e == nil {
			return
		}
		key := e.Value.(string)
		v, ok := g.cache[key]
		if !ok {
			g.lru.Remove(e)
			continue
		}
		if now.Before(v.Expiry) {
			return
		}
		g.lru.Remove(e)
		delete(g.cache, key)
	}
}

// prefetch resolves geolocation for many IPs before building dashboard JSON.
func (g *geoResolver) prefetch(ips []string, budget time.Duration) {
	if !g.enabled || budget <= 0 {
		return
	}
	seen := map[string]struct{}{}
	var need []string
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" || isPrivateIP(ip) {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		g.mu.Lock()
		cached, ok := g.cache[ip]
		fresh := ok && g.now().Before(cached.Expiry)
		// Claim the IP for this prefetch under the same lock that read
		// the cache: if a concurrent prefetch (e.g. the dashboard poll
		// overlapping an actor-detail poll) already has it in flight,
		// skip it here rather than issuing a duplicate HTTP lookup.
		// fetch() clears the inflight mark on every exit path.
		claim := !fresh && !g.inflight[ip]
		if claim {
			g.inflight[ip] = true
		}
		g.mu.Unlock()
		if !claim {
			continue
		}
		need = append(need, ip)
	}
	if len(need) == 0 {
		return
	}
	// releaseClaims clears inflight marks for IPs we claimed above but
	// will not actually fetch (over the per-call cap, or past the
	// deadline). Without this they'd stay marked in-flight forever and
	// block future prefetches of those IPs.
	releaseClaims := func(ips []string) {
		if len(ips) == 0 {
			return
		}
		g.mu.Lock()
		for _, ip := range ips {
			delete(g.inflight, ip)
		}
		g.mu.Unlock()
	}
	if len(need) > 48 {
		releaseClaims(need[48:])
		need = need[:48]
	}
	deadline := time.Now().Add(budget)
	var wg sync.WaitGroup
	for i, ip := range need {
		if time.Now().After(deadline) {
			releaseClaims(need[i:])
			break
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			g.fetch(ip)
		}(ip)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(budget):
	}
}

func (g *geoResolver) fetch(ip string) {
	select {
	case g.sem <- struct{}{}:
	default:
		g.mu.Lock()
		delete(g.inflight, ip)
		g.mu.Unlock()
		return
	}
	defer func() { <-g.sem }()

	url := geoLookupURL(ip, g.cfg)
	if url == "" {
		g.mu.Lock()
		delete(g.inflight, ip)
		g.mu.Unlock()
		return
	}
	resp, err := g.http.Get(url)
	if err != nil {
		g.mu.Lock()
		delete(g.inflight, ip)
		g.putLocked(ip, geoEntry{Expiry: g.now().Add(30 * time.Minute)})
		g.mu.Unlock()
		return
	}
	defer resp.Body.Close()

	var out struct {
		Status  string  `json:"status"`
		Country string  `json:"country"`
		City    string  `json:"city"`
		CC      string  `json:"countryCode"`
		Lat     float64 `json:"lat"`
		Lon     float64 `json:"lon"`
	}
	// Cap the response body: a misbehaving/hostile geo API shouldn't be able to
	// stream an unbounded body into the decoder. 64 KiB is far more than the
	// small JSON object ip-api returns.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		g.mu.Lock()
		delete(g.inflight, ip)
		g.putLocked(ip, geoEntry{Expiry: g.now().Add(30 * time.Minute)})
		g.mu.Unlock()
		return
	}

	ent := geoEntry{
		OK:      out.Status == "success",
		Lat:     out.Lat,
		Lon:     out.Lon,
		Country: out.Country,
		City:    out.City,
		CC:      out.CC,
	}
	if ent.OK {
		ent.Expiry = g.now().Add(24 * time.Hour)
	} else {
		ent.Expiry = g.now().Add(60 * time.Second)
	}
	g.mu.Lock()
	delete(g.inflight, ip)
	g.putLocked(ip, ent)
	g.mu.Unlock()

	if ent.OK && g.st != nil {
		payload, _ := json.Marshal(struct {
			OK      bool    `json:"ok"`
			Lat     float64 `json:"lat"`
			Lon     float64 `json:"lon"`
			Country string  `json:"country"`
			City    string  `json:"city"`
			CC      string  `json:"cc"`
		}{true, ent.Lat, ent.Lon, ent.Country, ent.City, ent.CC})
		_ = g.st.PutEnrichment(ip, "geo", string(payload))
	}
}

func isPrivateIP(s string) bool {
	ip := net.ParseIP(s)
	return ip == nil || ip.IsLoopback() || ip.IsPrivate()
}
