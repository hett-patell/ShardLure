package web

import (
	"container/list"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
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
	if key != "" {
		return fmt.Sprintf("https://pro.ip-api.com/json/%s?key=%s&fields=%s", ip, key, fields)
	}
	if strings.TrimSpace(os.Getenv("SHARDLURE_GEO_INSECURE_HTTP")) == "1" || cfg.InsecureHTTP {
		return fmt.Sprintf("http://ip-api.com/json/%s?fields=%s", ip, fields)
	}
	return ""
}

func newGeoResolver(cfg geoConfig) *geoResolver {
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
	defer g.mu.Unlock()
	if v, ok := g.cache[ip]; ok && g.now().Before(v.Expiry) {
		// Promote to MRU so the LRU eviction prefers IPs the
		// dashboard hasn't asked about in a while.
		g.lru.MoveToFront(v.elem)
		return *v
	}
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
		g.mu.Unlock()
		if ok && time.Now().Before(cached.Expiry) {
			continue
		}
		need = append(need, ip)
	}
	if len(need) == 0 {
		return
	}
	if len(need) > 48 {
		need = need[:48]
	}
	deadline := time.Now().Add(budget)
	var wg sync.WaitGroup
	for _, ip := range need {
		if time.Now().After(deadline) {
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
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
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
		Expiry:  g.now().Add(24 * time.Hour),
	}
	g.mu.Lock()
	delete(g.inflight, ip)
	g.putLocked(ip, ent)
	g.mu.Unlock()
}

func isPrivateIP(s string) bool {
	ip := net.ParseIP(s)
	return ip == nil || ip.IsLoopback() || ip.IsPrivate()
}
