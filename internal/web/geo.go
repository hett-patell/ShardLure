package web

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type geoEntry struct {
	OK      bool
	Lat     float64
	Lon     float64
	Country string
	City    string
	CC      string
	Expiry  time.Time
}

type geoResolver struct {
	mu       sync.Mutex
	cache    map[string]geoEntry
	inflight map[string]bool
	http     *http.Client
	sem      chan struct{}
	enabled  bool
	cfg      geoConfig
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
		cache:    map[string]geoEntry{},
		inflight: map[string]bool{},
		http:     &http.Client{Timeout: 2500 * time.Millisecond},
		sem:      make(chan struct{}, 6),
		enabled:  geoEnabled(cfg),
		cfg:      cfg,
	}
}

func (g *geoResolver) resolve(ip string) geoEntry {
	if !g.enabled || isPrivateIP(ip) {
		return geoEntry{}
	}
	g.mu.Lock()
	if v, ok := g.cache[ip]; ok && time.Now().Before(v.Expiry) {
		g.mu.Unlock()
		return v
	}
	if g.inflight[ip] {
		g.mu.Unlock()
		return geoEntry{}
	}
	g.inflight[ip] = true
	g.mu.Unlock()

	go g.fetch(ip)
	return geoEntry{}
}

// cached returns geolocation only if already resolved (never blocks on HTTP).
func (g *geoResolver) cached(ip string) geoEntry {
	if !g.enabled || isPrivateIP(ip) {
		return geoEntry{}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if v, ok := g.cache[ip]; ok && time.Now().Before(v.Expiry) {
		return v
	}
	return geoEntry{}
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
		g.cache[ip] = geoEntry{Expiry: time.Now().Add(30 * time.Minute)}
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
		g.cache[ip] = geoEntry{Expiry: time.Now().Add(30 * time.Minute)}
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
		Expiry:  time.Now().Add(24 * time.Hour),
	}
	g.mu.Lock()
	delete(g.inflight, ip)
	g.cache[ip] = ent
	g.mu.Unlock()
}

func isPrivateIP(s string) bool {
	ip := net.ParseIP(s)
	return ip == nil || ip.IsLoopback() || ip.IsPrivate()
}
