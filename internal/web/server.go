package web

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

type Server struct {
	st            *store.Store
	addr          string
	geo           *geoResolver
	dashboardAuth string
	home          homePoint
}

type Options struct {
	HomeLat     float64
	HomeLon     float64
	HomeCity    string
	HomeCountry string
	HomeCC      string
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
	return &Server{
		st:            st,
		addr:          addr,
		geo:           newGeoResolver(),
		dashboardAuth: strings.TrimSpace(os.Getenv("SHARDLURE_DASH_TOKEN")),
		home:          home,
	}
}

func (s *Server) Run() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/dashboard", s.handleDashboard)
	srv := &http.Server{
		Addr:         s.addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 20 * time.Second,
	}
	return srv.ListenAndServe()
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
	TopIPs       []topIPRow      `json:"topIps"`
	TopUsers     []topUserRow    `json:"topUsers"`
	TopCommands  []topCommandRow `json:"topCommands"`
	TopCountries []topCountryRow `json:"topCountries"`
	Hourly       []hourPoint     `json:"hourly"`
	Home         homePoint       `json:"home"`
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
	TS    string `json:"ts"`
	Kind  string `json:"kind"`
	IP    string `json:"ip"`
	User  string `json:"user"`
	Actor string `json:"actor"`
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
			g := s.geo.resolve(a.PrimaryIP)
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
			g := s.geo.resolve(row.Key)
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
		if cc != "" {
			countryRow, ok := countryStats[cc]
			if !ok {
				countryRow = &topCountryRow{CC: cc, Country: country}
				countryStats[cc] = countryRow
			}
			countryRow.Hits += row.Hits
		}
	}

	for _, row := range topUsers {
		resp.TopUsers = append(resp.TopUsers, topUserRow{User: row.Key, Hits: row.Hits})
	}
	for _, row := range topCommands {
		resp.TopCommands = append(resp.TopCommands, topCommandRow{Command: row.Key, Hits: row.Hits})
	}

	for _, c := range countryStats {
		resp.TopCountries = append(resp.TopCountries, *c)
	}
	sort.Slice(resp.TopCountries, func(i, j int) bool { return resp.TopCountries[i].Hits > resp.TopCountries[j].Hits })
	if len(resp.TopCountries) > 12 {
		resp.TopCountries = resp.TopCountries[:12]
	}
	resp.Summary.UniqueIPs = uniqueIPs
	resp.Summary.Countries = len(countryStats)

	for _, row := range hourly {
		resp.Hourly = append(resp.Hourly, hourPoint{T: row.Hour.Unix(), N: row.Hits})
	}

	for _, e := range events {
		resp.Recent = append(resp.Recent, recentRecord{
			TS:    e.TS.UTC().Format(time.RFC3339),
			Kind:  string(e.Kind),
			IP:    e.SrcIP,
			User:  e.Username,
			Actor: strings.TrimPrefix(e.ActorID, "journal:"),
		})
	}

	_ = json.NewEncoder(w).Encode(resp)
}

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
}

func newGeoResolver() *geoResolver {
	enabled := strings.TrimSpace(os.Getenv("SHARDLURE_GEO_HTTP")) == "1"
	return &geoResolver{
		cache:    map[string]geoEntry{},
		inflight: map[string]bool{},
		http:     &http.Client{Timeout: 1500 * time.Millisecond},
		sem:      make(chan struct{}, 4),
		enabled:  enabled,
	}
}

func (g *geoResolver) resolve(ip string) geoEntry {
	if !g.enabled {
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
	select {
	case g.sem <- struct{}{}:
	default:
		g.mu.Unlock()
		return geoEntry{}
	}
	g.inflight[ip] = true
	g.mu.Unlock()

	go g.fetch(ip)
	return geoEntry{}
}

func (g *geoResolver) fetch(ip string) {
	defer func() { <-g.sem }()

	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode,city,lat,lon", ip)
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

var _ = models.SourceJournal

const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>ShardLure Live</title>
<script src="https://unpkg.com/three@0.160.0/build/three.min.js"></script>
<script src="https://unpkg.com/globe.gl@2.32.0/dist/globe.gl.min.js"></script>
<style>
  :root {
    --bg: #02060d;
    --glass: rgba(12, 18, 28, 0.55);
    --glass-2: rgba(20, 28, 40, 0.55);
    --line: rgba(120, 160, 200, 0.14);
    --line-strong: rgba(120, 160, 200, 0.28);
    --text: #dde6f2;
    --dim: #7a8aa3;
    --accent: #ff5b6e;
    --accent-2: #4cc9f0;
    --good: #6ee7b7;
    --warn: #fbbf24;
    --mono: ui-monospace, SFMono-Regular, "JetBrains Mono", Consolas, monospace;
  }
  * { box-sizing: border-box; }
  html, body { height: 100%; margin: 0; overflow: hidden; }
  body {
    font: 13px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    background: radial-gradient(circle at 50% 50%, #050b18 0%, #01030a 70%);
    color: var(--text);
  }

  #globe {
    position: fixed; inset: 0;
    z-index: 0;
  }
  #vignette {
    position: fixed; inset: 0; z-index: 1; pointer-events: none;
    background:
      radial-gradient(ellipse at center, transparent 30%, rgba(0,0,0,0.55) 90%),
      linear-gradient(90deg, rgba(0,0,0,0.55) 0%, transparent 22%, transparent 78%, rgba(0,0,0,0.55) 100%);
  }

  .rail {
    position: fixed; top: 0; bottom: 0; z-index: 2;
    width: 320px; padding: 20px;
    display: flex; flex-direction: column; gap: 14px;
    pointer-events: none;
  }
  .rail.left  { left: 0; }
  .rail.right { right: 0; }
  .rail > * { pointer-events: auto; }

  .panel {
    background: var(--glass);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 14px 16px;
    backdrop-filter: blur(14px) saturate(140%);
    -webkit-backdrop-filter: blur(14px) saturate(140%);
    box-shadow: 0 1px 0 rgba(255,255,255,0.04) inset, 0 8px 24px rgba(0,0,0,0.35);
  }
  .panel h2 {
    margin: 0 0 10px;
    font-size: 10.5px; font-weight: 600;
    letter-spacing: 0.14em; text-transform: uppercase;
    color: var(--dim);
  }

  .title h1 {
    margin: 0 0 6px;
    font-size: 17px; font-weight: 600; letter-spacing: -0.005em;
  }
  .title .dot {
    display: inline-block; width: 8px; height: 8px;
    background: var(--accent); border-radius: 50%; margin-right: 9px;
    vertical-align: 2px;
    box-shadow: 0 0 0 0 var(--accent), 0 0 10px var(--accent);
    animation: pulse 1.8s infinite;
  }
  @keyframes pulse {
    0%   { box-shadow: 0 0 0 0 rgba(255,91,110,0.55), 0 0 10px rgba(255,91,110,0.8); }
    100% { box-shadow: 0 0 0 14px rgba(255,91,110,0), 0 0 10px rgba(255,91,110,0.8); }
  }
  .title .meta {
    color: var(--dim); font-family: var(--mono); font-size: 11px;
    line-height: 1.6;
  }
  .title .meta strong { color: var(--text); font-weight: 500; }

  .stats { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  .stat { background: var(--glass-2); border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; }
  .stat .num {
    font-family: var(--mono); font-size: 22px; font-weight: 600;
    line-height: 1.1; color: var(--text);
    font-variant-numeric: tabular-nums;
  }
  .stat .num.accent { color: var(--accent); }
  .stat .num.blue { color: var(--accent-2); }
  .stat .num.good { color: var(--good); }
  .stat .num.warn { color: var(--warn); }
  .stat .label { color: var(--dim); font-size: 10px; margin-top: 4px; letter-spacing: 0.06em; text-transform: uppercase; }

  table { width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 11.5px; table-layout: fixed; }
  th, td { text-align: left; padding: 5px 4px; border-bottom: 1px solid var(--line); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  th { color: var(--dim); font-weight: 500; font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em; padding-bottom: 7px; }
  td.n, th.n { text-align: right; color: var(--accent); font-variant-numeric: tabular-nums; }
  td .ip { color: var(--accent-2); }
  #top-countries th:nth-child(1), #top-countries td:nth-child(1) { width: calc(100% - 78px); }
  #top-countries th:nth-child(2), #top-countries td:nth-child(2) { width: 78px; }
  #top-ips th:nth-child(1), #top-ips td:nth-child(1) { width: 44%; }
  #top-ips th:nth-child(2), #top-ips td:nth-child(2) { width: 36%; }
  #top-ips th:nth-child(3), #top-ips td:nth-child(3) { width: 20%; }

  .rows {
    max-height: 230px; overflow: auto;
    font-family: var(--mono); font-size: 11px;
  }
  .row {
    padding: 5px 0; border-bottom: 1px dotted var(--line);
    display: grid; grid-template-columns: 56px minmax(0,1fr) 72px; gap: 8px; align-items: baseline;
  }
  .row .t { color: var(--dim); }
  .row .ip { color: var(--accent-2); }
  .row .u { color: var(--warn); }
  .row .p { color: var(--text); }
  .row .r { color: var(--accent); font-variant-numeric: tabular-nums; text-align: right; }
  .row > span { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; min-width: 0; }

  .feed {
    flex: 1; overflow: hidden; position: relative;
    font-family: var(--mono); font-size: 11px;
    -webkit-mask-image: linear-gradient(180deg, transparent 0, #000 24px, #000 calc(100% - 24px), transparent 100%);
            mask-image: linear-gradient(180deg, transparent 0, #000 24px, #000 calc(100% - 24px), transparent 100%);
  }
  .feed-inner { position: absolute; inset: 0; overflow-y: auto; padding-right: 6px; }
  .feed-inner::-webkit-scrollbar { width: 4px; }
  .feed-inner::-webkit-scrollbar-thumb { background: var(--line-strong); border-radius: 2px; }
  .feed-row {
    padding: 5px 0; border-bottom: 1px dotted var(--line);
    display: grid; grid-template-columns: 58px minmax(0,1fr) 88px 72px; gap: 8px; align-items: baseline;
    animation: fadein 0.4s ease;
  }
  @keyframes fadein { from { opacity: 0; transform: translateX(6px); } to { opacity: 1; transform: none; } }
  .feed-row .t { color: var(--dim); }
  .feed-row .ip { color: var(--accent-2); }
  .feed-row .u { color: var(--warn); }
  .feed-row .k { color: var(--text); }
  .feed-row .a { color: var(--dim); text-align: right; }

  .users { display: flex; flex-wrap: wrap; gap: 6px; }
  .users .pill {
    background: var(--glass-2);
    border: 1px solid var(--line);
    border-radius: 999px;
    padding: 3px 10px;
    font-family: var(--mono); font-size: 11px;
    color: var(--text);
  }
  .users .pill .n { color: var(--accent); margin-left: 5px; }

  .sparkline {
    position: fixed; left: 50%; bottom: 14px; transform: translateX(-50%);
    z-index: 2;
    width: clamp(360px, calc(100vw - 700px), 560px);
    background: var(--glass); border: 1px solid var(--line);
    border-radius: 10px; padding: 12px 16px 10px;
    backdrop-filter: blur(14px) saturate(140%);
    -webkit-backdrop-filter: blur(14px) saturate(140%);
  }
  .sparkline .label {
    color: var(--dim); font-family: var(--mono); font-size: 10px;
    text-transform: uppercase; letter-spacing: 0.08em;
    display: flex; justify-content: space-between; align-items: baseline;
    margin: 0 0 6px;
  }
  .sparkline canvas {
    display: block;
    width: 100%;
    height: 40px;
  }

  @media (max-width: 1100px) {
    .rail { width: 280px; padding: 14px; }
    .sparkline { display: none; }
  }
  @media (max-width: 760px) {
    .rail.left { width: 100%; height: auto; bottom: auto; padding: 10px; }
    .rail.right { display: none; }
  }
</style>
</head>
<body>

<div id="globe"></div>
<div id="vignette"></div>

<aside class="rail left">
  <section class="panel title">
    <h1><span class="dot"></span>ShardLure telemetry</h1>
    <div class="meta">
      source <strong>journal + actors db</strong><br/>
      origin <strong id="home-loc"> </strong><br/>
      updated <strong id="gen-at"> </strong>
    </div>
  </section>

  <section class="panel">
    <h2>Summary</h2>
    <div class="stats">
      <div class="stat"><div class="num accent" id="s-events">0</div><div class="label">events</div></div>
      <div class="stat"><div class="num blue" id="s-actors">0</div><div class="label">actors</div></div>
      <div class="stat"><div class="num good" id="s-ips">0</div><div class="label">unique IPs</div></div>
      <div class="stat"><div class="num warn" id="s-countries">0</div><div class="label">countries</div></div>
    </div>
  </section>

  <section class="panel">
    <h2>By country</h2>
    <table id="top-countries">
      <thead><tr><th>Country</th><th class="n">Hits</th></tr></thead>
      <tbody></tbody>
    </table>
  </section>

  <section class="panel">
    <h2>Top usernames tried</h2>
    <div class="users" id="top-users"></div>
  </section>

  <section class="panel">
    <h2>Top actors</h2>
    <div class="rows" id="actors"></div>
  </section>
</aside>

<aside class="rail right">
  <section class="panel" style="flex: 0 1 auto; max-height: 46vh; display: flex; flex-direction: column;">
    <h2>Top source IPs</h2>
    <div style="overflow:auto; flex:1;">
      <table id="top-ips">
        <thead><tr><th>IP</th><th>Loc</th><th class="n">Hits</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </section>

  <section class="panel">
    <h2>Top commands</h2>
    <div class="rows" id="top-commands"></div>
  </section>

  <section class="panel" style="flex: 1 1 auto; display: flex; flex-direction: column; min-height: 0;">
    <h2>Live feed</h2>
    <div class="feed"><div class="feed-inner" id="feed"></div></div>
  </section>
</aside>

<div class="sparkline panel">
  <div class="label"><span>Events / hour</span><span id="spark-max">peak 0</span></div>
  <canvas id="spark"></canvas>
</div>

<script>
const ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const esc = function(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function(c){ return ESC_MAP[c]; }); };
const fmt = function(n) { return Number(n || 0).toLocaleString(); };
const rel = function(ts) {
  const d = new Date(ts).getTime();
  if (!Number.isFinite(d)) return '-';
  const s = Math.max(0, Math.floor((Date.now() - d) / 1000));
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm';
  return Math.floor(s / 3600) + 'h';
};
const flag = function(cc) {
  if (!cc || cc === '??' || cc.length !== 2 || !/^[A-Za-z]{2}$/.test(cc)) return '<���';
  return String.fromCodePoint.apply(String, cc.toUpperCase().split('').map(function(c){ return 0x1F1A5 + c.charCodeAt(0); }));
};

const globe = Globe()(document.getElementById('globe'))
  .globeImageUrl('https://networkshard.com/ssh-attacks/img/earth-night.jpg')
  .bumpImageUrl('https://networkshard.com/ssh-attacks/img/earth-topology.png')
  .backgroundImageUrl('https://networkshard.com/ssh-attacks/img/night-sky.png')
  .backgroundColor('rgba(0,0,0,0)')
  .showGraticules(true)
  .atmosphereColor('#ff5b6e')
  .atmosphereAltitude(0.22)
  .pointColor(function(){ return '#ff5b6e'; })
  .pointAltitude(0.02)
  .pointRadius(0.22);

globe.controls().autoRotate = true;
globe.controls().autoRotateSpeed = 0.35;
globe.controls().enableZoom = true;
globe.controls().minDistance = 180;
globe.controls().maxDistance = 600;

const spark = document.getElementById('spark');
let sparkData = [];
let lastArcKey = '';

function drawSpark(series) {
  const ctx = spark.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const w = spark.clientWidth;
  const h = spark.clientHeight;
  if (!w || !h) return;
  spark.width = w * dpr;
  spark.height = h * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  if (!series.length) return;
  const minT = series[0].t;
  const maxT = series[series.length - 1].t;
  const maxV = Math.max.apply(null, series.map(function(p){ return p.n || 0; }));
  document.getElementById('spark-max').textContent = 'peak ' + fmt(maxV) + '/h';

  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, 'rgba(255,91,110,0.55)');
  grad.addColorStop(1, 'rgba(255,91,110,0.02)');
  const pad = 1;
  const xy = function(p) {
    return [
      ((p.t - minT) / (maxT - minT || 1)) * (w - pad * 2) + pad,
      h - pad - ((p.n || 0) / (maxV || 1)) * (h - pad * 2)
    ];
  };

  ctx.beginPath();
  series.forEach(function(p, i){ const q = xy(p); if (i) ctx.lineTo(q[0], q[1]); else ctx.moveTo(q[0], q[1]); });
  ctx.lineTo(w - pad, h); ctx.lineTo(pad, h); ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  ctx.beginPath();
  series.forEach(function(p, i){ const q = xy(p); if (i) ctx.lineTo(q[0], q[1]); else ctx.moveTo(q[0], q[1]); });
  ctx.strokeStyle = '#ff5b6e';
  ctx.lineWidth = 1.2;
  ctx.stroke();
}

function renderTopCountries(rows) {
  const body = document.querySelector('#top-countries tbody');
  body.innerHTML = '';
  (rows || []).slice(0, 10).forEach(function(r) {
    const tr = document.createElement('tr');
    tr.innerHTML =
      '<td>' + flag(r.cc) + ' ' + esc((r.country || r.cc || 'Unknown').slice(0, 18)) + '</td>' +
      '<td class="n">' + fmt(r.hits) + '</td>';
    body.appendChild(tr);
  });
}

function renderTopIPs(rows) {
  const body = document.querySelector('#top-ips tbody');
  body.innerHTML = '';
  (rows || []).slice(0, 20).forEach(function(r) {
    const loc = [r.city, r.country].filter(Boolean).join(', ');
    const tr = document.createElement('tr');
    tr.innerHTML =
      '<td><span class="ip">' + esc(r.ip) + '</span></td>' +
      '<td>' + flag(r.cc) + ' ' + esc((loc || 'Unknown').slice(0, 15)) + '</td>' +
      '<td class="n">' + fmt(r.hits) + '</td>';
    body.appendChild(tr);
  });
}

function renderTopUsers(rows) {
  const root = document.getElementById('top-users');
  root.innerHTML = '';
  (rows || []).slice(0, 16).forEach(function(r) {
    const p = document.createElement('span');
    p.className = 'pill';
    p.textContent = String(r.user || '');
    const n = document.createElement('span');
    n.className = 'n';
    n.textContent = fmt(r.hits);
    p.appendChild(n);
    root.appendChild(p);
  });
}

function renderTopCommands(rows) {
  const root = document.getElementById('top-commands');
  root.innerHTML = '';
  (rows || []).slice(0, 12).forEach(function(r) {
    const row = document.createElement('div');
    row.className = 'row';
    const shortCmd = String(r.command || '').length > 44 ? String(r.command || '').slice(0, 41) + '...' : String(r.command || '');
    row.innerHTML =
      '<span class="t">cmd</span>' +
      '<span class="p">' + esc(shortCmd) + '</span>' +
      '<span class="r">' + fmt(r.hits) + '</span>';
    root.appendChild(row);
  });
}

function renderActors(rows) {
  const root = document.getElementById('actors');
  root.innerHTML = '';
  (rows || []).slice(0, 14).forEach(function(a) {
    const row = document.createElement('div');
    row.className = 'row';
    row.innerHTML =
      '<span class="t">' + rel(a.lastSeen) + '</span>' +
      '<span><span class="ip">' + esc(a.ip) + '</span> <span class="p">' + esc(a.playbook || 'unknown') + '</span></span>' +
      '<span class="r">' + fmt(a.events) + '</span>';
    root.appendChild(row);
  });
}

function renderFeed(rows) {
  const root = document.getElementById('feed');
  root.innerHTML = '';
  (rows || []).slice(0, 48).forEach(function(e) {
    const row = document.createElement('div');
    row.className = 'feed-row';
    row.innerHTML =
      '<span class="t">' + rel(e.ts) + '</span>' +
      '<span><span class="ip">' + esc(e.ip) + '</span> <span class="k">' + esc(e.kind || '-') + '</span></span>' +
      '<span class="u">' + esc((e.user || '?').slice(0, 16)) + '</span>' +
      '<span class="a">' + esc((e.actor || '-').slice(0, 14)) + '</span>';
    root.appendChild(row);
  });
}

async function refresh() {
  const r = await fetch('/api/dashboard?_=' + Date.now(), { cache: 'no-store' });
  if (!r.ok) return;
  const d = await r.json();
  const summary = d.summary || {};
  const actors = d.actors || [];
  const recent = d.recent || [];
  const home = d.home || { lat: 19.076, lon: 72.8777, city: 'Mumbai', country: 'India', cc: 'IN' };

  document.getElementById('s-events').textContent = fmt(summary.eventCount);
  document.getElementById('s-actors').textContent = fmt(summary.actorCount);
  document.getElementById('s-ips').textContent = fmt(summary.uniqueIps);
  document.getElementById('s-countries').textContent = fmt(summary.countries);
  document.getElementById('home-loc').textContent = flag(home.cc) + ' ' + [home.city, home.country].filter(Boolean).join(', ');
  document.getElementById('gen-at').textContent = new Date(d.generatedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

  renderTopCountries(d.topCountries);
  renderTopIPs(d.topIps);
  renderTopUsers(d.topUsers);
  renderTopCommands(d.topCommands);
  renderActors(actors);
  renderFeed(recent);

  sparkData = (d.hourly || []).slice(-72);
  drawSpark(sparkData);

  const points = actors.filter(function(a) { return Number.isFinite(a.lat) && Number.isFinite(a.lon); })
    .sort(function(a, b) { return (b.events || 0) - (a.events || 0); })
    .map(function(a) { return { lat: a.lat, lng: a.lon, n: a.events || 0, ip: a.ip, playbook: a.playbook || '' }; });
  const maxN = Math.max.apply(null, [1].concat(points.map(function(p){ return p.n; })));
  globe.pointsData(points)
    .pointAltitude(function(p){ return 0.005 + 0.18 * Math.sqrt((p.n || 0) / maxN); })
    .pointRadius(function(p){ return 0.18 + 0.55 * Math.sqrt((p.n || 0) / maxN); })
    .pointLabel(function(p){
      return '<div style="font-family:ui-monospace,monospace;font-size:11px;background:rgba(12,18,28,0.85);border:1px solid rgba(120,160,200,0.28);padding:6px 9px;border-radius:6px;backdrop-filter:blur(10px);">' +
        '<span style="color:#4cc9f0">' + esc(p.ip) + '</span> <span style="color:#ff5b6e;font-weight:600">' + fmt(p.n) + 'x</span><br/>' +
        '<span style="color:#dde6f2">' + esc(p.playbook) + '</span></div>';
    });

  const arcs = points.slice(0, 80).map(function(p, idx) {
    return { startLat: p.lat, startLng: p.lng, endLat: home.lat, endLng: home.lon, idx: idx, n: p.n };
  });
  const arcKey = arcs.map(function(a){ return a.startLat.toFixed(2) + ',' + a.startLng.toFixed(2); }).join('|');
  if (arcKey !== lastArcKey) {
    lastArcKey = arcKey;
    globe.arcsData(arcs)
      .arcColor(function(){ return ['rgba(255,91,110,0.05)', 'rgba(255,91,110,0.85)']; })
      .arcStroke(function(a){ return 0.3 + 0.6 * Math.sqrt((a.n || 0) / maxN); })
      .arcDashLength(0.35)
      .arcDashGap(1.4)
      .arcDashAnimateTime(function(a){ return 1800 + (a.idx % 7) * 210; })
      .arcAltitudeAutoScale(0.5);
  }
}

refresh();
setInterval(refresh, 5000);
window.addEventListener('resize', function() { drawSpark(sparkData); });
</script>
</body>
</html>`
