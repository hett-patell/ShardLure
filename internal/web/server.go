package web

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"os"
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
}

type Options struct {
	HomeLat        float64
	HomeLon        float64
	HomeCity       string
	HomeCountry    string
	HomeCC         string
	GeoEnabled     bool
	GeoInsecureHTTP bool
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
	return &Server{
		st:            st,
		addr:          addr,
		geo:           newGeoResolver(geoOpts(len(opts) > 0, firstOpt)),
		dashboardAuth: strings.TrimSpace(os.Getenv("SHARDLURE_DASH_TOKEN")),
		home:          home,
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
	mux.HandleFunc("/api/ioc/list", s.handleIOCList)
	mux.HandleFunc("/api/ioc/csv", s.handleIOCCSV)
	mux.HandleFunc("/api/ioc/stix", s.handleIOCSTIX)
	mux.HandleFunc("/api/actor", s.handleActorDetail)
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/dashboard", s.handleDashboard)
	mux.HandleFunc("/api/capture", s.handleCapture)
	srv := &http.Server{
		Addr:         s.addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 20 * time.Second,
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
			TS:      e.TS.UTC().Format(time.RFC3339),
			Kind:    string(e.Kind),
			IP:      e.SrcIP,
			User:    e.Username,
			Actor:   actor.TrimActorPrefix(e.ActorID),
			Command: strings.TrimSpace(e.Command),
		})
	}

	_ = json.NewEncoder(w).Encode(resp)
}
