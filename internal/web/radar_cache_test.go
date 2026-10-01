package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func radarIPs(t *testing.T, s *Server) map[string]float64 {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleIntel(rec, httptest.NewRequest(http.MethodGet, "/api/intel", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/intel = %d %s", rec.Code, rec.Body.String())
	}
	var d struct {
		Radar []radarRow `json:"radar"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, r := range d.Radar {
		out[r.IP] = r.RateHour
	}
	return out
}

// The Brute-Force Radar used to re-count every event of the 24h window on
// each /api/intel poll (TopActorsByRecentRate, uncached). It is now derived
// from the same cached per-actor counts as the rates, so it moves with that
// cache, not with every request.
func TestRadarComesFromTheRatesCache(t *testing.T) {
	s, st := hasshTestServer(t)
	now := time.Now().UTC()
	add := func(ip string, n int) {
		for i := 0; i < n; i++ {
			addSummaryEvent(t, s, ip)
		}
		if err := st.UpsertActor(&models.Actor{ID: "cowrie:" + ip, Source: models.SourceCowrie, PrimaryIP: ip,
			FirstSeen: now, LastSeen: now, EventCount: n}); err != nil {
			t.Fatal(err)
		}
	}
	add("192.0.2.1", 3)
	first := radarIPs(t, s)
	if want := 3 / recentRateWindow.Hours(); first["192.0.2.1"] != want {
		t.Fatalf("radar = %v, want 192.0.2.1 at %v/h", first, want)
	}
	add("192.0.2.2", 5)
	if got := radarIPs(t, s); len(got) != 1 {
		t.Fatalf("radar recounted the window on a fresh cache: %v", got)
	}
	s.ratesCache.expire(statsTTL + time.Second)
	radarIPs(t, s) // stale, starts the refresh
	s.bg.wait()
	if got := radarIPs(t, s); got["192.0.2.2"] != 5/recentRateWindow.Hours() {
		t.Fatalf("radar after refresh = %v", got)
	}
}
