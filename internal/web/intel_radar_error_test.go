package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/networkshard/shardlure/internal/store"
)

// TestIntelRadarStoreErrorIsLoggedNotFatal: TopActorRatesFromCounts now
// returns store errors instead of skipping rows. /api/intel must still render
// (the radar is one widget) with no radar, and the failure must reach the log,
// once per window rather than once per 5 s poll.
func TestIntelRadarStoreErrorIsLoggedNotFatal(t *testing.T) {
	s, _ := hasshTestServer(t)
	calls := 0
	s.topActorRates = func(map[string]int, float64, int) ([]store.ActorRate, error) {
		calls++
		return nil, errors.New("database is locked: SELECT secret")
	}
	var buf bytes.Buffer
	prev, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(prevFlags) })

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		s.handleIntel(rec, httptest.NewRequest(http.MethodGet, "/api/intel", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("poll %d = %d %s", i, rec.Code, rec.Body.String())
		}
		var d struct {
			Radar []radarRow `json:"radar"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil || len(d.Radar) != 0 {
			t.Fatalf("poll %d radar %v err %v", i, d.Radar, err)
		}
	}
	if calls != 3 {
		t.Fatalf("radar read %d times, want 3", calls)
	}
	out := buf.String()
	if n := strings.Count(out, "web: intel_radar: operation_failed"); n != 1 {
		t.Fatalf("radar failure logged %d times, want once per window:\n%s", n, out)
	}
	if strings.Contains(out, "SELECT secret") {
		t.Fatal("raw store error reached the log")
	}
}
