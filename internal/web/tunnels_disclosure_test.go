package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// TestTunnelsDiscloseTrueTotal pins the disclosure contract of
// /api/intel/tunnels: `total` describes the WINDOW, `returned` describes the
// PAGE, and they are allowed to differ.
//
// The handler used to send Total: len(targets) — the LIMIT-capped page size — so
// asking for 3 destinations got back "total":3 even with more in the window, and
// the widget rendered "3 destinations" with nothing on screen to suggest the
// rest existed. Measured on the reference deployment: 9 destinations, 3 shown,
// 6 pivot targets silently dropped.
func TestTunnelsDiscloseTrueTotal(t *testing.T) {
	s := newIntelTestServer(t, nil)

	now := time.Now().UTC()
	// Five distinct destinations, descending hits so the page order is stable
	// and a truncated page is predictable.
	var events []*models.Event
	dests := []struct {
		ip   string
		port int
		hits int
	}{
		{"1.1.1.1", 22, 5},
		{"2.2.2.2", 80, 4},
		{"3.3.3.3", 443, 3},
		{"4.4.4.4", 3389, 2},
		{"5.5.5.5", 6379, 1},
	}
	for _, d := range dests {
		for i := 0; i < d.hits; i++ {
			events = append(events, &models.Event{
				TS: now.Add(-time.Duration(i+1) * time.Minute), Source: models.SourceCowrie,
				Kind: models.KindTunnel, SrcIP: "9.9.9.9", ActorID: "cowrie:a",
				DstIP: d.ip, DstPort: d.port,
			})
		}
	}
	if err := s.st.AppendEventsAndUpsertActorsAgg(events, nil); err != nil {
		t.Fatalf("append: %v", err)
	}

	get := func(query string) tunnelsResponse {
		t.Helper()
		w := httptest.NewRecorder()
		s.handleIntelTunnels(w, httptest.NewRequest(http.MethodGet, "/api/intel/tunnels"+query, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s → %d: %s", query, w.Code, w.Body.String())
		}
		var out tunnelsResponse
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	// Uncapped: total == returned == the whole population.
	full := get("?window=24h")
	if full.Total != 5 || full.Returned != 5 || len(full.Targets) != 5 {
		t.Fatalf("uncapped: total=%d returned=%d targets=%d, want 5/5/5",
			full.Total, full.Returned, len(full.Targets))
	}

	// Capped: the page shrinks, the total must NOT. This is the regression.
	capped := get("?window=24h&limit=2")
	if len(capped.Targets) != 2 || capped.Returned != 2 {
		t.Fatalf("limit=2: returned=%d targets=%d, want 2/2", capped.Returned, len(capped.Targets))
	}
	if capped.Total != 5 {
		t.Fatalf("limit=2: total=%d, want 5 — total reports the page size again, so the "+
			"widget claims the cap is the whole population and hides %d destinations",
			capped.Total, 5-capped.Total)
	}

	// A window narrow enough to exclude everything must report 0/0, not a stale
	// or all-time total: `total` is window-scoped, not lifetime.
	//
	// windowHoursFromQuery has a 1h floor, so age the events past it rather than
	// asking for a sub-hour window.
	pastEvents := []*models.Event{{
		TS: now.Add(-72 * time.Hour), Source: models.SourceCowrie, Kind: models.KindTunnel,
		SrcIP: "9.9.9.9", ActorID: "cowrie:a", DstIP: "8.8.8.8", DstPort: 53,
	}}
	if err := s.st.AppendEventsAndUpsertActorsAgg(pastEvents, nil); err != nil {
		t.Fatalf("append past: %v", err)
	}
	narrow := get("?window=24h")
	if narrow.Total != 5 {
		t.Fatalf("24h window total = %d, want 5: the 72h-old destination must not be "+
			"counted in a 24h window", narrow.Total)
	}
	wide := get("?window=168h")
	if wide.Total != 6 {
		t.Fatalf("7d window total = %d, want 6: the 72h-old destination belongs in a "+
			"7d window", wide.Total)
	}
}
