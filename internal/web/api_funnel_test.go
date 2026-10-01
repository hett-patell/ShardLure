package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/observability"
)

func TestIntelFunnelServesMonitorSnapshot(t *testing.T) {
	s := newIntelTestServer(t, nil)
	now := time.Now().UTC()
	s.monitor = observability.New(func() time.Time { return now }, 0)
	s.monitor.RecordFunnel(observability.FunnelSample{At: now, Valid: true,
		Day: observability.FunnelWindow{Connected: 12, Captured: 2}, Week: observability.FunnelWindow{Connected: 80, Captured: 9}})
	w := httptest.NewRecorder()
	s.handleIntelFunnel(w, httptest.NewRequest(http.MethodGet, "/api/intel/funnel", nil))
	var got funnelJSON
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Available || len(got.Stages) != 9 || got.Stages[0].Stage != "connected" || got.Stages[0].Day != 12 || got.Stages[0].Week != 80 || got.Stages[4].Stage != "captured" || got.Stages[4].Week != 9 {
		t.Fatalf("unexpected funnel response: %+v", got)
	}
}

func TestIntelFunnelWithoutMonitorIsUnavailable(t *testing.T) {
	s := newIntelTestServer(t, nil)
	s.monitor = nil
	w := httptest.NewRecorder()
	s.handleIntelFunnel(w, httptest.NewRequest(http.MethodGet, "/api/intel/funnel", nil))
	var got funnelJSON
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Available || got.Stages == nil {
		t.Fatalf("no monitor must give available=false with an empty (non-null) stage list: %+v", got)
	}
}

func TestFunnelPanelIsWiredAndEscaped(t *testing.T) {
	b, err := os.ReadFile("intel.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(b)
	for _, want := range []string{`id="panel-funnel"`, `id="funnel-table"`, `async function refreshFunnel()`, `esc(FUNNEL_LABELS[s.stage] || s.stage)`} {
		if !strings.Contains(page, want) {
			t.Fatalf("intel.html missing %q", want)
		}
	}
	if strings.Count(page, "refreshFunnel();") < 3 {
		t.Fatal("refreshFunnel must run on entering Blue, on the Blue poll and on a #tab=blue deep link")
	}
	src, _ := os.ReadFile("server.go")
	if !strings.Contains(string(src), `mux.HandleFunc("/api/intel/funnel", s.guardRead(s.handleIntelFunnel))`) {
		t.Fatal("funnel route must be registered read-only with guardRead")
	}
}
