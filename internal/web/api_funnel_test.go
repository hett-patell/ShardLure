package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/observability"
)

func getFunnel(t *testing.T, s *Server) funnelJSON {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleIntelFunnel(w, httptest.NewRequest(http.MethodGet, "/api/intel/funnel", nil))
	var got funnelJSON
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Stages == nil {
		t.Fatalf("stages must never be null: %s", w.Body.String())
	}
	return got
}

// Every field carries a distinct value so a Day/Week swap, a reordered stage
// or a truncated loop fails rather than matching by coincidence.
var funnelTestDay = observability.FunnelWindow{Connected: 101, LoggedIn: 102, RanCommands: 103, DownloadAttempt: 104,
	Captured: 105, NewPayloads: 106, SharedBazaar: 107, SharedURLhaus: 108, SharedThreatFox: 109}
var funnelTestWeek = observability.FunnelWindow{Connected: 701, LoggedIn: 702, RanCommands: 703, DownloadAttempt: 704,
	Captured: 705, NewPayloads: 706, SharedBazaar: 707, SharedURLhaus: 708, SharedThreatFox: 709}

func wantFunnelStages() []funnelStageJSON {
	names := []string{"connected", "logged_in", "ran_commands", "download_attempt", "captured",
		"new_payloads", "shared_bazaar", "shared_urlhaus", "shared_threatfox"}
	out := make([]funnelStageJSON, len(names))
	for i, n := range names {
		out[i] = funnelStageJSON{Stage: n, Day: int64(101 + i), Week: int64(701 + i)}
	}
	return out
}

func TestIntelFunnelServesMonitorSnapshot(t *testing.T) {
	s := newIntelTestServer(t, nil)
	now := time.Now().UTC()
	s.monitor = observability.New(func() time.Time { return now }, 0)
	s.monitor.RecordFunnel(observability.FunnelSample{At: now, Valid: true, Day: funnelTestDay, Week: funnelTestWeek})
	got := getFunnel(t, s)
	if !got.Available || got.At != now.Format(time.RFC3339) || !reflect.DeepEqual(got.Stages, wantFunnelStages()) {
		t.Fatalf("unexpected funnel response: %+v", got)
	}
}

func TestIntelFunnelUnavailableStates(t *testing.T) {
	base := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name       string
		setup      func(m *observability.Monitor, clock *time.Time)
		nilMonitor bool
		wantAt     bool
		wantStages int
	}{
		{name: "no monitor", nilMonitor: true},
		{name: "never sampled", setup: func(*observability.Monitor, *time.Time) {}},
		{name: "failed refresh after a good one", wantAt: true, wantStages: 9,
			setup: func(m *observability.Monitor, _ *time.Time) {
				m.RecordFunnel(observability.FunnelSample{At: base, Valid: true, Day: funnelTestDay, Week: funnelTestWeek})
				m.RecordFunnel(observability.FunnelSample{Valid: false})
			}},
		{name: "valid but older than the metrics age bound", wantAt: true, wantStages: 9,
			setup: func(m *observability.Monitor, clock *time.Time) {
				m.RecordFunnel(observability.FunnelSample{At: base, Valid: true, Day: funnelTestDay, Week: funnelTestWeek})
				*clock = base.Add(20 * time.Minute)
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newIntelTestServer(t, nil)
			clock := base
			if tc.nilMonitor {
				s.monitor = nil
			} else {
				s.monitor = observability.New(func() time.Time { return clock }, 0)
				tc.setup(s.monitor, &clock)
			}
			got := getFunnel(t, s)
			if got.Available {
				t.Fatalf("available must be false: %+v", got)
			}
			if (got.At != "") != tc.wantAt || len(got.Stages) != tc.wantStages {
				t.Fatalf("at=%q stages=%d, want at set=%v stages=%d", got.At, len(got.Stages), tc.wantAt, tc.wantStages)
			}
			if tc.wantStages > 0 && !reflect.DeepEqual(got.Stages, wantFunnelStages()) {
				t.Fatalf("last good values must be kept: %+v", got.Stages)
			}
		})
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

func TestSettingsStatusReportsCapturePause(t *testing.T) {
	s := newIntelTestServer(t, nil)
	// No monitor (static web mode): the key is present and false, never a
	// permanent false "capture paused" warning.
	s.monitor = nil
	nw := httptest.NewRecorder()
	s.handleSettingsStatus(nw, httptest.NewRequest(http.MethodGet, "/api/settings/status", nil))
	var none map[string]any
	if err := json.Unmarshal(nw.Body.Bytes(), &none); err != nil {
		t.Fatal(err)
	}
	if v, ok := none["capturePaused"]; !ok || v != false {
		t.Fatalf("nil monitor: capturePaused = %v (present %v), want false", v, ok)
	}
	s.monitor = observability.New(time.Now, 0)
	s.monitor.SetCapturePaused(true)
	w := httptest.NewRecorder()
	s.handleSettingsStatus(w, httptest.NewRequest(http.MethodGet, "/api/settings/status", nil))
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["capturePaused"] != true {
		t.Fatalf("capturePaused = %v, want true", got["capturePaused"])
	}
	page, _ := os.ReadFile("intel.html")
	if !strings.Contains(string(page), "d.capturePaused") {
		t.Fatal("the Settings live-status strip must surface capturePaused")
	}
}
