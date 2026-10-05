package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/capture"
	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/intel/bazaar"
	"github.com/networkshard/shardlure/internal/observability"
	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
)

func TestFunnelWindowCopiesEveryField(t *testing.T) {
	c := store.FunnelCounts{Connected: 1, LoggedIn: 2, RanCommands: 3, DownloadAttempt: 4, Captured: 5, NewPayloads: 6, SharedBazaar: 7, SharedURLhaus: 8, SharedThreatFox: 9}
	want := observability.FunnelWindow{Connected: 1, LoggedIn: 2, RanCommands: 3, DownloadAttempt: 4, Captured: 5, NewPayloads: 6, SharedBazaar: 7, SharedURLhaus: 8, SharedThreatFox: 9}
	if got := funnelWindow(c); got != want {
		t.Fatalf("funnelWindow = %+v, want %+v", got, want)
	}
}

func TestCollectFunnelRunsBothWindows(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "funnel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := collectFunnel(st)(context.Background()); err != nil {
		t.Fatalf("collectFunnel on an empty store: %v", err)
	}
}

// TestCollectFunnelUsesVetSizeFloor pins the wiring's share policy to
// bazaar.Vet's own floor: a zero-value SharePolicy would capture nothing,
// and a private floor would drift from Vet. Captured must count the sample
// at exactly MinSampleBytes and not the one a byte below it.
func TestCollectFunnelUsesVetSizeFloor(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "funnel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC()
	for _, a := range []struct {
		sha  string
		size int64
	}{{"aaaa", bazaar.MinSampleBytes - 1}, {"bbbb", bazaar.MinSampleBytes}} {
		if err := st.RecordArtifact(store.Artifact{TS: now, CreatedAt: now, FirstObservedAt: now, LastSuccessfulFetchAt: now, URL: "http://203.0.113.7/" + a.sha, SHA256: a.sha, SizeBytes: a.size, Origin: "quarantine_fetch", Status: "fetched"}); err != nil {
			t.Fatal(err)
		}
	}
	sample, err := collectFunnel(st)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sample.Day.Captured != 1 || sample.Week.Captured != 1 {
		t.Fatalf("Captured day=%d week=%d, want 1 and 1 (only the MinSampleBytes sample)", sample.Day.Captured, sample.Week.Captured)
	}
	if !sample.At.IsZero() {
		t.Fatalf("At = %v, want zero so the sampler stamps it with the monitor clock", sample.At)
	}
}

// TestFunnelSamplerStartsOnlyOnceServing pins that the funnel sampler lives in
// the workers hook: its first collection happens after seed and cache warm-up
// (phase serving), never during cold start, in both web and live modes.
func TestFunnelSamplerStartsOnlyOnceServing(t *testing.T) {
	for _, live := range []bool{false, true} {
		t.Run(map[bool]string{false: "web", true: "live"}[live], func(t *testing.T) {
			cfg := config.Default()
			cfg.DataDir = t.TempDir()
			cfg.Capture.Enabled = false
			cfg.RetentionDays = 0
			cfg.Observability.MinFreeBytes = 0
			cfg.Cowrie.JSONLog = filepath.Join(cfg.DataDir, "missing.json")
			cfg.GeoIP.Enabled = false
			st, err := store.Open(cfg.DBPath())
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			keys, err := settings.Load(st)
			if err != nil {
				t.Fatal(err)
			}
			var addr atomic.Value
			phase := make(chan string, 1)
			orig := funnelCollector
			t.Cleanup(func() { funnelCollector = orig })
			funnelCollector = func(st *store.Store) func(context.Context) (observability.FunnelSample, error) {
				inner := orig(st)
				var once atomic.Bool
				return func(ctx context.Context) (observability.FunnelSample, error) {
					if once.CompareAndSwap(false, true) {
						a, _ := addr.Load().(string)
						if a == "" {
							phase <- "before listener bound"
						} else {
							phase <- metricsPhase(t, a)
						}
					}
					return inner(ctx)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- runRuntime(ctx, st, keys, cfg, runtimeOptions{Addr: "127.0.0.1:0", Live: live, CowriePath: cfg.Cowrie.JSONLog, Interval: time.Second, OnListening: func(a net.Addr) { addr.Store(a.String()) }})
			}()
			select {
			case got := <-phase:
				if got != "serving" {
					t.Errorf("first funnel collection ran in phase %q, want serving", got)
				}
			case err := <-done:
				t.Fatalf("runtime exited before the funnel ran: %v", err)
			case <-time.After(runtimeJoinBound):
				t.Fatal("funnel sampler never ran")
			}
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(runtimeJoinBound):
				t.Fatal("runtime did not join")
			}
		})
	}
}

// metricsPhase returns the lifecycle phase /metrics reports as active.
func metricsPhase(t *testing.T, addr string) string {
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Errorf("GET /metrics: %v", err)
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	for _, p := range []string{"starting", "serving", "draining"} {
		if strings.Contains(string(body), `shardlure_phase{phase="`+p+`"} 1`) {
			return p
		}
	}
	t.Errorf("no active phase in /metrics (status %d)", resp.StatusCode)
	return ""
}

func TestCapturePauseNotifierSetsMonitor(t *testing.T) {
	m := observability.New(time.Now, 0)
	notify := capturePauseNotifier(m)
	notify(true, 1024)
	if !m.Snapshot().CapturePaused {
		t.Fatal("pause must reach the monitor")
	}
	notify(false, 1<<40)
	if m.Snapshot().CapturePaused {
		t.Fatal("resume must reach the monitor")
	}
}

// TestCaptureSpaceWiring pins the live wiring: the runner's gate reports to
// the monitor, and the URL worker shares that gate rather than writing
// quarantine fetches past the free-space floor.
func TestCaptureSpaceWiring(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "wiring.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Capture.EvidenceDir = t.TempDir()
	runner := capture.NewRunner(st, cfg)
	m := observability.New(time.Now, 0)
	wireCapturePause(runner, m)
	if runner.SpaceGate().OnChange == nil {
		t.Fatal("the runner's gate must report transitions")
	}
	runner.SpaceGate().OnChange(true, 1)
	if !m.Snapshot().CapturePaused {
		t.Fatal("the gate's OnChange must reach this monitor")
	}
	urlWorker := newURLWorker(st, runner, m)
	if urlWorker.Space != runner.SpaceGate() {
		t.Fatal("the URL worker must share the runner's SpaceGate")
	}
	if urlWorker.OnCycle == nil {
		t.Fatal("the URL worker must report cycles to the monitor")
	}
}

// TestRuntimeWiresSpaceGateBeforeWorkers pins the call sites the helper test
// cannot see. OnChange is written unlocked, so wireCapturePause must run right
// after NewRunner and before the first runner.Run (the seed hook), seed itself
// and the workers; otherwise it races Allow's locked read. The URL worker must
// be built by newURLWorker, the helper that shares the runner's SpaceGate.
// Comments are stripped and whitespace is flexible, so only real calls count.
func TestRuntimeWiresSpaceGateBeforeWorkers(t *testing.T) {
	src, err := os.ReadFile("runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	code := regexp.MustCompile(`(?m)//.*$`).ReplaceAllString(string(src), "")
	pos := func(pattern string) int {
		loc := regexp.MustCompile(pattern).FindStringIndex(code)
		if loc == nil {
			return -1
		}
		return loc[0]
	}
	// NewRunner's assignment followed directly by the wiring call: nothing but
	// whitespace between the two statements.
	if pos(`runner\s*=\s*capture\.NewRunner\([^)]*\)\s*wireCapturePause\(\s*runner\s*,\s*m\s*\)`) < 0 {
		t.Fatal("wireCapturePause(runner, m) must be the statement right after capture.NewRunner")
	}
	wire := pos(`wireCapturePause\(\s*runner\s*,\s*m\s*\)`)
	for name, pattern := range map[string]string{
		"the first runner.Run": `runner\.Run\(`,
		"the seed hook":        `seed\s*:=\s*func\(`,
		"the worker starts":    `workers\s*:=\s*func\(`,
	} {
		if p := pos(pattern); p < 0 || wire > p {
			t.Fatalf("wireCapturePause must precede %s (wire at %d, it at %d)", name, wire, p)
		}
	}
	if pos(`capture\.NewArtifactWorker\(`) >= 0 || pos(`urlWorker\s*:=\s*newURLWorker\(\s*st\s*,\s*runner\s*,\s*m\s*\)`) < 0 {
		t.Fatal("the live URL worker must be built by newURLWorker so it shares the runner's SpaceGate")
	}
}
