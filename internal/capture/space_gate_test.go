package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

func pausedGate() *SpaceGate {
	g := NewSpaceGate("/inert", 100)
	g.avail = func(string) (uint64, error) { return 1, nil }
	return g
}

// budgetGate allows the first `open` measurements, then reports a full disk
// until reopen is called.
func budgetGate(open int64) (*SpaceGate, func()) {
	var calls, closed atomic.Int64
	g := NewSpaceGate("/inert", 100)
	g.avail = func(string) (uint64, error) {
		if closed.Load() == 0 && calls.Add(1) <= open {
			return 500, nil
		}
		closed.Store(1)
		return 1, nil
	}
	return g, func() { closed.Store(0); calls.Store(-1 << 40) }
}

func newGatedRunner(t *testing.T) (*store.Store, *Runner) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "capture.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := config.Config{DataDir: dir}
	cfg.Capture.Enabled = true
	return st, NewRunner(st, cfg)
}

func writeDownload(t *testing.T, r *Runner, body []byte) string {
	t.Helper()
	sum := sha256.Sum256(body)
	name := hex.EncodeToString(sum[:])
	if err := os.MkdirAll(r.cowrieDownloadsDir(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.cowrieDownloadsDir(), name), body, 0600); err != nil {
		t.Fatal(err)
	}
	return name
}

func countEvidence(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if looksLikeSHA256(e.Name()) {
			n++
		}
	}
	return n
}

func TestSpaceGatePausesBelowFloorAndResumes(t *testing.T) {
	free := uint64(10)
	g := NewSpaceGate("/inert", 100)
	g.avail = func(string) (uint64, error) { return free, nil }
	var events []bool
	g.OnChange = func(paused bool, _ uint64) { events = append(events, paused) }

	if g.Allow() {
		t.Fatal("10 B free under a 100 B floor must pause")
	}
	if !g.Paused() {
		t.Fatal("Paused must report the pause")
	}
	if g.Allow() {
		t.Fatal("still below the floor")
	}
	free = 500
	if !g.Allow() {
		t.Fatal("above the floor must resume")
	}
	if len(events) != 2 || events[0] != true || events[1] != false {
		t.Fatalf("OnChange must fire once per transition, got %v", events)
	}
}

func TestSpaceGateFailsOpen(t *testing.T) {
	var nilGate *SpaceGate
	if !nilGate.Allow() {
		t.Fatal("a nil gate must allow")
	}
	off := NewSpaceGate("/inert", 0)
	off.avail = func(string) (uint64, error) { return 0, nil }
	if !off.Allow() {
		t.Fatal("a zero floor disables the guard")
	}
	broken := NewSpaceGate("/inert", 100)
	broken.avail = func(string) (uint64, error) { return 0, errors.New("statfs unsupported") }
	if !broken.Allow() {
		t.Fatal("unmeasurable free space must not stop capture; ENOSPC still fails the write itself")
	}
}

func TestPausedArtifactWorkerClaimsNothing(t *testing.T) {
	g := NewSpaceGate("/inert", 100)
	g.avail = func(string) (uint64, error) { return 1, nil }
	cycles := 0
	w := &ArtifactWorker{Space: g, OnCycle: func(begin bool, err error) {
		cycles++
		if err != nil {
			t.Fatalf("a pause must not be reported as a cycle failure: %v", err)
		}
	}}
	// st is nil: reaching DueArtifactCaptures would panic, proving the gate
	// runs before any claim (so a full disk never burns the retry budget).
	if err := w.tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if cycles != 2 {
		t.Fatalf("OnCycle begin+end must still fire while paused (keeps LastProgress fresh), got %d", cycles)
	}
}

func TestSpaceGateConcurrentNotificationsStayOrdered(t *testing.T) {
	var flip atomic.Uint64
	g := NewSpaceGate("/inert", 100)
	var last atomic.Uint64
	g.avail = func(string) (uint64, error) {
		free := uint64(1)
		if flip.Add(1)%2 == 0 {
			free = 500
		}
		last.Store(free)
		runtime.Gosched() // widen the measure-then-lock window an unlocked gate would race in
		return free, nil
	}
	var events []bool // appended only from OnChange, which Allow serializes
	g.OnChange = func(paused bool, _ uint64) {
		runtime.Gosched()
		events = append(events, paused)
	}

	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				g.Allow()
			}
		}()
	}
	wg.Wait()
	if len(events) == 0 {
		t.Fatal("no transitions observed")
	}
	for i, paused := range events {
		if want := i%2 == 0; paused != want {
			t.Fatalf("transition %d = %v, want strict alternation starting with pause: %v", i, paused, events)
		}
	}
	if events[len(events)-1] != g.Paused() {
		t.Fatalf("last notification %v disagrees with Paused() %v", events[len(events)-1], g.Paused())
	}
	if wantPaused := last.Load() < 100; g.Paused() != wantPaused {
		t.Fatalf("final state %v does not match the last measurement (%d B free)", g.Paused(), last.Load())
	}
}

func TestPausedFileWorkerClaimsNothing(t *testing.T) {
	// st nil: reaching ClaimFileCaptures would panic, proving the gate is first.
	dir := t.TempDir()
	w := &FileWorker{downloadsRoot: filepath.Join(dir, "dl"), evidenceRoot: filepath.Join(dir, "ev"), now: time.Now, space: pausedGate()}
	n, err := w.tick(t.Context())
	if n != 0 || err != nil {
		t.Fatalf("paused tick = %d, %v; want 0, nil (a pause is not a failure)", n, err)
	}
}

func TestPausedRunnerSkipsSyncButStillDiscovers(t *testing.T) {
	st, r := newGatedRunner(t)
	r.space = pausedGate()
	name := writeDownload(t, r, []byte("inert bytes"))
	if err := st.InsertEvent(&models.Event{TS: time.Now(), Source: models.SourceCowrie, Kind: models.KindFileDown, Filename: name, SHA256: name, Command: "https://example.test/inert"}); err != nil {
		t.Fatal(err)
	}

	if _, err := r.Run(t.Context()); err != nil {
		t.Fatalf("a paused Run must not fail the ingest worker: %v", err)
	}
	if _, err := os.Stat(filepath.Join(r.fetch.EvidenceDir, "cowrie", name)); !os.IsNotExist(err) {
		t.Fatalf("paused Run copied evidence: %v", err)
	}
	// Discovery still ran: the job is claimable once space returns.
	jobs, err := st.ClaimFileCaptures(t.Context(), time.Now(), 1, time.Minute)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("paused Run must still discover file captures: %+v %v", jobs, err)
	}
}

func TestDownloadSyncStopsWhenGateClosesMidPass(t *testing.T) {
	_, r := newGatedRunner(t)
	gate, reopen := budgetGate(1)
	r.space = gate
	for _, body := range []string{"inert one", "inert two", "inert three"} {
		writeDownload(t, r, []byte(body))
	}
	out := filepath.Join(r.fetch.EvidenceDir, "cowrie")

	n, err := r.syncCowrieDownloads()
	if err != nil {
		t.Fatalf("a mid-pass pause is not a failure: %v", err)
	}
	if n != 1 || countEvidence(t, out) != 1 {
		t.Fatalf("copied %d (evidence %d) after the gate closed; want exactly 1", n, countEvidence(t, out))
	}
	if !gate.Paused() {
		t.Fatal("gate should report the pause")
	}
	// The rest were left unrecorded, not failed: the next open pass takes them.
	reopen()
	n, err = r.syncCowrieDownloads()
	if err != nil || n != 2 || countEvidence(t, out) != 3 {
		t.Fatalf("resumed pass copied %d (evidence %d), err %v; want the remaining 2", n, countEvidence(t, out), err)
	}
}

func TestTTYTranscriptWaitsForSpace(t *testing.T) {
	_, r := newGatedRunner(t)
	// One measurement allowed: the raw tty copy passes, the transcript write
	// that follows it finds the gate closed.
	gate, reopen := budgetGate(1)
	r.space = gate
	name := strings.Repeat("d", 64)
	if err := os.MkdirAll(r.cowrieTTYDir(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.cowrieTTYDir(), name), []byte("inert short tty"), 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(r.fetch.EvidenceDir, "cowrie-tty")
	if _, err := r.syncCowrieTTY(); err != nil {
		t.Fatalf("a paused transcript is not a failure: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, name)); err != nil {
		t.Fatalf("raw tty should have been copied before the gate closed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, name+".txt")); !os.IsNotExist(err) {
		t.Fatalf("transcript written while paused: %v", err)
	}
	reopen()
	if _, err := r.syncCowrieTTY(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, name+".txt")); err != nil {
		t.Fatalf("transcript must be written once space returns: %v", err)
	}
}
