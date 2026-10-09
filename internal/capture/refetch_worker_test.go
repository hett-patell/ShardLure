package capture

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
)

// refetchFixture is one store, one loopback payload server whose body and
// status the test changes between ticks, and the fetcher and host gate the
// two workers share in the live runtime.
type refetchFixture struct {
	st    *store.Store
	fetch *SafeFetcher
	hosts *HostGate
	srv   *httptest.Server

	mu       sync.Mutex
	body     string
	status   int
	requests int
	onServe  func(*http.Request)
}

func newRefetchFixture(t *testing.T) *refetchFixture {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "refetch.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	fx := &refetchFixture{st: st, hosts: NewHostGate(), body: "#!/bin/sh\necho payload-v1\n", status: 200}
	fx.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fx.mu.Lock()
		fx.requests++
		body, status, hook := fx.body, fx.status, fx.onServe
		fx.mu.Unlock()
		if hook != nil {
			hook(r)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(fx.srv.Close)
	fx.fetch = NewSafeFetcher(t.TempDir(), 1<<20, 5*time.Second, nil)
	fx.fetch.TestLoopback = true
	return fx
}

func (fx *refetchFixture) set(body string, status int) {
	fx.mu.Lock()
	fx.body, fx.status = body, status
	fx.mu.Unlock()
}

func (fx *refetchFixture) count() int {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	return fx.requests
}

// capture queues url and lets the URL worker fetch it, which records the
// epoch-0 row and seeds the re-fetch schedule one hour out.
func (fx *refetchFixture) capture(t *testing.T, url string) {
	t.Helper()
	if err := fx.st.UpsertArtifact(store.Artifact{URL: url, TS: time.Now(), Origin: "quarantine_fetch", Status: "pending"}); err != nil {
		t.Fatal(err)
	}
	w := NewArtifactWorker(fx.st, fx.fetch, 5, time.Minute)
	w.Hosts = fx.hosts
	w.Refetch = true
	if err := w.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := fx.rowsFor(t, url); n != 1 {
		t.Fatalf("capture rows=%d", n)
	}
}

// worker returns a re-fetch worker whose clock the test steps.
func (fx *refetchFixture) worker(clock *time.Time) *RefetchWorker {
	w := NewRefetchWorker(fx.st, fx.fetch, fx.hosts)
	w.now = func() time.Time { return *clock }
	return w
}

func (fx *refetchFixture) rowsFor(t *testing.T, url string) int {
	t.Helper()
	var n int
	fx.query(t, `SELECT COUNT(*) FROM artifacts WHERE url=?`, []any{url}, &n)
	return n
}

func (fx *refetchFixture) query(t *testing.T, q string, args []any, dest ...any) {
	t.Helper()
	if err := fx.st.WithTx(func(tx *sql.Tx) error { return tx.QueryRow(q, args...).Scan(dest...) }); err != nil {
		t.Fatal(err)
	}
}

type scheduleRow struct {
	state    string
	checks   int
	failures int
	leased   bool
	next     string
}

func (fx *refetchFixture) schedule(t *testing.T, url string) scheduleRow {
	t.Helper()
	var r scheduleRow
	var lease sql.NullString
	fx.query(t, `SELECT state, checks, consecutive_failures, lease_until, next_check_at FROM refetch_schedule WHERE url=?`, []any{url},
		&r.state, &r.checks, &r.failures, &lease, &r.next)
	r.leased = lease.Valid
	return r
}

// quarantineFiles counts published blobs (temporary .fetch-* names excluded).
func (fx *refetchFixture) quarantineFiles(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(fx.fetch.EvidenceDir, "quarantine"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("temporary file left behind: %s", e.Name())
		}
		n++
	}
	return n
}

// (a) a due URL is fetched once per tick and a second tick before
// next_check_at does nothing; (b) the same body advances the epoch-0 row's
// fetch clock and reuses the quarantine file, a changed body becomes the
// epoch-1 row.
func TestRefetchWorkerFetchesDueURLOncePerSchedule(t *testing.T) {
	fx := newRefetchFixture(t)
	url := fx.srv.URL + "/bins/x.sh"
	fx.capture(t, url)
	if fx.count() != 1 || fx.quarantineFiles(t) != 1 {
		t.Fatalf("capture: requests=%d", fx.count())
	}

	clock := time.Now().UTC().Add(30 * time.Minute)
	w := fx.worker(&clock)
	if err := w.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fx.count() != 1 {
		t.Fatal("a URL that is not due yet was fetched")
	}

	clock = time.Now().UTC().Add(61 * time.Minute)
	if err := w.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fx.count() != 2 {
		t.Fatalf("due tick: requests=%d want 2", fx.count())
	}
	if n := fx.rowsFor(t, url); n != 1 {
		t.Fatalf("same body: rows=%d want 1", n)
	}
	var lastRefetch string
	fx.query(t, `SELECT last_refetch_at FROM artifacts WHERE url=? AND fetch_epoch=0`, []any{url}, &lastRefetch)
	if got, err := time.Parse(time.RFC3339Nano, lastRefetch); err != nil || !got.Equal(clock) {
		t.Fatalf("last_refetch_at=%s want %s (%v)", lastRefetch, clock.Format(time.RFC3339Nano), err)
	}
	// The same hash reuses quarantine/<sha256>: no second file.
	if n := fx.quarantineFiles(t); n != 1 {
		t.Fatalf("same-hash re-fetch left %d quarantine files, want 1", n)
	}
	if s := fx.schedule(t, url); s.checks != 1 || s.failures != 0 || s.leased || s.state != "active" {
		t.Fatalf("schedule after check: %+v", s)
	}

	// A second tick before next_check_at does nothing.
	if err := w.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fx.count() != 2 {
		t.Fatalf("second tick before next check fetched: requests=%d", fx.count())
	}

	// The server rotates its payload: the next due check records it at
	// epoch 1 beside the first-sight row.
	fx.set("#!/bin/sh\necho payload-v2\n", 200)
	clock = clock.Add(61 * time.Minute)
	if err := w.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fx.count() != 3 {
		t.Fatalf("rotated tick: requests=%d want 3", fx.count())
	}
	var rows, maxEpoch, minEpoch, shas int
	fx.query(t, `SELECT COUNT(*), MAX(fetch_epoch), MIN(fetch_epoch), COUNT(DISTINCT sha256) FROM artifacts WHERE url=? AND status='fetched'`,
		[]any{url}, &rows, &maxEpoch, &minEpoch, &shas)
	if rows != 2 || minEpoch != 0 || maxEpoch != 1 || shas != 2 {
		t.Fatalf("rotated payload: rows=%d epochs %d..%d shas=%d", rows, minEpoch, maxEpoch, shas)
	}
	if n := fx.quarantineFiles(t); n != 2 {
		t.Fatalf("rotated payload: quarantine files=%d want 2", n)
	}
}

// (c) a server error counts toward the offline streak and never inserts.
func TestRefetchWorkerServerErrorIsAFailure(t *testing.T) {
	fx := newRefetchFixture(t)
	url := fx.srv.URL + "/bins/x.sh"
	fx.capture(t, url)
	fx.set("oops", 500)
	clock := time.Now().UTC().Add(61 * time.Minute)
	w := fx.worker(&clock)
	if err := w.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fx.count() != 2 {
		t.Fatalf("requests=%d want 2", fx.count())
	}
	if s := fx.schedule(t, url); s.failures != 1 || s.checks != 1 || s.leased {
		t.Fatalf("schedule after 500: %+v", s)
	}
	if n := fx.rowsFor(t, url); n != 1 {
		t.Fatalf("a failed re-fetch inserted: rows=%d", n)
	}
	if n := fx.quarantineFiles(t); n != 1 {
		t.Fatalf("quarantine files=%d want 1", n)
	}
}

// (d) while another fetch holds the URL's host, a tick fetches nothing and
// hands the job back: lease cleared, no check spent, next check one tick out.
func TestRefetchWorkerBusyHostReleasesLease(t *testing.T) {
	fx := newRefetchFixture(t)
	url := fx.srv.URL + "/bins/x.sh"
	fx.capture(t, url)
	before := fx.schedule(t, url)
	release, ok := fx.hosts.TryAcquire(fx.srv.URL + "/other")
	if !ok {
		t.Fatal("gate refused the first holder")
	}
	clock := time.Now().UTC().Add(61 * time.Minute)
	w := fx.worker(&clock)
	if err := w.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fx.count() != 1 {
		t.Fatalf("busy host was fetched: requests=%d", fx.count())
	}
	// No check spent; next_check_at moves one tick out (M1).
	wantNext := clock.Add(store.RefetchReleaseDelay).UTC().Format("2006-01-02T15:04:05.000000000Z")
	if s := fx.schedule(t, url); s.leased || s.checks != 0 || s.failures != 0 || s.next == before.next || s.next != wantNext || s.state != "active" {
		t.Fatalf("busy host: schedule %+v (before %+v, want next %s)", s, before, wantNext)
	}
	// Once the host is free, the first tick after the push takes the job.
	release()
	clock = clock.Add(store.RefetchReleaseDelay + time.Second)
	if err := w.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fx.count() != 2 {
		t.Fatalf("freed host: requests=%d want 2", fx.count())
	}
	if s := fx.schedule(t, url); s.checks != 1 || s.leased {
		t.Fatalf("freed host: schedule %+v", s)
	}
}

// The re-fetch worker holds the host for the whole fetch, so the capture
// worker cannot fetch from the same server meanwhile.
func TestRefetchWorkerHoldsHostDuringFetch(t *testing.T) {
	fx := newRefetchFixture(t)
	url := fx.srv.URL + "/bins/x.sh"
	fx.capture(t, url)
	var held atomic.Bool
	fx.mu.Lock()
	fx.onServe = func(*http.Request) {
		if release, ok := fx.hosts.TryAcquire(fx.srv.URL + "/other"); ok {
			release()
		} else {
			held.Store(true)
		}
	}
	fx.mu.Unlock()
	clock := time.Now().UTC().Add(61 * time.Minute)
	if err := fx.worker(&clock).tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !held.Load() {
		t.Fatal("the host was not held during the re-fetch")
	}
	if _, ok := fx.hosts.TryAcquire(url); !ok {
		t.Fatal("the host was not released after the re-fetch")
	}
}

// A seeded URL the host gate can never key is settled as a failure, so its
// schedule advances to offline instead of being reclaimed every tick.
func TestRefetchWorkerUnparsableURLFails(t *testing.T) {
	fx := newRefetchFixture(t)
	bad := "http://[bad/x.sh"
	if err := fx.st.SeedRefetch(bad, time.Now().UTC().Add(-time.Minute), "aa"); err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Add(61 * time.Minute)
	w := fx.worker(&clock)
	for i := 1; i <= 6; i++ {
		if err := w.tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		s := fx.schedule(t, bad)
		if s.checks != i || s.failures != i || s.leased {
			t.Fatalf("tick %d: schedule %+v", i, s)
		}
		clock = clock.Add(61 * time.Minute)
	}
	if s := fx.schedule(t, bad); s.state != "offline" {
		t.Fatalf("six unparsable checks: state=%s want offline", s.state)
	}
	if fx.count() != 0 || fx.rowsFor(t, bad) != 0 {
		t.Fatalf("unparsable URL: requests=%d rows=%d", fx.count(), fx.rowsFor(t, bad))
	}
}

// A SpaceGate pause claims nothing: no lease, no check, no request.
func TestRefetchWorkerPausedClaimsNothing(t *testing.T) {
	fx := newRefetchFixture(t)
	url := fx.srv.URL + "/bins/x.sh"
	fx.capture(t, url)
	clock := time.Now().UTC().Add(61 * time.Minute)
	w := fx.worker(&clock)
	w.Space = NewSpaceGate(fx.fetch.EvidenceDir, 1<<62)
	var cycles []error
	w.OnCycle = func(start bool, err error) {
		if !start {
			cycles = append(cycles, err)
		}
	}
	if err := w.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fx.count() != 1 {
		t.Fatal("a paused tick fetched")
	}
	if s := fx.schedule(t, url); s.leased || s.checks != 0 || s.failures != 0 {
		t.Fatalf("paused tick touched the schedule: %+v", s)
	}
	if len(cycles) != 1 || cycles[0] != nil {
		t.Fatalf("a pause must report a successful cycle: %v", cycles)
	}
}

// Shutdown mid-fetch says nothing about the URL: no failure is recorded.
func TestRefetchWorkerCancelIsNotAFailure(t *testing.T) {
	fx := newRefetchFixture(t)
	url := fx.srv.URL + "/bins/x.sh"
	fx.capture(t, url)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fx.mu.Lock()
	fx.onServe = func(r *http.Request) {
		cancel()
		<-r.Context().Done()
	}
	fx.mu.Unlock()
	clock := time.Now().UTC().Add(61 * time.Minute)
	_ = fx.worker(&clock).tick(ctx)
	if s := fx.schedule(t, url); s.checks != 0 || s.failures != 0 {
		t.Fatalf("cancelled re-fetch was recorded: %+v", s)
	}
}

// (e) the capture worker spends no attempt while the host is busy, and
// fetches on the first tick after it is freed.
func TestArtifactWorkerBusyHostSpendsNoAttempt(t *testing.T) {
	fx := newRefetchFixture(t)
	url := fx.srv.URL + "/bins/y.sh"
	if err := fx.st.UpsertArtifact(store.Artifact{URL: url, TS: time.Now(), Origin: "quarantine_fetch", Status: "pending"}); err != nil {
		t.Fatal(err)
	}
	release, ok := fx.hosts.TryAcquire(fx.srv.URL + "/other")
	if !ok {
		t.Fatal("gate refused the first holder")
	}
	w := NewArtifactWorker(fx.st, fx.fetch, 5, time.Minute)
	w.Hosts = fx.hosts
	if err := w.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	var attempts int
	if err := fx.st.ArtifactAttemptCount(url, &attempts); err != nil {
		t.Fatal(err)
	}
	var lease sql.NullString
	fx.query(t, `SELECT lease_until FROM artifacts WHERE url=? AND fetch_epoch=0`, []any{url}, &lease)
	if fx.count() != 0 || attempts != 0 || lease.Valid {
		t.Fatalf("busy host: requests=%d attempts=%d leased=%v", fx.count(), attempts, lease.Valid)
	}
	release()
	if err := w.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fx.st.ArtifactAttemptCount(url, &attempts); err != nil {
		t.Fatal(err)
	}
	if fx.count() != 1 || attempts != 1 {
		t.Fatalf("freed host: requests=%d attempts=%d", fx.count(), attempts)
	}
	if _, ok := fx.hosts.TryAcquire(url); !ok {
		t.Fatal("the capture worker did not release the host")
	}
}

// A URL the gate can never key is not gated by the capture worker: the fetch
// settles it as invalid instead of leaving it at the head of the due queue.
func TestArtifactWorkerUnparsableURLIsNotStuck(t *testing.T) {
	fx := newRefetchFixture(t)
	bad := "http://[bad/y.sh"
	if err := fx.st.UpsertArtifact(store.Artifact{URL: bad, TS: time.Now(), Origin: "quarantine_fetch", Status: "pending"}); err != nil {
		t.Fatal(err)
	}
	w := NewArtifactWorker(fx.st, fx.fetch, 5, time.Minute)
	w.Hosts = fx.hosts
	if err := w.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	var status string
	fx.query(t, `SELECT status FROM artifacts WHERE url=? AND fetch_epoch=0`, []any{bad}, &status)
	if status != "invalid" {
		t.Fatalf("status=%s want invalid", status)
	}
}
