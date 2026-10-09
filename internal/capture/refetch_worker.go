package capture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"log"
	"net/url"
	"sync"
	"time"

	"github.com/networkshard/shardlure/internal/store"
)

// payloadShaped reports whether a fetched body's head looks like a payload a
// re-fetch could usefully yield again: an ELF, PE, zip/gzip/bzip2/xz/7z/tar
// archive, or a text script starting with "#!". Everything else (HTML, API
// JSON, an IP-echo answer, a Telegram sendMessage reply) is not re-fetched:
// such bodies change on every request, so each check would mint a new
// "sample", and a GET with side effects would be replayed ~50 times from the
// sensor's address (final review I3).
func payloadShaped(head []byte) bool {
	if hasBinaryMagic(head) {
		return true
	}
	return bytes.HasPrefix(head, []byte("#!")) && isTextScript(head)
}

// refetchSeedable reports whether a first capture may enter the re-fetch
// schedule: the URL carries no query string (a query is the shape of an API
// call or a tracking/exfiltration GET, not of a payload path) and the body is
// payload-shaped. An unparsable URL is not seeded (fail closed).
func refetchSeedable(rawURL string, head []byte) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.RawQuery != "" || u.ForceQuery {
		return false
	}
	return payloadShaped(head)
}

// errNotPayloadShaped stops a re-fetch's publication: the body is dropped
// with its temporary file and the check counts as a failure.
var errNotPayloadShaped = errors.New("re-fetched body is not payload-shaped")

// RefetchWorker drives the Phase C re-fetch schedule (store.NextRefetch):
// URLs that already served a payload are fetched again so a server that
// rotates its binary yields every build, not just the first one. It is a
// capacity-one worker like ArtifactWorker, handling at most one job per tick.
type RefetchWorker struct {
	OnCycle func(bool, error)
	// Space, when set, is consulted before every claim (see SpaceGate).
	Space *SpaceGate

	st       *store.Store
	fetch    *SafeFetcher
	hosts    *HostGate
	leaseDur time.Duration
	interval time.Duration
	// now is the schedule clock; tests replace it to step past next_check_at.
	now func() time.Time

	mu   sync.Mutex
	busy bool
}

// NewRefetchWorker creates a re-fetch worker. fetch and hosts must be the
// ones the URL capture worker uses: one evidence directory, one host gate.
func NewRefetchWorker(st *store.Store, fetch *SafeFetcher, hosts *HostGate) *RefetchWorker {
	if hosts == nil {
		hosts = NewHostGate()
	}
	return &RefetchWorker{
		st:       st,
		fetch:    fetch,
		hosts:    hosts,
		leaseDur: 2 * time.Minute,
		interval: 30 * time.Second,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// Run polls every 30 s until ctx is cancelled.
func (w *RefetchWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	w.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.tick(ctx)
		}
	}
}

func (w *RefetchWorker) tick(ctx context.Context) (cycleErr error) {
	if ctx.Err() != nil {
		return
	}
	w.mu.Lock()
	if w.busy {
		w.mu.Unlock()
		return
	}
	w.busy = true
	w.mu.Unlock()
	if w.OnCycle != nil {
		w.OnCycle(true, nil)
		defer func() { w.OnCycle(false, cycleErr) }()
	}
	defer func() {
		w.mu.Lock()
		w.busy = false
		w.mu.Unlock()
	}()

	// A pause is not a failure: nothing is claimed, so no check is spent
	// and the offline streak does not grow while the disk is full.
	if !w.Space.Allow() {
		return
	}
	job, err := w.st.ClaimRefetch(w.now(), w.leaseDur)
	if err != nil {
		cycleErr = err
		log.Print("capture-refetch: claim failed")
		return
	}
	if job == nil {
		return
	}
	// Raw URLs are evidence and can carry credentials; logs use a digest.
	urlID := sha256.Sum256([]byte(job.URL))

	if _, gateable := hostGateKeyFor(job.URL); !gateable {
		// The gate can never key this URL, so it could never be fetched.
		// Settle it as a failure: the streak takes it offline and then
		// done, instead of reclaiming it every tick forever.
		w.complete(*job, store.RefetchOutcome{Detail: "invalid URL"}, urlID, &cycleErr)
		return
	}
	release, ok := w.hosts.TryAcquire(job.URL)
	if !ok {
		// Another fetch holds this host. Hand the job back, pushed one tick
		// so other hosts' due rows go first; a busy host is not the URL's
		// failure.
		if err := w.st.ReleaseRefetch(*job, w.now()); err != nil && !errors.Is(err, store.ErrClaimStale) {
			cycleErr = err
			log.Printf("capture-refetch: release failed url_id=%x", urlID[:8])
		}
		return
	}
	defer release()

	// Leave time to persist the result before the fencing lease expires.
	deadline, cancel := context.WithTimeout(ctx, w.leaseDur*9/10)
	defer cancel()

	var completeErr error
	completed := false
	notShaped := false
	res, fetchErr := w.fetch.fetchWithPublication(deadline, job.URL, func(res *FetchResult, publish func() error) error {
		// Checked before publication, so a body that is not a payload
		// never reaches the evidence tree: fetchWithPublication removes the
		// temporary file when finalize refuses.
		if !payloadShaped(res.head) {
			notShaped = true
			return errNotPayloadShaped
		}
		return w.st.WithCaptureFileAccess(deadline, func() error {
			if err := publish(); err != nil {
				return err
			}
			completed = true
			_, completeErr = w.st.CompleteRefetch(*job, w.now(), store.RefetchOutcome{
				OK: true, SHA256: res.SHA256, LocalPath: res.LocalPath, Size: res.Size, Detail: res.Detail,
			})
			return completeErr
		})
	})
	if completed {
		if completeErr != nil && !errors.Is(completeErr, store.ErrClaimStale) {
			cycleErr = completeErr
			log.Printf("capture-refetch: complete failed url_id=%x", urlID[:8])
		}
		return
	}
	if notShaped {
		// The URL now answers with something that is not a payload: a
		// failed check (offline streak), never a new epoch.
		w.complete(*job, store.RefetchOutcome{Detail: "not payload-shaped"}, urlID, &cycleErr)
		return
	}
	if res != nil && res.Status == "fetched" {
		// Publication failed (I/O, retention guard, shutdown): not the URL's
		// fault. The lease lapses and the job is retried.
		cycleErr = fetchErr
		log.Printf("capture-refetch: publish failed url_id=%x", urlID[:8])
		return
	}
	if ctx.Err() != nil {
		// Shutdown mid-fetch says nothing about the URL; let the lease lapse.
		return
	}
	detail := "refetch failed"
	if res != nil && res.Detail != "" {
		detail = res.Detail
	} else if fetchErr != nil {
		detail = safeCaptureError(fetchErr, "refetch failed").Error()
	}
	w.complete(*job, store.RefetchOutcome{Detail: detail}, urlID, &cycleErr)
	return
}

// complete records an unsuccessful check (empty, blocked, invalid, failed,
// failed_permanently or a transport error): it counts toward the offline
// streak and never inserts an artifact.
func (w *RefetchWorker) complete(job store.RefetchJob, out store.RefetchOutcome, urlID [32]byte, cycleErr *error) {
	if _, err := w.st.CompleteRefetch(job, w.now(), out); err != nil && !errors.Is(err, store.ErrClaimStale) {
		*cycleErr = err
		log.Printf("capture-refetch: complete failed url_id=%x", urlID[:8])
	}
}
