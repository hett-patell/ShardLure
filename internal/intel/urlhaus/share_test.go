package urlhaus

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRecorder is an in-memory SubmitRecorder.
type fakeRecorder struct {
	mu        sync.Mutex
	submitted map[string]string
	failOn    string // URL whose URLhausSubmitted call should error
	recordErr error
}

func newFakeRecorder() *fakeRecorder {
	return &fakeRecorder{submitted: map[string]string{}}
}

func (f *fakeRecorder) URLhausSubmitted(url string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if url == f.failOn {
		return false, errors.New("boom")
	}
	_, ok := f.submitted[url]
	return ok, nil
}

func (f *fakeRecorder) RecordURLhausSubmission(url, status string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.recordErr != nil {
		return f.recordErr
	}
	f.submitted[url] = status
	return nil
}

// captureServer records every submission body it receives and answers the
// read-only lookup endpoint on /lookup, so Share's duplicate pre-check never
// reaches the real URLhaus in a test.
type captureServer struct {
	*httptest.Server
	mu      sync.Mutex
	bodies  []submitBody
	authKey string
	status  int
	reply   string

	// lookup state
	listed          map[string]bool
	lookupStatus    int    // non-zero = reply with this HTTP status
	lookupReply     string // non-empty = reply with this body verbatim
	lookupHits      int
	lookupAuthKey   string
	lookupURLs      []string
	lookupReject    map[string]bool // per-URL invalid_url answer
	lookupFailAfter int             // >0: lookup number N+1 onward answers 503
	lookupStatusSeq []int           // per-hit status; 0 = answer normally
}

func newCaptureServer(t *testing.T) *captureServer {
	t.Helper()
	cs := &captureServer{status: http.StatusOK, reply: `{"query_status":"ok"}`, listed: map[string]bool{}}
	cs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.mu.Lock()
		defer cs.mu.Unlock()
		if r.URL.Path == "/lookup" {
			cs.lookupHits++
			cs.lookupAuthKey = r.Header.Get("Auth-Key")
			_ = r.ParseForm()
			u := r.PostFormValue("url")
			cs.lookupURLs = append(cs.lookupURLs, u)
			if cs.lookupStatus != 0 {
				w.WriteHeader(cs.lookupStatus)
				_, _ = w.Write([]byte(cs.lookupReply))
				return
			}
			if n := cs.lookupHits; len(cs.lookupStatusSeq) >= n && cs.lookupStatusSeq[n-1] != 0 {
				w.WriteHeader(cs.lookupStatusSeq[n-1])
				return
			}
			if cs.lookupFailAfter > 0 && cs.lookupHits > cs.lookupFailAfter {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if cs.lookupReject[u] {
				_, _ = w.Write([]byte(`{"query_status":"invalid_url"}`))
				return
			}
			if cs.lookupReply != "" {
				_, _ = w.Write([]byte(cs.lookupReply))
				return
			}
			if cs.listed[u] {
				_, _ = w.Write([]byte(`{"query_status":"ok"}`))
				return
			}
			_, _ = w.Write([]byte(`{"query_status":"no_results"}`))
			return
		}
		cs.authKey = r.Header.Get("Auth-Key")
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var b submitBody
		_ = json.Unmarshal(raw, &b)
		cs.bodies = append(cs.bodies, b)
		w.WriteHeader(cs.status)
		_, _ = w.Write([]byte(cs.reply))
	}))
	t.Cleanup(cs.Close)
	return cs
}

// lookupEndpoint is what tests pass as Options.LookupEndpoint.
func (cs *captureServer) lookupEndpoint() string { return cs.URL + "/lookup" }

func (cs *captureServer) allEntries() []Entry {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	var out []Entry
	for _, b := range cs.bodies {
		out = append(out, b.Submission...)
	}
	return out
}

func TestShareSubmitsOnlyVettedURLs(t *testing.T) {
	cs := newCaptureServer(t)
	rec := newFakeRecorder()

	good := goodCandidate()
	privateIP := goodCandidate()
	privateIP.URL = "http://10.1.2.3/bins/x86"
	pseudoKey := goodCandidate()
	pseudoKey.URL = "cowrie-download:abc123"
	failedFetch := goodCandidate()
	failedFetch.URL = "http://evil.tld/gone"
	failedFetch.Status = "failed"

	submitted, skipped, err := Share(context.Background(), rec,
		[]Candidate{good, privateIP, pseudoKey, failedFetch},
		Options{APIKey: "k", Endpoint: cs.URL, LookupEndpoint: cs.lookupEndpoint(), LookupRateLimit: time.Millisecond, ExtraTags: []string{"shardlure"}, RateLimit: time.Millisecond, Now: vetNow})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if submitted != 1 {
		t.Errorf("submitted = %d, want 1", submitted)
	}
	if skipped != 3 {
		t.Errorf("skipped = %d, want 3", skipped)
	}

	entries := cs.allEntries()
	if len(entries) != 1 {
		t.Fatalf("server saw %d entries, want 1: %+v", len(entries), entries)
	}
	if entries[0].URL != good.URL {
		t.Errorf("submitted URL = %q, want %q", entries[0].URL, good.URL)
	}
	if entries[0].Threat != ThreatMalwareDownload {
		t.Errorf("threat = %q, want %q", entries[0].Threat, ThreatMalwareDownload)
	}
	if cs.authKey != "k" {
		t.Errorf("Auth-Key header = %q, want k", cs.authKey)
	}
	if got := rec.submitted[good.URL]; got != "ok" {
		t.Errorf("recorded status = %q, want ok", got)
	}
}

func TestShareLedgerFailureIsNotDurableSuccess(t *testing.T) {
	cs := newCaptureServer(t)
	rec := newFakeRecorder()
	ledgerErr := errors.New("ledger write failed")
	rec.recordErr = ledgerErr
	var progressSubmitted bool
	var progressReason string

	submitted, skipped, err := Share(context.Background(), rec, []Candidate{goodCandidate()}, Options{
		APIKey: "k", Endpoint: cs.URL, LookupEndpoint: cs.lookupEndpoint(), LookupRateLimit: time.Millisecond, RateLimit: time.Millisecond, Now: vetNow,
		OnProgress: func(_ Candidate, durable bool, reason string) {
			progressSubmitted = durable
			progressReason = reason
		},
	})
	if !errors.Is(err, ledgerErr) {
		t.Fatalf("error = %v, want ledger failure", err)
	}
	if submitted != 0 || skipped != 0 {
		t.Fatalf("submitted=%d skipped=%d, want 0/0", submitted, skipped)
	}
	if len(cs.allEntries()) != 1 {
		t.Fatalf("provider received %d entries, want 1", len(cs.allEntries()))
	}
	if progressSubmitted {
		t.Fatal("ledger failure was announced as durable success")
	}
	if !strings.Contains(progressReason, "ledger") {
		t.Fatalf("progress reason = %q, want sanitized ledger failure", progressReason)
	}
}

// The candidate carries no honeypot identifiers, so the wire payload can't
// contain them. This is the leak-prevention regression guard.
func TestShareBodyLeaksNoHoneypotIdentifiers(t *testing.T) {
	cs := newCaptureServer(t)
	rec := newFakeRecorder()
	_, _, err := Share(context.Background(), rec, []Candidate{goodCandidate()},
		Options{APIKey: "k", Endpoint: cs.URL, LookupEndpoint: cs.lookupEndpoint(), LookupRateLimit: time.Millisecond, RateLimit: time.Millisecond, Now: vetNow})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	cs.mu.Lock()
	raw, _ := json.Marshal(cs.bodies)
	cs.mu.Unlock()
	body := string(raw)
	for _, forbidden := range []string{"session", "src_ip", "local_path", "/var/lib/shardlure", "evidence"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Errorf("submission body leaked %q: %s", forbidden, body)
		}
	}
}

func TestShareSkipsAlreadySubmitted(t *testing.T) {
	cs := newCaptureServer(t)
	rec := newFakeRecorder()
	c := goodCandidate()
	rec.submitted[c.URL] = "ok" // pretend a previous run shipped it

	submitted, skipped, err := Share(context.Background(), rec, []Candidate{c},
		Options{APIKey: "k", Endpoint: cs.URL, LookupEndpoint: cs.lookupEndpoint(), LookupRateLimit: time.Millisecond, RateLimit: time.Millisecond, Now: vetNow})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if submitted != 0 || skipped != 1 {
		t.Errorf("submitted=%d skipped=%d, want 0/1", submitted, skipped)
	}
	if n := len(cs.allEntries()); n != 0 {
		t.Errorf("server should see nothing, saw %d", n)
	}
}

// URLhaus already listing a URL is not a failure: record it in the ledger as
// already_listed (terminal for dedup) and never put it on the wire. Before the
// pre-check, a batch of mostly-duplicate URLs failed with an unreadable
// response and nothing was recorded.
func TestShareRecordsURLsAlreadyListedUpstream(t *testing.T) {
	cs := newCaptureServer(t)
	rec := newFakeRecorder()
	already := goodCandidate()
	fresh := goodCandidate()
	fresh.URL = "http://185.7.214.9/bins/fresh"
	cs.listed[already.URL] = true

	var reasons []string
	submitted, skipped, err := Share(context.Background(), rec, []Candidate{already, fresh}, Options{
		APIKey: "k", Endpoint: cs.URL, LookupEndpoint: cs.lookupEndpoint(), LookupRateLimit: time.Millisecond, RateLimit: time.Millisecond, Now: vetNow,
		OnProgress: func(_ Candidate, ok bool, reason string) {
			if !ok {
				reasons = append(reasons, reason)
			}
		},
	})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if submitted != 1 || skipped != 1 {
		t.Fatalf("submitted=%d skipped=%d, want 1/1", submitted, skipped)
	}
	entries := cs.allEntries()
	if len(entries) != 1 || entries[0].URL != fresh.URL {
		t.Fatalf("wire entries = %+v, want only %q", entries, fresh.URL)
	}
	if got := rec.submitted[already.URL]; got != StatusAlreadyListed {
		t.Errorf("ledger status for the listed URL = %q, want %q", got, StatusAlreadyListed)
	}
	if got := rec.submitted[fresh.URL]; got != "ok" {
		t.Errorf("ledger status for the fresh URL = %q, want ok", got)
	}
	if len(reasons) != 1 || reasons[0] != ReasonAlreadyListed {
		t.Errorf("skip reasons = %v, want [%q]", reasons, ReasonAlreadyListed)
	}
	if cs.lookupHits != 2 {
		t.Errorf("lookups = %d, want 2 (one per vetted candidate)", cs.lookupHits)
	}
	if cs.lookupAuthKey != "k" {
		t.Errorf("lookup Auth-Key = %q, want k", cs.lookupAuthKey)
	}
}

// already_listed is terminal for dedup: a later run must skip the URL from the
// ledger without another network round trip.
func TestShareSkipsAlreadyListedWithoutLookup(t *testing.T) {
	cs := newCaptureServer(t)
	rec := newFakeRecorder()
	c := goodCandidate()
	rec.submitted[c.URL] = StatusAlreadyListed

	submitted, skipped, err := Share(context.Background(), rec, []Candidate{c}, Options{
		APIKey: "k", Endpoint: cs.URL, LookupEndpoint: cs.lookupEndpoint(), LookupRateLimit: time.Millisecond, RateLimit: time.Millisecond, Now: vetNow,
	})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if submitted != 0 || skipped != 1 {
		t.Errorf("submitted=%d skipped=%d, want 0/1", submitted, skipped)
	}
	if cs.lookupHits != 0 {
		t.Errorf("lookups = %d, want 0: the ledger already settled it", cs.lookupHits)
	}
	if n := len(cs.allEntries()); n != 0 {
		t.Errorf("wire entries = %d, want 0", n)
	}
}

// If the already_listed ledger write fails, stop before submitting anything:
// a broken ledger leaves even real submissions unrecorded upstream.
func TestShareAlreadyListedLedgerFailureStops(t *testing.T) {
	cs := newCaptureServer(t)
	rec := newFakeRecorder()
	seedErr := errors.New("ledger write failed")
	rec.recordErr = seedErr
	listed := goodCandidate()
	next := goodCandidate()
	next.URL = "http://185.7.214.9/next"
	cs.listed[listed.URL] = true

	submitted, _, err := Share(context.Background(), rec, []Candidate{listed, next}, Options{
		APIKey: "k", Endpoint: cs.URL, LookupEndpoint: cs.lookupEndpoint(), LookupRateLimit: time.Millisecond, RateLimit: time.Millisecond, Now: vetNow,
	})
	if !errors.Is(err, seedErr) {
		t.Fatalf("error = %v, want the ledger failure", err)
	}
	if submitted != 0 {
		t.Errorf("submitted = %d, want 0", submitted)
	}
	if n := len(cs.allEntries()); n != 0 {
		t.Errorf("wire entries = %d, want 0 (the run stops at the failing ledger)", n)
	}
}

// A plaintext already_queued answer (another reporter won the race between our
// lookup and the POST) is "already listed", not a submission of ours.
func TestShareCountsPlaintextAlreadyQueuedAsListed(t *testing.T) {
	cs := newCaptureServer(t)
	c := goodCandidate()
	cs.reply = "already_queued: " + c.URL
	rec := newFakeRecorder()
	var reason string

	submitted, skipped, err := Share(context.Background(), rec, []Candidate{c}, Options{
		APIKey: "k", Endpoint: cs.URL, LookupEndpoint: cs.lookupEndpoint(), LookupRateLimit: time.Millisecond, RateLimit: time.Millisecond, Now: vetNow,
		OnProgress: func(_ Candidate, ok bool, r string) {
			if !ok {
				reason = r
			}
		},
	})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if submitted != 0 || skipped != 1 {
		t.Errorf("submitted=%d skipped=%d, want 0/1", submitted, skipped)
	}
	if got := rec.submitted[c.URL]; got != StatusAlreadyListed {
		t.Errorf("ledger status = %q, want %q", got, StatusAlreadyListed)
	}
	if reason != ReasonAlreadyListed {
		t.Errorf("progress reason = %q, want %q", reason, ReasonAlreadyListed)
	}
}

// A lookup failure skips the candidate: submitting something we could not
// check is exactly what produced the unreadable batch response.
func TestShareLookupFailureSkipsCandidate(t *testing.T) {
	cs := newCaptureServer(t)
	cs.lookupStatus = http.StatusServiceUnavailable
	rec := newFakeRecorder()

	submitted, skipped, err := Share(context.Background(), rec, []Candidate{goodCandidate()}, Options{
		APIKey: "k", Endpoint: cs.URL, LookupEndpoint: cs.lookupEndpoint(), LookupRateLimit: time.Millisecond, RateLimit: time.Millisecond, Now: vetNow,
	})
	if err == nil {
		t.Fatal("a failed listing check must surface an error")
	}
	if submitted != 0 || skipped != 1 {
		t.Errorf("submitted=%d skipped=%d, want 0/1", submitted, skipped)
	}
	if n := len(cs.allEntries()); n != 0 {
		t.Errorf("unchecked URL reached the wire (%d entries)", n)
	}
	if len(rec.submitted) != 0 {
		t.Errorf("a failed check must not be recorded, got %v", rec.submitted)
	}
}

// A down lookup endpoint must not cost one timeout per candidate: stop after a
// short streak of failures. Nothing is submitted either way (every check
// failed), but the run must not hang or hammer abuse.ch.
func TestShareStopsAfterRepeatedLookupFailures(t *testing.T) {
	cs := newCaptureServer(t)
	cs.lookupStatus = http.StatusServiceUnavailable
	var cands []Candidate
	for i := 0; i < 10; i++ {
		c := goodCandidate()
		c.URL = "http://185.7.214.9/x-" + strconv.Itoa(i)
		cands = append(cands, c)
	}

	_, _, err := Share(context.Background(), newFakeRecorder(), cands, Options{
		APIKey: "k", Endpoint: cs.URL, LookupEndpoint: cs.lookupEndpoint(), LookupRateLimit: time.Millisecond, RateLimit: time.Millisecond, Now: vetNow,
	})
	if err == nil {
		t.Fatal("a failing lookup endpoint must surface an error")
	}
	if cs.lookupHits != lookupFailStreakLimit {
		t.Errorf("lookups = %d, want %d (stop at the streak limit)", cs.lookupHits, lookupFailStreakLimit)
	}
	if n := len(cs.allEntries()); n != 0 {
		t.Errorf("wire entries = %d, want 0", n)
	}
}

// A per-URL rejection is not an endpoint failure: URLhaus may not accept a URL
// in its query API, and three such candidates at the head of the newest-first
// list must not block every later one.
func TestSharePerURLRejectionDoesNotBlockLaterCandidates(t *testing.T) {
	cs := newCaptureServer(t)
	cs.lookupReject = map[string]bool{}
	var cands []Candidate
	for i := 0; i < 4; i++ {
		c := goodCandidate()
		c.URL = "http://185.7.214.9/reject-" + strconv.Itoa(i)
		cands = append(cands, c)
		cs.lookupReject[c.URL] = true
	}
	good := goodCandidate()
	good.URL = "http://185.7.214.9/bins/ok"
	cands = append(cands, good)

	submitted, skipped, err := Share(context.Background(), newFakeRecorder(), cands, Options{
		APIKey: "k", Endpoint: cs.URL, LookupEndpoint: cs.lookupEndpoint(), LookupRateLimit: time.Millisecond, RateLimit: time.Millisecond, Now: vetNow,
	})
	if err == nil {
		t.Fatal("the unchecked candidates must still be reported")
	}
	if submitted != 1 || skipped != 4 {
		t.Errorf("submitted=%d skipped=%d, want 1/4", submitted, skipped)
	}
	if cs.lookupHits != 5 {
		t.Errorf("lookups = %d, want 5 (every candidate checked)", cs.lookupHits)
	}
	entries := cs.allEntries()
	if len(entries) != 1 || entries[0].URL != good.URL {
		t.Errorf("wire entries = %+v, want only %q", entries, good.URL)
	}
}

// An endpoint outage after some checks succeeded must not throw away the
// verified queue: those URLs are known not to be listed.
func TestShareEndpointOutageStillSubmitsVerifiedQueue(t *testing.T) {
	cs := newCaptureServer(t)
	cs.lookupFailAfter = 1 // the first check succeeds, every later one is 503
	first := goodCandidate()
	first.URL = "http://185.7.214.9/first"
	rest := []Candidate{first}
	for i := 0; i < 4; i++ {
		c := goodCandidate()
		c.URL = "http://185.7.214.9/rest-" + strconv.Itoa(i)
		rest = append(rest, c)
	}

	submitted, skipped, err := Share(context.Background(), newFakeRecorder(), rest, Options{
		APIKey: "k", Endpoint: cs.URL, LookupEndpoint: cs.lookupEndpoint(), LookupRateLimit: time.Millisecond, RateLimit: time.Millisecond, Now: vetNow,
	})
	if err == nil {
		t.Fatal("the outage must be surfaced")
	}
	if submitted != 1 || skipped != lookupFailStreakLimit {
		t.Errorf("submitted=%d skipped=%d, want 1/%d", submitted, skipped, lookupFailStreakLimit)
	}
	if cs.lookupHits != 1+lookupFailStreakLimit {
		t.Errorf("lookups = %d, want %d", cs.lookupHits, 1+lookupFailStreakLimit)
	}
	entries := cs.allEntries()
	if len(entries) != 1 || entries[0].URL != first.URL {
		t.Errorf("wire entries = %+v, want the verified %q", entries, first.URL)
	}
}

// A success between failures resets the streak, so a transient blip does not
// abort a run.
func TestShareLookupFailureStreakResetsOnSuccess(t *testing.T) {
	cs := newCaptureServer(t)
	cs.lookupStatusSeq = []int{503, 503, 0, 503, 503, 0}
	var cands []Candidate
	for i := 0; i < len(cs.lookupStatusSeq); i++ {
		c := goodCandidate()
		c.URL = "http://185.7.214.9/seq-" + strconv.Itoa(i)
		cands = append(cands, c)
	}

	submitted, skipped, err := Share(context.Background(), newFakeRecorder(), cands, Options{
		APIKey: "k", Endpoint: cs.URL, LookupEndpoint: cs.lookupEndpoint(), LookupRateLimit: time.Millisecond, RateLimit: time.Millisecond, Now: vetNow,
	})
	if err == nil {
		t.Fatal("the transient failures must still be surfaced")
	}
	// Hits 1, 2, 4 and 5 failed; hits 3 and 6 cleared and were submitted. The
	// run must reach the last candidate (a streak that never reset would have
	// stopped after hit 5).
	if submitted != 2 || skipped != 4 {
		t.Errorf("submitted=%d skipped=%d, want 2/4 (the streak reset)", submitted, skipped)
	}
	if cs.lookupHits != len(cands) {
		t.Errorf("lookups = %d, want %d", cs.lookupHits, len(cands))
	}
}

// An auth failure will fail every lookup, so stop after the first rather than
// walking the whole candidate list.
func TestShareStopsOnLookupAuthFailure(t *testing.T) {
	cs := newCaptureServer(t)
	cs.lookupStatus = http.StatusUnauthorized
	one, two := goodCandidate(), goodCandidate()
	two.URL += "-second"

	_, _, err := Share(context.Background(), newFakeRecorder(), []Candidate{one, two}, Options{
		APIKey: "bad", Endpoint: cs.URL, LookupEndpoint: cs.lookupEndpoint(), LookupRateLimit: time.Millisecond, RateLimit: time.Millisecond, Now: vetNow,
	})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("error = %v, want ErrUnauthorized", err)
	}
	if cs.lookupHits != 1 {
		t.Errorf("lookups = %d, want 1 (stopped after the auth failure)", cs.lookupHits)
	}
	if n := len(cs.allEntries()); n != 0 {
		t.Errorf("batch reached the wire after an auth failure (%d entries)", n)
	}
}

// A URL URLhaus already lists costs no submission budget: it is a skip, like a
// Vet reject, and must not consume one of --limit's slots.
func TestShareAlreadyListedCostsNoSubmissionBudget(t *testing.T) {
	cs := newCaptureServer(t)
	listed := goodCandidate()
	first := goodCandidate()
	first.URL = "http://185.7.214.9/a"
	second := goodCandidate()
	second.URL = "http://185.7.214.9/b"
	cs.listed[listed.URL] = true

	var unexamined int
	submitted, skipped, err := Share(context.Background(), newFakeRecorder(), []Candidate{listed, first, second}, Options{
		APIKey: "k", Endpoint: cs.URL, LookupEndpoint: cs.lookupEndpoint(), LookupRateLimit: time.Millisecond, RateLimit: time.Millisecond, Now: vetNow,
		MaxSubmissions: 1,
		OnLimitReached: func(n int) { unexamined = n },
	})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if submitted != 1 || skipped != 1 {
		t.Errorf("submitted=%d skipped=%d, want 1/1", submitted, skipped)
	}
	if unexamined != 1 {
		t.Errorf("unexamined = %d, want 1", unexamined)
	}
	entries := cs.allEntries()
	if len(entries) != 1 || entries[0].URL != first.URL {
		t.Errorf("wire entries = %+v, want only %q", entries, first.URL)
	}
}

// Dry-run promises not to contact URLhaus, so it must not perform list checks
// either.
func TestShareDryRunMakesNoLookupRequests(t *testing.T) {
	cs := newCaptureServer(t)
	submitted, _, err := Share(context.Background(), newFakeRecorder(), []Candidate{goodCandidate()}, Options{
		Endpoint: cs.URL, LookupEndpoint: cs.lookupEndpoint(), LookupRateLimit: time.Millisecond, DryRun: true, RateLimit: time.Millisecond, Now: vetNow,
	})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if submitted != 1 {
		t.Errorf("dry-run submitted = %d, want 1", submitted)
	}
	if cs.lookupHits != 0 {
		t.Errorf("dry-run made %d lookup requests, want 0", cs.lookupHits)
	}
}

func TestShareDryRunNeverPosts(t *testing.T) {
	cs := newCaptureServer(t)
	rec := newFakeRecorder()
	submitted, _, err := Share(context.Background(), rec, []Candidate{goodCandidate()},
		Options{Endpoint: cs.URL, LookupEndpoint: cs.lookupEndpoint(), LookupRateLimit: time.Millisecond, DryRun: true, RateLimit: time.Millisecond, Now: vetNow})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if submitted != 1 {
		t.Errorf("dry-run should report 1 would-submit, got %d", submitted)
	}
	if n := len(cs.allEntries()); n != 0 {
		t.Errorf("dry-run must not POST, server saw %d entries", n)
	}
	if len(rec.submitted) != 0 {
		t.Errorf("dry-run must not record, got %v", rec.submitted)
	}
}

func TestShareRequiresAPIKeyUnlessDryRun(t *testing.T) {
	rec := newFakeRecorder()
	if _, _, err := Share(context.Background(), rec, []Candidate{goodCandidate()}, Options{}); !errors.Is(err, ErrMissingAPIKey) {
		t.Errorf("err = %v, want ErrMissingAPIKey", err)
	}
	if _, _, err := Share(context.Background(), rec, nil, Options{APIKey: "k"}); !errors.Is(err, ErrEmptyBatch) {
		t.Errorf("err = %v, want ErrEmptyBatch", err)
	}
}

// An auth failure must abort immediately rather than replay every batch
// against an endpoint that will reject all of them.
func TestShareStopsOnUnauthorized(t *testing.T) {
	cs := newCaptureServer(t)
	cs.status = http.StatusUnauthorized
	rec := newFakeRecorder()

	var cands []Candidate
	for i := 0; i < 60; i++ { // > default batch size, so >1 batch would be sent
		c := goodCandidate()
		c.URL = "http://185.7.214.3/bins/x86-" + strconv.Itoa(i)
		cands = append(cands, c)
	}
	submitted, _, err := Share(context.Background(), rec, cands,
		Options{APIKey: "bad", Endpoint: cs.URL, LookupEndpoint: cs.lookupEndpoint(), LookupRateLimit: time.Millisecond, RateLimit: time.Millisecond, Now: vetNow})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if submitted != 0 {
		t.Errorf("submitted = %d, want 0", submitted)
	}
	cs.mu.Lock()
	batches := len(cs.bodies)
	cs.mu.Unlock()
	if batches != 1 {
		t.Errorf("should stop after the first 401, sent %d batches", batches)
	}
	if len(rec.submitted) != 0 {
		t.Error("a rejected submission must not be recorded (so it retries later)")
	}
}

func TestShareBatchesLargeSets(t *testing.T) {
	cs := newCaptureServer(t)
	rec := newFakeRecorder()
	var cands []Candidate
	for i := 0; i < 55; i++ {
		c := goodCandidate()
		c.URL = "http://185.7.214.3/x-" + strconv.Itoa(i)
		cands = append(cands, c)
	}
	submitted, _, err := Share(context.Background(), rec, cands,
		Options{APIKey: "k", Endpoint: cs.URL, LookupEndpoint: cs.lookupEndpoint(), LookupRateLimit: time.Millisecond, BatchSize: 25, RateLimit: time.Millisecond, Now: vetNow})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if submitted != 55 {
		t.Errorf("submitted = %d, want 55", submitted)
	}
	cs.mu.Lock()
	batches := len(cs.bodies)
	cs.mu.Unlock()
	if batches != 3 { // 25 + 25 + 5
		t.Errorf("batches = %d, want 3", batches)
	}
	if n := len(cs.allEntries()); n != 55 {
		t.Errorf("total entries = %d, want 55", n)
	}
}

func TestSharePacesAfterFailedBatch(t *testing.T) {
	var mu sync.Mutex
	var attempts []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/lookup" {
			_, _ = w.Write([]byte("{\"query_status\":\"no_results\"}"))
			return
		}
		mu.Lock()
		attempts = append(attempts, time.Now())
		n := len(attempts)
		mu.Unlock()
		if n == 1 {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte("{\"query_status\":\"ok\"}"))
	}))
	defer srv.Close()

	one, two := goodCandidate(), goodCandidate()
	two.URL += "-second"
	_, _, err := Share(context.Background(), newFakeRecorder(), []Candidate{one, two}, Options{
		APIKey: "k", Endpoint: srv.URL, LookupEndpoint: srv.URL + "/lookup", LookupRateLimit: time.Millisecond, BatchSize: 1, RateLimit: 100 * time.Millisecond, Now: vetNow,
	})
	if err == nil {
		t.Fatal("first failed batch must be returned")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(attempts) != 2 {
		t.Fatalf("attempts=%d, want 2", len(attempts))
	}
	if gap := attempts[1].Sub(attempts[0]); gap < 80*time.Millisecond {
		t.Fatalf("failed batch was followed after %v, want configured pacing", gap)
	}
}

func TestShareCollapsesDuplicateURLs(t *testing.T) {
	cs := newCaptureServer(t)
	rec := newFakeRecorder()
	c := goodCandidate()
	submitted, skipped, err := Share(context.Background(), rec, []Candidate{c, c, c},
		Options{APIKey: "k", Endpoint: cs.URL, LookupEndpoint: cs.lookupEndpoint(), LookupRateLimit: time.Millisecond, RateLimit: time.Millisecond, Now: vetNow})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if submitted != 1 || skipped != 2 {
		t.Errorf("submitted=%d skipped=%d, want 1/2", submitted, skipped)
	}
}

func TestClientRejectsEmptyInputs(t *testing.T) {
	c := NewClient("")
	if c.endpoint != DefaultEndpoint {
		t.Errorf("endpoint = %q, want default", c.endpoint)
	}
	if _, err := c.Submit(context.Background(), "", []Entry{{URL: "http://x.tld/a"}}, false); !errors.Is(err, ErrMissingAPIKey) {
		t.Errorf("err = %v, want ErrMissingAPIKey", err)
	}
	if _, err := c.Submit(context.Background(), "k", nil, false); !errors.Is(err, ErrNoEntries) {
		t.Errorf("err = %v, want ErrNoEntries", err)
	}
}

// anonymous is a STRING on the wire ("0"/"1"), per the documented API.
func TestClientAnonymousFlagIsStringy(t *testing.T) {
	cs := newCaptureServer(t)
	c := NewClient(cs.URL)
	if _, err := c.Submit(context.Background(), "k", []Entry{{URL: "http://x.tld/a", Threat: ThreatMalwareDownload}}, true); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if got := cs.bodies[0].Anonymous; got != "1" {
		t.Errorf("anonymous = %q, want \"1\"", got)
	}
}
