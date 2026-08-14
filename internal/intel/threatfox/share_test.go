package threatfox

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// fakeRecorder is an in-memory SubmitRecorder keyed on the IOC value.
type fakeRecorder struct {
	mu        sync.Mutex
	submitted map[string]string // ioc -> status
	failOn    string            // ioc whose ThreatFoxSubmitted call errors
}

func newFakeRecorder() *fakeRecorder { return &fakeRecorder{submitted: map[string]string{}} }

func (f *fakeRecorder) ThreatFoxSubmitted(ioc string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ioc == f.failOn {
		return false, io.ErrUnexpectedEOF
	}
	_, ok := f.submitted[ioc]
	return ok, nil
}

func (f *fakeRecorder) RecordThreatFoxSubmission(ioc, iocType, malware, status string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.submitted[ioc] = status
	return nil
}

func (f *fakeRecorder) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.submitted) }

// okServer answers every submit with the confirmed success shape, counting
// how many IOCs it received. reply lets a test force duplicated/ignored.
type okServer struct {
	*httptest.Server
	mu     sync.Mutex
	iocs   []string
	mode   string // "ok" (default), "duplicate", "ignore"
	status string // override query_status (e.g. "illegal_auth_key")
}

func newOKServer(t *testing.T) *okServer {
	t.Helper()
	s := &okServer{mode: "ok"}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			IOCs []string `json:"iocs"`
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		s.mu.Lock()
		s.iocs = append(s.iocs, body.IOCs...)
		mode, status := s.mode, s.status
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if status != "" {
			_, _ = w.Write([]byte(`{"query_status":"` + status + `"}`))
			return
		}
		ok, dup, ign := "[]", "[]", "[]"
		list, _ := json.Marshal(body.IOCs)
		switch mode {
		case "duplicate":
			dup = string(list)
		case "ignore":
			ign = string(list)
		default:
			ok = string(list)
		}
		_, _ = w.Write([]byte(`{"query_status":"ok","data":{"ok":` + ok + `,"ignored":` + ign + `,"duplicated":` + dup + `,"reward":5}}`))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *okServer) received() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.iocs) }

func freshCandidate(i int) Candidate {
	c := goodCandidate()
	c.URL = "http://45.155.205." + strconv.Itoa(10+i) + "/bins/mirai.x86"
	// distinct hash per candidate so IOC dedup is per-candidate
	c.SHA256 = "aa" + strconv.Itoa(1000+i) + "c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8"
	return c
}

// TestShareSubmitsVettedCandidateIOCs: a good candidate yields 3 IOCs, all sent
// and recorded; submitted counts the CANDIDATE once.
func TestShareSubmitsVettedCandidateIOCs(t *testing.T) {
	srv := newOKServer(t)
	rec := newFakeRecorder()
	submitted, skipped, err := Share(context.Background(), rec, []Candidate{goodCandidate()}, Options{
		APIKey: "k", Endpoint: srv.URL, RateLimit: time.Millisecond, Now: vetNow,
	})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if submitted != 1 || skipped != 0 {
		t.Fatalf("submitted=%d skipped=%d, want 1/0", submitted, skipped)
	}
	if srv.received() != 3 {
		t.Errorf("server received %d IOCs, want 3 (url + ip:port + sha256)", srv.received())
	}
	if rec.count() != 3 {
		t.Errorf("recorded %d IOCs in ledger, want 3", rec.count())
	}
}

// TestShareLimitBoundsSubmissionsNotCandidates: unvettable candidates ahead of
// fresh ones must not eat the budget.
func TestShareLimitBoundsSubmissionsNotCandidates(t *testing.T) {
	srv := newOKServer(t)
	rec := newFakeRecorder()
	bad := func(i int) Candidate { c := freshCandidate(i); c.Family = "komari"; return c } // unmappable
	cands := []Candidate{
		bad(0), bad(1), bad(2),
		freshCandidate(3), freshCandidate(4), freshCandidate(5),
	}
	var limitHit int
	submitted, skipped, err := Share(context.Background(), rec, cands, Options{
		APIKey: "k", Endpoint: srv.URL, RateLimit: time.Millisecond, Now: vetNow,
		MaxSubmissions: 2,
		OnLimitReached: func(u int) { limitHit = u },
	})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if submitted != 2 {
		t.Fatalf("submitted=%d, want 2 — the 3 komari candidates must not spend the budget", submitted)
	}
	if skipped != 3 {
		t.Errorf("skipped=%d, want 3 (the unmappable-family candidates)", skipped)
	}
	if limitHit != 1 {
		t.Errorf("OnLimitReached=%d, want 1 (one fresh candidate left unexamined)", limitHit)
	}
}

// TestShareDryRunCountsPreviews: --dry-run --limit N previews N candidates and
// never touches the network.
func TestShareDryRunCountsPreviews(t *testing.T) {
	srv := newOKServer(t)
	rec := newFakeRecorder()
	cands := []Candidate{freshCandidate(0), freshCandidate(1), freshCandidate(2), freshCandidate(3)}
	previews := 0
	_, _, err := Share(context.Background(), rec, cands, Options{
		DryRun: true, RateLimit: time.Millisecond, MaxSubmissions: 2, Now: vetNow,
		OnProgress: func(_ Candidate, submitted bool, _ int, _ string) {
			if submitted {
				previews++
			}
		},
	})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if previews != 2 {
		t.Fatalf("dry-run previewed %d, want 2", previews)
	}
	if srv.received() != 0 {
		t.Errorf("dry-run hit the network (%d IOCs)", srv.received())
	}
}

// TestShareDuplicateIsRecordedNotRetried: an already-known IOC (duplicated
// array) is a success — recorded, counted as submitted.
func TestShareDuplicateIsRecordedNotRetried(t *testing.T) {
	srv := newOKServer(t)
	srv.mode = "duplicate"
	rec := newFakeRecorder()
	submitted, _, err := Share(context.Background(), rec, []Candidate{goodCandidate()}, Options{
		APIKey: "k", Endpoint: srv.URL, RateLimit: time.Millisecond, Now: vetNow,
	})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if submitted != 1 {
		t.Errorf("submitted=%d, want 1 (a duplicate is a successful contribution)", submitted)
	}
	if rec.count() != 3 {
		t.Errorf("duplicate IOCs must still be recorded so we don't re-POST them; got %d", rec.count())
	}
}

// TestShareIgnoredIsFailureNotRecorded: an `ignored` IOC (ThreatFox rejected
// it) is a failure — NOT recorded, surfaces an error.
func TestShareIgnoredIsFailureNotRecorded(t *testing.T) {
	srv := newOKServer(t)
	srv.mode = "ignore"
	rec := newFakeRecorder()
	submitted, _, err := Share(context.Background(), rec, []Candidate{goodCandidate()}, Options{
		APIKey: "k", Endpoint: srv.URL, RateLimit: time.Millisecond, Now: vetNow,
	})
	if err == nil {
		t.Error("an ignored (rejected) IOC must surface an error")
	}
	if submitted != 0 {
		t.Errorf("submitted=%d, want 0 (nothing landed)", submitted)
	}
	if rec.count() != 0 {
		t.Errorf("rejected IOCs must NOT be recorded (so a fixed run retries); got %d", rec.count())
	}
}

// TestShareAuthFailureStopsRun: an illegal auth key halts the whole run.
func TestShareAuthFailureStopsRun(t *testing.T) {
	srv := newOKServer(t)
	srv.status = "illegal_auth_key"
	rec := newFakeRecorder()
	_, _, err := Share(context.Background(), rec, []Candidate{freshCandidate(0), freshCandidate(1)}, Options{
		APIKey: "bad", Endpoint: srv.URL, RateLimit: time.Millisecond, Now: vetNow,
	})
	if err == nil {
		t.Fatal("illegal auth key must return an error")
	}
	if rec.count() != 0 {
		t.Errorf("nothing should be recorded on auth failure; got %d", rec.count())
	}
}

// TestShareZeroLimitUnbounded: 0 submits everything.
func TestShareZeroLimitUnbounded(t *testing.T) {
	srv := newOKServer(t)
	rec := newFakeRecorder()
	cands := []Candidate{freshCandidate(0), freshCandidate(1), freshCandidate(2)}
	fired := false
	submitted, _, err := Share(context.Background(), rec, cands, Options{
		APIKey: "k", Endpoint: srv.URL, RateLimit: time.Millisecond, Now: vetNow,
		MaxSubmissions: 0,
		OnLimitReached: func(int) { fired = true },
	})
	if err != nil {
		t.Fatalf("Share: %v", err)
	}
	if submitted != 3 {
		t.Errorf("submitted=%d, want 3 (unbounded)", submitted)
	}
	if fired {
		t.Error("OnLimitReached fired with no limit")
	}
}
