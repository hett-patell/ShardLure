package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func fileCaptureEvent(at time.Time, name string) *models.Event {
	return &models.Event{TS: at, Source: models.SourceCowrie, Kind: models.KindFileDown, SrcIP: "198.51.100.1", SessionID: "inert-session", ActorID: "cowrie:inert", Filename: name, Command: "https://example.test/payload", SHA256: strings.Repeat("a", 64)}
}

func TestFileCaptureDiscoveryBurstAndLateEventSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file-discovery.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	base := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	var events []*models.Event
	for i := 0; i < 1200; i++ {
		events = append(events, &models.Event{TS: base, Source: models.SourceCowrie, Kind: models.KindConnect})
	}
	for i := 0; i < 406; i++ {
		at := base.Add(time.Duration(i) * time.Second)
		if i == 405 {
			at = base.Add(-24 * time.Hour)
		}
		events = append(events, fileCaptureEvent(at, fmt.Sprintf("/cowrie/downloads/inert-%03d", i)))
	}
	if err := s.AppendEventsAndUpsertActorsAgg(events, nil); err != nil {
		t.Fatal(err)
	}
	if queued, err := s.DiscoverFileCaptures(context.Background(), 100); err != nil || queued != 0 {
		t.Fatalf("history page queued=%d err=%v", queued, err)
	}
	var cursor int64
	if err := s.db.QueryRow("SELECT offset FROM ingest_state WHERE source='capture' AND path='file-downloads-v1'").Scan(&cursor); err != nil || cursor != 100 {
		t.Fatalf("bounded cursor=%d err=%v", cursor, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	queued := 0
	for i := 0; i < 20; i++ {
		n, err := s.DiscoverFileCaptures(context.Background(), 100)
		if err != nil {
			t.Fatal(err)
		}
		queued += n
	}
	var total, distinct int
	if err := s.db.QueryRow("SELECT COUNT(*),COUNT(DISTINCT event_id) FROM capture_file_jobs").Scan(&total, &distinct); err != nil {
		t.Fatal(err)
	}
	if queued != 406 || total != 406 || distinct != 406 {
		t.Fatalf("burst lost work: queued=%d total=%d distinct=%d", queued, total, distinct)
	}
	var source, observed string
	if err := s.db.QueryRow("SELECT source_name,observed_at FROM capture_file_jobs WHERE event_id=?", events[len(events)-1].ID).Scan(&source, &observed); err != nil {
		t.Fatal(err)
	}
	if source != "inert-405" || observed != "2026-09-20T10:00:00.000000000Z" {
		t.Fatalf("late provenance changed: %q %q", source, observed)
	}
	if held, err := s.CaptureFileProtected(context.Background(), source); err != nil || !held {
		t.Fatalf("queued source not held: %v %v", held, err)
	}
}

func TestFileCaptureDiscoveryFailureRollsBackJobsAndCursor(t *testing.T) {
	s := newTestStore(t, "file-rollback.db")
	base := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	var events []*models.Event
	for i := 0; i < 405; i++ {
		events = append(events, fileCaptureEvent(base, fmt.Sprint(i)))
	}
	if err := s.AppendEventsAndUpsertActorsAgg(events, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DiscoverFileCaptures(context.Background(), 200); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("CREATE TRIGGER reject_file_job BEFORE INSERT ON capture_file_jobs WHEN NEW.event_id=202 BEGIN SELECT RAISE(ABORT,'inert failure'); END"); err != nil {
		t.Fatal(err)
	}
	if n, err := s.DiscoverFileCaptures(context.Background(), 100); err == nil || n != 0 {
		t.Fatalf("failed batch committed: %d %v", n, err)
	}
	var n, cursor int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM capture_file_jobs").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow("SELECT offset FROM ingest_state WHERE source='capture' AND path='file-downloads-v1'").Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if n != 200 || cursor != 200 {
		t.Fatalf("partial progress n=%d cursor=%d", n, cursor)
	}
	if _, err := s.db.Exec("DROP TRIGGER reject_file_job"); err != nil {
		t.Fatal(err)
	}
	if n, err := s.DiscoverFileCaptures(context.Background(), 100); err != nil || n != 100 {
		t.Fatalf("retry=%d err=%v", n, err)
	}
}

func claimedFileFixture(t *testing.T) (*Store, FileCaptureJob, time.Time) {
	t.Helper()
	s := newTestStore(t, "claimed-file.db")
	now := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	if err := s.InsertEvent(fileCaptureEvent(now.Add(-time.Hour), "inert-file")); err != nil {
		t.Fatal(err)
	}
	if n, err := s.DiscoverFileCaptures(context.Background(), 10); err != nil || n != 1 {
		t.Fatalf("discover=%d err=%v", n, err)
	}
	jobs, err := s.ClaimFileCaptures(context.Background(), now, 1, time.Minute)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim=%+v err=%v", jobs, err)
	}
	return s, jobs[0], now
}

func TestFileCaptureCompletionFencesExpiredAndReplacedLeases(t *testing.T) {
	s, old, now := claimedFileFixture(t)
	result := FileCaptureResult{Status: FileCaptureArchived, SHA256: strings.Repeat("a", 64), SizeBytes: 123, LocalPath: "/inert/evidence/payload"}
	if err := s.CompleteFileCapture(context.Background(), old, now.Add(time.Minute), result); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("expired completion=%v", err)
	}
	// Once an expiry was observed, a wall-clock rewind cannot revive that token.
	if err := s.CompleteFileCapture(context.Background(), old, now.Add(time.Second), result); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("rewind revived lease: %v", err)
	}
	jobs, err := s.ClaimFileCaptures(context.Background(), now.Add(10*time.Minute), 1, time.Minute)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("reclaim=%+v %v", jobs, err)
	}
	if jobs[0].LeaseToken <= old.LeaseToken {
		t.Fatal("lease token not advanced")
	}
	if err := s.CompleteFileCapture(context.Background(), old, now.Add(10*time.Minute+time.Second), result); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("replaced lease wrote: %v", err)
	}
	if err := s.CompleteFileCapture(context.Background(), jobs[0], now.Add(10*time.Minute+time.Second), result); err != nil {
		t.Fatal(err)
	}
	if held, err := s.CaptureFileProtected(context.Background(), old.SourceName); err != nil || held {
		t.Fatalf("terminal source remains held=%v %v", held, err)
	}
}

func TestFileCaptureBackwardClockCannotValidateOrReclaimLease(t *testing.T) {
	s, job, now := claimedFileFixture(t)
	result := FileCaptureResult{Status: FileCaptureArchived, SHA256: strings.Repeat("a", 64), SizeBytes: 1, LocalPath: "/inert/evidence/payload"}
	if err := s.CompleteFileCapture(context.Background(), job, now.Add(-time.Second), result); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("pre-claim completion=%v", err)
	}
	if jobs, err := s.ClaimFileCaptures(context.Background(), now.Add(-time.Hour), 10, time.Minute); err != nil || len(jobs) != 0 {
		t.Fatalf("backward clock reclaimed=%+v %v", jobs, err)
	}
	if err := s.CompleteFileCapture(context.Background(), job, now.Add(time.Second), result); !errors.Is(err, ErrClaimStale) {
		t.Fatalf("backward-invalidated lease revived: %v", err)
	}
}

func TestFileCaptureIndependentStoresClaimOnlyOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "independent.db")
	a, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	now := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	if err := a.InsertEvent(fileCaptureEvent(now, "shared")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DiscoverFileCaptures(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	jobs := make(chan []FileCaptureJob, 2)
	errs := make(chan error, 2)
	for _, s := range []*Store{a, b} {
		wg.Add(1)
		go func(s *Store) {
			defer wg.Done()
			<-start
			claimed, err := s.ClaimFileCaptures(context.Background(), now, 1, time.Minute)
			jobs <- claimed
			errs <- err
		}(s)
	}
	close(start)
	wg.Wait()
	close(jobs)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	n := 0
	for batch := range jobs {
		n += len(batch)
	}
	if n != 1 {
		t.Fatalf("independent stores claimed %d copies", n)
	}
}

func TestFileCaptureCompletionPreservesQuarantineProvenanceAndIsAtomic(t *testing.T) {
	s, job, now := claimedFileFixture(t)
	oldAt := now.Add(-7 * 24 * time.Hour)
	if err := s.RecordArtifact(Artifact{TS: oldAt, URL: job.DeliveryURL, Origin: "quarantine_fetch", Status: "fetched", LocalPath: "/inert/previous", SHA256: strings.Repeat("b", 64), SizeBytes: 321, LastSuccessfulFetchAt: oldAt}); err != nil {
		t.Fatal(err)
	}
	var oldTime string
	if err := s.db.QueryRow("SELECT last_successful_fetch_at FROM artifacts WHERE url=?", job.DeliveryURL).Scan(&oldTime); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("CREATE TRIGGER reject_file_artifact BEFORE INSERT ON artifacts WHEN NEW.origin='cowrie_file_download' BEGIN SELECT RAISE(ABORT,'inert failure'); END"); err != nil {
		t.Fatal(err)
	}
	result := FileCaptureResult{Status: FileCaptureArchived, LocalPath: "/inert/evidence/file", SHA256: strings.Repeat("a", 64), SizeBytes: 123}
	if err := s.CompleteFileCapture(context.Background(), job, now.Add(time.Second), result); err == nil {
		t.Fatal("job completed despite artifact failure")
	}
	var state string
	if err := s.db.QueryRow("SELECT state FROM capture_file_jobs WHERE id=?", job.ID).Scan(&state); err != nil || state != "leased" {
		t.Fatalf("partial completion state=%q %v", state, err)
	}
	if _, err := s.db.Exec("DROP TRIGGER reject_file_artifact"); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteFileCapture(context.Background(), job, now.Add(2*time.Second), result); err != nil {
		t.Fatal(err)
	}
	var oldHash, currentTime string
	if err := s.db.QueryRow("SELECT sha256,last_successful_fetch_at FROM artifacts WHERE url=?", job.DeliveryURL).Scan(&oldHash, &currentTime); err != nil {
		t.Fatal(err)
	}
	if oldHash != strings.Repeat("b", 64) || currentTime != oldTime {
		t.Fatalf("quarantine provenance overwritten: %q %q", oldHash, currentTime)
	}
	var observed, fetched string
	if err := s.db.QueryRow("SELECT first_observed_at,last_successful_fetch_at FROM artifacts WHERE url=?", "cowrie-event:"+fmt.Sprint(job.EventID)).Scan(&observed, &fetched); err != nil {
		t.Fatal(err)
	}
	if observed != "2026-09-21T09:00:00.000000000Z" || fetched != observed {
		t.Fatalf("archival fabricated remote freshness: observed=%q fetched=%q", observed, fetched)
	}
}

func TestFileCaptureDiscoveryBoundsMaximumMetadataByBytes(t *testing.T) {
	s := newTestStore(t, "file-byte-page.db")
	now := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	url := "https://example.test/" + strings.Repeat("x", 65536-len("https://example.test/"))
	name := strings.Repeat("n", 255)
	var events []*models.Event
	for i := 0; i < 80; i++ {
		e := fileCaptureEvent(now, strings.Repeat("d/", 1900)+name)
		e.Command = url
		e.SessionID = strings.Repeat("s", 1024)
		e.ActorID = "cowrie:" + strings.Repeat("a", 1017)
		events = append(events, e)
	}
	if err := s.AppendEventsAndUpsertActorsAgg(events, nil); err != nil {
		t.Fatal(err)
	}
	n, err := s.DiscoverFileCaptures(context.Background(), 1000)
	if err != nil || n <= 0 || n >= 80 {
		t.Fatalf("byte budget not enforced n=%d err=%v", n, err)
	}
	var cursor int
	if err := s.db.QueryRow("SELECT offset FROM ingest_state WHERE source='capture' AND path='file-downloads-v1'").Scan(&cursor); err != nil || cursor != n {
		t.Fatalf("page stopped without exact checkpoint: %d/%d %v", cursor, n, err)
	}
	for i := 0; i < 5; i++ {
		if _, err := s.DiscoverFileCaptures(context.Background(), 1000); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM capture_file_jobs WHERE state='pending' AND source_name=? AND delivery_url=?", name, url).Scan(&count); err != nil || count != 80 {
		t.Fatalf("maximum accepted fields were truncated/rejected: %d %v", count, err)
	}
}

func TestFileCaptureMalformedRowsProduceTerminalDiagnostics(t *testing.T) {
	s := newTestStore(t, "file-invalid.db")
	now := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	var events []*models.Event
	for _, name := range []string{"bad-time", "bad\x00name", "bad-hash", "good"} {
		events = append(events, fileCaptureEvent(now, name))
	}
	events[2].SHA256 = "private-invalid-hash"
	if err := s.AppendEventsAndUpsertActorsAgg(events, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTx(func(tx *sql.Tx) error {
		_, err := tx.Exec("UPDATE events SET ts='private-invalid-time',ts_unix_ns=NULL WHERE id=?", events[0].ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := s.DiscoverFileCaptures(context.Background(), 10); err != nil || n != 4 {
		t.Fatalf("malformed row wedged discovery: %d %v", n, err)
	}
	rows, err := s.db.Query("SELECT state,reason FROM capture_file_jobs ORDER BY event_id")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var state, reason string
		if err := rows.Scan(&state, &reason); err != nil {
			t.Fatal(err)
		}
		got = append(got, state+":"+reason)
	}
	rows.Close()
	want := []string{"rejected:invalid_timestamp", "rejected:invalid_source", "rejected:invalid_hash", "pending:"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("diagnostics=%v want=%v", got, want)
	}
	jobs, err := s.ClaimFileCaptures(context.Background(), now, 10, time.Minute)
	if err != nil || len(jobs) != 1 || jobs[0].SourceName != "good" {
		t.Fatalf("invalid row claimed: %+v %v", jobs, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.DiscoverFileCaptures(ctx, 10); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel=%v", err)
	}
}

func TestFileCaptureRetryBudgetAndSourceProtection(t *testing.T) {
	s, job, now := claimedFileFixture(t)
	for attempt := 1; attempt <= 5; attempt++ {
		if job.Attempts != attempt {
			t.Fatalf("attempt=%d want %d", job.Attempts, attempt)
		}
		if err := s.CompleteFileCapture(context.Background(), job, now.Add(time.Second), FileCaptureResult{Status: FileCaptureRetry, Reason: "missing_source"}); err != nil {
			t.Fatal(err)
		}
		if held, err := s.CaptureFileProtected(context.Background(), job.SourceName); err != nil || held != (attempt < 5) {
			t.Fatalf("attempt %d source held=%v err=%v", attempt, held, err)
		}
		now = now.Add(10 * time.Minute)
		jobs, err := s.ClaimFileCaptures(context.Background(), now, 1, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if attempt < 5 {
			if len(jobs) != 1 {
				t.Fatalf("retry disappeared: %+v", jobs)
			}
			job = jobs[0]
		} else if len(jobs) != 0 {
			t.Fatal("sixth attempt was allowed")
		}
	}
	var state, reason string
	var attempts int
	if err := s.db.QueryRow("SELECT state,reason,attempts FROM capture_file_jobs WHERE id=?", job.ID).Scan(&state, &reason, &attempts); err != nil {
		t.Fatal(err)
	}
	if state != "failed" || reason != "attempts_exhausted" || attempts != 5 {
		t.Fatalf("exhaustion=%s/%s/%d", state, reason, attempts)
	}
}

func TestCaptureDiscoveryCommandPagesBoundBytes(t *testing.T) {
	s := newTestStore(t, "command-byte-page.db")
	now := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	var events []*models.Event
	for i := 0; i < 9; i++ {
		events = append(events, &models.Event{TS: now, Source: models.SourceCowrie, Kind: models.KindCommand, Command: fmt.Sprint(i) + strings.Repeat("x", (1<<20)-1)})
	}
	if err := s.AppendEventsAndUpsertActorsAgg(events, nil); err != nil {
		t.Fatal(err)
	}
	extract := func(command string) []string { return []string{"https://example.test/" + command[:1]} }
	n, err := s.DiscoverCommandArtifacts(context.Background(), 1000, extract)
	if err != nil || n <= 0 || n >= 9 {
		t.Fatalf("command byte budget not enforced: %d %v", n, err)
	}
	var cursor int
	if err := s.db.QueryRow("SELECT offset FROM ingest_state WHERE source='capture' AND path='command-artifacts-v1'").Scan(&cursor); err != nil || cursor != n {
		t.Fatalf("command checkpoint=%d/%d %v", cursor, n, err)
	}
	for i := 0; i < 5; i++ {
		if _, err := s.DiscoverCommandArtifacts(context.Background(), 1000, extract); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM artifacts").Scan(&count); err != nil || count != 9 {
		t.Fatalf("paged commands lost: %d %v", count, err)
	}
}

func TestCaptureDiscoveryMalformedCommandHasDurableDiagnostic(t *testing.T) {
	s := newTestStore(t, "bad-command-discovery.db")
	now := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	bad := &models.Event{TS: now, Source: models.SourceCowrie, Kind: models.KindCommand, Command: "bad-time"}
	good := &models.Event{TS: now, Source: models.SourceCowrie, Kind: models.KindCommand, Command: "good"}
	if err := s.AppendEventsAndUpsertActorsAgg([]*models.Event{bad, good}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE events SET ts='private-invalid-command-time',ts_unix_ns=NULL WHERE id=?", bad.ID); err != nil {
		t.Fatal(err)
	}
	n, err := s.DiscoverCommandArtifacts(context.Background(), 10, func(cmd string) []string { return []string{"https://example.test/" + cmd} })
	if err != nil || n != 1 {
		t.Fatalf("bad command stalled later discovery: n=%d err=%v", n, err)
	}
	var reason string
	if err := s.db.QueryRow("SELECT reason FROM capture_discovery_errors WHERE event_id=?", bad.ID).Scan(&reason); err != nil || reason != "invalid_timestamp" {
		t.Fatalf("missing durable diagnostic: %q %v", reason, err)
	}
}

func TestCaptureDiscoveryCommandFanoutHasBoundedTerminalOutcome(t *testing.T) {
	s := newTestStore(t, "fanout.db")
	e := &models.Event{TS: time.Now(), Source: models.SourceCowrie, Kind: models.KindCommand, Command: "inert command"}
	if err := s.InsertEvent(e); err != nil {
		t.Fatal(err)
	}
	n, err := s.DiscoverCommandArtifacts(context.Background(), 10, func(string) []string {
		var urls []string
		for i := 0; i < 513; i++ {
			urls = append(urls, fmt.Sprintf("https://example.test/%d", i))
		}
		return urls
	})
	if err != nil || n != 0 {
		t.Fatalf("unbounded fanout partially queued: %d %v", n, err)
	}
	var reason string
	if err := s.db.QueryRow("SELECT reason FROM capture_discovery_errors WHERE event_id=?", e.ID).Scan(&reason); err != nil || reason != "too_many_urls" {
		t.Fatalf("fanout diagnostic=%q %v", reason, err)
	}
}

func TestFileCaptureMalformedQueuedMetadataDoesNotBlockOtherJobs(t *testing.T) {
	s := newTestStore(t, "bad-queued-job.db")
	now := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	for _, name := range []string{"bad", "good"} {
		if err := s.InsertEvent(fileCaptureEvent(now, name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DiscoverFileCaptures(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE capture_file_jobs SET observed_at='private-corrupt-observation' WHERE source_name='bad'"); err != nil {
		t.Fatal(err)
	}
	jobs, err := s.ClaimFileCaptures(context.Background(), now, 10, time.Minute)
	if err != nil || len(jobs) != 1 || jobs[0].SourceName != "good" {
		t.Fatalf("one bad queued row blocked others: %+v err=%v", jobs, err)
	}
	var state, reason string
	if err := s.db.QueryRow("SELECT state,reason FROM capture_file_jobs WHERE source_name='bad'").Scan(&state, &reason); err != nil || state != "rejected" || reason != "invalid_timestamp" {
		t.Fatalf("bad queued metadata not diagnosed: %q %q err=%v", state, reason, err)
	}
}

func TestFileCaptureDiscoveryPreservesLiteralNativeBasename(t *testing.T) {
	name := "literal\\name"
	if filepath.Base(name) != name {
		t.Skip("backslash is a native path separator")
	}
	s := newTestStore(t, "literal-basename.db")
	if err := s.InsertEvent(fileCaptureEvent(time.Now(), filepath.Join("downloads", name))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DiscoverFileCaptures(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	var got string
	if err := s.db.QueryRow("SELECT source_name FROM capture_file_jobs").Scan(&got); err != nil || got != name {
		t.Fatalf("source name was reinterpreted: got=%q want=%q err=%v", got, name, err)
	}
}

func TestFileCaptureExpiredFinalAttemptTerminatesAndReleasesSource(t *testing.T) {
	s, job, now := claimedFileFixture(t)
	for attempt := 2; attempt <= 5; attempt++ {
		now = now.Add(2 * time.Minute)
		jobs, err := s.ClaimFileCaptures(context.Background(), now, 1, time.Minute)
		if err != nil || len(jobs) != 1 || jobs[0].Attempts != attempt {
			t.Fatalf("expired reclaim %d=%+v err=%v", attempt, jobs, err)
		}
	}
	jobs, err := s.ClaimFileCaptures(context.Background(), now.Add(2*time.Minute), 1, time.Minute)
	if err != nil || len(jobs) != 0 {
		t.Fatalf("sixth crash retry=%+v %v", jobs, err)
	}
	if held, err := s.CaptureFileProtected(context.Background(), job.SourceName); err != nil || held {
		t.Fatalf("exhausted source held=%v %v", held, err)
	}
	var state, reason string
	if err := s.db.QueryRow("SELECT state,reason FROM capture_file_jobs WHERE id=?", job.ID).Scan(&state, &reason); err != nil || state != "failed" || reason != "attempts_exhausted" {
		t.Fatalf("crashed worker not terminal: %q %q %v", state, reason, err)
	}
}

func TestFileCaptureResultRejectsRawReasonsWithoutChangingLease(t *testing.T) {
	s, job, now := claimedFileFixture(t)
	err := s.CompleteFileCapture(context.Background(), job, now, FileCaptureResult{Status: FileCaptureRetry, Reason: "private-token-and-url"})
	if err == nil || strings.Contains(err.Error(), "private-token") {
		t.Fatalf("raw result reason accepted/leaked: %v", err)
	}
	if err := s.CompleteFileCapture(context.Background(), job, now, FileCaptureResult{Status: FileCaptureRetry, Reason: FileCaptureMissingSource}); err != nil {
		t.Fatalf("validation failure changed lease: %v", err)
	}
}

func TestFileCaptureWithoutRecordedHashDoesNotInventRemoteFetchProof(t *testing.T) {
	s := newTestStore(t, "unknown-fetch-proof.db")
	now := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	e := fileCaptureEvent(now.Add(-time.Hour), "mutable-name")
	e.SHA256 = ""
	if err := s.InsertEvent(e); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DiscoverFileCaptures(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	jobs, err := s.ClaimFileCaptures(context.Background(), now, 1, time.Minute)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim=%+v %v", jobs, err)
	}
	if err := s.CompleteFileCapture(context.Background(), jobs[0], now.Add(time.Second), FileCaptureResult{Status: FileCaptureArchived, LocalPath: "/inert/evidence/current-bytes", SHA256: strings.Repeat("b", 64), SizeBytes: 123}); err != nil {
		t.Fatal(err)
	}
	// The bytes are archived, but an unverified mutable filename cannot prove
	// that today's bytes are what the old remote fetch delivered.
	if err := s.TouchArtifactTS("cowrie-event:"+fmt.Sprint(e.ID), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BackfillArtifactTimes(context.Background(), 100); err != nil {
		t.Fatal(err)
	}
	var fetched sql.NullString
	var observed, hash string
	if err := s.db.QueryRow("SELECT last_successful_fetch_at,first_observed_at,sha256 FROM artifacts WHERE url=?", "cowrie-event:"+fmt.Sprint(e.ID)).Scan(&fetched, &observed, &hash); err != nil {
		t.Fatal(err)
	}
	if fetched.Valid || observed != "2026-09-21T09:00:00.000000000Z" || hash != strings.Repeat("b", 64) {
		t.Fatalf("invented remote proof: fetched=%+v observed=%q hash=%q", fetched, observed, hash)
	}
}

func TestCaptureDiscoveryBoundsRepeatedURLWork(t *testing.T) {
	s := newTestStore(t, "repeated-url-work.db")
	var events []*models.Event
	for i := 0; i < 10; i++ {
		events = append(events, &models.Event{TS: time.Now(), Source: models.SourceCowrie, Kind: models.KindCommand, Command: "same captured urls"})
	}
	if err := s.AppendEventsAndUpsertActorsAgg(events, nil); err != nil {
		t.Fatal(err)
	}
	var urls []string
	for i := 0; i < 512; i++ {
		urls = append(urls, fmt.Sprintf("https://example.test/%d", i))
	}
	extract := func(string) []string { return urls }
	if _, err := s.DiscoverCommandArtifacts(context.Background(), 1000, extract); err != nil {
		t.Fatal(err)
	}
	var cursor int
	if err := s.db.QueryRow("SELECT offset FROM ingest_state WHERE source='capture' AND path='command-artifacts-v1'").Scan(&cursor); err != nil || cursor <= 0 || cursor >= 10 {
		t.Fatalf("dedup hits bypassed work budget: cursor=%d err=%v", cursor, err)
	}
	for i := 0; i < 5; i++ {
		if _, err := s.DiscoverCommandArtifacts(context.Background(), 1000, extract); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM artifacts").Scan(&count); err != nil || count != 512 {
		t.Fatalf("bounded retries changed URL dedup: %d %v", count, err)
	}
}

func TestFileCaptureSourceProtectionUsesPartialIndex(t *testing.T) {
	s := newTestStore(t, "source-index.db")
	rows, err := s.db.Query("EXPLAIN QUERY PLAN "+fileCaptureProtectionQuery, "inert-source")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var a, b, c int
		var detail string
		if err := rows.Scan(&a, &b, &c, &detail); err != nil {
			t.Fatal(err)
		}
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	plan := strings.Join(details, "\n")
	if !strings.Contains(plan, "SEARCH capture_file_jobs") || !strings.Contains(plan, "idx_file_capture_source_live") || strings.Contains(plan, "SCAN capture_file_jobs") {
		t.Fatalf("source hold lookup scans queue:\n%s", plan)
	}
}

func fileUploadEvent(at time.Time, hash string) *models.Event {
	// Cowrie's upload event: filename is the attacker's name for the file,
	// url/destfile the fake-filesystem path; the bytes sit at <shasum>.
	return &models.Event{TS: at, Source: models.SourceCowrie, Kind: models.KindFileUp, SrcIP: "198.51.100.7", SessionID: "inert-upload-session", ActorID: "cowrie:inert-upload", Filename: "sshd", Command: "/bin/sshd", SHA256: hash}
}

func fileJobRow(t *testing.T, s *Store, eventID int64) (source, expected, session, srcIP, actor, state, reason string) {
	t.Helper()
	if err := s.db.QueryRow("SELECT source_name,expected_sha256,session_id,src_ip,actor_id,state,reason FROM capture_file_jobs WHERE event_id=?", eventID).Scan(&source, &expected, &session, &srcIP, &actor, &state, &reason); err != nil {
		t.Fatalf("job for event %d: %v", eventID, err)
	}
	return
}

func TestUploadDiscoveryQueuesTheContentAddressedSource(t *testing.T) {
	s := newTestStore(t, "upload-discovery.db")
	hash := strings.Repeat("b", 64)
	up := fileUploadEvent(time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC), strings.ToUpper(hash))
	// An attacker-chosen name longer than the filename bound must not reject
	// an upload: its source is the hash, so the name is never read.
	long := fileUploadEvent(up.TS, hash)
	long.Filename = strings.Repeat("n", 5000)
	if err := s.AppendEventsAndUpsertActorsAgg([]*models.Event{up, long}, nil); err != nil {
		t.Fatal(err)
	}
	if n, err := s.DiscoverFileCaptures(context.Background(), 10); err != nil || n != 2 {
		t.Fatalf("discover=%d err=%v", n, err)
	}
	for _, ev := range []*models.Event{up, long} {
		source, expected, session, srcIP, actor, state, reason := fileJobRow(t, s, ev.ID)
		if source != hash || expected != hash || state != FileCapturePending || reason != "" {
			t.Fatalf("upload job source=%q expected=%q state=%q reason=%q", source, expected, state, reason)
		}
		if session != "inert-upload-session" || srcIP != "198.51.100.7" || actor != "cowrie:inert-upload" {
			t.Fatalf("upload job lost its session binding: %q %q %q", session, srcIP, actor)
		}
	}
	if held, err := s.CaptureFileProtected(context.Background(), hash); err != nil || !held {
		t.Fatalf("queued upload source not held: %v %v", held, err)
	}
}

func TestUploadDiscoveryRejectsAnUploadWithoutAHash(t *testing.T) {
	s := newTestStore(t, "upload-nohash.db")
	for _, hash := range []string{"", "not-a-hash"} {
		if err := s.InsertEvent(fileUploadEvent(time.Now(), hash)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DiscoverFileCaptures(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	for id := int64(1); id <= 2; id++ {
		source, _, _, _, _, state, reason := fileJobRow(t, s, id)
		if source != "" || state != FileCaptureRejected || reason != FileCaptureInvalidHash {
			t.Fatalf("event %d: source=%q state=%q reason=%q", id, source, state, reason)
		}
	}
	if held, err := s.CaptureFileProtected(context.Background(), "sshd"); err != nil || held {
		t.Fatalf("the attacker's filename became a protected source: %v %v", held, err)
	}
}

func TestUploadBackfillQueuesOnlyUploadsTheOldCursorPassed(t *testing.T) {
	s := newTestStore(t, "upload-backfill.db")
	at := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	oldDown := fileCaptureEvent(at, "/cowrie/downloads/old-download")
	oldUp1 := fileUploadEvent(at, strings.Repeat("c", 64))
	oldUp2 := fileUploadEvent(at, strings.Repeat("d", 64))
	if err := s.AppendEventsAndUpsertActorsAgg([]*models.Event{oldDown, oldUp1, &models.Event{TS: at, Source: models.SourceCowrie, Kind: models.KindConnect}, oldUp2}, nil); err != nil {
		t.Fatal(err)
	}
	// A database the downloads-only discovery already walked: the cursor is
	// past all four events and the old download has its (finished) job.
	if err := s.ensureFileCaptureTable(); err != nil {
		t.Fatal(err)
	}
	stamp := captureTime(at)
	if _, err := s.db.Exec("INSERT INTO ingest_state(source,path,inode,offset,head_sig,updated_at) VALUES('capture',?,0,?,'',?)", fileCaptureDiscoveryPath, oldUp2.ID, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("INSERT INTO capture_file_jobs(event_id,source_name,state,next_attempt_at,created_at,updated_at) VALUES(?,'old-download','archived',?,?,?)", oldDown.ID, stamp, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	newUp := fileUploadEvent(at.Add(time.Hour), strings.Repeat("e", 64))
	if err := s.InsertEvent(newUp); err != nil {
		t.Fatal(err)
	}
	// The upgraded discovery pins the ceiling at the old cursor and reads on.
	if n, err := s.DiscoverFileCaptures(context.Background(), 10); err != nil || n != 1 {
		t.Fatalf("new discovery=%d err=%v", n, err)
	}
	var ceiling, progress int64
	if err := s.db.QueryRow("SELECT inode,offset FROM ingest_state WHERE source='capture' AND path=?", fileUploadBackfillPath).Scan(&ceiling, &progress); err != nil || ceiling != oldUp2.ID || progress != 0 {
		t.Fatalf("backfill row ceiling=%d progress=%d err=%v", ceiling, progress, err)
	}
	// limit 1: a full page resumes after its last row.
	if n, err := s.BackfillUploadCaptures(context.Background(), 1); err != nil || n != 1 {
		t.Fatalf("backfill page 1=%d err=%v", n, err)
	}
	if n, err := s.BackfillUploadCaptures(context.Background(), 1); err != nil || n != 1 {
		t.Fatalf("backfill page 2=%d err=%v", n, err)
	}
	if n, err := s.BackfillUploadCaptures(context.Background(), 1); err != nil || n != 0 {
		t.Fatalf("backfill page 3=%d err=%v", n, err)
	}
	if err := s.db.QueryRow("SELECT offset FROM ingest_state WHERE source='capture' AND path=?", fileUploadBackfillPath).Scan(&progress); err != nil || progress != ceiling {
		t.Fatalf("backfill did not finish: %d of %d (%v)", progress, ceiling, err)
	}
	var total, uploads int
	var downState string
	if err := s.db.QueryRow("SELECT COUNT(*),SUM(expected_sha256 IN (?,?,?)) FROM capture_file_jobs", strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64)).Scan(&total, &uploads); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow("SELECT state FROM capture_file_jobs WHERE event_id=?", oldDown.ID).Scan(&downState); err != nil {
		t.Fatal(err)
	}
	if total != 4 || uploads != 3 || downState != "archived" {
		t.Fatalf("jobs total=%d uploads=%d processed download=%q; want 4, 3, archived (never re-queued)", total, uploads, downState)
	}
	for _, ev := range []*models.Event{oldUp1, oldUp2} {
		if _, _, session, _, _, state, _ := fileJobRow(t, s, ev.ID); session != "inert-upload-session" || state != FileCapturePending {
			t.Fatalf("backfilled upload %d: session=%q state=%q", ev.ID, session, state)
		}
	}
}

func TestFreshDatabaseHasNothingToBackfill(t *testing.T) {
	s := newTestStore(t, "upload-backfill-fresh.db")
	if err := s.InsertEvent(fileUploadEvent(time.Now(), strings.Repeat("f", 64))); err != nil {
		t.Fatal(err)
	}
	if n, err := s.DiscoverFileCaptures(context.Background(), 10); err != nil || n != 1 {
		t.Fatalf("discover=%d err=%v", n, err)
	}
	if n, err := s.BackfillUploadCaptures(context.Background(), 10); err != nil || n != 0 {
		t.Fatalf("backfill=%d err=%v", n, err)
	}
}

func TestUploadBackfillHoldsSourceRetention(t *testing.T) {
	s := newTestStore(t, "upload-backfill-hold.db")
	s.SetCaptureRetentionPolicy(CaptureRetentionPolicy{FilesEnabled: true})
	if err := s.InsertEvent(fileUploadEvent(time.Now(), strings.Repeat("a", 64))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DiscoverFileCaptures(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE ingest_state SET inode=5,offset=0 WHERE source='capture' AND path=?", fileUploadBackfillPath); err != nil {
		t.Fatal(err)
	}
	removed := false
	ok, err := s.RemoveCaptureSourceIfSafe(context.Background(), strings.Repeat("9", 64), func() (bool, error) { removed = true; return true, nil })
	if err != nil || ok || removed {
		t.Fatalf("source removed while the upload backfill was pending: %v %v %v", ok, removed, err)
	}
	if _, err := s.db.Exec("UPDATE ingest_state SET offset=5 WHERE source='capture' AND path=?", fileUploadBackfillPath); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.RemoveCaptureSourceIfSafe(context.Background(), strings.Repeat("9", 64), func() (bool, error) { return true, nil }); err != nil || !ok {
		t.Fatalf("finished backfill still holds: %v %v", ok, err)
	}
}

func TestUploadMissingSourceFailsWithoutRetry(t *testing.T) {
	s := newTestStore(t, "upload-missing.db")
	now := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	up := fileUploadEvent(now.Add(-time.Hour), strings.Repeat("a", 64))
	down := fileCaptureEvent(now.Add(-time.Hour), "inert-download")
	if err := s.AppendEventsAndUpsertActorsAgg([]*models.Event{up, down}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DiscoverFileCaptures(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	jobs, err := s.ClaimFileCaptures(context.Background(), now, 2, time.Minute)
	if err != nil || len(jobs) != 2 {
		t.Fatalf("claim=%+v err=%v", jobs, err)
	}
	for _, job := range jobs {
		if err := s.CompleteFileCapture(context.Background(), job, now, FileCaptureResult{Status: FileCaptureRetry, Reason: FileCaptureMissingSource}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, _, _, state, reason := fileJobRow(t, s, up.ID); state != FileCaptureFailed || reason != FileCaptureMissingSource {
		t.Fatalf("missing upload state=%q reason=%q; want terminal failed/missing_source", state, reason)
	}
	if _, _, _, _, _, state, reason := fileJobRow(t, s, down.ID); state != FileCaptureRetry || reason != FileCaptureMissingSource {
		t.Fatalf("missing download state=%q reason=%q; want retry", state, reason)
	}
	if held, err := s.CaptureFileProtected(context.Background(), strings.Repeat("a", 64)); err != nil || held {
		t.Fatalf("failed upload still holds its source: %v %v", held, err)
	}
}

func TestUploadBackfillStartsAtTheOldestRetainedEvent(t *testing.T) {
	s := newTestStore(t, "upload-backfill-start.db")
	at := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	var events []*models.Event
	for i := 0; i < 5; i++ {
		events = append(events, &models.Event{TS: at, Source: models.SourceCowrie, Kind: models.KindConnect})
	}
	if err := s.AppendEventsAndUpsertActorsAgg(events, nil); err != nil {
		t.Fatal(err)
	}
	// Retention purged ids 1..3; the old cursor sits at the newest event.
	if _, err := s.db.Exec("DELETE FROM events WHERE id<=3"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("INSERT INTO ingest_state(source,path,inode,offset,head_sig,updated_at) VALUES('capture',?,0,5,'',?)", fileCaptureDiscoveryPath, captureTime(at)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DiscoverFileCaptures(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	var ceiling, progress int64
	if err := s.db.QueryRow("SELECT inode,offset FROM ingest_state WHERE source='capture' AND path=?", fileUploadBackfillPath).Scan(&ceiling, &progress); err != nil || ceiling != 5 || progress != 3 {
		t.Fatalf("backfill ceiling=%d progress=%d err=%v; want 5 and 3", ceiling, progress, err)
	}
}
