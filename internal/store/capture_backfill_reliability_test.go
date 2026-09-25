package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func TestReviewArtifactBackfillPreservesNewLease(t *testing.T) {
	st := captureIntegrityStore(t)
	now := time.Now().UTC()
	const u = "https://example.test/legacy"
	if _, err := st.execWrite(`INSERT INTO artifacts(ts,url,origin,status,created_at,attempt_count) VALUES(?,?,'quarantine_fetch','capturing',?,0)`, captureTime(now), u, captureTime(now)); err != nil {
		t.Fatal(err)
	}
	if err := st.ClaimArtifactCapture(u, now, now.Add(time.Hour), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := st.BackfillArtifactTimes(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	if err := st.CompleteArtifactCapture(u, 1, "fetched", "", "/inert-fixture", "sha", 128, nil); err != nil {
		t.Fatalf("new claim lost its lease during artifact backfill: %v", err)
	}
}

func TestArtifactBackfillPreservesCompletedState(t *testing.T) {
	for _, status := range []string{"fetched", "failed", "blocked", "empty", "invalid", "failed_permanently"} {
		t.Run(status, func(t *testing.T) {
			st := captureIntegrityStore(t)
			now := time.Now().UTC()
			const u = "https://example.test/completed"
			if _, err := st.execWrite(`INSERT INTO artifacts(ts,url,origin,status,created_at) VALUES(?,?,'quarantine_fetch','capturing',?)`, captureTime(now.Add(-time.Hour)), u, captureTime(now.Add(-time.Hour))); err != nil {
				t.Fatal(err)
			}
			if err := st.ClaimArtifactCapture(u, now, now.Add(time.Hour), 0); err != nil {
				t.Fatal(err)
			}
			if err := st.CompleteArtifactCapture(u, 1, status, "current result", "/inert-current", "current", 256, nil); err != nil {
				t.Fatal(err)
			}
			// A new binary may complete a legacy row before the background repair.
			// Keep this case even if Claim starts repairing observations itself.
			if _, err := st.execWrite(`UPDATE artifacts SET first_observed_at=NULL,last_seen_at=NULL WHERE url=?`, u); err != nil {
				t.Fatal(err)
			}
			before := artifactCaptureState(t, st, u)
			if _, err := st.BackfillArtifactTimes(context.Background(), 10); err != nil {
				t.Fatal(err)
			}
			if after := artifactCaptureState(t, st, u); !reflect.DeepEqual(after, before) {
				t.Fatalf("completed capture changed: before=%v after=%v", before, after)
			}
		})
	}
}

func TestArtifactBackfillPreservesLiveModernLeaseWithMissingObservations(t *testing.T) {
	st := captureIntegrityStore(t)
	now := time.Now().UTC()
	const u = "https://example.test/live-legacy"
	if _, err := st.execWrite(`INSERT INTO artifacts(ts,url,origin,status,created_at,attempt_count,last_fetch_attempt_at,lease_until) VALUES(?,?,'quarantine_fetch','capturing',?,1,?,?)`, captureTime(now.Add(-time.Hour)), u, captureTime(now.Add(-time.Hour)), captureTime(now), captureTime(now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	before := artifactCaptureState(t, st, u)
	if _, err := st.BackfillArtifactTimes(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	if after := artifactCaptureState(t, st, u); !reflect.DeepEqual(after, before) {
		t.Fatalf("live capture changed: before=%v after=%v", before, after)
	}
	if err := st.CompleteArtifactCapture(u, 1, "fetched", "", "/inert", "sha", 128, nil); err != nil {
		t.Fatal(err)
	}
}

func artifactCaptureState(t *testing.T, st *Store, url string) []any {
	t.Helper()
	const columns = `status,detail,local_path,sha256,size_bytes,attempt_count,next_attempt_at,lease_until,last_fetch_attempt_at,last_successful_fetch_at`
	values := make([]any, 10)
	dest := make([]any, len(values))
	for i := range values {
		dest[i] = &values[i]
	}
	if err := st.db.QueryRow(`SELECT `+columns+` FROM artifacts WHERE url=?`, url).Scan(dest...); err != nil {
		t.Fatal(err)
	}
	return values
}

func TestArtifactBackfillRepairsPastOldCursorAndResumes(t *testing.T) {
	st := captureIntegrityStore(t)
	for i := 1; i <= 3; i++ {
		if _, err := st.execWrite(`INSERT INTO artifacts(ts,url,origin,status,created_at,last_seen_at) VALUES('2026-01-02T00:00:00Z',?,'quarantine_fetch','fetched','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z')`, fmt.Sprintf("https://example.test/skipped-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.execWrite(`INSERT INTO ingest_state(source,path,inode,offset,head_sig,updated_at) VALUES('migration','artifacts-v19',0,999,'','2026-01-02T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		result, err := st.BackfillArtifactTimes(context.Background(), 1)
		if err != nil || result.Scanned != 1 || result.Updated != 1 || result.Done {
			t.Fatalf("batch %d: result=%+v err=%v", i, result, err)
		}
	}
	result, err := st.BackfillArtifactTimes(context.Background(), 1)
	if err != nil || result.Scanned != 0 || result.Updated != 0 || !result.Done {
		t.Fatalf("finished repair: result=%+v err=%v", result, err)
	}
	var repaired int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM artifacts WHERE first_observed_at='2026-01-01T00:00:00.000000000Z' AND last_successful_fetch_at='2026-01-01T00:00:00.000000000Z'`).Scan(&repaired); err != nil || repaired != 3 {
		t.Fatalf("repaired=%d err=%v", repaired, err)
	}
}

func TestArtifactTouchBeforeBackfillPreservesSourceProvenance(t *testing.T) {
	for _, discovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("discovery=%t", discovery), func(t *testing.T) {
			st := captureIntegrityStore(t)
			const u = "https://example.test/imported"
			// An imported source predates registration. Touch must preserve the
			// original ts before replacing it with a new observation.
			if _, err := st.execWrite(`INSERT INTO artifacts(ts,url,origin,status,created_at,attempt_count) VALUES('2026-01-01T00:00:00Z',?,'quarantine_fetch','fetched','2026-01-10T00:00:00Z',1)`, u); err != nil {
				t.Fatal(err)
			}
			seen := time.Date(2026, 9, 20, 0, 0, 0, 123456789, time.UTC)
			if discovery {
				if err := st.InsertEvent(&models.Event{TS: seen, Source: models.SourceCowrie, Kind: models.KindCommand, Command: "wget " + u}); err != nil {
					t.Fatal(err)
				}
				if _, err := st.DiscoverCommandArtifacts(context.Background(), 10, func(string) []string { return []string{u} }); err != nil {
					t.Fatal(err)
				}
			} else if err := st.TouchArtifactTS(u, seen); err != nil {
				t.Fatal(err)
			}
			if _, err := st.BackfillArtifactTimes(context.Background(), 10); err != nil {
				t.Fatal(err)
			}
			var first, fetched, last string
			if err := st.db.QueryRow(`SELECT COALESCE(first_observed_at,''),COALESCE(last_successful_fetch_at,''),last_seen_at FROM artifacts WHERE url=?`, u).Scan(&first, &fetched, &last); err != nil {
				t.Fatal(err)
			}
			if first != "2026-01-01T00:00:00.000000000Z" || fetched != first || last != "2026-09-20T00:00:00.123456789Z" {
				t.Fatalf("first=%q fetched=%q last=%q", first, fetched, last)
			}
		})
	}
}

func TestArtifactBackfillConcurrentTouchesAndClaims(t *testing.T) {
	st := captureIntegrityStore(t)
	now := time.Now().UTC()
	const count = 24
	for i := 0; i < count; i++ {
		if _, err := st.execWrite(`INSERT INTO artifacts(ts,url,origin,status,created_at) VALUES(?,?,'quarantine_fetch','capturing',?)`, captureTime(now.Add(-time.Hour)), fmt.Sprintf("https://example.test/concurrent-%d", i), captureTime(now.Add(-time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, count+2)
	start := make(chan struct{})
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			u := fmt.Sprintf("https://example.test/concurrent-%d", i)
			if err := st.ClaimArtifactCapture(u, now, now.Add(time.Hour), 0); err != nil {
				errs <- err
				return
			}
			if err := st.TouchArtifactTS(u, now.Add(time.Minute)); err != nil {
				errs <- err
				return
			}
			errs <- st.CompleteArtifactCapture(u, 1, "fetched", "current", "/inert", "sha", 128, nil)
		}(i)
	}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for {
				result, err := st.BackfillArtifactTimes(context.Background(), 1)
				if err != nil || result.Done {
					errs <- err
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	var intact int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM artifacts WHERE status='fetched' AND attempt_count=1 AND lease_until IS NULL AND last_seen_at=? AND last_successful_fetch_at>=? AND first_observed_at=?`, captureTime(now.Add(time.Minute)), captureTime(now), captureTime(now.Add(-time.Hour))).Scan(&intact); err != nil || intact != count {
		t.Fatalf("intact captures=%d want=%d err=%v", intact, count, err)
	}
}

func TestArtifactBackfillBoundsSparsePagesAndAdvancesPastInvalidRows(t *testing.T) {
	st := captureIntegrityStore(t)
	if err := st.WithTx(func(tx *sql.Tx) error {
		for i := 1; i <= 501; i++ {
			if _, err := tx.Exec(`INSERT INTO artifacts(id,ts,url,origin,status,created_at,first_observed_at,last_seen_at) VALUES(?,'2026-01-01T00:00:00Z',?,'quarantine_fetch','pending','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`, i, fmt.Sprintf("row-%d", i)); err != nil {
				return err
			}
		}
		_, err := tx.Exec(`UPDATE artifacts SET ts='malformed',first_observed_at=NULL,last_seen_at=NULL WHERE id=250;
UPDATE artifacts SET first_observed_at=NULL,last_seen_at=NULL WHERE id=501`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	first, err := st.BackfillArtifactTimes(context.Background(), 1000000)
	if err != nil || first.Scanned != 500 || first.Updated != 1 || first.Invalid != 1 || first.Done {
		t.Fatalf("bounded page=%+v err=%v", first, err)
	}
	second, err := st.BackfillArtifactTimes(context.Background(), 1000000)
	if err != nil || second.Scanned != 1 || second.Updated != 1 || second.Invalid != 0 || !second.Done {
		t.Fatalf("resumed page=%+v err=%v", second, err)
	}
	third, err := st.BackfillArtifactTimes(context.Background(), 1000000)
	if err != nil || third.Scanned != 0 || third.Updated != 0 || !third.Done {
		t.Fatalf("finished page=%+v err=%v", third, err)
	}
}

func TestArtifactTouchMalformedLegacyObservationDoesNotInventFetch(t *testing.T) {
	for _, discovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("discovery=%t", discovery), func(t *testing.T) {
			st := captureIntegrityStore(t)
			const u = "https://example.test/unknown-observation"
			if _, err := st.execWrite(`INSERT INTO artifacts(ts,url,origin,status,created_at) VALUES('private-malformed-source',?,'quarantine_fetch','fetched','2026-09-01T00:00:00Z')`, u); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			if discovery {
				if err := st.InsertEvent(&models.Event{TS: now, Source: models.SourceCowrie, Kind: models.KindCommand, Command: "wget " + u}); err != nil {
					t.Fatal(err)
				}
				if _, err := st.DiscoverCommandArtifacts(context.Background(), 10, func(string) []string { return []string{u} }); err != nil {
					t.Fatal(err)
				}
			} else if err := st.TouchArtifactTS(u, now); err != nil {
				t.Fatal(err)
			}
			if _, err := st.BackfillArtifactTimes(context.Background(), 10); err != nil {
				t.Fatal(err)
			}
			var fetched sql.NullString
			var seen string
			if err := st.db.QueryRow(`SELECT last_successful_fetch_at,last_seen_at FROM artifacts WHERE url=?`, u).Scan(&fetched, &seen); err != nil {
				t.Fatal(err)
			}
			if fetched.Valid || seen != captureTime(now) {
				t.Fatalf("unknown fetch=%v observed=%q", fetched, seen)
			}
		})
	}
}

func TestArtifactBackfillRollsBackRepairAndCursor(t *testing.T) {
	st := captureIntegrityStore(t)
	if _, err := st.execWrite(`INSERT INTO artifacts(ts,url,origin,status,created_at) VALUES
('2026-01-01T00:00:00Z','first','quarantine_fetch','fetched','2026-01-01T00:00:00Z'),
('2026-01-01T00:00:00Z','second','quarantine_fetch','fetched','2026-01-01T00:00:00Z');
CREATE TRIGGER reject_artifact_repair BEFORE UPDATE ON artifacts WHEN NEW.url='second' BEGIN SELECT RAISE(ABORT,'injected private evidence'); END;`); err != nil {
		t.Fatal(err)
	}
	if result, err := st.BackfillArtifactTimes(context.Background(), 10); err == nil || result != (ArtifactTimeBackfillResult{}) {
		t.Fatalf("failed repair: result=%+v err=%v", result, err)
	} else if strings.Contains(err.Error(), "private evidence") {
		t.Fatalf("backfill error exposed database evidence: %v", err)
	}
	var repaired int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM artifacts WHERE first_observed_at IS NOT NULL`).Scan(&repaired); err != nil || repaired != 0 {
		t.Fatalf("partial batch committed: count=%d err=%v", repaired, err)
	}
	if _, err := st.execWrite(`DROP TRIGGER reject_artifact_repair`); err != nil {
		t.Fatal(err)
	}
	if result, err := st.BackfillArtifactTimes(context.Background(), 10); err != nil || result.Updated != 2 {
		t.Fatalf("retry: result=%+v err=%v", result, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := st.BackfillArtifactTimes(ctx, 10); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation = %v", err)
	}
}

func TestCaptureMalformedLegacyScheduleFailsClosedBeforeBackfill(t *testing.T) {
	for _, schedule := range []string{"not-a-time", "2000-01-01", "2000-01-01T00:00:00Z-secret"} {
		t.Run(schedule, func(t *testing.T) {
			st := captureIntegrityStore(t)
			const u = "https://example.test/malformed"
			if _, err := st.execWrite(`INSERT INTO artifacts(ts,url,origin,status,created_at,attempt_count,next_attempt_at) VALUES('2026-01-01T00:00:00Z',?,'quarantine_fetch','failed','2026-01-01T00:00:00Z',1,?)`, u, schedule); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			if err := st.ClaimArtifactCapture(u, now, now.Add(time.Hour), 1); !errors.Is(err, ErrClaimStale) {
				t.Fatalf("malformed schedule claimed: %v", err)
			}
			if _, err := st.BackfillArtifactTimes(context.Background(), 10); err != nil {
				t.Fatal(err)
			}
			var status, detail string
			var attempts int
			var next sql.NullString
			if err := st.db.QueryRow(`SELECT status,detail,attempt_count,next_attempt_at FROM artifacts WHERE url=?`, u).Scan(&status, &detail, &attempts, &next); err != nil {
				t.Fatal(err)
			}
			if status != "failed_permanently" || detail != "invalid legacy capture schedule" || attempts != 1 || next.Valid {
				t.Fatalf("status=%q detail=%q attempts=%d next=%v", status, detail, attempts, next)
			}
		})
	}
}

func TestReviewTouchedLegacyArtifactStillBackfills(t *testing.T) {
	st := captureIntegrityStore(t)
	now := time.Now().UTC()
	old := now.Add(-time.Hour)
	const u = "https://example.test/reobserved"
	if _, err := st.execWrite(`INSERT INTO artifacts(ts,url,origin,status,created_at,attempt_count,local_path,sha256,size_bytes) VALUES(?,?,'quarantine_fetch','fetched',?,1,'/inert-fixture','inert',128)`, old.Format(time.RFC3339Nano), u, old.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := st.TouchArtifactTS(u, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.BackfillArtifactTimes(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	var fetched string
	if err := st.db.QueryRow(`SELECT COALESCE(last_successful_fetch_at,'') FROM artifacts WHERE url=?`, u).Scan(&fetched); err != nil {
		t.Fatal(err)
	}
	if fetched != captureTime(old) {
		t.Fatalf("fetch provenance = %q; want original observation %q", fetched, captureTime(old))
	}
}

func TestReviewLegacyCaptureBudgetHonorsOldLease(t *testing.T) {
	st := captureIntegrityStore(t)
	now := time.Now().UTC()
	const u = "https://example.test/leased"
	if _, err := st.execWrite(`INSERT INTO artifacts(ts,url,origin,status,created_at,attempt_count,next_attempt_at) VALUES(?,?,'quarantine_fetch','capturing',?,5,?)`, captureTime(now), u, captureTime(now), captureTime(now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DueArtifactCaptures(now, 1, 5); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := st.db.QueryRow(`SELECT status FROM artifacts WHERE url=?`, u).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "capturing" {
		t.Fatalf("active pre-v19 lease was terminated as %q before migration", status)
	}
	if _, err := st.DueArtifactCaptures(now.Add(2*time.Hour), 1, 5); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRow(`SELECT status FROM artifacts WHERE url=?`, u).Scan(&status); err != nil || status != "failed_permanently" {
		t.Fatalf("expired legacy lease: status=%q err=%v", status, err)
	}
}
