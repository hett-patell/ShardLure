package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestV19OpenDoesNotRewriteLegacyArtifactRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v18-schema-only.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
INSERT INTO schema_migrations VALUES(18, '2026-01-01T00:00:00Z');
CREATE TABLE artifacts (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
src_ip TEXT, session_id TEXT, actor_id TEXT, url TEXT NOT NULL UNIQUE,
local_path TEXT, sha256 TEXT, size_bytes INTEGER DEFAULT 0, origin TEXT NOT NULL,
status TEXT NOT NULL, detail TEXT, created_at TEXT NOT NULL,
attempt_count INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT);
INSERT INTO artifacts(ts,url,origin,status,created_at,attempt_count)
VALUES('2026-01-01T00:00:00Z','https://example.com/legacy','quarantine_fetch','fetched','2026-01-01T00:00:00Z',1);`)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var first sql.NullString
	if err := st.db.QueryRow(`SELECT first_observed_at FROM artifacts WHERE url='https://example.com/legacy'`).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if first.Valid {
		t.Fatalf("Open rewrote legacy artifact timestamp to %q", first.String)
	}
}

func TestArtifactBackfillQuarantinesMalformedLegacySchedules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v18-bad-schedule.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
INSERT INTO schema_migrations VALUES(18, '2026-01-01T00:00:00Z');
CREATE TABLE artifacts (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
src_ip TEXT, session_id TEXT, actor_id TEXT, url TEXT NOT NULL UNIQUE,
local_path TEXT, sha256 TEXT, size_bytes INTEGER DEFAULT 0, origin TEXT NOT NULL,
status TEXT NOT NULL, detail TEXT, created_at TEXT NOT NULL,
attempt_count INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT);
INSERT INTO artifacts(ts,url,origin,status,created_at,attempt_count,next_attempt_at) VALUES
('2026-01-01T00:00:00Z','https://example.com/failed','quarantine_fetch','failed','2026-01-01T00:00:00Z',2,'not-a-time'),
('2026-01-01T00:00:00Z','https://example.com/capturing','quarantine_fetch','capturing','2026-01-01T00:00:00Z',2,'not-a-time');`)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	result, err := st.BackfillArtifactTimes(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if result.Invalid != 2 || result.Updated != 2 || !result.Done {
		t.Fatalf("result=%+v, want two quarantined rows", result)
	}
	rows, err := st.db.Query(`SELECT status,detail FROM artifacts ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var status, detail string
		if err := rows.Scan(&status, &detail); err != nil {
			t.Fatal(err)
		}
		if status != "failed_permanently" || detail != "invalid legacy capture schedule" {
			t.Fatalf("status/detail=%q/%q", status, detail)
		}
	}
	due, err := st.DueArtifactCaptures(time.Now(), 10, 5)
	if err != nil || len(due) != 0 {
		t.Fatalf("due=%v err=%v, malformed schedules must fail closed", due, err)
	}
}

func TestPopulatedV18CaptureMigrationAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v18.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	// Actual pre-v19 artifact shape, not a current DB with a forged version.
	_, err = db.Exec(`CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
INSERT INTO schema_migrations VALUES(18, '2026-01-01T00:00:00Z');
CREATE TABLE artifacts (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
src_ip TEXT, session_id TEXT, actor_id TEXT, url TEXT NOT NULL UNIQUE,
local_path TEXT, sha256 TEXT, size_bytes INTEGER DEFAULT 0, origin TEXT NOT NULL,
status TEXT NOT NULL, detail TEXT, created_at TEXT NOT NULL,
attempt_count INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT);`)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	old := now.Add(-30 * 24 * time.Hour)
	precise := old.Add(123456789 * time.Nanosecond)
	for _, row := range []struct {
		name, status, ts, created string
		attempts                  int
		next                      any
	}{
		{"redelivered", "fetched", captureTime(now), captureTime(old), 1, nil},
		{"backfill", "fetched", captureTime(old), captureTime(now), 1, nil},
		{"precision", "fetched", captureTime(precise), captureTime(precise.Add(time.Nanosecond)), 1, nil},
		{"unknown", "fetched", "corrupt-timestamp", captureTime(now), 1, nil},
		{"lease", "capturing", captureTime(old), captureTime(old), 2, now.Add(time.Hour).Format(time.RFC3339Nano)},
		{"retry", "failed", captureTime(old), captureTime(old), 2, now.Add(-time.Minute).Format(time.RFC3339Nano)},
	} {
		_, err := db.Exec(`INSERT INTO artifacts(ts,url,sha256,size_bytes,local_path,origin,status,created_at,attempt_count,next_attempt_at) VALUES(?,?,?,128,'/fixture','quarantine_fetch',?,?,?,?)`, row.ts, "https://example.com/"+row.name, row.name, row.status, row.created, row.attempts, row.next)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for pass := 0; pass < 2; pass++ {
		st, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer st.Close()
			for {
				result, err := st.BackfillArtifactTimes(context.Background(), 2)
				if err != nil {
					t.Fatal(err)
				}
				if result.Done {
					break
				}
			}
			rows, err := st.ListRecentArtifacts(20)
			if err != nil || len(rows) != 6 {
				t.Fatalf("pass %d rows=%+v err=%v", pass, rows, err)
			}
			for _, a := range rows {
				switch a.SHA256 {
				case "redelivered", "backfill":
					if !a.LastSuccessfulFetchAt.Equal(old) || !a.FirstObservedAt.Equal(old) {
						t.Errorf("legacy freshness inflated: %+v", a)
					}
				case "precision":
					if !a.LastSuccessfulFetchAt.Equal(precise) {
						t.Errorf("legacy precision lost: %s want %s", a.LastSuccessfulFetchAt, precise)
					}
				case "unknown":
					if !a.LastSuccessfulFetchAt.IsZero() {
						t.Errorf("unknown legacy provenance became eligible: %+v", a)
					}
				}
			}
			eligible, err := st.URLhausCandidates(3, 0)
			if err != nil || len(eligible) != 0 {
				t.Errorf("migration made stale/unknown fetch eligible: %+v err=%v", eligible, err)
			}
			due, err := st.DueArtifactCaptures(now, 20, 5)
			if err != nil || len(due) != 1 || due[0] != "https://example.com/retry" {
				t.Fatalf("lease/retry migration: due=%v err=%v", due, err)
			}
			var lease, next sql.NullString
			var attempts int
			if err := st.db.QueryRow(`SELECT lease_until,next_attempt_at,attempt_count FROM artifacts WHERE sha256='lease'`).Scan(&lease, &next, &attempts); err != nil {
				t.Fatal(err)
			}
			if !lease.Valid || next.Valid || attempts != 2 {
				t.Errorf("lease=%+v next=%+v attempts=%d", lease, next, attempts)
			}
			if pass == 0 {
				if err := st.TouchArtifactTS("https://example.com/backfill", now.Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
			}
		}()
	}
}
