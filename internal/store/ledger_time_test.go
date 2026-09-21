package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLedgerV22PreservesLegacyDataAndOptionalTables(t *testing.T) {
	for _, optional := range []bool{false, true} {
		t.Run(fmt.Sprint(optional), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "legacy.db")
			s, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.Exec(`DROP TABLE bazaar_uploads; DROP TABLE urlhaus_submissions; DROP TABLE threatfox_submissions;
DELETE FROM schema_migrations WHERE version>=22;
CREATE TABLE bazaar_uploads(sha256 TEXT PRIMARY KEY, uploaded_at TEXT NOT NULL, response_status TEXT NOT NULL, mb_url TEXT);
INSERT INTO bazaar_uploads VALUES('old-sample','2026-09-21T11:00:00+01:00','file_already_known','https://example.test/bazaar');`)
			if err != nil {
				t.Fatal(err)
			}
			if optional {
				_, err = db.Exec(`CREATE TABLE urlhaus_submissions(url TEXT PRIMARY KEY, submitted_at TEXT NOT NULL, status TEXT NOT NULL);
INSERT INTO urlhaus_submissions VALUES('old-url','2026-09-21T10:00:00.5000Z','ok');
CREATE TABLE threatfox_submissions(ioc TEXT PRIMARY KEY,ioc_type TEXT NOT NULL,malware TEXT NOT NULL,submitted_at TEXT NOT NULL,status TEXT NOT NULL);
INSERT INTO threatfox_submissions VALUES('old-ioc','url','elf.mirai','2026-09-21T10:00:00.5Z','duplicated');`)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			var raw string
			var key sql.NullString
			if err := s.db.QueryRow("SELECT uploaded_at,uploaded_at_key FROM bazaar_uploads").Scan(&raw, &key); err != nil {
				t.Fatal(err)
			}
			if raw != "2026-09-21T11:00:00+01:00" || key.Valid {
				t.Fatalf("Open rewrote historical data: %q %+v", raw, key)
			}
			for _, f := range ledgerFixtures() {
				rows, err := f.list(s, 0)
				if err != nil {
					t.Fatal(err)
				}
				want := 0
				if optional || f.name == "bazaar" {
					want = 1
				}
				if len(rows) != want {
					t.Fatalf("%s rows=%v want %d", f.name, rows, want)
				}
				for _, id := range rows {
					if yes, err := f.recorded(s, id); err != nil || !yes {
						t.Fatalf("lost %s dedup=%v err=%v", f.name, yes, err)
					}
				}
			}
			for {
				r, err := s.BackfillLedgerTimes(context.Background(), 1)
				if err != nil {
					t.Fatal(err)
				}
				if r.Done {
					break
				}
			}
			if err := s.db.QueryRow("SELECT uploaded_at,uploaded_at_key FROM bazaar_uploads").Scan(&raw, &key); err != nil {
				t.Fatal(err)
			}
			if raw != "2026-09-21T11:00:00+01:00" || key.String != "2026-09-21T10:00:00.000000000Z" {
				t.Fatalf("repair raw=%q key=%+v", raw, key)
			}
			rows, err := s.ListBazaarUploads(0)
			if err != nil || len(rows) != 1 || rows[0].ResponseStatus != "file_already_known" || rows[0].MBURL != "https://example.test/bazaar" {
				t.Fatalf("metadata changed: %+v err=%v", rows, err)
			}
		})
	}
}

func TestLedgerMixedFormatsAndBoundedRepairRestart(t *testing.T) {
	for _, f := range ledgerFixtures() {
		t.Run(f.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "restart.db")
			s, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { s.Close() }()
			base := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
			fixtures := []struct{ id, raw string }{
				{"whole", "2026-09-21T10:00:00Z"},
				{"f1", "2026-09-21T10:00:00.1Z"}, {"f2", "2026-09-21T10:00:00.12Z"},
				{"f3", "2026-09-21T10:00:00.123Z"}, {"f4", "2026-09-21T10:00:00.1234Z"},
				{"f5", "2026-09-21T10:00:00.12345Z"}, {"f6", "2026-09-21T10:00:00.123456Z"},
				{"f7", "2026-09-21T10:00:00.1234567Z"}, {"f8", "2026-09-21T10:00:00.12345678Z"},
				{"f9", "2026-09-21T10:00:00.123456789Z"},
				{"offset-a", "2026-09-21T04:00:00.5-06:00"}, {"offset-b", "2026-09-21T11:00:00.500000000+01:00"},
				{"nano", "2026-09-21T10:00:00.500000001Z"},
			}
			for i, row := range fixtures {
				at, err := time.Parse(time.RFC3339Nano, row.raw)
				if err != nil {
					t.Fatal(err)
				}
				if err := f.record(s, row.id, at); err != nil {
					t.Fatal(err)
				}
				if i%2 == 0 {
					if _, err := s.db.Exec("UPDATE "+f.table+" SET "+f.timestamp+"=?,"+f.timestamp+"_key=NULL WHERE "+f.primary+"=?", row.raw, row.id); err != nil {
						t.Fatal(err)
					}
				}
			}
			want := []string{"nano", "offset-a", "offset-b", "f9", "f8", "f7", "f6", "f5", "f4", "f3", "f2", "f1", "whole"}
			check := func() {
				t.Helper()
				rows, err := f.list(s, 0)
				if err != nil || !reflect.DeepEqual(rows, want) {
					t.Fatalf("order=%v err=%v", rows, err)
				}
				n, last, err := f.stats(s)
				if err != nil || n != 13 || !last.Equal(base.Add(500000001)) {
					t.Fatalf("stats=%d %s err=%v", n, last, err)
				}
			}
			check()
			first, err := s.BackfillLedgerTimes(context.Background(), 2)
			if err != nil || first.Scanned != 2 || first.Updated != 1 || first.Done {
				t.Fatalf("first=%+v err=%v", first, err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = Open(path)
			if err != nil {
				t.Fatal(err)
			}
			check()
			for attempts := 0; ; attempts++ {
				if attempts > 20 {
					t.Fatal("repair did not finish")
				}
				r, err := s.BackfillLedgerTimes(context.Background(), 2)
				if err != nil || r.Scanned > 2 || r.Invalid != 0 {
					t.Fatalf("batch=%+v err=%v", r, err)
				}
				check()
				if r.Done {
					break
				}
			}
			var missing int
			if err := s.db.QueryRow("SELECT COUNT(*) FROM " + f.table + " WHERE " + f.timestamp + "_key IS NULL").Scan(&missing); err != nil || missing != 0 {
				t.Fatalf("missing=%d err=%v", missing, err)
			}
			for _, row := range fixtures {
				if yes, err := f.recorded(s, row.id); err != nil || !yes {
					t.Fatalf("dedup %s=%v err=%v", row.id, yes, err)
				}
			}
			// An old writer changes an already-visited row without knowing keys.
			if _, err := s.db.Exec("PRAGMA recursive_triggers=ON; UPDATE " + f.table + " SET " + f.timestamp + "='2026-09-21T10:00:02Z' WHERE " + f.primary + "='whole'"); err != nil {
				t.Fatal(err)
			}
			rows, err := f.list(s, 1)
			if err != nil || !reflect.DeepEqual(rows, []string{"whole"}) {
				t.Fatalf("stale key after old write: %v %v", rows, err)
			}
			for {
				r, err := s.BackfillLedgerTimes(context.Background(), 2)
				if err != nil {
					t.Fatal(err)
				}
				if r.Done {
					break
				}
			}
			var key string
			if err := s.db.QueryRow("SELECT " + f.timestamp + "_key FROM " + f.table + " WHERE " + f.primary + "='whole'").Scan(&key); err != nil || key != "2026-09-21T10:00:02.000000000Z" {
				t.Fatalf("revisit key=%q err=%v", key, err)
			}
		})
	}
}

func TestLedgerRepairInvalidRowsAdvanceAndRemainRecorded(t *testing.T) {
	for _, f := range ledgerFixtures() {
		t.Run(f.name, func(t *testing.T) {
			s := newTestStore(t, "invalid-repair.db")
			for _, id := range []string{"bad", "good"} {
				if err := f.record(s, id, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.db.Exec("UPDATE " + f.table + " SET " + f.timestamp + "_key=NULL," + f.timestamp + "=CASE WHEN " + f.primary + "='bad' THEN '!private-value' ELSE '2026-09-21T10:00:00Z' END"); err != nil {
				t.Fatal(err)
			}
			r, err := s.BackfillLedgerTimes(context.Background(), 1)
			if err != nil || r.Invalid != 1 || r.Updated != 0 || r.Scanned != 1 {
				t.Fatalf("invalid=%+v err=%v", r, err)
			}
			r, err = s.BackfillLedgerTimes(context.Background(), 1)
			if err != nil || r.Invalid != 0 || r.Updated != 1 || r.Scanned != 1 {
				t.Fatalf("next=%+v err=%v", r, err)
			}
			r, err = s.BackfillLedgerTimes(context.Background(), 1)
			if err != nil || !r.Done || r.Scanned != 0 {
				t.Fatalf("done=%+v err=%v", r, err)
			}
			var raw string
			var key sql.NullString
			if err := s.db.QueryRow("SELECT "+f.timestamp+","+f.timestamp+"_key FROM "+f.table+" WHERE "+f.primary+"='bad'").Scan(&raw, &key); err != nil {
				t.Fatal(err)
			}
			if raw != "!private-value" || key.Valid {
				t.Fatalf("invalid data changed: %q %+v", raw, key)
			}
			if yes, err := f.recorded(s, "bad"); err != nil || !yes {
				t.Fatalf("invalid row resubmits: %v %v", yes, err)
			}
			if _, err := f.list(s, 1); err == nil || strings.Contains(err.Error(), "private-value") {
				t.Fatalf("read=%v", err)
			}
			if _, err := s.db.Exec("UPDATE " + f.table + " SET " + f.timestamp + "='2026-09-21T10:00:01Z' WHERE " + f.primary + "='bad'"); err != nil {
				t.Fatal(err)
			}
			r, err = s.BackfillLedgerTimes(context.Background(), 1)
			if err != nil || r.Updated != 1 {
				t.Fatalf("corrected=%+v err=%v", r, err)
			}
		})
	}
}

func TestLedgerRepairRollsBackKeysAndCursor(t *testing.T) {
	s := newTestStore(t, "rollback.db")
	for _, id := range []string{"a", "b"} {
		if err := s.RecordURLhausSubmission(id, "ok", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec(`UPDATE urlhaus_submissions SET submitted_at_key=NULL;
CREATE TRIGGER reject_repair BEFORE UPDATE OF submitted_at_key ON urlhaus_submissions WHEN NEW.url='b' AND NEW.submitted_at_key IS NOT NULL BEGIN SELECT RAISE(ABORT,'private-database-error'); END;`); err != nil {
		t.Fatal(err)
	}
	r, err := s.BackfillLedgerTimes(context.Background(), 10)
	if err == nil || strings.Contains(err.Error(), "private-database-error") || r.Scanned != 0 || r.Updated != 0 {
		t.Fatalf("failed batch=%+v err=%v", r, err)
	}
	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM urlhaus_submissions WHERE submitted_at_key IS NOT NULL").Scan(&n); err != nil || n != 0 {
		t.Fatalf("partial keys=%d err=%v", n, err)
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM ingest_state WHERE source='migration' AND path LIKE 'ledger-%'").Scan(&n); err != nil || n != 0 {
		t.Fatalf("partial cursor=%d err=%v", n, err)
	}
	if _, err := s.db.Exec("DROP TRIGGER reject_repair"); err != nil {
		t.Fatal(err)
	}
	r, err = s.BackfillLedgerTimes(context.Background(), 10)
	if err != nil || r.Updated != 2 || !r.Done {
		t.Fatalf("retry=%+v err=%v", r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.BackfillLedgerTimes(ctx, 10); err != context.Canceled {
		t.Fatalf("cancel=%v", err)
	}
}

func TestLedgerRepairConcurrentWrites(t *testing.T) {
	s := newTestStore(t, "concurrent.db")
	base := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 30; i++ {
		if err := s.RecordURLhausSubmission(fmt.Sprintf("old-%02d", i), "ok", base); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec("UPDATE urlhaus_submissions SET submitted_at_key=NULL"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			if err := s.RecordURLhausSubmission(fmt.Sprintf("old-%02d", i), "updated", base.Add(time.Second)); err != nil {
				errs <- err
				return
			}
			if err := s.RecordURLhausSubmission(fmt.Sprintf("new-%02d", i), "ok", base.Add(2*time.Second)); err != nil {
				errs <- err
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			r, err := s.BackfillLedgerTimes(context.Background(), 3)
			if err != nil {
				errs <- err
				return
			}
			if r.Done {
				return
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	rows, err := s.ListURLhausSubmissions(0)
	if err != nil || len(rows) != 60 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	for _, r := range rows {
		want := base.Add(2 * time.Second)
		if strings.HasPrefix(r.URL, "old-") {
			want = base.Add(time.Second)
			if r.Status != "updated" {
				t.Fatal("status overwritten")
			}
		}
		if !r.SubmittedAt.Equal(want) {
			t.Fatalf("overwritten time: %+v", r)
		}
	}
}

func TestLedgerTimeScalarStrictAndSanitized(t *testing.T) {
	s := newTestStore(t, "scalar.db")
	for _, row := range []struct {
		raw  any
		want string
	}{
		{"2026-09-21T10:00:00Z", "2026-09-21T10:00:00.000000000Z"},
		{"2026-09-21T11:00:00.000000001+01:00", "2026-09-21T10:00:00.000000001Z"},
		{"0000-01-01T00:00:00Z", "0000-01-01T00:00:00.000000000Z"},
		{"9999-12-31T23:59:59.999999999Z", "9999-12-31T23:59:59.999999999Z"},
		{nil, ""}, {12, ""}, {"", ""}, {"private-invalid-value", ""},
		{"2026-09-21T10:00:00.1234567891Z", ""},
		{"2026-09-21T10:00:00,5Z", ""},
		{"2026-09-21T1:00:00Z", ""},
		{"2026-09-21T10:00:00+24:00", ""},
		{"2026-09-21T10:00:00+01:60", ""},
		{"0000-01-01T00:00:00+01:00", ""},
		{"9999-12-31T23:59:59-01:00", ""},
	} {
		var got string
		err := s.db.QueryRow("SELECT shardlure_time_key(?)", row.raw).Scan(&got)
		if row.want != "" {
			if err != nil || got != row.want {
				t.Errorf("valid raw=%v got=%q err=%v", row.raw, got, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("accepted unsupported time %v: %q", row.raw, got)
		} else if strings.Contains(err.Error(), "private-invalid-value") {
			t.Fatalf("raw timestamp leaked: %v", err)
		}
	}
}

func TestLedgerInvalidNativeKeyFailsRatherThanReportingWrongOrder(t *testing.T) {
	for _, f := range ledgerFixtures() {
		t.Run(f.name, func(t *testing.T) {
			s := newTestStore(t, "invalid-key.db")
			if err := f.record(s, "recorded", time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"!private-corrupt-key", "2026-09-21T10:00:00Z", "2026-09-21T10:00:01.000000000Z"} {
				if _, err := s.db.Exec("UPDATE "+f.table+" SET "+f.timestamp+"_key=?", key); err != nil {
					t.Fatal(err)
				}
				if _, err := f.list(s, 1); err == nil || strings.Contains(err.Error(), "private-corrupt-key") {
					t.Errorf("key %q list error=%v", key, err)
				}
				if _, _, err := f.stats(s); err == nil || strings.Contains(err.Error(), "private-corrupt-key") {
					t.Errorf("key %q stats error=%v", key, err)
				}
				if f.name == "bazaar" {
					if _, err := s.ListBazaarUploadsWithArtifacts(1); err == nil {
						t.Errorf("joined read accepted %q", key)
					}
				}
			}
		})
	}
}

func TestLedgerIndexedLimitLatestAndAllocationBounds(t *testing.T) {
	for i, f := range ledgerFixtures() {
		t.Run(f.name, func(t *testing.T) {
			s := newTestStore(t, "indexed.db")
			seed := func(first, n int) {
				t.Helper()
				err := s.WithTx(func(tx *sql.Tx) error {
					columns, values := f.primary+","+f.timestamp+","+f.timestamp+"_key,status", "?,?,?,'ok'"
					if f.name == "bazaar" {
						columns = f.primary + "," + f.timestamp + "," + f.timestamp + "_key,response_status"
					}
					if f.name == "threatfox" {
						columns += ",ioc_type,malware"
						values += ",'url','elf.mirai'"
					}
					stmt, err := tx.Prepare("INSERT INTO " + f.table + "(" + columns + ") VALUES(" + values + ")")
					if err != nil {
						return err
					}
					defer stmt.Close()
					for id := first; id < first+n; id++ {
						if _, err := stmt.Exec(fmt.Sprintf("row-%05d", id), "2026-09-21T10:00:00Z", "2026-09-21T10:00:00.000000000Z"); err != nil {
							return err
						}
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			seed(0, 10)
			read := func() {
				rows, err := f.list(s, 1)
				if err != nil || len(rows) != 1 {
					t.Fatalf("limit rows=%v err=%v", rows, err)
				}
				_, _, err = f.stats(s)
				if err != nil {
					t.Fatal(err)
				}
			}
			small := testing.AllocsPerRun(2, read)
			seed(10, 3000)
			large := testing.AllocsPerRun(2, read)
			if large > small*3+400 {
				t.Fatalf("allocation growth small=%.0f large=%.0f", small, large)
			}
			t.Logf("limit/stats allocations small=%.0f large=%.0f", small, large)
			// One legacy entry must not scalar-scan all 3010 migrated entries.
			if _, err := s.db.Exec("UPDATE " + f.table + " SET " + f.timestamp + "_key=NULL WHERE " + f.primary + "='row-00000'"); err != nil {
				t.Fatal(err)
			}
			mixed := testing.AllocsPerRun(2, read)
			if mixed > large*3+400 {
				t.Fatalf("mixed allocation growth migrated=%.0f mixed=%.0f", large, mixed)
			}
			q, args := orderedLedgerQuery(submissionLedger(i), f.primary+","+f.timestamp, 1)
			for _, query := range []struct {
				sql    string
				args   []any
				latest bool
			}{{q, args, false}, {latestLedgerTimeSQL(submissionLedger(i)), nil, true}} {
				rows, err := s.db.Query("EXPLAIN QUERY PLAN "+query.sql, query.args...)
				if err != nil {
					t.Fatal(err)
				}
				var details []string
				for rows.Next() {
					var a, b, c int
					var d string
					if err := rows.Scan(&a, &b, &c, &d); err != nil {
						t.Fatal(err)
					}
					details = append(details, d)
				}
				if err := rows.Err(); err != nil {
					t.Fatal(err)
				}
				rows.Close()
				plan := strings.Join(details, "\n")
				if !strings.Contains(plan, "idx_"+f.name+"_time_key") || !strings.Contains(plan, "idx_"+f.name+"_legacy_time") {
					t.Fatalf("missing native/legacy indexes:\n%s", plan)
				}
				if query.latest && strings.Contains(plan, "TEMP B-TREE") {
					t.Fatalf("latest sorted history:\n%s", plan)
				}
				if !query.latest {
					parts := strings.SplitN(plan, "RIGHT", 2)
					if len(parts) != 2 || strings.Contains(parts[0], "TEMP B-TREE") {
						t.Fatalf("native LIMIT sorted history:\n%s", plan)
					}
				}
			}
		})
	}
}

// These adapters exercise public ledger methods; expected instants and order
// are hand-written, independent of the SQL/time helpers being tested.
type ledgerFixture struct {
	name, table, timestamp, primary string
	record                          func(*Store, string, time.Time) error
	list                            func(*Store, int) ([]string, error)
	stats                           func(*Store) (int, time.Time, error)
	recorded                        func(*Store, string) (bool, error)
}

func ledgerFixtures() []ledgerFixture {
	return []ledgerFixture{
		{"bazaar", "bazaar_uploads", "uploaded_at", "sha256",
			func(s *Store, id string, at time.Time) error {
				return s.RecordBazaarUpload(BazaarUpload{SHA256: id, UploadedAt: at, ResponseStatus: "inserted"})
			},
			func(s *Store, n int) ([]string, error) {
				rows, err := s.ListBazaarUploads(n)
				var ids []string
				for _, r := range rows {
					ids = append(ids, r.SHA256)
				}
				return ids, err
			},
			func(s *Store) (int, time.Time, error) {
				r, err := s.BazaarUploadStats(time.Time{}, SharePolicy{})
				return r.TotalUploaded, r.LastUploadAt, err
			},
			(*Store).BazaarUploadRecorded},
		{"urlhaus", "urlhaus_submissions", "submitted_at", "url",
			func(s *Store, id string, at time.Time) error { return s.RecordURLhausSubmission(id, "ok", at) },
			func(s *Store, n int) ([]string, error) {
				rows, err := s.ListURLhausSubmissions(n)
				var ids []string
				for _, r := range rows {
					ids = append(ids, r.URL)
				}
				return ids, err
			},
			func(s *Store) (int, time.Time, error) {
				r, err := s.URLhausSubmissionStats(3)
				return r.TotalSubmitted, r.LastSubmittedAt, err
			},
			(*Store).URLhausSubmitted},
		{"threatfox", "threatfox_submissions", "submitted_at", "ioc",
			func(s *Store, id string, at time.Time) error {
				return s.RecordThreatFoxSubmission(id, "url", "elf.mirai", "ok", at)
			},
			func(s *Store, n int) ([]string, error) {
				rows, err := s.ListThreatFoxSubmissions(n)
				var ids []string
				for _, r := range rows {
					ids = append(ids, r.IOC)
				}
				return ids, err
			},
			func(s *Store) (int, time.Time, error) {
				r, err := s.ThreatFoxSubmissionStats(3)
				return r.TotalSubmitted, r.LastSubmittedAt, err
			},
			(*Store).ThreatFoxSubmitted},
	}
}

func TestURLhausHistoryOrdersInstants(t *testing.T) {
	s := newTestStore(t, "ledger.db")
	base := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	for _, row := range []struct {
		id string
		at time.Time
	}{{"https://example.test/older", base}, {"https://example.test/newer", base.Add(time.Second / 2)}} {
		if err := s.RecordURLhausSubmission(row.id, "ok", row.at); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.ListURLhausSubmissions(1)
	if err != nil || len(rows) != 1 || rows[0].URL != "https://example.test/newer" {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
}

func TestLedgerHistoriesAndLatestStatsOrderInstants(t *testing.T) {
	for _, f := range ledgerFixtures() {
		t.Run(f.name, func(t *testing.T) {
			s := newTestStore(t, "history.db")
			base := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
			for _, row := range []struct {
				id    string
				delta time.Duration
			}{{"older", 0}, {"newer", time.Second / 2}, {"tie-b", time.Second / 2}, {"tie-a", time.Second / 2}, {"nano", time.Second/2 + 1}} {
				if err := f.record(s, row.id, base.Add(row.delta)); err != nil {
					t.Fatal(err)
				}
			}
			rows, err := f.list(s, 0)
			if err != nil || !reflect.DeepEqual(rows, []string{"nano", "newer", "tie-a", "tie-b", "older"}) {
				t.Errorf("history=%v err=%v", rows, err)
			}
			limited, err := f.list(s, 1)
			if err != nil || !reflect.DeepEqual(limited, []string{"nano"}) {
				t.Errorf("limited=%v err=%v", limited, err)
			}
			n, last, err := f.stats(s)
			if err != nil || n != 5 || !last.Equal(base.Add(time.Second/2+1)) {
				t.Errorf("stats count=%d last=%s err=%v", n, last, err)
			}
			if f.name == "bazaar" {
				rows, err := s.ListBazaarUploadsWithArtifacts(1)
				if err != nil || len(rows) != 1 || rows[0].SHA256 != "nano" {
					t.Errorf("joined=%+v err=%v", rows, err)
				}
			}
		})
	}
}

func TestLedgerMalformedHistoryFailsWithoutLeaking(t *testing.T) {
	for _, f := range ledgerFixtures() {
		t.Run(f.name, func(t *testing.T) {
			s := newTestStore(t, "malformed.db")
			if err := f.record(s, "private-ioc", time.Now()); err != nil {
				t.Fatal(err)
			}
			// Simulate an old writer: a low-sorting invalid value must not disappear
			// behind LIMIT 1 or MAX, and a public error must not echo the source.
			if _, err := s.db.Exec("UPDATE " + f.table + " SET " + f.timestamp + "='!secret-time'"); err != nil {
				t.Fatal(err)
			}
			if err := f.record(s, "valid", time.Now()); err != nil {
				t.Fatal(err)
			}
			_, err := f.list(s, 1)
			if err == nil || strings.Contains(err.Error(), "secret-time") || strings.Contains(err.Error(), "private-ioc") {
				t.Errorf("list error=%v", err)
			}
			_, _, err = f.stats(s)
			if err == nil || strings.Contains(err.Error(), "secret-time") || strings.Contains(err.Error(), "private-ioc") {
				t.Errorf("stats error=%v", err)
			}
			if yes, err := f.recorded(s, "private-ioc"); err != nil || !yes {
				t.Fatalf("dedup lost: recorded=%v err=%v", yes, err)
			}
		})
	}
}
