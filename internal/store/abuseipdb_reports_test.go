package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAbuseIPDBReportedIPsContextFiltersWindowInBulk(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "abuse-bulk.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	if err := st.RecordAbuseIPDBReport("8.8.8.8", "reported", 80, []int{18, 22}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordAbuseIPDBReport("1.1.1.1", "reported", 70, []int{18, 22}, now.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}

	reported, err := st.AbuseIPDBReportedIPsContext(context.Background(),
		[]string{" 8.8.8.8 ", "1.1.1.1", "9.9.9.9", "8.8.8.8", ""}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !reported["8.8.8.8"] || reported["1.1.1.1"] || reported["9.9.9.9"] {
		t.Fatalf("bulk reported set = %v", reported)
	}
}

func TestAbuseIPDBReportedIPsContextHonorsCancellation(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "abuse-bulk-cancel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = st.AbuseIPDBReportedIPsContext(ctx, []string{"8.8.8.8"}, 24*time.Hour)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled bulk lookup: %v, want context.Canceled", err)
	}
}

func TestAbuseIPDBReportedUsesExactTimestampInstants(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "abuse-offset.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.ensureAbuseReportsTable(); err != nil {
		t.Fatal(err)
	}

	ip := "8.8.8.8"
	recent := time.Now().UTC().Add(-30 * time.Minute)
	offsetText := recent.In(time.FixedZone("minus-14", -14*60*60)).Format(time.RFC3339Nano)
	if _, err := st.db.Exec(`INSERT INTO abuseipdb_reports(ip,reported_at,status) VALUES(?,?,?)`,
		ip, offsetText, "reported"); err != nil {
		t.Fatal(err)
	}

	reported, err := st.AbuseIPDBReported(ip, time.Hour)
	if err != nil || !reported {
		t.Fatalf("single lookup reported=%v err=%v, want recent offset timestamp suppressed", reported, err)
	}
	bulk, err := st.AbuseIPDBReportedIPsContext(context.Background(), []string{ip}, time.Hour)
	if err != nil || !bulk[ip] {
		t.Fatalf("bulk lookup=%v err=%v, want recent offset timestamp suppressed", bulk, err)
	}
}

func TestAbuseIPDBReportedRejectsMalformedLedgerTimestamp(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "abuse-malformed.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.ensureAbuseReportsTable(); err != nil {
		t.Fatal(err)
	}

	ip := "9.9.9.9"
	if _, err := st.db.Exec(`INSERT INTO abuseipdb_reports(ip,reported_at,status) VALUES(?,?,?)`,
		ip, "not-a-time", "reported"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AbuseIPDBReported(ip, time.Hour); err == nil || !strings.Contains(err.Error(), ip) {
		t.Fatalf("single lookup error = %v, want contextual parse failure", err)
	}
	if _, err := st.AbuseIPDBReportedIPsContext(context.Background(), []string{ip}, time.Hour); err == nil || !strings.Contains(err.Error(), ip) {
		t.Fatalf("bulk lookup error = %v, want contextual parse failure", err)
	}
}

// TestAbuseReportWindowDedup verifies the time-windowed dedup: a freshly
// recorded IP is "reported" within the window but reportable again once the
// window passes (checked by recording an old timestamp), and that stats/list
// round-trip categories.
func TestAbuseReportWindowDedup(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "abuse.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ip := "203.0.113.7"
	// Not yet reported.
	if ok, err := st.AbuseIPDBReported(ip, 24*time.Hour); err != nil || ok {
		t.Fatalf("expected not-reported, got ok=%v err=%v", ok, err)
	}

	// Record a report 48h ago.
	old := time.Now().Add(-48 * time.Hour)
	if err := st.RecordAbuseIPDBReport(ip, "reported", 100, []int{18, 22}, old); err != nil {
		t.Fatal(err)
	}
	// Within a 24h window it's stale → reportable again.
	if ok, _ := st.AbuseIPDBReported(ip, 24*time.Hour); ok {
		t.Fatal("48h-old report should be reportable again within a 24h window")
	}
	// Within a 72h window it's still suppressed.
	if ok, _ := st.AbuseIPDBReported(ip, 72*time.Hour); !ok {
		t.Fatal("48h-old report should be suppressed within a 72h window")
	}
	// within<=0 means "ever reported".
	if ok, _ := st.AbuseIPDBReported(ip, 0); !ok {
		t.Fatal("within<=0 should report ever-reported=true")
	}

	// Re-record fresh; now it's suppressed in a 24h window.
	if err := st.RecordAbuseIPDBReport(ip, "reported", 100, []int{18, 22}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if ok, _ := st.AbuseIPDBReported(ip, 24*time.Hour); !ok {
		t.Fatal("fresh report should be suppressed within a 24h window")
	}

	// Stats + list.
	stats, err := st.AbuseReportStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.TotalReported != 1 {
		t.Fatalf("expected 1 reported IP (upsert), got %d", stats.TotalReported)
	}
	rows, err := st.ListAbuseReports(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].IP != ip {
		t.Fatalf("list = %+v", rows)
	}
	if len(rows[0].Categories) != 2 || rows[0].Categories[0] != 18 || rows[0].Categories[1] != 22 {
		t.Fatalf("categories round-trip failed: %v", rows[0].Categories)
	}
}

func TestAbuseReportStatsAndListOrderExactInstants(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "abuse-order.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.ensureAbuseReportsTable(); err != nil {
		t.Fatal(err)
	}

	rows := []struct{ ip, ts string }{
		{ip: "1.1.1.1", ts: "2026-01-01T01:00:00+02:00"},
		{ip: "8.8.8.8", ts: "2026-01-01T00:00:00Z"},
		{ip: "9.9.9.9", ts: "2026-01-01T00:00:00.100000000Z"},
	}
	for _, row := range rows {
		if _, err := st.db.Exec(`INSERT INTO abuseipdb_reports(ip,reported_at,status) VALUES(?,?,?)`,
			row.ip, row.ts, "reported"); err != nil {
			t.Fatal(err)
		}
	}

	stats, err := st.AbuseReportStats()
	if err != nil {
		t.Fatal(err)
	}
	wantLatest := time.Date(2026, 1, 1, 0, 0, 0, int(100*time.Millisecond), time.UTC)
	if stats.TotalReported != 3 || !stats.LastReportAt.Equal(wantLatest) {
		t.Fatalf("stats=%+v, want total 3 latest %v", stats, wantLatest)
	}
	listed, err := st.ListAbuseReports(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 || listed[0].IP != "9.9.9.9" || listed[1].IP != "8.8.8.8" {
		t.Fatalf("list order=%+v, want 9.9.9.9 then 8.8.8.8", listed)
	}
}

func TestAbuseReportStatsAndListRejectMalformedTime(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "abuse-list-malformed.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.ensureAbuseReportsTable(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO abuseipdb_reports(ip,reported_at,status) VALUES(?,?,?)`,
		"8.8.4.4", "not-a-time", "reported"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AbuseReportStats(); err == nil || !strings.Contains(err.Error(), "8.8.4.4") {
		t.Fatalf("stats error=%v, want contextual parse failure", err)
	}
	if _, err := st.ListAbuseReports(1); err == nil || !strings.Contains(err.Error(), "8.8.4.4") {
		t.Fatalf("list error=%v, want contextual parse failure", err)
	}
}
