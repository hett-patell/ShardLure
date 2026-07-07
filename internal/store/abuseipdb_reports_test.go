package store

import (
	"path/filepath"
	"testing"
	"time"
)

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
