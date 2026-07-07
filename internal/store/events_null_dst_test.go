package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// TestEventProjectionsTolerateNullDstIP guards the regression where migration
// v11 added dst_ip as a nullable column with no default, leaving every
// pre-migration row with dst_ip=NULL. The event SELECT projections scan dst_ip
// into a Go string, and the driver can't convert NULL→string — which 500'd
// every windowed endpoint (mitre/ttp/ioc/deobf/graph/timeline) and the session
// detail. The projections COALESCE dst_ip to ” so a NULL reads as empty.
func TestEventProjectionsTolerateNullDstIP(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "nulldst.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Insert a row with dst_ip explicitly NULL (what a pre-v11 row looks like
	// after the ADD COLUMN). Bypass insertEvent, which would write ''.
	ts := time.Now().UTC()
	// Real post-migration rows have every other string column populated (by
	// insertEvent) and ONLY dst_ip NULL (the freshly-ADDed column). Mirror that
	// so the test isolates the dst_ip regression rather than incidental NULLs.
	if _, err := st.execWrite(
		`INSERT INTO events (ts, source, kind, src_ip, src_port, username, password,
		   session_id, hassh, ssh_client, command, sha256, filename, dst_ip, dst_port, raw, actor_id)
		 VALUES (?, 'cowrie', 'command', '1.2.3.4', 0, 'root', '', 's1', '', '', 'id', '', '', NULL, 0, '', 'cowrie:x')`,
		ts.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	// Every projection that scans dst_ip must tolerate the NULL.
	if _, err := st.EventsSince(ts.Add(-time.Hour), 10); err != nil {
		t.Fatalf("EventsSince: %v", err)
	}
	if _, err := st.EventsSinceAll(ts.Add(-time.Hour)); err != nil {
		t.Fatalf("EventsSinceAll: %v", err)
	}
	if _, err := st.SessionEvents("s1"); err != nil {
		t.Fatalf("SessionEvents: %v", err)
	}
	if err := st.IterateEventsBySource(models.SourceCowrie, func(*models.Event) error { return nil }); err != nil {
		t.Fatalf("IterateEventsBySource: %v", err)
	}

	// And the value reads as empty string, not a scan error.
	evs, err := st.SessionEvents("s1")
	if err != nil {
		t.Fatalf("SessionEvents(2): %v", err)
	}
	if len(evs) != 1 || evs[0].DstIP != "" {
		t.Fatalf("expected 1 event with empty DstIP, got %+v", evs)
	}
}
