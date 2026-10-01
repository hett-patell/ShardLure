package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func ingestStateDump(t *testing.T, s *Store) string {
	t.Helper()
	rows, err := s.db.Query(`SELECT source||'/'||path||'='||offset FROM ingest_state ORDER BY source, path`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := ""
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			t.Fatal(err)
		}
		out += r + ";"
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func setIngestOffset(t *testing.T, s *Store, source, path string, v int64) {
	t.Helper()
	if _, err := s.db.Exec(`INSERT INTO ingest_state(source,path,inode,offset,head_sig,updated_at) VALUES(?,?,0,?,'','x')
ON CONFLICT(source,path) DO UPDATE SET offset=excluded.offset`, source, path, v); err != nil {
		t.Fatal(err)
	}
}

// The dashboard explains why an edit has not applied yet, so the status is
// read on request paths: it must never write, start the deadline clock or
// release the hold (ScriptRebuildHold does all three and stays worker-only).
func TestScriptRebuildHoldStatusIsReadOnly(t *testing.T) {
	s := newTestStore(t, "hold_status.db")
	ctx := context.Background()
	check := func(want ScriptRebuildHoldStatus) {
		t.Helper()
		before := ingestStateDump(t, s)
		got, err := s.ScriptRebuildHoldStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("status = %+v, want %+v", got, want)
		}
		if after := ingestStateDump(t, s); after != before {
			t.Fatalf("status wrote ingest_state:\n before %s\n after  %s", before, after)
		}
	}
	check(ScriptRebuildHoldStatus{})

	// Event 400 exists: the recording target is the mark lowered to
	// MAX(events.id) (holdRecordTarget), so a mark above every event would read
	// as already recorded.
	if _, err := s.db.Exec(`INSERT INTO events(id,ts,source,kind) VALUES(400,'2026-09-01T00:00:00Z','cowrie','connect')`); err != nil {
		t.Fatal(err)
	}
	setIngestOffset(t, s, scriptVersionSource, scriptHoldHWMPath, 400)
	setIngestOffset(t, s, evidenceCursorSource, evidenceCursorPath, 100)
	check(ScriptRebuildHoldStatus{Held: true, Phase: "recording", Recorded: 100, Target: 400})

	// Past the mark but before the worker's first check: settling, no deadline
	// yet, and the status must not start the clock itself.
	setIngestOffset(t, s, evidenceCursorSource, evidenceCursorPath, 400)
	check(ScriptRebuildHoldStatus{Held: true, Phase: "settling", Recorded: 400, Target: 400})

	until := time.Unix(time.Now().Add(20*time.Minute).Unix(), 0)
	setIngestOffset(t, s, scriptVersionSource, scriptHoldDeadlinePath, until.Unix())
	check(ScriptRebuildHoldStatus{Held: true, Phase: "settling", Recorded: 400, Target: 400, Until: until})

	// A --replace sentinel: the target is measured, not stored.
	setIngestOffset(t, s, scriptVersionSource, scriptHoldHWMPath, scriptHoldRemeasure)
	setIngestOffset(t, s, evidenceCursorSource, evidenceCursorPath, 0)
	if _, err := s.db.Exec(`DELETE FROM events`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO events(id,ts,source,kind) VALUES(7,'2026-09-01T00:00:00Z','cowrie','connect')`); err != nil {
		t.Fatal(err)
	}
	check(ScriptRebuildHoldStatus{Held: true, Phase: "recording", Recorded: 0, Target: 7})
}

// ForceScriptRebuild removes exactly the stored normaliser version: the hold,
// the recorder cursor, other ingest cursors and campaign rows stay for the
// worker's reset to handle.
func TestForceScriptRebuildDeletesOnlyTheVersionRow(t *testing.T) {
	s := newTestStore(t, "force_rebuild.db")
	ctx := context.Background()
	setIngestOffset(t, s, scriptVersionSource, scriptVersionPath, 3)
	// Event 400 exists: the recording target is the mark lowered to
	// MAX(events.id) (holdRecordTarget), so a mark above every event would read
	// as already recorded.
	if _, err := s.db.Exec(`INSERT INTO events(id,ts,source,kind) VALUES(400,'2026-09-01T00:00:00Z','cowrie','connect')`); err != nil {
		t.Fatal(err)
	}
	setIngestOffset(t, s, scriptVersionSource, scriptHoldHWMPath, 400)
	setIngestOffset(t, s, evidenceCursorSource, evidenceCursorPath, 100)
	setIngestOffset(t, s, "cowrie", "/var/log/cowrie.json", 12345)
	if _, err := s.db.Exec(`INSERT INTO campaign_edits(campaign_id,action,arg,who,created_at) VALUES('c-000000000001','rename','Keep','cli','x')`); err != nil {
		t.Fatal(err)
	}
	before := ingestStateDump(t, s)
	if err := s.ForceScriptRebuild(ctx); err != nil {
		t.Fatal(err)
	}
	after := ingestStateDump(t, s)
	if want := strings.Replace(before, "script_version/normaliser=3;", "", 1); after != want || want == before {
		t.Fatalf("ingest_state after:\n %s\nwant\n %s", after, want)
	}
	var edits int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM campaign_edits`).Scan(&edits); err != nil || edits != 1 {
		t.Fatalf("campaign_edits %d %v", edits, err)
	}
	// Idempotent: a second request with nothing stored is not an error.
	if err := s.ForceScriptRebuild(ctx); err != nil {
		t.Fatal(err)
	}
}
