package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSettleOnlyAfterIdleAndResettleOnLateCommands(t *testing.T) {
	s := newTestStore(t, "settle.db")
	ctx := context.Background()
	now := time.Now().UTC()
	cowrieEvent(t, s, "s1", "cowrie:a", "command", injector, "", "", now.Add(-20*time.Minute))
	if _, err := s.RecordCampaignEvidence(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	if n, err := s.SettleSessionScripts(ctx, now.Add(-30*time.Minute), 100); err != nil || n != 0 {
		t.Fatalf("settled before idle: %d %v", n, err)
	}
	if n, err := s.SettleSessionScripts(ctx, now.Add(-10*time.Minute), 100); err != nil || n != 1 {
		t.Fatalf("settle: %d %v", n, err)
	}
	var fp1 string
	s.db.QueryRow(`SELECT fingerprint FROM session_scripts WHERE session_id='s1'`).Scan(&fp1)
	cowrieEvent(t, s, "s1", "cowrie:a", "command", "crontab -r", "", "", now.Add(-15*time.Minute))
	if _, err := s.RecordCampaignEvidence(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.SettleSessionScripts(ctx, now.Add(-10*time.Minute), 100); n != 1 {
		t.Fatal("late command did not re-settle")
	}
	var fp2 string
	s.db.QueryRow(`SELECT fingerprint FROM session_scripts WHERE session_id='s1'`).Scan(&fp2)
	if fp1 == "" || fp1 == fp2 {
		t.Fatalf("fingerprints %q %q", fp1, fp2)
	}
	if err := s.PruneOrphanScripts(ctx); err != nil {
		t.Fatal(err)
	}
	var scripts int
	s.db.QueryRow(`SELECT COUNT(*) FROM scripts`).Scan(&scripts)
	if scripts != 1 {
		t.Fatalf("stale script rows kept: %d", scripts)
	}
}

func TestFamiliesAndMaterialisedView(t *testing.T) {
	s := newTestStore(t, "families.db")
	ctx := context.Background()
	old := time.Now().UTC().Add(-time.Hour)
	base := `cd ~; chattr -ia .ssh; rm -rf .ssh && mkdir .ssh && chmod 700 .ssh && echo "root\n%s\n%s" | passwd && crontab -r`
	cowrieEvent(t, s, "s1", "cowrie:a", "command", strings.ReplaceAll(base, "%s", "Abc123xyz789"), "", "", old)
	cowrieEvent(t, s, "s2", "cowrie:b", "command", strings.ReplaceAll(base, "%s", "Qwe987rty654")+" && history -c", "", "", old)
	if _, err := s.RecordCampaignEvidence(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SettleSessionScripts(ctx, time.Now().UTC(), 100); err != nil {
		t.Fatal(err)
	}
	if n, err := s.AssignScriptFamilies(ctx, 500); err != nil || n != 2 {
		t.Fatalf("assigned %d %v", n, err)
	}
	if err := s.RebuildScriptFamilies(ctx, 3000); err != nil {
		t.Fatal(err)
	}
	var families, links int
	var variants string
	s.db.QueryRow(`SELECT COUNT(*), MAX(variants), MAX(links) FROM script_families`).Scan(&families, &variants, &links)
	if families != 1 || strings.Count(variants, `"fingerprint"`) != 2 || links != 1 {
		t.Fatalf("families=%d links=%d variants=%s", families, links, variants)
	}
}

func TestAssignScriptFamiliesHonoursCancellation(t *testing.T) {
	s := newTestStore(t, "families-cancel.db")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.AssignScriptFamilies(ctx, 500); err == nil {
		t.Fatal("cancelled pass reported success")
	}
}

// A family representative outlives its own sessions while members remain,
// then goes once the last member is pruned.
func TestPruneKeepsRepresentativeWithMembers(t *testing.T) {
	s := newTestStore(t, "prune-rep.db")
	ctx := context.Background()
	old := time.Now().UTC().Add(-time.Hour)
	base := `cd ~; chattr -ia .ssh; rm -rf .ssh && mkdir .ssh && chmod 700 .ssh && echo "root\n%s\n%s" | passwd && crontab -r`
	cowrieEvent(t, s, "s1", "cowrie:a", "command", strings.ReplaceAll(base, "%s", "Abc123xyz789"), "", "", old)
	cowrieEvent(t, s, "s2", "cowrie:b", "command", strings.ReplaceAll(base, "%s", "Qwe987rty654")+" && history -c", "", "", old)
	if _, err := s.RecordCampaignEvidence(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SettleSessionScripts(ctx, time.Now().UTC(), 100); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AssignScriptFamilies(ctx, 500); err != nil {
		t.Fatal(err)
	}
	var rep string
	if err := s.db.QueryRow(`SELECT fingerprint FROM scripts WHERE family=fingerprint`).Scan(&rep); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM session_scripts WHERE fingerprint=?`, rep); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		var n int
		s.db.QueryRow(`SELECT COUNT(*) FROM scripts`).Scan(&n)
		return n
	}
	if err := s.PruneOrphanScripts(ctx); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 2 {
		t.Fatalf("representative with members pruned: %d scripts", n)
	}
	if _, err := s.db.Exec(`DELETE FROM session_scripts`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.PruneOrphanScripts(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := count(); n != 0 {
		t.Fatalf("orphans kept: %d", n)
	}
}

// An updated_at ahead of the settle clock (wall clock stepped back) must not
// leave the session pending forever.
func TestSettleClockBehindUpdatedAtDoesNotLoop(t *testing.T) {
	s := newTestStore(t, "settle-race.db")
	ctx := context.Background()
	now := time.Now().UTC()
	cowrieEvent(t, s, "s1", "cowrie:a", "command", injector, "", "", now.Add(-20*time.Minute))
	if _, err := s.RecordCampaignEvidence(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE session_scripts SET updated_at=? WHERE session_id='s1'`, formatFixedUTC(now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if n, err := s.SettleSessionScripts(ctx, now, 100); err != nil || n != 1 {
		t.Fatalf("settle: %d %v", n, err)
	}
	var settledAt, updatedAt string
	s.db.QueryRow(`SELECT settled_at, updated_at FROM session_scripts WHERE session_id='s1'`).Scan(&settledAt, &updatedAt)
	if settledAt < updatedAt {
		t.Fatalf("settled_at %s behind updated_at %s: would re-settle every pass", settledAt, updatedAt)
	}
	if n, _ := s.SettleSessionScripts(ctx, now, 100); n != 0 {
		t.Fatalf("settled session re-settled without new lines: %d", n)
	}
}
