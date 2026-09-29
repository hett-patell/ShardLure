package campaign

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/networkshard/shardlure/internal/intel/bazaar"
	"github.com/networkshard/shardlure/internal/safefile"
	"github.com/networkshard/shardlure/internal/script"
	"github.com/networkshard/shardlure/internal/store"
)

const (
	regroupEvery = 10 * time.Minute
	settleIdle   = 10 * time.Minute
	// recordWindow is one RecordCampaignEvidence transaction, i.e. one writeMu
	// hold. 5,000 rowids matches the MaintenancePurge chunk convention (a
	// 50,000 window held writeMu 0.4-1 s on ARM); the store clamps to it too.
	recordWindow = 5000
	// maxWindowsPerTick is high enough that recordBudget, not the window
	// count, sets backlog throughput. writeMu is released between windows,
	// so ingest interleaves with a long backfill.
	maxWindowsPerTick = 40
	// recordBudget stops a tick's backlog recording early (RecordCampaignEvidence
	// also caps the bytes each window reads).
	recordBudget = 5 * time.Second
	settleBatch  = 2000
	familyBatch  = 500
	maxBackoff   = 10 * time.Minute

	emptyFileSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	// unclassified is familyOf's answer when the payload's file could not be
	// read (no evidence root, no fetched artifact, outside the root, not a
	// regular file, read error). Such a payload does not link: the generic-
	// build exclusion could not run, so it fails closed.
	unclassified = "\x00unclassified"
)

// genericFamilies are public builds that many unrelated operators deploy.
// Compared lower-case: bazaar.Classify returns "XMRig".
var genericFamilies = map[string]bool{"xmrig": true, "coinminer": true}

// linkingKinds are the evidence kinds that may link sessions. HASSH, client
// version and download host are context only and never link.
var linkingKinds = map[string]bool{"ssh_key": true, "payload": true}

// logf is log.Printf; a variable so a test can capture what a tick reports.
var logf = log.Printf

// beforeSave is a test seam: it runs between reading the edit log and saving
// the grouping, so a test can append an edit in that window.
var beforeSave func()

// Worker drives the campaign pipeline from the live runtime: record evidence
// in bounded windows, settle scripts, assign families, regroup, prune.
type Worker struct {
	st            *store.Store
	retentionDays int
	evidenceRoot  string
	// classify reads an already-pinned file (see familyOf); a field so a
	// test can observe which file was handed over.
	classify func(f *os.File) (string, error)
	// window and maxWindows are recordWindow and maxWindowsPerTick; fields so
	// a test can make a small backlog span several windows and ticks.
	window, maxWindows int
	// scriptVersion is script.Version; a field so a test can run a worker
	// built with another normaliser version.
	scriptVersion int
	// idle is settleIdle; a field so a test can settle without waiting.
	idle time.Duration

	wake atomic.Bool

	// mu serialises the whole pipeline. AssignScriptFamilies and
	// PruneOrphanScripts assume one sequential caller (a concurrent prune can
	// delete a representative an in-flight assign pass loaded), and it makes
	// Regroup single-flight. Everything below is guarded by mu.
	mu       sync.Mutex
	families map[string]string // sha256 -> lower-case family; successful reads only
	// root is the evidence root, opened once (lazily, by familyOf) as a
	// pinned descriptor; rootPath is the absolute configured path artifact
	// paths are made relative to. nil until an open succeeds, so a root that
	// does not exist yet is retried on a later pass.
	root      *safefile.Root
	rootPath  string
	lastGroup time.Time
	drained   bool
	pending   bool // regroup owed: backlog just drained, or the last attempt failed
	failures  int
	retryAt   time.Time
	// lastErr is the failure that started the current backoff; Tick returns
	// it on every tick inside the window so the caller keeps reporting it.
	lastErr error
	// versionChecked is set once the stored script lines are known to match
	// scriptVersion (see the start of tick).
	versionChecked bool
	// holdClear is set once the store reports no script-rebuild hold. A hold
	// is only ever created by the reset at the start of a lease-holding
	// process, so after it is clear the per-tick check is skipped. A new
	// process, or this one after regaining the lease, reads the hold from
	// the store again.
	holdClear bool
	// leaseOwner identifies this process to the cross-process worker lease
	// (store.AcquireCampaignLease), leaseTTL is the lease's lifetime (a field
	// so a test can expire it quickly), leaseUntil is when the lease this
	// process holds runs out (zero while it holds none) and leaseLost
	// records that another process was seen holding it, so the fact is
	// logged once, not every tick.
	leaseOwner string
	leaseTTL   time.Duration
	leaseUntil time.Time
	leaseLost  bool
	// clock is time.Now for the lease decisions; a field so a test can expire
	// a lease without sleeping (the store takes the time explicitly).
	clock func() time.Time
	// editsSeen is the largest campaign_edits ID the last regroup read. Wake
	// is per process, and with the lease only one process regroups: an edit
	// POSTed to a `shardlure web` beside the `live` daemon wakes the wrong
	// process, so each tick also compares the store's latest edit ID with
	// this and regroups on a new one, whichever process recorded it.
	editsSeen int64
}

// ErrRegroupHeld is Regroup's answer while a script rebuild holds regroups
// (see store.ScriptRebuildHold). Tick keeps the regroup owed instead.
var ErrRegroupHeld = errors.New("campaign: regroup held until rebuilt scripts settle")

// ErrLeaseHeldElsewhere means another process holds the campaign worker
// lease, so this one runs no part of the pipeline. Tick swallows it (a skipped
// tick is not a failure and starts no backoff); Regroup returns it.
var ErrLeaseHeldElsewhere = errors.New("campaign: another process holds the campaign worker lease")

// ErrLeaseLapsed means the lease this process held ran out during a phase
// (recording, settling, classifying or grouping stalled past the TTL, or the
// store no longer names this process as the holder), so the write the phase
// led to was refused: another process may have run the pipeline meanwhile.
// It is a failure (backoff, reported), and the next tick retakes the lease
// as a takeover, which re-runs the version and hold checks.
var ErrLeaseLapsed = errors.New("campaign: the worker lease lapsed during a phase; the write was refused")

// campaignLeaseTTL bounds how long a crashed owner blocks the pipeline. The
// holder renews at half-life (every ~30 s of ticks, one small write) and
// again before the settle and regroup phases, so a tick can lose the lease
// only if one phase stalls for over 30 s.
const campaignLeaseTTL = time.Minute

func NewWorker(st *store.Store, retentionDays int, evidenceRoot string) *Worker {
	return &Worker{st: st, retentionDays: retentionDays, evidenceRoot: evidenceRoot, families: map[string]string{},
		window: recordWindow, maxWindows: maxWindowsPerTick, scriptVersion: script.Version, idle: settleIdle,
		leaseOwner: leaseOwnerID(), leaseTTL: campaignLeaseTTL, clock: time.Now,
		classify: func(f *os.File) (string, error) {
			c, err := bazaar.ClassifyFile(f)
			return c.Family, err
		}}
}

// leaseOwnerID is "<pid>:<random>": the pid names the process in the log line
// the other side prints, the random part keeps a recycled pid from renewing
// a dead process's lease.
func leaseOwnerID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		binary.LittleEndian.PutUint64(b[:], uint64(time.Now().UnixNano()))
	}
	return fmt.Sprintf("%d:%s", os.Getpid(), hex.EncodeToString(b[:]))
}

// Close releases the campaign worker lease, so a process started next takes
// over at once instead of waiting out the TTL, and the evidence root
// descriptor familyOf holds. The worker must not tick afterwards. It runs at
// shutdown, where the caller cannot act on an error, so failures are logged
// here rather than returned (and dropped).
func (w *Worker) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.leaseUntil.IsZero() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := w.st.ReleaseCampaignLease(ctx, w.leaseOwner); err != nil {
			logf("campaigns: releasing the worker lease: %v", err)
		}
		cancel()
		w.leaseUntil = time.Time{}
	}
	if w.root == nil {
		return
	}
	if err := w.root.Close(); err != nil {
		logf("campaigns: closing the evidence root: %v", err)
	}
	w.root = nil
}

// holdLease makes sure this process holds the campaign worker lease, taking
// or renewing it once less than half its TTL is left, and returns
// ErrLeaseHeldElsewhere when another process has it. Two processes on one
// database (`shardlure live` beside a separately started `shardlure web`)
// both start this worker, and AssignScriptFamilies, PruneOrphanScripts, the
// version reset and the hold release all assume a single sequential caller;
// the lease gives them one.
//
// An acquire is a takeover, not a renewal, when this process holds no lease
// or the one it held has lapsed on its own clock (a phase stalled past the
// TTL: another process may have held and released it in between, unseen).
// A takeover re-reads the rebuild hold from the store and re-runs the
// normaliser version check: the other holder may have run a version reset,
// or a `scripts --rebuild` may have deleted the version row, meanwhile, and
// a stale holdClear let this process regroup through that hold (audit M-1),
// while a stale versionChecked missed the rebuild until a restart (cmd audit
// M2). Only a lease seen lost (leaseUntil zero) reset them before.
func (w *Worker) holdLease(ctx context.Context, now time.Time) error {
	if !w.leaseUntil.IsZero() && now.Before(w.leaseUntil.Add(-w.leaseTTL/2)) {
		return nil
	}
	takeover := w.leaseUntil.IsZero() || !now.Before(w.leaseUntil)
	held, err := w.st.AcquireCampaignLease(ctx, w.leaseOwner, now, w.leaseTTL)
	if err != nil {
		return err
	}
	if !held {
		if !w.leaseLost {
			owner, _, _ := w.st.CampaignLeaseHolder(ctx)
			logf("campaigns: another shardlure process (%s) holds the campaign worker lease; this process leaves the campaign pipeline to it until that lease is released or expires", owner)
			w.leaseLost = true
		}
		w.leaseUntil = time.Time{}
		return ErrLeaseHeldElsewhere
	}
	if takeover {
		// The version check runs at the start of the next tick when the
		// takeover happens mid-tick; the hold is re-read by this tick's
		// rebuildHeld either way.
		w.holdClear, w.versionChecked = false, false
		if w.leaseLost {
			logf("campaigns: this process now holds the campaign worker lease")
			w.leaseLost = false
		}
	}
	w.leaseUntil = now.Add(w.leaseTTL)
	return nil
}

// fenceLease guards a write that assumes single ownership (SaveGrouping,
// RebuildScriptFamilies): the lease must still be live on this process's
// clock and renewable in the store under this owner, else ErrLeaseLapsed.
// The clock alone is not a fence: holdLease skips the store for up to half
// the TTL on the process's monotonic clock, while the other process judges
// expiry on the wall-clock expiry stored in the row, so a wall-clock step
// forward of more than the half-life lets it take over unseen; the renewal
// asks the row (audit M-2). One small write per regroup.
func (w *Worker) fenceLease(ctx context.Context) error {
	now := w.clock()
	if !w.leaseLive(now) {
		return ErrLeaseLapsed
	}
	held, err := w.st.AcquireCampaignLease(ctx, w.leaseOwner, now, w.leaseTTL)
	if err != nil {
		return err
	}
	if !held {
		w.leaseUntil = time.Time{}
		return ErrLeaseLapsed
	}
	w.leaseUntil = now.Add(w.leaseTTL)
	return nil
}

// leaseLive reports whether the lease this process holds is unexpired on
// its own clock; the cheap half of the fence, enough before a bounded write
// that only ever runs right after a phase that renewed against the store.
func (w *Worker) leaseLive(now time.Time) bool {
	return !w.leaseUntil.IsZero() && now.Before(w.leaseUntil)
}

// Wake asks for a regroup on the next tick (an operator edit arrived). It
// never blocks, so request handlers can call it.
func (w *Worker) Wake() { w.wake.Store(true) }

// Tick runs one pass. After a failure it backs off exponentially (10 s
// doubling, capped at 10 min) so a persistent error cannot burn CPU every
// tick. A tick inside the window does no work but returns the failure that
// started it, so the monitor keeps the worker's error flag up and its last
// success stale for as long as the worker is not actually succeeding.
// Returning nil here made a permanently failing worker read healthy: the
// error flag was set for the <=5 s between a real attempt and the next
// cycle, then cleared and "last success" advanced, so with the backoff at
// 10 min /metrics said healthy more than 99% of the time. That is how the
// rc1->rc2 upgrade failure (a missing table on the first statement of every
// tick) stayed invisible on the rehearsal box (fix-all review I1). The same
// error value is returned on every tick of a window, so a caller that logs
// on change logs a streak once.
func (w *Worker) Tick(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if time.Now().Before(w.retryAt) {
		return w.lastErr
	}
	err := w.tick(ctx)
	if errors.Is(err, ErrLeaseHeldElsewhere) {
		// Another process runs the pipeline: nothing to do, nothing wrong.
		return nil
	}
	if err != nil {
		w.failures++
		w.retryAt = time.Now().Add(min(5*time.Second<<min(w.failures, 7), maxBackoff))
		w.lastErr = err
		return err
	}
	w.failures, w.retryAt, w.lastErr = 0, time.Time{}, nil
	return nil
}

func (w *Worker) tick(ctx context.Context) error {
	// The lease first: a process that does not hold it runs nothing below,
	// the version reset included.
	if err := w.holdLease(ctx, w.clock()); err != nil {
		return err
	}
	// Once per process, before recording: stored lines are pre-computed
	// encodings, so lines from an older normaliser would fingerprint the same
	// script differently from new sessions. On a version mismatch the store
	// drops the script-derived rows (chunked) and rewinds the recorder, and
	// this tick starts re-recording from the first event. Evidence and
	// campaign identity are kept. A failure retries on the next tick, with
	// the usual backoff; nothing is recorded until it succeeds.
	if !w.versionChecked {
		reset, err := w.st.ResetScriptsForVersion(ctx, w.scriptVersion)
		if err != nil {
			return err
		}
		w.versionChecked = true
		if reset {
			logf("campaigns: script normaliser version %d: rebuilding script lines and fingerprints from the retained commands", w.scriptVersion)
		}
	}
	start := time.Now()
	skipped := 0
	// Reported even when a later window fails: earlier windows' rows are
	// already behind the cursor and will not be seen again.
	defer func() {
		if skipped > 0 {
			logf("campaigns: skipped %d Cowrie events with an unusable timestamp (no ts_unix_ns and unparseable ts); they are not recorded as evidence", skipped)
		}
	}()
	done := false
	for i := 0; i < w.maxWindows && ctx.Err() == nil && time.Since(start) < recordBudget; i++ {
		res, err := w.st.RecordCampaignEvidence(ctx, w.window)
		if err != nil {
			return err // the window rolled back: its rows were not skipped yet
		}
		skipped += res.Skipped
		if done = res.Done; done {
			break
		}
	}
	// Judged on how the tick ENDS, not per window: a burst larger than one
	// window that drains inside this tick is ordinary ingest and must not
	// owe an extra regroup. Only a backlog that outlives the tick (first
	// start, a burst beyond the tick's budget, or the rows a replace-ingest
	// re-inserted above the parked cursor) defers every regroup until it
	// drains, and then one runs. That includes a Wake and an edit recorded by
	// another process: a regroup over a partial backlog sees only the
	// evidence recorded so far, and SaveGrouping replaces campaign_ids with
	// what it saw, so every campaign whose evidence was still queued lost its
	// assignment and came back under a fresh ID, its name left on an empty
	// shell (audit I-2: reached through `ingest cowrie --replace` plus a
	// restart, or an edit during a first-start backfill). The wake flag is
	// left set, so the drain's regroup applies the edit.
	switch {
	case !done:
		w.drained = false
	case !w.drained:
		w.drained, w.pending = true, true
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Recording can run up to its 5 s budget: renew the lease before the
	// phases that assume a single caller, and stop here if it was lost.
	if err := w.holdLease(ctx, w.clock()); err != nil {
		return err
	}
	// settle -> assign -> (regroup, rebuild) -> prune, sequentially in this
	// goroutine under w.mu: AssignScriptFamilies and PruneOrphanScripts assume
	// a single sequential caller. Prune runs only on a tick that settled or
	// regrouped (it takes writeMu, so an idle tick must not pay for it) and
	// frees representatives one level per such pass.
	settled, err := w.st.SettleSessionScripts(ctx, time.Now().Add(-w.idle), settleBatch)
	if err != nil {
		return err
	}
	if _, err := w.st.AssignScriptFamilies(ctx, familyBatch); err != nil {
		return err
	}
	held, err := w.rebuildHeld(ctx)
	if err != nil {
		return err
	}
	// While held or not drained, nothing regroups, a Wake included: the wake
	// flag and pending stay set, so the regroup owed runs on the first tick
	// after the hold ends or the backlog drains (the edit itself is already
	// recorded). An edit recorded by another process (see editsSeen) counts
	// as a wake too. editsSeen starts at 0 in every process, so on the first
	// drained tick after a restart any edit at all reads as new; that tick
	// owes a regroup anyway (pending), so it costs nothing extra, and it can
	// only run once the tick has checked the backlog.
	woken := false
	if !held && w.drained {
		latest, err := w.st.LatestCampaignEditID(ctx)
		if err != nil {
			return err
		}
		woken = w.wake.Swap(false) || latest > w.editsSeen
	}
	regrouped := false
	if !held && w.drained && (woken || w.pending || time.Since(w.lastGroup) >= regroupEvery) {
		if err := w.holdLease(ctx, w.clock()); err != nil {
			if woken {
				w.Wake() // not regrouped: keep the edit's wake for when the lease is back
			}
			return err
		}
		err := w.regroup(ctx)
		switch {
		case errors.Is(err, store.ErrStaleGrouping):
			// An edit landed between reading the edit log and saving. Not a
			// failure: regroup again on the next tick, without backoff.
			w.Wake()
		case err != nil:
			w.pending = true // retried once the backoff expires
			return err
		default:
			w.pending, w.lastGroup, regrouped = false, time.Now(), true
		}
	}
	// PruneOrphanScripts is a DELETE ... WHERE NOT EXISTS scan under writeMu.
	// Orphans appear only when a session re-settles under a new fingerprint
	// or a regroup rebuilds families (retention orphans are collected on the
	// next such tick), so an idle 5 s tick does not take the writer lock for
	// nothing.
	if settled == 0 && !regrouped {
		return nil
	}
	// Prune assumes the single caller too: a concurrent prune can delete a
	// representative an in-flight assign pass loaded. The settle and assign
	// phases before it are bounded (a batch and a 2 s budget), so the clock
	// half of the fence is enough here.
	if !w.leaseLive(w.clock()) {
		return ErrLeaseLapsed
	}
	return w.st.PruneOrphanScripts(ctx)
}

// Regroup recomputes and saves the campaigns now. It shares Tick's lock, so
// it never runs concurrently with a tick or another Regroup.
func (w *Worker) Regroup(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.holdLease(ctx, w.clock()); err != nil {
		return err
	}
	held, err := w.rebuildHeld(ctx)
	if err != nil {
		return err
	}
	if held {
		return ErrRegroupHeld
	}
	return w.regroup(ctx)
}

// rebuildHeld reports whether a script rebuild still holds regroups. A
// regroup before the re-recorded sessions settle would drop every script
// assignment, and the renamed campaign would come back under a new ID; the
// store releases the hold (carrying assignments to the new fingerprints)
// once the rebuild has settled. See store.ResetScriptsForVersion.
func (w *Worker) rebuildHeld(ctx context.Context) (bool, error) {
	if w.holdClear {
		return false, nil
	}
	held, err := w.st.ScriptRebuildHold(ctx, time.Now())
	if err != nil {
		return false, err
	}
	w.holdClear = !held
	return held, nil
}

func (w *Worker) regroup(ctx context.Context) error {
	// Commonness is measured against Cowrie actors seen within the retention
	// window, the same population the evidence itself is kept for.
	since := time.Time{}
	if w.retentionDays > 0 {
		since = time.Now().AddDate(0, 0, -w.retentionDays)
	}
	population, err := w.st.CowrieActorPopulation(ctx, since)
	if err != nil {
		return err
	}
	// The stale check in SaveGrouping compares against the largest edit ID fed
	// into this Group call, so it must come from this same read.
	edits, err := w.st.CampaignEdits(ctx)
	if err != nil {
		return err
	}
	in := Input{Edits: make([]Edit, 0, len(edits))}
	var lastEdit int64
	for _, e := range edits {
		in.Edits = append(in.Edits, Edit{ID: e.ID, CampaignID: e.CampaignID, Action: e.Action, Arg: e.Arg})
		lastEdit = max(lastEdit, e.ID)
	}
	ev, err := w.st.CampaignEvidenceRows(ctx)
	if err != nil {
		return err
	}
	scripts, err := w.st.SettledScriptRows(ctx)
	if err != nil {
		return err
	}
	ids, aliases, err := w.st.CampaignIdentity(ctx)
	if err != nil {
		return err
	}
	for _, a := range ids {
		in.Assignments = append(in.Assignments, Assignment{Kind: a.Kind, Value: a.Value, CampaignID: a.CampaignID, Seq: a.Seq})
	}
	in.Aliases = aliases
	seen := map[string]bool{}
	in.Occurrences = linkingOccurrences(ev, scripts, population, func(sha string) string {
		seen[sha] = true
		if ctx.Err() != nil { // cancelled: stop reading files, fail closed
			return unclassified
		}
		return w.familyOf(ctx, sha)
	})
	for sha := range w.families { // keep the memo to payloads still in evidence
		if !seen[sha] {
			delete(w.families, sha)
		}
	}
	// Classifying can open thousands of payload files on the first regroup
	// of a process (the memo is empty): renew the lease before grouping so
	// the fence below does not refuse a save for that alone.
	if err := w.holdLease(ctx, w.clock()); err != nil {
		return err
	}
	// Group takes the tick context: a regroup that outlives the cycle budget
	// or a shutdown stops inside Group and never reaches SaveGrouping.
	out, err := Group(ctx, in)
	if err != nil {
		return err
	}
	rows, assign := groupingRows(out)
	if beforeSave != nil {
		beforeSave()
	}
	// The save replaces every derived row and assumes no other process is
	// doing the same: the lease must still be this process's, in the store,
	// right here (audit M-2).
	if err := w.fenceLease(ctx); err != nil {
		return err
	}
	if err := w.st.SaveGrouping(ctx, rows, assign, out.Aliases, lastEdit); err != nil {
		return err
	}
	w.editsSeen = lastEdit // the saved grouping includes every edit up to here
	return w.st.RebuildScriptFamilies(ctx, population)
}

// groupingRows maps Group's output onto the store rows. SaveGrouping rejects
// a whole grouping on any empty or duplicate identifier, so nothing here may produce one:
// Reasons is always a JSON array, "[]" at minimum.
func groupingRows(out Output) ([]store.CampaignRow, []store.CampaignAssignmentRow) {
	rows := make([]store.CampaignRow, 0, len(out.Campaigns))
	for _, c := range out.Campaigns {
		search := make([]string, 0, len(c.Values)+2)
		for _, s := range append([]string{c.Name, c.SuggestedName}, c.Values...) {
			if s != "" {
				search = append(search, s)
			}
		}
		r := store.CampaignRow{ID: c.ID, AnchorKind: c.AnchorKind, AnchorValue: c.AnchorValue, SuggestedName: c.SuggestedName,
			Name: c.Name, Notes: c.Notes, FirstSeen: c.FirstSeen, LastSeen: c.LastSeen, Actors: len(c.Members), IPs: c.IPs,
			Sessions: c.Sessions, Kinds: strings.Join(c.Kinds, ","), Search: strings.Join(search, " "),
			Members: make([]store.CampaignMemberRow, 0, len(c.Members))}
		for _, m := range c.Members {
			r.Members = append(r.Members, store.CampaignMemberRow{ActorID: m.ActorID, Sessions: m.Sessions, IPs: m.IPs, Reasons: reasonsJSON(m.Reasons)})
		}
		rows = append(rows, r)
	}
	assign := make([]store.CampaignAssignmentRow, 0, len(out.Assignments))
	for _, a := range out.Assignments {
		assign = append(assign, store.CampaignAssignmentRow{Kind: a.Kind, Value: a.Value, CampaignID: a.CampaignID, Seq: a.Seq})
	}
	return rows, assign
}

type reasonJSON struct {
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	Label     string `json:"label"` // always present: the API contract lists it
	FirstSeen string `json:"firstSeen"`
}

func reasonsJSON(rs []Reason) string {
	out := make([]reasonJSON, len(rs)) // non-nil: marshals as [] when empty
	for i, r := range rs {
		out[i] = reasonJSON{Kind: r.Kind, Value: r.Value, Label: r.Label, FirstSeen: r.FirstSeen.UTC().Format(time.RFC3339)}
	}
	b, err := json.Marshal(out)
	if err != nil { // strings and a formatted time cannot fail; stay valid anyway
		return "[]"
	}
	return string(b)
}

// familyOf classifies a payload by its captured file and returns the
// lower-case family, "" when the classifier names none, or unclassified when
// the file could not be read. The content is only classified, never executed.
// Successful reads are memoised (a file hash is immutable); misses are not,
// so a later capture is picked up.
//
// The file is opened through a pinned descriptor on the evidence root
// (safefile.Root.OpenRegular) and the classifier reads that descriptor, not a
// path. Resolving and checking a path, then re-opening it by name, left a
// window in which a symlink or another file could be swapped in at the
// artifact path. OpenRegular refuses a symlink in any component, a hardlinked
// file (Nlink != 1: a link to a file elsewhere on the filesystem), a FIFO or
// device (probed with O_PATH, so a FIFO never blocks), a mount crossing, and
// any path outside the root.
func (w *Worker) familyOf(ctx context.Context, sha string) string {
	if f, ok := w.families[sha]; ok {
		return f
	}
	if w.evidenceRoot == "" || ctx.Err() != nil {
		return unclassified
	}
	p, ok, err := w.st.ArtifactPathForSHA256(ctx, sha)
	if err != nil || !ok {
		return unclassified
	}
	root, err := w.evidence()
	if err != nil {
		return unclassified
	}
	rel, ok := relativeTo(w.rootPath, p)
	if !ok {
		return unclassified
	}
	f, err := root.OpenRegular(rel)
	if err != nil {
		return unclassified
	}
	defer f.Close()
	fam, err := w.classify(f)
	if err != nil {
		return unclassified
	}
	fam = strings.ToLower(fam)
	w.families[sha] = fam
	return fam
}

// evidence opens the evidence root once per worker. A failure (the directory
// does not exist yet, a symlinked or unsupported root) is not remembered, so
// it is retried on the next lookup; until then payloads fail closed.
func (w *Worker) evidence() (*safefile.Root, error) {
	if w.root != nil {
		return w.root, nil
	}
	abs, err := filepath.Abs(w.evidenceRoot)
	if err != nil {
		return nil, err
	}
	r, err := safefile.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	w.root, w.rootPath = r, abs
	return r, nil
}

// relativeTo maps an artifact's recorded absolute path onto the root. Only a
// lexical mapping: nothing is resolved here, OpenRegular refuses symlinks. A
// path outside the root (or the root itself) is refused.
func relativeTo(root, p string) (string, bool) {
	if !filepath.IsAbs(p) {
		return "", false
	}
	rel, err := filepath.Rel(root, filepath.Clean(p))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false
	}
	return rel, true
}

// linkingOccurrences applies the link rules. Counts are distinct actors per
// value. Only ssh_key, payload and script values link: a key must not be
// common; a payload must have a known size >= bazaar.MinSampleBytes, not be
// the empty file, not be a generic public build (xmrig, coinminer) or
// unclassifiable, and not be common; a script must pass script.LinkDecision.
//
// A payload the classifier read but could not name still links: the spec
// excludes only known generic builds, and the classifier is precision-first,
// so most real droppers (packed or Go-built ELFs) carry no family. Requiring a
// name would stop payloads linking at all.
func linkingOccurrences(ev []store.EvidenceRow, scripts []store.ScriptOccRow, population int, familyOf func(string) string) []Occurrence {
	actors := map[string]map[string]bool{}
	count := func(k, actor string) {
		if actors[k] == nil {
			actors[k] = map[string]bool{}
		}
		actors[k][actor] = true
	}
	usable := func(value, session, actor string) bool { return value != "" && session != "" && actor != "" }
	for _, e := range ev {
		if linkingKinds[e.Kind] && usable(e.Value, e.SessionID, e.ActorID) {
			count(vkey(e.Kind, e.Value), e.ActorID)
		}
	}
	for _, s := range scripts {
		if usable(s.Fingerprint, s.SessionID, s.ActorID) {
			count(vkey("script", s.Fingerprint), s.ActorID)
		}
	}
	families := map[string]string{} // one lookup per distinct payload per pass
	var out []Occurrence
	for _, e := range ev {
		if !linkingKinds[e.Kind] || !usable(e.Value, e.SessionID, e.ActorID) {
			continue
		}
		if common, _ := script.Common(len(actors[vkey(e.Kind, e.Value)]), population); common {
			continue
		}
		family := ""
		if e.Kind == "payload" {
			if e.SizeBytes < bazaar.MinSampleBytes || e.Value == emptyFileSHA256 { // unknown size is -1: fails closed
				continue
			}
			f, ok := families[e.Value]
			if !ok {
				f = familyOf(e.Value)
				families[e.Value] = f
			}
			if f == unclassified || genericFamilies[strings.ToLower(f)] {
				continue
			}
			family = strings.ToLower(f)
		}
		out = append(out, Occurrence{Kind: e.Kind, Value: e.Value, Label: e.Label, Family: family, SessionID: e.SessionID,
			ActorID: e.ActorID, IP: e.IP, FirstSeen: e.FirstSeen, LastSeen: e.LastSeen})
	}
	for _, s := range scripts {
		if !usable(s.Fingerprint, s.SessionID, s.ActorID) {
			continue
		}
		if links, _ := script.LinkDecision(s.Distinctive, len(actors[vkey("script", s.Fingerprint)]), population); !links {
			continue
		}
		out = append(out, Occurrence{Kind: "script", Value: s.Fingerprint, SessionID: s.SessionID, ActorID: s.ActorID,
			IP: s.IP, FirstSeen: s.FirstSeen, LastSeen: s.LastSeen})
	}
	return out
}
