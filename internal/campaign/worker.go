package campaign

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/networkshard/shardlure/internal/intel/bazaar"
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

// beforeSave is a test seam: it runs between reading the edit log and saving
// the grouping, so a test can append an edit in that window.
var beforeSave func()

// Worker drives the campaign pipeline from the live runtime: record evidence
// in bounded windows, settle scripts, assign families, regroup, prune.
type Worker struct {
	st            *store.Store
	retentionDays int
	evidenceRoot  string
	classify      func(path string) (string, error)
	// window and maxWindows are recordWindow and maxWindowsPerTick; fields so
	// a test can make a small backlog span several windows and ticks.
	window, maxWindows int

	wake atomic.Bool

	// mu serialises the whole pipeline. AssignScriptFamilies and
	// PruneOrphanScripts assume one sequential caller (a concurrent prune can
	// delete a representative an in-flight assign pass loaded), and it makes
	// Regroup single-flight. Everything below is guarded by mu.
	mu        sync.Mutex
	families  map[string]string // sha256 -> lower-case family; successful reads only
	lastGroup time.Time
	drained   bool
	pending   bool // regroup owed: backlog just drained, or the last attempt failed
	failures  int
	retryAt   time.Time
}

func NewWorker(st *store.Store, retentionDays int, evidenceRoot string) *Worker {
	return &Worker{st: st, retentionDays: retentionDays, evidenceRoot: evidenceRoot, families: map[string]string{},
		window: recordWindow, maxWindows: maxWindowsPerTick,
		classify: func(p string) (string, error) {
			c, err := bazaar.Classify(p)
			return c.Family, err
		}}
}

// Wake asks for a regroup on the next tick (an operator edit arrived). It
// never blocks, so request handlers can call it.
func (w *Worker) Wake() { w.wake.Store(true) }

// Tick runs one pass. After a failure it backs off exponentially (10 s
// doubling, capped at 10 min) so a persistent error cannot burn CPU every
// tick; ticks inside the window are no-ops.
func (w *Worker) Tick(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if time.Now().Before(w.retryAt) {
		return nil
	}
	if err := w.tick(ctx); err != nil {
		w.failures++
		w.retryAt = time.Now().Add(min(5*time.Second<<min(w.failures, 7), maxBackoff))
		return err
	}
	w.failures, w.retryAt = 0, time.Time{}
	return nil
}

func (w *Worker) tick(ctx context.Context) error {
	start := time.Now()
	for i := 0; i < w.maxWindows && ctx.Err() == nil && time.Since(start) < recordBudget; i++ {
		res, err := w.st.RecordCampaignEvidence(ctx, w.window)
		if err != nil {
			return err
		}
		if !res.Done {
			// A backlog (first start, a burst, or a replace-ingest that
			// rewound the cursor): scheduled regroups wait until it drains,
			// then one runs. A Wake still regroups at once.
			w.drained = false
			continue
		}
		if !w.drained {
			w.drained, w.pending = true, true
		}
		break
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// settle -> assign -> (regroup, rebuild) -> prune, sequentially in this
	// goroutine under w.mu: AssignScriptFamilies and PruneOrphanScripts assume
	// a single sequential caller. Prune frees representatives one level per
	// pass, which is fine at one call per tick.
	if _, err := w.st.SettleSessionScripts(ctx, time.Now().Add(-settleIdle), settleBatch); err != nil {
		return err
	}
	if _, err := w.st.AssignScriptFamilies(ctx, familyBatch); err != nil {
		return err
	}
	woken := w.wake.Swap(false)
	if woken || w.pending || (w.drained && time.Since(w.lastGroup) >= regroupEvery) {
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
			w.pending, w.lastGroup = false, time.Now()
		}
	}
	return w.st.PruneOrphanScripts(ctx)
}

// Regroup recomputes and saves the campaigns now. It shares Tick's lock, so
// it never runs concurrently with a tick or another Regroup.
func (w *Worker) Regroup(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.regroup(ctx)
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
	if err := ctx.Err(); err != nil {
		return err
	}
	out := Group(in)
	rows, assign := groupingRows(out)
	if beforeSave != nil {
		beforeSave()
	}
	if err := w.st.SaveGrouping(ctx, rows, assign, out.Aliases, lastEdit); err != nil {
		return err
	}
	return w.st.RebuildScriptFamilies(ctx, population)
}

// groupingRows maps Group's output onto the store rows. SaveGrouping rejects
// a whole grouping on any empty identifier, so nothing here may produce one:
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
// the file could not be read. Only regular files inside the configured
// evidence root are read (after resolving symlinks on both sides), and the
// content is only classified, never executed. Successful reads are memoised
// (a file hash is immutable); misses are not, so a later capture is picked
// up.
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
	root, err := filepath.EvalSymlinks(w.evidenceRoot)
	if err != nil {
		return unclassified
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil || !within(root, real) {
		return unclassified
	}
	// A FIFO or device would block or misread the classifier.
	if fi, err := os.Lstat(real); err != nil || !fi.Mode().IsRegular() {
		return unclassified
	}
	fam, err := w.classify(real)
	if err != nil {
		return unclassified
	}
	fam = strings.ToLower(fam)
	w.families[sha] = fam
	return fam
}

func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
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
