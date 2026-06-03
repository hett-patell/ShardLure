package cowrie

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/actor"
	"github.com/networkshard/shardlure/internal/netmatch"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

type Result struct {
	Events  int
	Actors  int
	Skipped int
}

type cowrieLine struct {
	EventID     string `json:"eventid"`
	Timestamp   string `json:"timestamp"`
	SrcIP       string `json:"src_ip"`
	SrcPort     any    `json:"src_port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	Session     string `json:"session"`
	HASSH       string `json:"hassh"`
	SSHVersion  string `json:"version"`
	Input       string `json:"input"`
	Message     string `json:"message"`
	URL         string `json:"url"`
	Outfile     string `json:"outfile"`
	Filename    string `json:"filename"`
	DstPath     string `json:"destfile"`
	SHA256      string `json:"shasum"`
	Fingerprint string `json:"fingerprint"`
}

func IngestFile(st *store.Store, path string, adminIPs []string, replace bool) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	events, skipped, _, bindings, err := parseReader(f)
	if err != nil {
		return nil, err
	}
	persistTTYBindings(st, bindings)
	res, err := persistEvents(st, events, adminIPs, replace)
	if res != nil {
		res.Skipped = skipped
	}
	return res, err
}

func IngestFileAppend(st *store.Store, path string, adminIPs []string) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Result{}, nil
		}
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	inode := fileInode(fi)

	prev, _, err := st.GetIngestState(models.SourceCowrie, path)
	if err != nil {
		return nil, err
	}

	// Reset offset if the file was rotated (different inode) or truncated.
	startOffset := prev.Offset
	if prev.Inode != 0 && prev.Inode != inode {
		backfillRotatedLogs(st, path, adminIPs)
	}
	if prev.Inode != inode || fi.Size() < startOffset {
		startOffset = 0
	}
	if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
		return nil, err
	}

	events, skipped, consumed, bindings, err := parseReader(f)
	if err != nil {
		return nil, err
	}
	persistTTYBindings(st, bindings)

	// Advance offset by exactly the bytes the scanner consumed, not by
	// fi.Size(): cowrie may have appended more bytes between Stat() and
	// EOF, and we don't want to claim those bytes were scanned.
	newOffset := startOffset + consumed
	if newOffset > fi.Size() {
		newOffset = fi.Size()
	}
	newState := store.IngestState{
		Source: models.SourceCowrie,
		Path:   path,
		Inode:  inode,
		Offset: newOffset,
	}

	fresh, err := batchDedupCowrie(st, events)
	if err != nil {
		return nil, err
	}
	if len(fresh) == 0 {
		if err := st.SetIngestState(newState); err != nil {
			return nil, err
		}
		return &Result{Skipped: skipped}, nil
	}
	res, err := syncCowrieActors(st, fresh, adminIPs)
	if res != nil {
		res.Skipped = skipped
	}
	if err != nil {
		return res, err
	}
	if err := st.SetIngestState(newState); err != nil {
		return res, err
	}
	return res, nil
}

// batchDedupCowrie filters events that already exist in the DB. Identity
// matches store.EventExists (source, kind, ts, src_ip, session_id,
// username, command). Uses a single IN-list query over ts to avoid the
// previous N+1 EventExists pattern.
func batchDedupCowrie(st *store.Store, candidates []*models.Event) ([]*models.Event, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	tsSet := make(map[string]struct{}, len(candidates))
	for _, e := range candidates {
		tsSet[e.TS.UTC().Format(time.RFC3339Nano)] = struct{}{}
	}
	tsList := make([]string, 0, len(tsSet))
	for t := range tsSet {
		tsList = append(tsList, t)
	}
	existing := make(map[cowrieIdentity]struct{}, len(tsList))
	const chunk = 400
	for i := 0; i < len(tsList); i += chunk {
		end := i + chunk
		if end > len(tsList) {
			end = len(tsList)
		}
		batch := tsList[i:end]
		placeholders := make([]string, len(batch))
		args := make([]any, 0, len(batch)+1)
		args = append(args, models.SourceCowrie)
		for j, t := range batch {
			placeholders[j] = "?"
			args = append(args, t)
		}
		query := "SELECT ts, kind, src_ip, session_id, username, command FROM events WHERE source=? AND ts IN (" +
			strings.Join(placeholders, ",") + ")"
		if err := st.QueryRows(query, args, func(scan func(...any) error) error {
			var id cowrieIdentity
			if err := scan(&id.TS, &id.Kind, &id.IP, &id.Session, &id.Username, &id.Command); err != nil {
				return err
			}
			existing[id] = struct{}{}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	out := make([]*models.Event, 0, len(candidates))
	for _, e := range candidates {
		id := cowrieIdentity{
			TS:       e.TS.UTC().Format(time.RFC3339Nano),
			Kind:     e.Kind,
			IP:       e.SrcIP,
			Session:  e.SessionID,
			Username: e.Username,
			Command:  e.Command,
		}
		if _, ok := existing[id]; ok {
			continue
		}
		existing[id] = struct{}{}
		out = append(out, e)
	}
	return out, nil
}

// persistTTYBindings stores cowrie ttylog sha->session bindings so the
// capture pass can stamp session_id onto cowrie-tty artifacts. Best
// effort: a write failure here is logged via the store's normal error
// path but does not block event ingest.
func persistTTYBindings(st *store.Store, bindings []ttyBinding) {
	for _, b := range bindings {
		_ = st.RecordCowrieTTYBinding(b.SHA, b.SessionID, b.TS)
	}
}

type cowrieIdentity struct {
	TS       string
	Kind     models.EventKind
	IP       string
	Session  string
	Username string
	Command  string
}

// BackfillRotatedLogs ingests cowrie.json.* siblings (historical rotated logs).
func BackfillRotatedLogs(st *store.Store, currentPath string, adminIPs []string) {
	backfillRotatedLogs(st, currentPath, adminIPs)
}

// backfillRotatedLogs ingests cowrie.json.YYYY-MM-DD siblings when the active log rotates.
func backfillRotatedLogs(st *store.Store, currentPath string, adminIPs []string) {
	dir := filepath.Dir(currentPath)
	base := filepath.Base(currentPath)
	matches, err := filepath.Glob(filepath.Join(dir, base+".*"))
	if err != nil {
		return
	}
	for _, p := range matches {
		if p == currentPath {
			continue
		}
		_, _ = IngestFileAppend(st, p, adminIPs)
	}
}

// syncCowrieActors re-aggregates only the cowrie actors the fresh batch
// touched, instead of streaming the entire cowrie event history every tick.
// For each touched actor ID it streams just that actor's persisted events
// (served by idx_events_actor), folds in the fresh in-memory events, and
// upserts the result — leaving every untouched actor exactly as it was. A live
// ingest tick is now O(events-for-touched-actors) rather than O(all history).
//
// Correctness: a cowrie actor's aggregate depends only on its own events, and
// AssignCowrieActorIDs stamps each fresh event with its actor ID, so the
// touched-ID set is exactly the actors whose aggregate can change. Admin
// events get a blank ActorID and are excluded.
func syncCowrieActors(st *store.Store, fresh []*models.Event, adminIPs []string) (*Result, error) {
	admin := actor.AdminSet(adminIPs)
	actor.AssignCowrieActorIDs(fresh, admin)

	touched := touchedActorIDs(fresh)
	if len(touched) == 0 {
		// Only admin/skipped events in this batch — persist them but touch no
		// actors. (Events are still recorded for telemetry completeness.)
		if err := st.AppendEventsAndUpsertActorsAgg(fresh, nil); err != nil {
			return nil, err
		}
		return &Result{Events: len(fresh), Actors: 0}, nil
	}

	actors, err := buildCowrieActorsForIDs(st, fresh, touched, admin)
	if err != nil {
		return nil, err
	}
	if err := st.AppendEventsAndUpsertActorsAgg(fresh, actors); err != nil {
		return nil, err
	}
	return &Result{Events: len(fresh), Actors: len(actors)}, nil
}

// touchedActorIDs returns the distinct non-empty actor IDs stamped on the
// fresh events (admin events have a blank ID and are skipped).
func touchedActorIDs(fresh []*models.Event) []string {
	seen := map[string]struct{}{}
	var ids []string
	for _, e := range fresh {
		if e == nil || e.ActorID == "" {
			continue
		}
		if _, ok := seen[e.ActorID]; ok {
			continue
		}
		seen[e.ActorID] = struct{}{}
		ids = append(ids, e.ActorID)
	}
	return ids
}

// buildCowrieActorsForIDs streams the persisted events for just the touched
// actor IDs past the collector, folds in the fresh batch, and returns the
// aggregated actors for those IDs only.
func buildCowrieActorsForIDs(st *store.Store, fresh []*models.Event, ids []string, admin *netmatch.Set) ([]*models.AggregatedActor, error) {
	cc := actor.NewCowrieCollector(admin)
	if err := st.IterateEventsByActorIDs(ids, func(e *models.Event) error {
		cc.Add(e)
		return nil
	}); err != nil {
		return nil, err
	}
	for _, e := range fresh {
		cc.Add(e)
	}
	return cc.Finalize(), nil
}

// buildCowrieActorsFromDB streams persisted cowrie events past the actor
// collector (so the full event set never lives in memory) and folds in the
// fresh batch before producing aggregated actors.
func buildCowrieActorsFromDB(st *store.Store, fresh []*models.Event, admin *netmatch.Set) ([]*models.AggregatedActor, error) {
	cc := actor.NewCowrieCollector(admin)
	if err := st.IterateEventsBySource(models.SourceCowrie, func(e *models.Event) error {
		cc.Add(e)
		return nil
	}); err != nil {
		return nil, err
	}
	for _, e := range fresh {
		cc.Add(e)
	}
	return cc.Finalize(), nil
}

func persistEvents(st *store.Store, events []*models.Event, adminIPs []string, replace bool) (*Result, error) {
	admin := actor.AdminSet(adminIPs)
	actor.AssignCowrieActorIDs(events, admin)
	if replace {
		// Replace: events slice IS the universe. No DB scan needed.
		actors := actor.BuildFromCowrieAggregated(events, admin)
		if err := st.ReplaceSourceEventsAndActorsAgg(models.SourceCowrie, events, actors); err != nil {
			return nil, fmt.Errorf("persist cowrie events and actors: %w", err)
		}
		return &Result{Events: len(events), Actors: len(actors)}, nil
	}
	actors, err := buildCowrieActorsFromDB(st, events, admin)
	if err != nil {
		return nil, err
	}
	if err := st.AppendEventsAndReplaceActorsAgg(models.SourceCowrie, events, actors); err != nil {
		return nil, fmt.Errorf("persist cowrie events and actors: %w", err)
	}
	return &Result{Events: len(events), Actors: len(actors)}, nil
}

// ttyBinding pairs a closed cowrie ttylog (named by its sha256) with the
// session that produced it. Cowrie emits this mapping in
// `cowrie.log.closed` events, which we DON'T persist as regular events
// (no useful kind), so we surface them as a side output of parsing.
type ttyBinding struct {
	SHA       string
	SessionID string
	TS        time.Time
}

// parseReader returns parsed events, the count of skipped/malformed lines,
// and the exact number of bytes consumed by the scanner. The byte count is
// used by IngestFileAppend to advance the persisted offset accurately,
// without skipping a partial line at the tail if the writer (cowrie) appended
// more data while we were reading.
func parseReader(r io.Reader) ([]*models.Event, int, int64, []ttyBinding, error) {
	var out []*models.Event
	var bindings []ttyBinding
	var skipped int
	var consumed int64
	sc := bufio.NewScanner(r)
	buf := make([]byte, 0, 256*1024)
	sc.Buffer(buf, 2*1024*1024)
	for sc.Scan() {
		raw := sc.Bytes()
		// +1 for the line terminator the scanner already stripped.
		// (Last line may lack one; we don't advance the offset past EOF
		// so the extra +1 there is harmless — capped by the actual file size.)
		consumed += int64(len(raw)) + 1
		line := strings.TrimSpace(string(raw))
		if line == "" {
			continue
		}
		var rec cowrieLine
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			skipped++
			continue
		}
		// Sidechannel: cowrie.log.closed carries the sha->session
		// binding for a freshly-renamed ttylog. We capture it here
		// rather than turning it into a top-level event kind to
		// avoid polluting MITRE/IOC/UI surfaces with operational
		// noise from cowrie's own log rotation.
		if rec.EventID == "cowrie.log.closed" && rec.SHA256 != "" && rec.Session != "" {
			if ts, ok := parseTS(rec.Timestamp); ok {
				bindings = append(bindings, ttyBinding{
					SHA:       strings.ToLower(strings.TrimSpace(rec.SHA256)),
					SessionID: rec.Session,
					TS:        ts,
				})
			}
		}
		e, ok := toEvent(rec, line)
		if !ok {
			skipped++
			continue
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, skipped, consumed, nil, err
	}
	return out, skipped, consumed, bindings, nil
}

func toEvent(r cowrieLine, raw string) (*models.Event, bool) {
	if r.SrcIP == "" {
		return nil, false
	}
	kind, ok := mapKind(r.EventID)
	if !ok {
		return nil, false
	}
	ts, ok := parseTS(r.Timestamp)
	if !ok {
		return nil, false
	}
	srcPort := toInt(r.SrcPort)
	// Command captures the actual shell input from `cowrie.command.input`
	// events, or the fetched URL on `file_download`. We must NOT fall
	// back to r.Message: that field carries human-readable banners like
	// "Remote SSH version: ..." and "login attempt [...] failed" on
	// connect / failed-password events, which would pollute Top
	// Commands and any IOC extraction that walks the command column.
	command := strings.TrimSpace(r.Input)
	if command == "" && (kind == models.KindFileUp || kind == models.KindFileDown) && r.URL != "" {
		command = strings.TrimSpace(r.URL)
	}
	filename := r.Filename
	if filename == "" {
		filename = r.Outfile
	}
	if filename == "" {
		filename = r.DstPath
	}
	sshClient := r.SSHVersion
	if sshClient == "" {
		sshClient = r.Fingerprint
	}
	return &models.Event{
		TS:        ts,
		Source:    models.SourceCowrie,
		Kind:      kind,
		SrcIP:     r.SrcIP,
		SrcPort:   srcPort,
		Username:  r.Username,
		Password:  r.Password,
		SessionID: r.Session,
		HASSH:     r.HASSH,
		SSHClient: sshClient,
		Command:   command,
		SHA256:    strings.TrimSpace(r.SHA256),
		Filename:  filename,
		Raw:       raw,
	}, true
}

func mapKind(eventID string) (models.EventKind, bool) {
	switch eventID {
	case "cowrie.login.failed":
		return models.KindFailedPass, true
	case "cowrie.login.success":
		return models.KindAccepted, true
	case "cowrie.client.version", "cowrie.session.connect":
		return models.KindConnect, true
	case "cowrie.command.input":
		return models.KindCommand, true
	case "cowrie.session.file_upload":
		return models.KindFileUp, true
	case "cowrie.session.file_download":
		return models.KindFileDown, true
	case "cowrie.direct-tcpip.request", "cowrie.tunnel.local", "cowrie.tunnel.remote":
		return models.KindTunnel, true
	default:
		return "", false
	}
}

func parseTS(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05.000000Z",
		"2006-01-02T15:04:05Z",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func toInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case string:
		i, _ := strconv.Atoi(strings.TrimSpace(n))
		return i
	default:
		return 0
	}
}
