package cowrie

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

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

// IngestFile is the full-replace ingest: it parses the whole file and replaces
// the cowrie source's events + actors. The replace bool is retained for call-
// site symmetry with the journal ingester and is always true in practice — the
// incremental/append path is IngestFileAppend, which dedups.
func IngestFile(st *store.Store, path string, adminIPs []string, replace bool) (*Result, error) {
	_ = replace // always a full replace; see persistEvents doc comment
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Full replace of a complete static file: process a final line even if it
	// lacks a trailing newline.
	events, skipped, _, bindings, err := parseReader(f, true)
	if err != nil {
		return nil, err
	}
	persistTTYBindings(st, bindings)
	res, err := persistEvents(st, events, adminIPs)
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

	// headSig fingerprints the file's first bytes. copytruncate-style rotation
	// truncates in place and regrows, keeping the inode — so inode+size checks
	// alone can miss it and skip the new content. A changed head signature
	// (vs. the persisted one) means the file was replaced, so reset to 0.
	headSig := headSignature(f)

	// Reset offset if the file was rotated (different inode), truncated, or
	// replaced in place (same inode, different head — copytruncate).
	startOffset := prev.Offset
	rotatedInPlace := prev.Inode == inode && prev.HeadSig != "" && headSig != "" && prev.HeadSig != headSig
	if (prev.Inode != 0 && prev.Inode != inode) || rotatedInPlace {
		backfillRotatedLogs(st, path, adminIPs)
	}
	if prev.Inode != inode || fi.Size() < startOffset || rotatedInPlace {
		startOffset = 0
	}
	if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
		return nil, err
	}

	// Incremental tail: hold back an unterminated final line (cowrie may be
	// mid-write) so we don't consume past it and lose the event.
	events, skipped, consumed, bindings, err := parseReader(f, false)
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
		Source:  models.SourceCowrie,
		Path:    path,
		Inode:   inode,
		Offset:  newOffset,
		HeadSig: headSig,
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
		args := make([]any, 0, len(batch))
		for j, t := range batch {
			placeholders[j] = "?"
			args = append(args, t)
		}
		// Filter on ts only, NOT source. Any `source=...` constraint (param or
		// literal) makes SQLite pick the covering idx_events_identity on the
		// source= prefix and scan EVERY cowrie row in the table; `ts IN (...)`
		// alone uses idx_events_ts as point lookups (both verified via EXPLAIN
		// QUERY PLAN). We re-apply the source filter in Go so semantics are
		// unchanged — a non-cowrie row sharing a ts can't match a cowrie
		// candidate's identity tuple anyway, but filtering keeps it exact.
		query := "SELECT source, ts, kind, src_ip, session_id, username, command FROM events WHERE ts IN (" +
			strings.Join(placeholders, ",") + ")"
		if err := st.QueryRows(query, args, func(scan func(...any) error) error {
			var src string
			var id cowrieIdentity
			if err := scan(&src, &id.TS, &id.Kind, &id.IP, &id.Session, &id.Username, &id.Command); err != nil {
				return err
			}
			if src != string(models.SourceCowrie) {
				return nil
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
		// Best-effort, but surface failures: a corrupt or unreadable rotated
		// log was previously swallowed silently, hiding lost telemetry.
		if _, err := IngestFileAppend(st, p, adminIPs); err != nil {
			log.Printf("cowrie backfill: ingest %s failed: %v", p, err)
		}
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

// persistEvents handles the full-replace ingest (IngestFile, replace=true):
// the events slice IS the entire cowrie universe, so we rebuild every actor
// from it and atomically replace the source's events + actors. There is no
// append branch here on purpose — the append/dedup path is IngestFileAppend,
// which dedups via batchDedupCowrie before writing. A non-replace branch here
// would insert without dedup and double-count on re-ingest, so it is omitted.
func persistEvents(st *store.Store, events []*models.Event, adminIPs []string) (*Result, error) {
	admin := actor.AdminSet(adminIPs)
	actor.AssignCowrieActorIDs(events, admin)
	actors := actor.BuildFromCowrieAggregated(events, admin)
	if err := st.ReplaceSourceEventsAndActorsAgg(models.SourceCowrie, events, actors); err != nil {
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

// headSignature fingerprints the first bytes of a file so the append-mode
// reader can detect copytruncate-style rotation (truncate-in-place + regrow,
// which keeps the inode). Uses ReadAt so the file's read cursor is untouched.
// Returns "" on any error — callers treat an empty/unknown signature as "can't
// tell", falling back to the inode+size heuristic rather than over-resetting.
func headSignature(f *os.File) string {
	buf := make([]byte, 512)
	n, err := f.ReadAt(buf, 0)
	if n == 0 || (err != nil && err != io.EOF) {
		return ""
	}
	sum := sha256.Sum256(buf[:n])
	return hex.EncodeToString(sum[:8]) // 64-bit prefix is plenty for change detection
}

// maxLineBytes caps a single cowrie JSON line. Cowrie logs attacker-controlled
// fields (command input, username, password) verbatim, so a line can be made
// arbitrarily large; we discard anything past this bound rather than buffer it.
const maxLineBytes = 2 * 1024 * 1024

// lineChunk is one logical line read from the cowrie log.
type lineChunk struct {
	data       []byte // line body (without the trailing newline); empty if oversized
	length     int64  // bytes of the body actually on disk (excluding the newline)
	terminated bool   // true if a trailing '\n' was present
	oversized  bool   // true if the line exceeded maxLineBytes and was discarded
}

// readLineBounded reads up to and including the next '\n'. If the line exceeds
// `max`, it keeps draining bytes to the newline (so the caller learns the true
// on-disk length and terminator state, and can advance the offset past the
// poison line) but discards the body to bound memory. The returned error is
// io.EOF when the stream ended; chunk.terminated distinguishes a complete line
// from a partial tail.
func readLineBounded(br *bufio.Reader, max int) (lineChunk, error) {
	var buf []byte
	var length int64
	oversized := false
	for {
		b, err := br.ReadByte()
		if err != nil {
			return lineChunk{data: buf, length: length, terminated: false, oversized: oversized}, err
		}
		if b == '\n' {
			return lineChunk{data: buf, length: length, terminated: true, oversized: oversized}, nil
		}
		length++
		if int64(len(buf)) < int64(max) {
			buf = append(buf, b)
		} else if !oversized {
			oversized = true
			buf = nil // drop what we accumulated; we only drain to the newline now
		}
	}
}

// parseReader returns parsed events, the count of skipped/malformed lines,
// and the exact number of bytes consumed (newline-terminated). The byte count
// lets IngestFileAppend advance the persisted offset accurately.
//
// processFinalPartial controls the unterminated trailing line:
//   - false (incremental append): a final line without '\n' is treated as a
//     partial mid-write — NOT parsed and NOT counted in `consumed`, so the
//     offset stays before it and it is re-read once cowrie finishes the line.
//   - true (full-replace of a complete static file): the trailing line is a
//     legitimate final record and is parsed.
func parseReader(r io.Reader, processFinalPartial bool) ([]*models.Event, int, int64, []ttyBinding, error) {
	var out []*models.Event
	var bindings []ttyBinding
	var skipped int
	var consumed int64

	// We use bufio.Reader (not bufio.Scanner) deliberately. Scanner aborts the
	// whole parse with ErrTooLong on a single over-long line, and since the
	// caller advances the persisted offset by `consumed`, a return-without-
	// progress permanently stalls incremental ingest at that byte (an attacker
	// can trigger this with one giant SSH command). With a reader we can skip a
	// poison line yet still advance past it, and we can tell a newline-
	// terminated line from a partial tail (cowrie mid-write) so we don't count
	// the partial line in `consumed` and lose it.
	br := bufio.NewReaderSize(r, 256*1024)
	for {
		chunk, err := readLineBounded(br, maxLineBytes)
		if len(chunk.data) == 0 && chunk.terminated && err == nil {
			// Empty (blank) line with terminator: count its byte and move on.
			consumed++
			continue
		}
		if !chunk.terminated {
			// No trailing newline: an incomplete final line. For incremental
			// ingest, leave the offset before it so it's re-read once complete.
			// For a full replace of a complete file, process it as the last
			// record. Oversized unterminated tails are always discarded.
			if processFinalPartial && !chunk.oversized && len(chunk.data) > 0 {
				if line := strings.TrimSpace(string(chunk.data)); line != "" {
					if rec, ok := decodeCowrieLine(line, &bindings); ok {
						if e, ok := toEvent(rec, line); ok {
							out = append(out, e)
						} else {
							skipped++
						}
					} else {
						skipped++
					}
				}
			}
			break
		}

		// A complete line: its bytes plus the newline are durably consumed,
		// whether or not it parses.
		consumed += chunk.length + 1

		if chunk.oversized {
			// Line exceeded the cap; we discarded its body but consumed its
			// bytes so ingest advances instead of wedging. Count as skipped.
			skipped++
			if err != nil {
				break
			}
			continue
		}

		if line := strings.TrimSpace(string(chunk.data)); line != "" {
			if rec, ok := decodeCowrieLine(line, &bindings); ok {
				if e, ok := toEvent(rec, line); ok {
					out = append(out, e)
				} else {
					skipped++
				}
			} else {
				skipped++
			}
		}

		if err != nil {
			break // io.EOF after a fully-terminated line
		}
	}
	return out, skipped, consumed, bindings, nil
}

// decodeCowrieLine unmarshals one JSON line into a cowrieLine. It also captures
// the cowrie.log.closed sha->session sidechannel binding (appended to *bindings)
// rather than surfacing it as a top-level event, to keep MITRE/IOC/UI free of
// cowrie's own log-rotation noise. Returns ok=false on malformed JSON.
func decodeCowrieLine(line string, bindings *[]ttyBinding) (cowrieLine, bool) {
	var rec cowrieLine
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		return cowrieLine{}, false
	}
	if rec.EventID == "cowrie.log.closed" && rec.SHA256 != "" && rec.Session != "" {
		if ts, ok := parseTS(rec.Timestamp); ok {
			*bindings = append(*bindings, ttyBinding{
				SHA:       strings.ToLower(strings.TrimSpace(rec.SHA256)),
				SessionID: rec.Session,
				TS:        ts,
			})
		}
	}
	return rec, true
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
		Username:  clip(r.Username, maxFieldBytes),
		Password:  clip(r.Password, maxFieldBytes),
		SessionID: r.Session,
		HASSH:     r.HASSH,
		SSHClient: clip(sshClient, maxFieldBytes),
		Command:   clip(command, maxFieldBytes),
		SHA256:    strings.TrimSpace(r.SHA256),
		Filename:  clip(filename, maxFieldBytes),
		Raw:       clip(raw, maxRawBytes),
	}, true
}

// Field caps bound how much attacker-controlled text we persist per event.
// Real cowrie commands/usernames are far smaller; these only fence off abuse
// (a multi-hundred-KB "command") so the DB, in-memory event batches, and the
// dashboard can't be bloated by a single crafted line. Truncation is a pure
// byte-prefix so it stays deterministic — the dedup identity tuple includes
// username+command, and a stable prefix keeps re-ingest dedup correct.
const (
	maxFieldBytes = 64 * 1024
	maxRawBytes   = 256 * 1024
)

// clip truncates s to at most max bytes, on a UTF-8 rune boundary so we never
// emit an invalid trailing rune.
func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func mapKind(eventID string) (models.EventKind, bool) {
	switch eventID {
	case "cowrie.login.failed":
		return models.KindFailedPass, true
	case "cowrie.login.success":
		return models.KindAccepted, true
	case "cowrie.session.connect":
		return models.KindConnect, true
	case "cowrie.client.version":
		// Distinct from the connection itself: this is the client's identity
		// banner (hassh/ssh_client). Kept as its own kind so it is not counted
		// as a second connect for the same session. See KindClientVersion.
		return models.KindClientVersion, true
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
