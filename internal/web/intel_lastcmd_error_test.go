package web

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

// TestIntelLastCommandErrorIsLoggedNotFatal: LastCommandsForActors names
// idx_events_actor_cmd via INDEXED BY, so an out-of-band DROP INDEX (healed
// only at the next Open) fails the read on every poll. /api/intel must still
// render its actors with a blank "Last cmd" column, and the failure must reach
// the log once per window, never as the raw SQL error.
func TestIntelLastCommandErrorIsLoggedNotFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lastcmd.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatalf("settings.Load: %v", err)
	}
	s := New(st, keys, "127.0.0.1:0")
	now := time.Now().UTC()
	if err := st.UpsertActor(&models.Actor{
		ID: "cowrie:10.9.9.9", Source: models.SourceCowrie, PrimaryIP: "10.9.9.9",
		FirstSeen: now.Add(-time.Hour), LastSeen: now, EventCount: 3,
	}); err != nil {
		t.Fatalf("UpsertActor: %v", err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := raw.Exec(`DROP INDEX idx_events_actor_cmd`); err != nil {
		t.Fatalf("drop index: %v", err)
	}
	_ = raw.Close()
	if _, err := st.LastCommandsForActors([]string{"cowrie:10.9.9.9"}); err == nil {
		t.Fatal("precondition: LastCommandsForActors should fail without its index")
	}

	var buf bytes.Buffer
	prev, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(prevFlags) })

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		s.handleIntel(rec, httptest.NewRequest(http.MethodGet, "/api/intel", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("poll %d = %d %s", i, rec.Code, rec.Body.String())
		}
		var d struct {
			Actors []intelActorRow `json:"actors"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
			t.Fatalf("poll %d decode: %v", i, err)
		}
		if len(d.Actors) != 1 || d.Actors[0].LastCommand != "" {
			t.Fatalf("poll %d actors = %+v, want the one actor with a blank last command", i, d.Actors)
		}
	}
	out := buf.String()
	if n := strings.Count(out, "web: intel_last_command: operation_failed"); n != 1 {
		t.Fatalf("last-command failure logged %d times, want once per window:\n%s", n, out)
	}
	if strings.Contains(out, "no such index") {
		t.Fatal("raw store error reached the log")
	}
}
