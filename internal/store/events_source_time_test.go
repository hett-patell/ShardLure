package store

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/networkshard/shardlure/pkg/models"
)

func TestEventSourceAndActorStreamsUseExactTimeAndStableIDs(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "events-source-time.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	texts := []string{
		"2026-01-01T01:00:00+02:00",
		"2026-01-01T00:00:00Z",
		"2026-01-01T00:00:00.100000000Z",
		"2026-01-01T00:00:00.100000000Z",
	}
	var ids []int64
	for _, ts := range texts {
		res, err := st.db.Exec(`INSERT INTO events(ts,source,kind,actor_id) VALUES(?,?,?,?)`,
			ts, models.SourceCowrie, models.KindConnect, "cowrie:test")
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		ids = append(ids, id)
	}
	want := []int64{ids[0], ids[1], ids[2], ids[3]}
	var sourceIDs []int64
	if err := st.IterateEventsBySource(models.SourceCowrie, func(e *models.Event) error {
		sourceIDs = append(sourceIDs, e.ID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sourceIDs, want) {
		t.Fatalf("source IDs=%v, want %v", sourceIDs, want)
	}
	var actorIDs []int64
	if err := st.IterateEventsByActorIDs([]string{"cowrie:test"}, func(e *models.Event) error {
		actorIDs = append(actorIDs, e.ID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actorIDs, want) {
		t.Fatalf("actor IDs=%v, want %v", actorIDs, want)
	}
}

func TestEventSourceStreamsRejectMalformedTime(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "events-source-malformed.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.db.Exec(`INSERT INTO events(ts,source,kind,actor_id) VALUES('not-a-time','cowrie','connect','cowrie:bad')`); err != nil {
		t.Fatal(err)
	}
	if err := st.IterateEventsBySource(models.SourceCowrie, func(*models.Event) error { return nil }); err == nil || !strings.Contains(err.Error(), "event") {
		t.Fatalf("source stream error=%v, want contextual parse failure", err)
	}
	if err := st.IterateEventsByActorIDs([]string{"cowrie:bad"}, func(*models.Event) error { return nil }); err == nil || !strings.Contains(err.Error(), "event") {
		t.Fatalf("actor stream error=%v, want contextual parse failure", err)
	}
}
