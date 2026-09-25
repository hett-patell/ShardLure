package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func TestPopulatedLegacyEventProjectionsAfterMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT,ts TEXT NOT NULL,source TEXT NOT NULL,kind TEXT NOT NULL,src_ip TEXT,username TEXT);
INSERT INTO events(ts,source,kind) VALUES('2026-07-03T11:00:00Z','cowrie','command')`)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Optional columns added to a populated table remain NULL, as do values
	// omitted by older producers. Supply identifiers only to select this row.
	if _, err := s.execWrite(`UPDATE events SET session_id='legacy',actor_id='cowrie:legacy',command='id',src_port=NULL,dst_port=NULL`); err != nil {
		t.Fatal(err)
	}
	since := time.Date(2026, 7, 3, 10, 0, 0, 0, time.UTC)
	check := func(e *models.Event) error {
		if e.Password != "" || e.HASSH != "" || e.SrcPort != 0 || e.DstPort != 0 || e.SrcIP != "" || e.Username != "" {
			t.Errorf("legacy optional values=%+v", e)
		}
		return nil
	}
	tests := map[string]func() error{
		"source":        func() error { return s.IterateEventsBySource(models.SourceCowrie, check) },
		"actor":         func() error { return s.IterateEventsByActorIDs([]string{"cowrie:legacy"}, check) },
		"window stream": func() error { return s.IterateEventsSince(since, check) },
		"window capped": func() error {
			rows, total, err := s.EventsSinceCapped(since, 10)
			if err == nil {
				if len(rows) != 1 || total != 1 {
					t.Errorf("rows=%d total=%d", len(rows), total)
				}
				for _, e := range rows {
					check(e)
				}
			}
			return err
		},
		"session": func() error {
			rows, err := s.SessionEvents("legacy")
			if err == nil {
				for _, e := range rows {
					check(e)
				}
			}
			return err
		},
		"recent":   func() error { _, err := s.RecentEvents(10); return err },
		"commands": func() error { _, err := s.RecentCommandEvents(10); return err },
	}
	for name, fn := range tests {
		t.Run(name, func(t *testing.T) {
			if err := fn(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
