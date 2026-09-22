package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func TestRemapOnlyStorageAndReplayPointers(t *testing.T) {
	st := newTestStore(t, "source.db")
	old := t.TempDir()
	target := t.TempDir()
	if err := st.UpsertArtifact(Artifact{TS: time.Now(), URL: "inert", LocalPath: filepath.Join(old, "evidence", "blob")}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertEvent(&models.Event{TS: time.Now(), Source: models.SourceCowrie, Kind: models.KindCommand, Command: old}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetIngestState(IngestState{Source: models.SourceCowrie, Path: filepath.Join(old, "logs", "cowrie.json"), Inode: 123, Offset: 999, HeadSig: "old"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "snapshot.db")
	if _, err := SnapshotDatabase(context.Background(), st.path, path); err != nil {
		t.Fatal(err)
	}
	src := map[string]string{"evidence": filepath.Join(old, "evidence"), "cowrie-logs": filepath.Join(old, "logs")}
	dst := map[string]string{"evidence": filepath.Join(target, "evidence"), "cowrie-logs": filepath.Join(target, "logs")}
	if err := RemapSnapshotPaths(context.Background(), path, src, dst); err != nil {
		t.Fatal(err)
	}
	db := snapshotTestDB(t, path)
	var local, command, replay string
	var inode, offset int
	if err := db.QueryRow("SELECT local_path FROM artifacts").Scan(&local); err != nil || local != filepath.Join(target, "evidence", "blob") {
		t.Fatalf("artifact remap %q %v", local, err)
	}
	if err := db.QueryRow("SELECT command FROM events").Scan(&command); err != nil || command != old {
		t.Fatal("event evidence was rewritten")
	}
	if err := db.QueryRow("SELECT path,inode,offset FROM ingest_state WHERE source='cowrie'").Scan(&replay, &inode, &offset); err != nil || replay != filepath.Join(target, "logs", "cowrie.json") || inode != 0 || offset != 0 {
		t.Fatalf("unsafe replay cursor %q %d %d %v", replay, inode, offset, err)
	}
	checked, err := InspectSnapshot(context.Background(), path)
	if err != nil || checked.Schema != 24 {
		t.Fatalf("remap changed schema or journal state: %+v %v", checked, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := RemapSnapshotPaths(ctx, path, src, dst); !errors.Is(err, context.Canceled) {
		t.Fatalf("remap cancellation lost: %v", err)
	}
}

func TestRemapOlderSchemaAndRejectsExecutableTriggers(t *testing.T) {
	for _, trigger := range []bool{false, true} {
		t.Run(fmt.Sprint(trigger), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "old.db")
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.Exec("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY); INSERT INTO schema_migrations VALUES(1); CREATE TABLE events(id INTEGER PRIMARY KEY,command TEXT); CREATE TABLE actors(id TEXT PRIMARY KEY,notes TEXT); INSERT INTO actors VALUES('inert','operator note'); CREATE TABLE artifacts(id INTEGER PRIMARY KEY,local_path TEXT); INSERT INTO artifacts VALUES(1,'/old/blob')")
			if err != nil {
				db.Close()
				t.Fatal(err)
			}
			if trigger {
				if _, err := db.Exec("CREATE TRIGGER surprise AFTER UPDATE OF local_path ON artifacts BEGIN UPDATE actors SET notes='wrong'; END"); err != nil {
					db.Close()
					t.Fatal(err)
				}
			}
			db.Close()
			err = RemapSnapshotPaths(context.Background(), path, map[string]string{"evidence": "/old"}, map[string]string{"evidence": "/new"})
			if trigger && err == nil {
				t.Fatal("untrusted remap trigger executed")
			}
			if !trigger && err != nil {
				t.Fatal(err)
			}
			checked, err := InspectSnapshot(context.Background(), path)
			if err != nil || checked.Schema != 1 {
				t.Fatalf("old source migrated: %+v %v", checked, err)
			}
			inspect := snapshotTestDB(t, path)
			var note, local string
			if err := inspect.QueryRow("SELECT notes FROM actors").Scan(&note); err != nil || note != "operator note" {
				t.Fatal("non-path data modified")
			}
			want := "/new/blob"
			if trigger {
				want = "/old/blob"
			}
			if err := inspect.QueryRow("SELECT local_path FROM artifacts").Scan(&local); err != nil || local != want {
				t.Fatalf("unexpected storage mutation %q %v", local, err)
			}
		})
	}
}

func TestRemapRejectsUnusableStoredDestinations(t *testing.T) {
	for _, to := range []string{"/new/\x00invalid", "/new/\xff", "/new/" + strings.Repeat("a", 4096)} {
		if _, err := remapStoredPath("/old/blob", "evidence", map[string]string{"evidence": "/old"}, map[string]string{"evidence": to}); err == nil {
			t.Error("unusable path would be persisted")
		}
	}
}
