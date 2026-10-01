package backup

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/ingest/cowrie"
	"github.com/networkshard/shardlure/internal/safefile"
	"github.com/networkshard/shardlure/internal/store"
)

func TestRestoreReplayRebasesCursorWithoutDuplicatingEvents(t *testing.T) {
	f := newFixture(t)
	log := `{"eventid":"cowrie.command.input","input":"echo inert","session":"inert-session","src_ip":"192.0.2.23","timestamp":"2026-09-21T01:00:00Z"}` + "\n"
	if err := os.WriteFile(f.SourceLog, []byte(log), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := cowrie.IngestFileAppend(f.Store, f.SourceLog, nil); err != nil {
		t.Fatal(err)
	}
	before, err := f.Store.EventCount()
	if err != nil || before != 4 {
		t.Fatalf("fixture ingest=%d %v", before, err)
	}
	bundle := filepath.Join(t.TempDir(), "backup")
	if _, err := Create(context.Background(), CreateOptions{ConfigPath: f.Config, Output: bundle}); err != nil {
		t.Fatal(err)
	}
	to := filepath.Join(t.TempDir(), "restore")
	if _, err := Restore(context.Background(), RestoreOptions{Input: bundle, To: to}); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(filepath.Join(to, "shardlure.recovery.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	restored, err := store.Open(filepath.Join(to, "shardlure.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if _, err := cowrie.IngestFileAppend(restored, cfg.Cowrie.JSONLog, nil); err != nil {
		t.Fatal(err)
	}
	after, err := restored.EventCount()
	if err != nil || after != 4 {
		t.Fatalf("recovery replay duplicated history: %d %v", after, err)
	}
}

func TestBackupHonorsExplicitOperationDeadline(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	ops := nativeOperations()
	nativeCopy := ops.copy
	ops.copy = func(ctx context.Context, role string, w io.Writer, r io.Reader, n int64) (int64, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) < time.Hour {
			return 0, errors.New("explicit deadline was shortened")
		}
		return nativeCopy(ctx, role, w, r, n)
	}
	if _, err := createWithOperations(ctx, CreateOptions{ConfigPath: f.Config, Output: filepath.Join(t.TempDir(), "backup")}, ops); err != nil {
		t.Fatalf("--timeout override ignored: %v", err)
	}
}

func TestRestoreRoundTripPreservesLogicalData(t *testing.T) {
	f := newFixture(t)
	// A one-off import can leave a checkpoint outside the configured live-log
	// root. It is historical metadata, not a source the restore may open or a
	// reason to make an otherwise complete evidence backup unrestorable.
	imports := []string{filepath.Join(t.TempDir(), "archive.json"), filepath.Join(t.TempDir(), "archive.json")}
	for _, path := range imports {
		if err := f.Store.SetIngestState(store.IngestState{Source: "cowrie", Path: path, Inode: 123, Offset: 999, HeadSig: "old"}); err != nil {
			t.Fatal(err)
		}
	}
	bundle := filepath.Join(t.TempDir(), "backup")
	m, err := Create(context.Background(), CreateOptions{ConfigPath: f.Config, Output: bundle})
	if err != nil {
		t.Fatal(err)
	}
	to := filepath.Join(t.TempDir(), "recovered")
	report, err := Restore(context.Background(), RestoreOptions{Input: bundle, To: to})
	if err != nil || report.TableCounts["events"] != 3 {
		t.Fatalf("restore %+v %v", report, err)
	}
	b, err := os.ReadFile(filepath.Join(to, "evidence", "quarantine", fixtureHash()))
	if err != nil || string(b) != inertEvidence {
		t.Fatal("restored evidence differs")
	}
	db, err := sql.Open("sqlite", filepath.Join(to, "shardlure.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, path := range imports {
		var inode, offset int64
		var head string
		if err := db.QueryRow("SELECT inode,offset,head_sig FROM ingest_state WHERE source='cowrie' AND path=?", path).Scan(&inode, &offset, &head); err != nil || inode != 0 || offset != 0 || head != "" {
			t.Fatalf("historical import checkpoint lost or left active: inode=%d offset=%d head=%q err=%v", inode, offset, head, err)
		}
	}
	var note, value, local string
	var events, ledger int
	if err := db.QueryRow("SELECT notes FROM actors").Scan(&note); err != nil || note != "operator note" {
		t.Fatal("operator annotation lost")
	}
	if err := db.QueryRow("SELECT value FROM app_settings WHERE key='fixture.key'").Scan(&value); err != nil || value != "never-send-fixture-value" {
		t.Fatal("settings modified")
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM events").Scan(&events); err != nil || events != 3 {
		t.Fatal("events lost")
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM urlhaus_submissions").Scan(&ledger); err != nil || ledger != 1 {
		t.Fatal("submission ledger lost")
	}
	if err := db.QueryRow("SELECT local_path FROM artifacts LIMIT 1").Scan(&local); err != nil || local != filepath.Join(to, "evidence", "quarantine", fixtureHash()) {
		t.Fatalf("dangling old evidence path %q %v", local, err)
	}
	cfg, err := config.Load(filepath.Join(to, "shardlure.recovery.yaml"))
	if err != nil || cfg.DataDir != to || cfg.Capture.Enabled || cfg.RetentionDays != 0 {
		t.Fatalf("unsafe recovery configuration: %v", err)
	}
	original, err := os.ReadFile(f.Config)
	if err != nil {
		t.Fatal(err)
	}
	preserved, err := os.ReadFile(filepath.Join(to, "metadata", "config.yaml"))
	if err != nil || string(original) != string(preserved) {
		t.Fatal("original config not preserved")
	}
	if _, err := os.Stat(filepath.Join(to, "recovery-report.json")); err != nil {
		t.Fatal(err)
	}
	checked, err := Verify(context.Background(), bundle)
	if err != nil || checked.Schema != m.Schema || checked.TableCounts["events"] != 3 {
		t.Fatalf("source bundle modified: %v", err)
	}
}

func TestRestoreDryRunAndDestinationSafety(t *testing.T) {
	f := newFixture(t)
	bundle := filepath.Join(t.TempDir(), "backup")
	if _, err := Create(context.Background(), CreateOptions{ConfigPath: f.Config, Output: bundle}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SHARDLURE_CONFIG", "/inert/not/a/config")
	for _, kind := range []string{"dry-run", "empty", "existing", "inside-bundle", "inside-source", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			to := filepath.Join(t.TempDir(), "new")
			opts := RestoreOptions{Input: bundle, To: to}
			ctx := context.Background()
			switch kind {
			case "dry-run":
				opts.DryRun = true
			case "empty", "existing":
				if err := os.Mkdir(to, 0700); err != nil {
					t.Fatal(err)
				}
				if kind == "existing" {
					if err := os.WriteFile(filepath.Join(to, "keep"), []byte("keep"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "inside-bundle":
				opts.To = filepath.Join(bundle, "new")
			case "inside-source":
				opts.To = filepath.Join(f.Evidence, "new")
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			_, err := Restore(ctx, opts)
			if kind == "dry-run" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(to); !os.IsNotExist(err) {
					t.Fatal("dry-run created output")
				}
				return
			}
			if err == nil {
				t.Fatal("unsafe restore succeeded")
			}
			if kind == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel identity %v", err)
			}
			if kind == "existing" {
				if b, err := os.ReadFile(filepath.Join(to, "keep")); err != nil || string(b) != "keep" {
					t.Fatal("existing data overwritten")
				}
			}
		})
	}
}

func TestRestoreLatePublicationFailureStaysIncomplete(t *testing.T) {
	f := newFixture(t)
	bundle := filepath.Join(t.TempDir(), "backup")
	if _, err := Create(context.Background(), CreateOptions{ConfigPath: f.Config, Output: bundle}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "restore")
	ops := nativeOperations()
	ops.publish = func(root *safefile.Root, a, b string) error {
		if err := root.PublishNoReplace(a, b); err != nil {
			return err
		}
		return safefile.ErrSync
	}
	_, err := restoreWithOperations(context.Background(), RestoreOptions{Input: bundle, To: out}, ops)
	if err == nil {
		t.Fatal("late restore failure reported success")
	}
	if _, err := os.Stat(filepath.Join(out, incompleteName)); err != nil {
		t.Fatal("uncertain restore lost its marker")
	}
	if _, err := Verify(context.Background(), bundle); err != nil {
		t.Fatal("failed restore changed source")
	}
}

func TestRestoreNamesRefusedTargetAncestor(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission refusal test must run as a non-root user")
	}
	f := newFixture(t)
	bundle := filepath.Join(t.TempDir(), "backup")
	if _, err := Create(context.Background(), CreateOptions{ConfigPath: f.Config, Output: bundle}); err != nil {
		t.Fatal(err)
	}
	shared := t.TempDir()
	if err := os.Chmod(shared, 0770); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(shared, 0700) })
	_, err := Restore(context.Background(), RestoreOptions{Input: bundle, To: filepath.Join(shared, "new")})
	if !errors.Is(err, ErrUnsafePath) || !strings.Contains(err.Error(), "writable by group or others") {
		t.Fatalf("restore refusal hides its reason: %v", err)
	}
	if path, _, ok := RefusedPath(err); !ok || path != shared {
		t.Fatalf("refused path = %q %v, want %q", path, ok, shared)
	}
}

// Premerge store-read M6: no backup test seeded the campaign tables. The
// operator's edits and names (campaign_edits is never purged) must survive
// create -> restore, every table must be counted, and the remap must leave
// the recorder's cursor and reset epoch alone: it resets only
// source='cowrie' cursors, and widening it would zero the epoch that fences
// the recorder against a concurrent --replace.
func TestRestoreRoundTripKeepsCampaignTables(t *testing.T) {
	f := newFixture(t)
	db, err := sql.Open("sqlite", filepath.Join(f.Root, "shardlure.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const ts, fp = "2026-09-21T00:00:00.000000000Z", "1111111111111111111111111111111111111111111111111111111111111111"
	seed := map[string]string{
		"campaigns":            `INSERT INTO campaigns(id,name,notes,actors,ips,sessions,updated_at) VALUES('c-00000000000a','Operator Name','operator notes',1,1,1,'` + ts + `')`,
		"campaign_members":     `INSERT INTO campaign_members(campaign_id,actor_id,sessions,ips,reasons) VALUES('c-00000000000a','cowrie:inert',1,1,'')`,
		"campaign_ids":         `INSERT INTO campaign_ids(kind,value,campaign_id,seq) VALUES('script','` + fp + `','c-00000000000a',1)`,
		"campaign_aliases":     `INSERT INTO campaign_aliases(old_id,new_id,created_at) VALUES('c-00000000000b','c-00000000000a','` + ts + `')`,
		"campaign_edits":       `INSERT INTO campaign_edits(campaign_id,action,arg,who,created_at) VALUES('c-00000000000a','rename','Operator Name','cli','` + ts + `')`,
		"campaign_evidence":    `INSERT INTO campaign_evidence(kind,value,session_id,actor_id,first_seen,last_seen) VALUES('script','` + fp + `','s1','cowrie:inert','` + ts + `','` + ts + `')`,
		"scripts":              `INSERT INTO scripts(fingerprint,normalized,display,command_count,distinctive,family,family_distance,token_count,first_seen,last_seen) VALUES('` + fp + `','n','inert command',1,1,'` + fp + `',0,1,'` + ts + `','` + ts + `')`,
		"script_families":      `INSERT INTO script_families(family,display,variants,sessions,actors,ips,command_count,distinctive,links,reason,first_seen,last_seen) VALUES('` + fp + `','inert command','[]',1,1,1,1,1,1,'r','` + ts + `','` + ts + `')`,
		"session_scripts":      `INSERT INTO session_scripts(session_id,actor_id,first_seen,last_seen,updated_at,settled_at,fingerprint) VALUES('s1','cowrie:inert','` + ts + `','` + ts + `','` + ts + `','` + ts + `','` + fp + `')`,
		"session_script_lines": `INSERT INTO session_script_lines(session_id,event_id,line) VALUES('s1',2,'inert command')`,
		"script_version_carry": `INSERT INTO script_version_carry(session_id,fingerprint) VALUES('s1','` + fp + `')`,
	}
	for table, q := range seed {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", table, err)
		}
	}
	if _, err := db.Exec(`INSERT INTO ingest_state(source,path,inode,offset,head_sig,updated_at) VALUES('campaign','evidence-v1',7,123,'','` + ts + `')`); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(t.TempDir(), "backup")
	if _, err := Create(context.Background(), CreateOptions{ConfigPath: f.Config, Output: bundle}); err != nil {
		t.Fatal(err)
	}
	to := filepath.Join(t.TempDir(), "recovered")
	report, err := Restore(context.Background(), RestoreOptions{Input: bundle, To: to})
	if err != nil {
		t.Fatal(err)
	}
	for table := range seed {
		if report.TableCounts[table] != 1 {
			t.Errorf("restore report counts %d rows in %s, want 1", report.TableCounts[table], table)
		}
	}
	restored, err := store.Open(filepath.Join(to, "shardlure.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	c, err := restored.GetCampaign(context.Background(), "Operator Name")
	if err != nil || c.ID != "c-00000000000a" || c.Notes != "operator notes" || len(c.Edits) != 1 || c.Edits[0].Arg != "Operator Name" {
		t.Fatalf("restored campaign %+v %v", c, err)
	}
	if id, ok, err := restored.ResolveCampaignID(context.Background(), "c-00000000000b"); err != nil || !ok || id != "c-00000000000a" {
		t.Fatalf("alias lost: %q %v %v", id, ok, err)
	}
	var epoch, offset int64
	rdb, err := sql.Open("sqlite", filepath.Join(to, "shardlure.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer rdb.Close()
	if err := rdb.QueryRow(`SELECT inode, offset FROM ingest_state WHERE source='campaign' AND path='evidence-v1'`).Scan(&epoch, &offset); err != nil || epoch != 7 || offset != 123 {
		t.Fatalf("recorder cursor after restore: epoch %d offset %d %v; want 7 and 123 untouched", epoch, offset, err)
	}
}
