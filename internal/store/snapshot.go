package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/networkshard/shardlure/internal/safefile"
	"modernc.org/sqlite"
	"modernc.org/sqlite/vfs"
)

type EvidenceReference struct {
	Path, SHA256 string
	SizeBytes    int64
}
type SnapshotInfo struct {
	Schema      int
	TableCounts map[string]int64
}

var (
	ErrSnapshotInvalid   = errors.New("snapshot: invalid standalone database")
	ErrSnapshotSchema    = errors.New("snapshot: unsupported schema")
	ErrSnapshotOperation = errors.New("snapshot: operation failed")
)

type snapshotFailure struct{ cause error }

func (e *snapshotFailure) Error() string { return ErrSnapshotOperation.Error() }
func (e *snapshotFailure) Unwrap() error { return e.cause }
func safeSnapshotError(err error) error {
	if err == nil {
		return nil
	}
	return &snapshotFailure{err}
}

// Identifiers and schema gates are application-owned, never supplied by a
// manifest or sqlite_schema. Optional/lazy tables may legitimately be absent.
var snapshotTables = [...]struct {
	name  string
	since int
}{
	{"schema_migrations", 1}, {"events", 1}, {"actors", 1}, {"actor_ips", 1}, {"actor_users", 1},
	{"ingest_state", 1}, {"app_settings", 1}, {"artifacts", 1}, {"ip_enrichment", 1},
	{"cowrie_tty_index", 1}, {"bazaar_uploads", 1}, {"abuseipdb_reports", 1},
	{"urlhaus_submissions", 1}, {"threatfox_submissions", 1}, {"payload_intel", 1},
	{"cowrie_session_hassh", 1}, {"cowrie_session_meta", 1}, {"journal_summaries", 23},
	{"capture_file_jobs", 24}, {"capture_discovery_errors", 24},
}

const latestSnapshotSchema = 24

type snapshotQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func snapshotTablePresent(ctx context.Context, q snapshotQueryer, name string) (bool, error) {
	var kind, definition string
	err := q.QueryRowContext(ctx, "SELECT type,COALESCE(substr(sql,1,128),'') FROM sqlite_schema WHERE name=?", name).Scan(&kind, &definition)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if kind != "table" || !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(definition)), "CREATE TABLE") {
		return false, ErrSnapshotSchema
	}
	return true, nil
}

func snapshotSchema(ctx context.Context, q snapshotQueryer) (int, error) {
	for _, name := range []string{"schema_migrations", "events", "actors"} {
		ok, err := snapshotTablePresent(ctx, q, name)
		if err != nil {
			return 0, err
		}
		if !ok {
			return 0, ErrSnapshotSchema
		}
	}
	var schema, minimum int
	if err := q.QueryRowContext(ctx, "SELECT MIN(version),MAX(version) FROM schema_migrations").Scan(&minimum, &schema); err != nil {
		return 0, ErrSnapshotSchema
	}
	if minimum < 1 || schema < 1 || schema > latestSnapshotSchema {
		return 0, ErrSnapshotSchema
	}
	return schema, nil
}

func readSnapshotInfo(ctx context.Context, q snapshotQueryer) (SnapshotInfo, error) {
	schema, err := snapshotSchema(ctx, q)
	if err != nil {
		return SnapshotInfo{}, err
	}
	var integrity string
	if err := q.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil {
		return SnapshotInfo{}, err
	}
	if integrity != "ok" {
		return SnapshotInfo{}, ErrSnapshotInvalid
	}
	info := SnapshotInfo{Schema: schema, TableCounts: make(map[string]int64, len(snapshotTables))}
	for _, table := range snapshotTables {
		if table.since > schema {
			continue
		}
		present, err := snapshotTablePresent(ctx, q, table.name)
		if err != nil {
			return SnapshotInfo{}, err
		}
		if !present {
			continue
		}
		var n int64
		if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM \""+table.name+"\"").Scan(&n); err != nil {
			return SnapshotInfo{}, err
		}
		info.TableCounts[table.name] = n
	}
	return info, nil
}

type snapshotBackup interface {
	Step(int32) (bool, error)
	Finish() error
}

func runSnapshotBackup(ctx context.Context, b snapshotBackup) (result error) {
	defer func() { result = errors.Join(result, b.Finish()) }()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		more, err := b.Step(256)
		if err != nil {
			var coded interface{ Code() int }
			if !errors.As(err, &coded) || (coded.Code()&255 != 5 && coded.Code()&255 != 6) {
				return err
			}
			timer := time.NewTimer(25 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			continue
		}
		if !more {
			return nil
		}
	}
}

func copyLiveSQLite(ctx context.Context, source, destination string) error {
	sourceURI, err := sqliteFileURI(source, url.Values{"mode": {"ro"}, "_pragma": {"busy_timeout(25)", "query_only(ON)", "trusted_schema(OFF)"}})
	if err != nil {
		return err
	}
	db, err := sql.Open("sqlite", sourceURI)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN"); err != nil {
		return err
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	// Pin an actual read snapshot before Step: otherwise online backup is free
	// to restart on a later commit and need not finish under continuous writes.
	if _, err := snapshotSchema(ctx, conn); err != nil {
		return err
	}
	destURI, err := sqliteFileURI(destination, url.Values{"mode": {"rw"}, "_pragma": {"busy_timeout(25)"}})
	if err != nil {
		return err
	}
	return conn.Raw(func(dc any) error {
		source, ok := dc.(interface {
			NewBackup(string) (*sqlite.Backup, error)
		})
		if !ok {
			return ErrSnapshotOperation
		}
		b, err := source.NewBackup(destURI)
		if err != nil {
			return err
		}
		return runSnapshotBackup(ctx, b)
	})
}

// SnapshotDatabase copies a stable committed source through SQLite's online
// backup API, without migrations, capture, or source backfills. Its destination
// must not exist. Failed staging is retained for recovery, never overwritten.
func SnapshotDatabase(ctx context.Context, source, destination string) (SnapshotInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return SnapshotInfo{}, err
	}
	if err := CheckDatabaseOwner(source); err != nil {
		return SnapshotInfo{}, err
	}
	sourceInfo, err := os.Lstat(source)
	if err != nil || !sourceInfo.Mode().IsRegular() {
		return SnapshotInfo{}, safeSnapshotError(ErrDatabaseAccess)
	}
	if err := CheckDatabaseOwner(destination); err != nil {
		return SnapshotInfo{}, err
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		return SnapshotInfo{}, safefile.ErrExists
	}
	parent, err := safefile.OpenRoot(filepath.Dir(destination))
	if err != nil {
		return SnapshotInfo{}, err
	}
	defer parent.Close()
	if err := parent.CheckOutput(); err != nil {
		return SnapshotInfo{}, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return SnapshotInfo{}, safeSnapshotError(err)
	}
	stageName := ".snapshot-" + hex.EncodeToString(nonce[:]) + ".db"
	stagePath := filepath.Join(filepath.Dir(destination), stageName)
	stage, err := parent.CreateExclusive(stageName, 0600)
	if err != nil {
		return SnapshotInfo{}, err
	}
	initial, err := stage.Stat()
	closeErr := stage.Close()
	if err != nil || closeErr != nil {
		return SnapshotInfo{}, ErrSnapshotOperation
	}
	if err := copyLiveSQLite(ctx, source, stagePath); err != nil {
		return SnapshotInfo{}, safeSnapshotError(err)
	}
	// Only the destination is normalized. It must be a standalone DELETE-mode
	// database before hashing or read-only VFS inspection; never ignore live WAL.
	uri, err := sqliteFileURI(stagePath, url.Values{"mode": {"rw"}, "_pragma": {"busy_timeout(25)", "trusted_schema(OFF)"}})
	if err != nil {
		return SnapshotInfo{}, err
	}
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return SnapshotInfo{}, safeSnapshotError(err)
	}
	db.SetMaxOpenConns(1)
	var mode string
	err = db.QueryRowContext(ctx, "PRAGMA journal_mode=DELETE").Scan(&mode)
	err = errors.Join(err, db.Close())
	if err != nil || mode != "delete" {
		return SnapshotInfo{}, safeSnapshotError(errors.Join(err, ErrSnapshotInvalid))
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(stagePath + suffix); !errors.Is(err, os.ErrNotExist) {
			return SnapshotInfo{}, ErrSnapshotInvalid
		}
	}
	checked, err := parent.OpenRegular(stageName)
	if err != nil {
		return SnapshotInfo{}, err
	}
	final, err := checked.Stat()
	if err != nil || !os.SameFile(initial, final) {
		checked.Close()
		return SnapshotInfo{}, safefile.ErrChanged
	}
	info, err := InspectSnapshotFile(ctx, checked)
	if err == nil {
		err = checked.Sync()
	}
	err = errors.Join(err, checked.Close())
	if err != nil {
		return SnapshotInfo{}, safeSnapshotError(err)
	}
	if err := ctx.Err(); err != nil {
		return SnapshotInfo{}, err
	}
	if err := parent.PublishNoReplace(stageName, filepath.Base(destination)); err != nil {
		return SnapshotInfo{}, err
	}
	return info, nil
}

// snapshotFileFS exposes one logical name, never a pathname SQLite can use to
// escape into adjacent host files. Each VFS open gets its own independent seek
// cursor; view.Close must not close the caller-owned protected descriptor.
type snapshotFileFS struct {
	file *os.File
	info fs.FileInfo
}
type snapshotFileView struct {
	*io.SectionReader
	info fs.FileInfo
}

// v1.34.5's vfs.FS.Close frees a sqlite3_malloc allocation with libc.free,
// corrupting the allocator (reproduced by the repeated public inspection tests).
// Keep ONE bounded process-lifetime VFS registration, not one leaked VFS per
// operation. Scoped entries are removed only after all their SQL handles close;
// the eight-slot admission bound prevents unbounded in-flight descriptor maps.
// No untrusted path ever becomes a host filesystem lookup.
type snapshotVFSRegistry struct {
	once   sync.Once
	mu     sync.RWMutex
	name   string
	handle *vfs.FS
	err    error
	serial uint64
	files  map[string]snapshotFileFS
	slots  chan struct{}
}

var snapshotVFS = snapshotVFSRegistry{files: make(map[string]snapshotFileFS), slots: make(chan struct{}, 8)}

func (r *snapshotVFSRegistry) Open(name string) (fs.File, error) {
	r.mu.RLock()
	file, ok := r.files[name]
	r.mu.RUnlock()
	if !ok {
		return nil, fs.ErrNotExist
	}
	return file.Open("snapshot.db")
}

func (r *snapshotVFSRegistry) register(ctx context.Context, file snapshotFileFS) (string, string, func(), error) {
	select {
	case r.slots <- struct{}{}:
	case <-ctx.Done():
		return "", "", nil, ctx.Err()
	}
	r.once.Do(func() { r.name, r.handle, r.err = vfs.New(r) })
	if r.err != nil {
		<-r.slots
		return "", "", nil, r.err
	}
	r.mu.Lock()
	r.serial++
	key := fmt.Sprintf("snapshot-%d.db", r.serial)
	r.files[key] = file
	r.mu.Unlock()
	release := func() { r.mu.Lock(); delete(r.files, key); r.mu.Unlock(); <-r.slots }
	return r.name, key, release, nil
}

func (v *snapshotFileView) Stat() (fs.FileInfo, error) { return v.info, nil }
func (v *snapshotFileView) Close() error               { return nil }
func (f snapshotFileFS) Open(name string) (fs.File, error) {
	if name != "snapshot.db" {
		return nil, fs.ErrNotExist
	}
	return &snapshotFileView{io.NewSectionReader(f.file, 0, f.info.Size()), f.info}, nil
}

func withSnapshotFile(ctx context.Context, file *os.File, visit func(*sql.DB) error) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if file == nil {
		return ErrSnapshotInvalid
	}
	before, err := file.Stat()
	if err != nil {
		return safeSnapshotError(err)
	}
	if !before.Mode().IsRegular() || before.Size() < 100 {
		return ErrSnapshotInvalid
	}
	var header [100]byte
	if _, err := file.ReadAt(header[:], 0); err != nil {
		return ErrSnapshotInvalid
	}
	if string(header[:16]) != "SQLite format 3\x00" || header[18] != 1 || header[19] != 1 {
		return ErrSnapshotInvalid
	}
	name, logicalName, release, err := snapshotVFS.register(ctx, snapshotFileFS{file, before})
	if err != nil {
		return safeSnapshotError(err)
	}
	defer release()
	db, err := sql.Open("sqlite", "file:"+logicalName+"?"+url.Values{"vfs": {name}, "mode": {"ro"}, "immutable": {"1"}, "_pragma": {"query_only(ON)", "trusted_schema(OFF)"}}.Encode())
	if err != nil {
		return safeSnapshotError(err)
	}
	db.SetMaxOpenConns(1)
	defer func() { result = errors.Join(result, db.Close()) }()
	if err := visit(db); err != nil {
		return err
	}
	after, err := file.Stat()
	if err != nil || !safefile.SameFileState(before, after) {
		return safefile.ErrChanged
	}
	return nil
}

func InspectSnapshot(ctx context.Context, path string) (SnapshotInfo, error) {
	root, err := safefile.OpenRoot(filepath.Dir(path))
	if err != nil {
		return SnapshotInfo{}, err
	}
	defer root.Close()
	f, err := root.OpenRegular(filepath.Base(path))
	if err != nil {
		return SnapshotInfo{}, err
	}
	defer f.Close()
	// A standalone bundle may not depend on any adjacent journal or WAL, even
	// one whose bytes an immutable SQLite connection would silently ignore.
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(path + suffix); !errors.Is(err, os.ErrNotExist) {
			return SnapshotInfo{}, ErrSnapshotInvalid
		}
	}
	return InspectSnapshotFile(ctx, f)
}

func InspectSnapshotFile(ctx context.Context, file *os.File) (SnapshotInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	var info SnapshotInfo
	err := withSnapshotFile(ctx, file, func(db *sql.DB) error { var err error; info, err = readSnapshotInfo(ctx, db); return err })
	return info, safeSnapshotError(err)
}

func IterateSnapshotEvidence(ctx context.Context, file *os.File, visit func(EvidenceReference) error) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	if visit == nil {
		return ErrSnapshotOperation
	}
	return safeSnapshotError(withSnapshotFile(ctx, file, func(db *sql.DB) error {
		schema, err := snapshotSchema(ctx, db)
		if err != nil {
			return err
		}
		for _, source := range []struct {
			table, path, hash, size, key string
			since                        int
		}{
			{"artifacts", "local_path", "sha256", "size_bytes", "id", 1},
			{"capture_file_jobs", "result_path", "result_sha256", "result_size", "id", 24},
		} {
			if schema < source.since {
				continue
			}
			present, err := snapshotTablePresent(ctx, db, source.table)
			if err != nil {
				return err
			}
			if !present {
				continue
			}
			query := "SELECT CASE WHEN length(CAST(" + source.path + " AS BLOB))<=4096 THEN " + source.path + " END, CASE WHEN length(CAST(COALESCE(" + source.hash + ",'') AS BLOB))<=64 THEN COALESCE(" + source.hash + ",'') END, COALESCE(" + source.size + ",0) FROM " + source.table + " WHERE COALESCE(" + source.path + ",'')<>'' ORDER BY " + source.key
			if err := streamSnapshotEvidence(ctx, db, query, visit); err != nil {
				return err
			}
		}
		return nil
	}))
}

func streamSnapshotEvidence(ctx context.Context, db *sql.DB, query string, visit func(EvidenceReference) error) error {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var ref EvidenceReference
		var path, hash sql.NullString
		if err := rows.Scan(&path, &hash, &ref.SizeBytes); err != nil {
			return err
		}
		if !path.Valid || !hash.Valid || !utf8.ValidString(path.String) || strings.ContainsRune(path.String, 0) || ref.SizeBytes < 0 {
			return ErrSnapshotInvalid
		}
		if hash.String != "" && !validCaptureHash(hash.String) {
			return ErrSnapshotInvalid
		}
		ref.Path, ref.SHA256 = path.String, strings.ToLower(hash.String)
		if err := visit(ref); err != nil {
			return err
		}
	}
	return rows.Err()
}
