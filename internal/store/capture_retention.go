package store

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/safefile"
)

type CaptureRetentionPolicy struct {
	CommandsEnabled, FilesEnabled bool
	// EvidenceRoot is explicit deletion authority, never inferred from DB paths.
	// Empty means metadata-only retention, leaving all filesystem bytes intact.
	EvidenceRoot string
}

// Lock order is captureMu -> writeMu -> SQLite transaction. Capture callbacks
// may use ordinary store writes, but must not re-enter discovery/retention.
func (s *Store) SetCaptureRetentionPolicy(policy CaptureRetentionPolicy) {
	s.captureMu.Lock()
	defer s.captureMu.Unlock()
	s.capturePolicy = policy
}

// WithCaptureFileAccess ties final file publication/adoption to its durable
// record against retention. Long source copying/hashing stays outside it.
func (s *Store) WithCaptureFileAccess(ctx context.Context, fn func() error) error {
	s.captureMu.Lock()
	defer s.captureMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn()
}

// captureEventCeilingTx is called with captureMu held. No active consumers
// means no hold. A missing checkpoint for an enabled consumer means hold all.
func (s *Store) captureEventCeilingTx(tx *sql.Tx) (int64, error) {
	ceiling := int64(math.MaxInt64)
	for _, consumer := range []struct {
		enabled bool
		path    string
	}{{s.capturePolicy.CommandsEnabled, "command-artifacts-v1"}, {s.capturePolicy.FilesEnabled, fileCaptureDiscoveryPath}} {
		if !consumer.enabled {
			continue
		}
		var cursor int64
		err := tx.QueryRow("SELECT offset FROM ingest_state WHERE source='capture' AND path=?", consumer.path).Scan(&cursor)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return 0, err
		}
		ceiling = min(ceiling, cursor)
	}
	return ceiling, nil
}

// RemoveCaptureSourceIfSafe keeps the source decision and one unlink atomic
// against discovery and leases. The callback performs only filesystem work;
// it must never call Store methods. Already queued jobs remain protected even
// when capture is disabled. Undiscovered file history conservatively holds all
// source names until its required provenance has been committed.
func (s *Store) RemoveCaptureSourceIfSafe(ctx context.Context, name string, remove func() (bool, error)) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := s.ensureFileCaptureTable(); err != nil {
		return false, err
	}
	s.captureMu.Lock()
	defer s.captureMu.Unlock()
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if s.capturePolicy.FilesEnabled {
		var cursor, latest int64
		err := s.db.QueryRowContext(ctx, "SELECT offset FROM ingest_state WHERE source='capture' AND path=?", fileCaptureDiscoveryPath).Scan(&cursor)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
		if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(id),0) FROM events").Scan(&latest); err != nil {
			return false, err
		}
		if cursor < latest {
			return false, nil
		}
	}
	var held bool
	if err := s.db.QueryRowContext(ctx, fileCaptureProtectionQuery, name).Scan(&held); err != nil {
		return false, err
	}
	if held {
		return false, nil
	}
	return remove()
}

const artifactRetentionPage = 256

type expiredArtifact struct {
	id   int64
	path string
}

// Each page is bounded in both row count and field size. Preflight parses all
// timestamps before any deletion; a malformed later page must not authorize
// partially guessing chronological retention. Each deleting page revalidates.
func artifactRetentionPageTx(q sqlQueryer, cursor int64, cutoff time.Time) ([]expiredArtifact, int64, int, error) {
	rows, err := q.Query(`SELECT id,
CASE WHEN length(CAST(COALESCE(last_seen_at,ts,created_at,'') AS BLOB))<=64 THEN COALESCE(last_seen_at,ts,created_at,'') END,
CASE WHEN length(CAST(COALESCE(local_path,'') AS BLOB))<=4096 THEN COALESCE(local_path,'') END,
origin='quarantine_fetch' AND (status='capturing' OR (status IN ('pending','failed') AND attempt_count<5))
FROM artifacts WHERE id>? ORDER BY id LIMIT ?`, cursor, artifactRetentionPage)
	if err != nil {
		return nil, cursor, 0, err
	}
	defer rows.Close()
	var expired []expiredArtifact
	n := 0
	for rows.Next() {
		var id int64
		var raw, path sql.NullString
		var live bool
		if err := rows.Scan(&id, &raw, &path, &live); err != nil {
			return nil, cursor, n, err
		}
		cursor = id
		n++
		at, err := parseLedgerTimestamp(raw.String)
		if !raw.Valid || !path.Valid || err != nil {
			return nil, cursor, n, errors.New("capture retention: invalid artifact metadata")
		}
		if !live && at.Before(cutoff) {
			expired = append(expired, expiredArtifact{id, path.String})
		}
	}
	return expired, cursor, n, rows.Err()
}

func (s *Store) purgeArtifacts(cutoff time.Time) error {
	var cursor int64
	for {
		_, end, n, err := artifactRetentionPageTx(s.db, cursor, cutoff)
		if err != nil {
			return err
		}
		cursor = end
		if n < artifactRetentionPage {
			break
		}
	}
	cursor = 0
	for {
		n, err := func() (int, error) {
			s.captureMu.Lock()
			defer s.captureMu.Unlock()
			s.writeMu.Lock()
			defer s.writeMu.Unlock()
			tx, err := s.db.Begin()
			if err != nil {
				return 0, err
			}
			defer tx.Rollback()
			// Acquire the SQLite writer before the selection, including against
			// other Store handles, rather than upgrading a stale read snapshot.
			if _, err := tx.Exec("DELETE FROM artifacts WHERE id=-1"); err != nil {
				return 0, err
			}
			rows, end, n, err := artifactRetentionPageTx(tx, cursor, cutoff)
			if err != nil {
				return 0, err
			}
			ids := make([]int64, 0, len(rows))
			for _, row := range rows {
				ids = append(ids, row.id)
			}
			if err := deleteRowsByID(tx, "artifacts", ids); err != nil {
				return 0, err
			}
			if err := tx.Commit(); err != nil {
				return 0, err
			}
			cursor = end
			// Publication/adoption uses captureMu across finalization and its
			// durable record. Keep it held until the last reference-checked unlink.
			for _, row := range rows {
				if row.path == "" || s.capturePolicy.EvidenceRoot == "" {
					continue
				}
				var baseHeld bool
				if err := s.db.QueryRow("SELECT EXISTS(SELECT 1 FROM artifacts WHERE local_path=? LIMIT 1)", row.path).Scan(&baseHeld); err != nil {
					return n, err
				}
				if baseHeld {
					continue
				} // raw evidence owns its transcript too
				for _, path := range []string{row.path, row.path + ".txt"} {
					var held bool
					if err := s.db.QueryRow("SELECT EXISTS(SELECT 1 FROM artifacts WHERE local_path=? LIMIT 1)", path).Scan(&held); err != nil {
						return n, err
					}
					if !held {
						if err := s.removeEvidenceFile(path); err != nil {
							return n, err
						}
					}
				}
			}
			return n, nil
		}()
		if err != nil {
			return err
		}
		if n < artifactRetentionPage {
			return nil
		}
	}
}

// Called with captureMu and writeMu held. Opening a configured root is not
// permission to follow a stored path elsewhere, or touch SQLite/its sidecars.
func (s *Store) removeEvidenceFile(path string) error {
	root, err := filepath.Abs(s.capturePolicy.EvidenceRoot)
	if err != nil {
		return safefile.ErrUnsafePath
	}
	if !filepath.IsAbs(path) {
		return safefile.ErrUnsafePath
	}
	path = filepath.Clean(path)
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return safefile.ErrUnsafePath
	}
	for _, protected := range []string{s.path, s.path + "-wal", s.path + "-shm", s.path + "-journal"} {
		if path == protected {
			return safefile.ErrUnsafePath
		}
	}
	parent, err := safefile.OpenRoot(filepath.Dir(path))
	if errors.Is(err, safefile.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer parent.Close()
	if err := parent.CheckOutput(); err != nil {
		return err
	}
	f, err := parent.OpenRegular(filepath.Base(path))
	if errors.Is(err, safefile.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	info, statErr := f.Stat()
	closeErr := f.Close()
	if statErr != nil || closeErr != nil {
		return safefile.ErrIO
	}
	if err := parent.RemoveIfUnchanged(filepath.Base(path), info); err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, safefile.ErrNotExist) {
		return err
	}
	return nil
}

func (s *Store) purgeCaptureDiagnostics(cutoff time.Time) error {
	for _, target := range []struct{ table, key, clock, predicate string }{
		{"capture_file_jobs", "id", "updated_at", "state IN ('archived','rejected','failed') AND NOT EXISTS(SELECT 1 FROM events WHERE events.id=capture_file_jobs.event_id)"},
		{"capture_discovery_errors", "event_id", "created_at", "NOT EXISTS(SELECT 1 FROM events WHERE events.id=capture_discovery_errors.event_id)"},
	} {
		var cursor int64
		for {
			n := 0
			err := s.WithTx(func(tx *sql.Tx) error {
				rows, err := tx.Query("SELECT "+target.key+","+target.clock+" FROM "+target.table+" WHERE "+target.key+">? AND "+target.predicate+" ORDER BY "+target.key+" LIMIT ?", cursor, artifactRetentionPage)
				if err != nil {
					return err
				}
				var ids []int64
				for rows.Next() {
					var id int64
					var raw string
					if err := rows.Scan(&id, &raw); err != nil {
						rows.Close()
						return err
					}
					cursor = id
					n++
					at, err := parseLedgerTimestamp(raw)
					if err != nil {
						rows.Close()
						return errors.New("capture retention: invalid diagnostic time")
					}
					if at.Before(cutoff) {
						ids = append(ids, id)
					}
				}
				readErr := rows.Err()
				rows.Close()
				if readErr != nil {
					return readErr
				}
				for _, id := range ids {
					if _, err := tx.Exec("DELETE FROM "+target.table+" WHERE "+target.key+"=? AND "+target.predicate, id); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return err
			}
			if n < artifactRetentionPage {
				break
			}
		}
	}
	return nil
}
