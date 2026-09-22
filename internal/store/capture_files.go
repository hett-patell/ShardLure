package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	FileCapturePending           = "pending"
	FileCaptureLeased            = "leased"
	FileCaptureRetry             = "retry"
	FileCaptureArchived          = "archived"
	FileCaptureRejected          = "rejected"
	FileCaptureFailed            = "failed"
	FileCaptureInvalidTime       = "invalid_timestamp"
	FileCaptureInvalidSource     = "invalid_source"
	FileCaptureInvalidHash       = "invalid_hash"
	FileCaptureInvalidMetadata   = "invalid_metadata"
	FileCaptureMissingSource     = "missing_source"
	FileCaptureHashMismatch      = "hash_mismatch"
	FileCaptureSourceChanged     = "source_changed"
	FileCaptureTooLarge          = "too_large"
	FileCaptureEmpty             = "empty"
	FileCaptureReadFailure       = "read_failure"
	FileCaptureWriteFailure      = "write_failure"
	FileCaptureCanceled          = "canceled"
	FileCaptureLeaseExpired      = "lease_expired"
	FileCaptureAttemptsExhausted = "attempts_exhausted"
)

const fileCaptureDiscoveryPath = "file-downloads-v1"
const captureDiscoveryPageBytes = 4 << 20
const fileCaptureMaxAttempts = 5
const fileCaptureLiveStates = "('pending','retry','leased')"
const fileCaptureImmediate = "0001-01-01T00:00:00.000000000Z"

type FileCaptureJob struct {
	ID, EventID, LeaseToken                                            int64
	SourceName, DeliveryURL, SrcIP, SessionID, ActorID, ExpectedSHA256 string
	ObservedAt                                                         time.Time
	Attempts                                                           int
}

type FileCaptureResult struct {
	Status, Reason, LocalPath, SHA256 string
	SizeBytes                         int64
}

const captureFilesSchema = `CREATE TABLE IF NOT EXISTS capture_file_jobs(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 event_id INTEGER NOT NULL UNIQUE,
 source_name TEXT NOT NULL DEFAULT '', delivery_url TEXT NOT NULL DEFAULT '',
 src_ip TEXT NOT NULL DEFAULT '',session_id TEXT NOT NULL DEFAULT '',actor_id TEXT NOT NULL DEFAULT '',
 expected_sha256 TEXT NOT NULL DEFAULT '',observed_at TEXT,
 state TEXT NOT NULL CHECK(state IN ('pending','retry','leased','archived','rejected','failed')),
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0 AND attempts<=5),
 next_attempt_at TEXT NOT NULL,lease_started_at TEXT,lease_until TEXT,last_clock_at TEXT,
 lease_token INTEGER NOT NULL DEFAULT 0,
 result_sha256 TEXT NOT NULL DEFAULT '',result_path TEXT NOT NULL DEFAULT '',result_size INTEGER NOT NULL DEFAULT 0,
 reason TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_file_capture_due ON capture_file_jobs(next_attempt_at,id) WHERE state IN ('pending','retry','leased');
CREATE INDEX IF NOT EXISTS idx_file_capture_lease ON capture_file_jobs(lease_until,id) WHERE state='leased';
CREATE INDEX IF NOT EXISTS idx_file_capture_source_live ON capture_file_jobs(source_name) WHERE state IN ('pending','retry','leased');
CREATE TABLE IF NOT EXISTS capture_discovery_errors(
 event_id INTEGER PRIMARY KEY,kind TEXT NOT NULL,
 reason TEXT NOT NULL CHECK(reason IN ('invalid_timestamp','invalid_metadata','too_many_urls')),
 created_at TEXT NOT NULL
);`

func (s *Store) ensureFileCaptureTable() error {
	s.onceFileCapture.Do(func() { _, s.errFileCapture = s.execWrite(captureFilesSchema) })
	return s.errFileCapture
}

func (s *Store) migrateFileCaptures(now string) error {
	return s.WithTx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(captureFilesSchema); err != nil {
			return err
		}
		_, err := tx.Exec("INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(24,?)", now)
		return err
	})
}

// Bound database text before it crosses into Go. Non-file rows must not copy
// their command bodies at all just because discovery advances past them.
func boundedFileField(column string, limit int) string {
	return boundedCaptureField("kind='file_download' AND source='cowrie'", column, limit)
}

var fileDiscoveryQuery = "SELECT id,kind='file_download' AND source='cowrie'," +
	boundedFileField("ts", 64) + "," + boundedFileField("filename", 4096) + "," + boundedFileField("command", 65536) + "," +
	boundedFileField("src_ip", 64) + "," + boundedFileField("session_id", 1024) + "," + boundedFileField("actor_id", 1024) + "," + boundedFileField("sha256", 64) +
	" FROM events WHERE id>? ORDER BY id LIMIT ?"

func validCaptureHash(raw string) bool {
	if len(raw) != 64 {
		return false
	}
	_, err := hex.DecodeString(raw)
	return err == nil
}

func fileSourceName(raw string) (string, bool) {
	if raw == "" || strings.ContainsRune(raw, 0) || !utf8.ValidString(raw) {
		return "", false
	}
	// Preserve native filename bytes. On Unix, a backslash is a literal name
	// character, not a separator to reinterpret as a different source file.
	name := filepath.Base(raw)
	if name == "." || name == ".." || name == string(filepath.Separator) || filepath.VolumeName(name) != "" || len(name) > 255 {
		return "", false
	}
	return name, true
}

func (s *Store) DiscoverFileCaptures(ctx context.Context, limit int) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if limit <= 0 || limit > 2000 {
		limit = 2000
	}
	if err := s.ensureFileCaptureTable(); err != nil {
		return 0, err
	}
	queued := 0
	err := s.WithTx(func(tx *sql.Tx) error {
		// First acquire the SQLite writer, not a deferred read snapshot: separate
		// Store instances must not both discover from the same stale checkpoint.
		now := captureTime(time.Now())
		if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO ingest_state(source,path,inode,offset,head_sig,updated_at) VALUES('capture',?,0,0,'',?)", fileCaptureDiscoveryPath, now); err != nil {
			return err
		}
		var cursor int64
		if err := tx.QueryRowContext(ctx, "SELECT offset FROM ingest_state WHERE source='capture' AND path=?", fileCaptureDiscoveryPath).Scan(&cursor); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, fileDiscoveryQuery, cursor, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		end, used := cursor, 0
		for rows.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}
			var id int64
			var applicable bool
			var fields [7]sql.NullString
			if err := rows.Scan(&id, &applicable, &fields[0], &fields[1], &fields[2], &fields[3], &fields[4], &fields[5], &fields[6]); err != nil {
				return err
			}
			end = id
			used += 64
			if !applicable {
				continue
			}
			reason := ""
			for i, f := range fields {
				used += len(f.String)
				if !f.Valid || !utf8.ValidString(f.String) || (i != 1 && strings.ContainsRune(f.String, 0)) {
					reason = FileCaptureInvalidMetadata
				}
			}
			var observed any
			at, parseErr := parseLedgerTimestamp(fields[0].String)
			if reason == "" && (parseErr != nil || at.IsZero()) {
				reason = FileCaptureInvalidTime
			}
			if parseErr == nil && !at.IsZero() {
				observed = captureTime(at)
			}
			name, valid := fileSourceName(fields[1].String)
			if reason == "" && !valid {
				reason = FileCaptureInvalidSource
			}
			hash := strings.ToLower(fields[6].String)
			if reason == "" && hash != "" && !validCaptureHash(hash) {
				reason = FileCaptureInvalidHash
			}
			state := FileCapturePending
			if reason != "" {
				state = FileCaptureRejected
			}
			res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO capture_file_jobs(event_id,source_name,delivery_url,src_ip,session_id,actor_id,expected_sha256,observed_at,state,next_attempt_at,reason,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, name, fields[2].String, fields[3].String, fields[4].String, fields[5].String, hash, observed, state, fileCaptureImmediate, reason, now, now)
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return err
			}
			queued += int(n)
			if used >= captureDiscoveryPageBytes {
				break
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if end == cursor {
			return nil
		}
		_, err = tx.ExecContext(ctx, "UPDATE ingest_state SET offset=?,updated_at=? WHERE source='capture' AND path=?", end, now, fileCaptureDiscoveryPath)
		return err
	})
	if err != nil {
		return 0, err
	}
	return queued, nil
}

const fileCaptureProtectionQuery = "SELECT EXISTS(SELECT 1 FROM capture_file_jobs INDEXED BY idx_file_capture_source_live WHERE source_name=? AND state IN " + fileCaptureLiveStates + " LIMIT 1)"

func (s *Store) CaptureFileProtected(ctx context.Context, sourceName string) (bool, error) {
	if err := s.ensureFileCaptureTable(); err != nil {
		return false, err
	}
	var held bool
	err := s.db.QueryRowContext(ctx, fileCaptureProtectionQuery, sourceName).Scan(&held)
	return held, err
}

const fileJobColumns = "id,event_id,lease_token,source_name,delivery_url,src_ip,session_id,actor_id,expected_sha256,observed_at,attempts"

var errFileCaptureObservation = errors.New("file capture: invalid observation")

func scanFileCaptureJob(row rowScan) (FileCaptureJob, error) {
	var job FileCaptureJob
	var observed sql.NullString
	if err := row.Scan(&job.ID, &job.EventID, &job.LeaseToken, &job.SourceName, &job.DeliveryURL, &job.SrcIP, &job.SessionID, &job.ActorID, &job.ExpectedSHA256, &observed, &job.Attempts); err != nil {
		return job, err
	}
	var err error
	if job.ObservedAt, err = parseLedgerTimestamp(observed.String); err != nil || !observed.Valid || job.ObservedAt.IsZero() {
		return job, errFileCaptureObservation
	}
	return job, nil
}

func (s *Store) ClaimFileCaptures(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]FileCaptureJob, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if now.IsZero() || lease <= 0 || lease > time.Hour || len(captureTime(now.Add(lease))) != 30 {
		return nil, errors.New("file capture: invalid lease")
	}
	if limit <= 0 || limit > 32 {
		limit = 32
	}
	if err := s.ensureFileCaptureTable(); err != nil {
		return nil, err
	}
	key, until := captureTime(now), captureTime(now.Add(lease))
	var jobs []FileCaptureJob
	err := s.WithTx(func(tx *sql.Tx) error {
		// A write first takes the WAL writer lock even for independent Store
		// instances. No read-then-upgrade race can double-claim a snapshot.
		if _, err := tx.ExecContext(ctx, `UPDATE capture_file_jobs SET state='failed',reason='attempts_exhausted',lease_token=lease_token+1,lease_until=NULL,last_clock_at=?,updated_at=?
WHERE state='leased' AND attempts>=5 AND lease_until<=? AND (last_clock_at IS NULL OR last_clock_at<=?)`, key, key, key, key); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `UPDATE capture_file_jobs SET state='leased',attempts=attempts+1,lease_token=lease_token+1,
lease_started_at=?,lease_until=?,last_clock_at=?,updated_at=?
WHERE id IN (SELECT id FROM capture_file_jobs INDEXED BY idx_file_capture_due
WHERE state IN ('pending','retry','leased') AND attempts<5 AND next_attempt_at<=?
AND (lease_until IS NULL OR lease_until<=?) AND (last_clock_at IS NULL OR last_clock_at<=?)
ORDER BY next_attempt_at,id LIMIT ?) RETURNING `+fileJobColumns, key, until, key, key, key, key, key, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		type invalidJob struct {
			id     int64
			reason string
		}
		var invalid []invalidJob
		for rows.Next() {
			job, err := scanFileCaptureJob(rows)
			if err != nil {
				reason := FileCaptureInvalidMetadata
				if errors.Is(err, errFileCaptureObservation) {
					reason = FileCaptureInvalidTime
				}
				invalid = append(invalid, invalidJob{job.ID, reason})
				continue
			}
			jobs = append(jobs, job)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, bad := range invalid {
			if _, err := tx.ExecContext(ctx, "UPDATE capture_file_jobs SET state='rejected',reason=?,lease_until=NULL WHERE id=? AND state='leased'", bad.reason, bad.id); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].ID < jobs[j].ID })
	return jobs, nil
}

func validFileCaptureReason(reason string) bool {
	switch reason {
	case FileCaptureInvalidTime, FileCaptureInvalidSource, FileCaptureInvalidHash, FileCaptureInvalidMetadata,
		FileCaptureMissingSource, FileCaptureHashMismatch, FileCaptureSourceChanged, FileCaptureTooLarge, FileCaptureEmpty,
		FileCaptureReadFailure, FileCaptureWriteFailure, FileCaptureCanceled, FileCaptureLeaseExpired, FileCaptureAttemptsExhausted:
		return true
	}
	return false
}

func validateFileCaptureResult(result FileCaptureResult) error {
	invalid := errors.New("file capture: invalid result")
	if result.Status == FileCaptureArchived {
		if result.Reason != "" || !validCaptureHash(result.SHA256) || result.SizeBytes <= 0 || result.LocalPath == "" || len(result.LocalPath) > 4096 || strings.ContainsRune(result.LocalPath, 0) || !utf8.ValidString(result.LocalPath) {
			return invalid
		}
		return nil
	}
	if result.Status != FileCaptureRetry && result.Status != FileCaptureRejected && result.Status != FileCaptureFailed {
		return invalid
	}
	if !validFileCaptureReason(result.Reason) || result.LocalPath != "" || result.SHA256 != "" || result.SizeBytes != 0 {
		return invalid
	}
	return nil
}

func (s *Store) CompleteFileCapture(ctx context.Context, job FileCaptureJob, now time.Time, result FileCaptureResult) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateFileCaptureResult(result); err != nil {
		return err
	}
	if now.IsZero() || len(captureTime(now)) != 30 || job.ID <= 0 || job.LeaseToken <= 0 {
		return ErrClaimStale
	}
	if err := s.ensureFileCaptureTable(); err != nil {
		return err
	}
	if err := s.ensureArtifactsTable(); err != nil {
		return err
	}
	key := captureTime(now)
	stale := false
	err := s.WithTx(func(tx *sql.Tx) error {
		// This no-op on last_clock is a conditional write, so it locks and
		// validates the row before reading any provenance or recording a result.
		res, err := tx.ExecContext(ctx, `UPDATE capture_file_jobs SET last_clock_at=?
WHERE id=? AND lease_token=? AND state='leased' AND lease_started_at<=? AND lease_until>?
AND (last_clock_at IS NULL OR last_clock_at<=?)`, key, job.ID, job.LeaseToken, key, key, key)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			stale = true
			// Commit a fence for an observed expiry or backwards clock. Otherwise
			// a later rewind into the old wall-clock interval could revive this
			// token. A different worker's token is never invalidated by this call.
			_, err := tx.ExecContext(ctx, `UPDATE capture_file_jobs SET
state=CASE WHEN attempts>=5 THEN 'failed' ELSE 'retry' END,
reason=CASE WHEN attempts>=5 THEN 'attempts_exhausted' ELSE 'lease_expired' END,
lease_token=lease_token+1,lease_until=NULL,
next_attempt_at=MAX(COALESCE(last_clock_at,?),?),last_clock_at=MAX(COALESCE(last_clock_at,?),?),updated_at=?
WHERE id=? AND lease_token=? AND state='leased'
AND (lease_until<=? OR lease_started_at>? OR last_clock_at>?)`, key, key, key, key, key, job.ID, job.LeaseToken, key, key, key)
			return err
		}
		stored, err := scanFileCaptureJob(tx.QueryRowContext(ctx, "SELECT "+fileJobColumns+" FROM capture_file_jobs WHERE id=?", job.ID))
		if err != nil {
			return err
		}
		state, reason := result.Status, result.Reason
		next := key
		if state == FileCaptureRetry {
			if stored.Attempts >= fileCaptureMaxAttempts {
				state, reason = FileCaptureFailed, FileCaptureAttemptsExhausted
			} else {
				next = captureTime(now.Add(30 * time.Second * time.Duration(1<<uint(stored.Attempts-1))))
			}
		}
		if state == FileCaptureArchived {
			result.SHA256 = strings.ToLower(result.SHA256)
			if stored.ExpectedSHA256 != "" && stored.ExpectedSHA256 != result.SHA256 {
				return errors.New("file capture: result hash mismatch")
			}
			url := "cowrie-event:" + fmt.Sprint(stored.EventID)
			observed := captureTime(stored.ObservedAt)
			var fetched any
			if stored.ExpectedSHA256 != "" {
				fetched = observed
			}
			// Archive bytes even without an original hash, but do not claim
			// today's mutable filename proves an older remote fetch's contents.
			// Unknown freshness stays NULL and outbound Vet remains fail-closed.
			insert, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO artifacts(ts,src_ip,session_id,actor_id,url,local_path,sha256,size_bytes,origin,status,detail,created_at,first_observed_at,last_seen_at,last_successful_fetch_at)
VALUES(?,?,?,?,?,?,?,?,'cowrie_file_download','fetched','',?,?,?,?)`, observed, stored.SrcIP, stored.SessionID, stored.ActorID, url, result.LocalPath, result.SHA256, result.SizeBytes, key, observed, observed, fetched)
			if err != nil {
				return err
			}
			added, err := insert.RowsAffected()
			if err != nil {
				return err
			}
			if added == 0 {
				// Recognize only the same existing result. Never overwrite old
				// artifact keys, another origin's lease, or remote fetch freshness.
				var same bool
				if err := tx.QueryRowContext(ctx, "SELECT status='fetched' AND origin='cowrie_file_download' AND sha256=? AND size_bytes=? AND local_path=? FROM artifacts WHERE url=?", result.SHA256, result.SizeBytes, result.LocalPath, url).Scan(&same); err != nil {
					return err
				}
				if !same {
					return errors.New("file capture: artifact identity conflict")
				}
			}
		}
		res, err = tx.ExecContext(ctx, `UPDATE capture_file_jobs SET state=?,reason=?,result_path=?,result_sha256=?,result_size=?,next_attempt_at=?,lease_until=NULL,updated_at=?
WHERE id=? AND state='leased' AND lease_token=?`, state, reason, result.LocalPath, result.SHA256, result.SizeBytes, next, key, stored.ID, stored.LeaseToken)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrClaimStale
		}
		return nil
	})
	if err != nil {
		return err
	}
	if stale {
		return ErrClaimStale
	}
	return nil
}
