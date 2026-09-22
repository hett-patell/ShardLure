package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var ErrOperationalUnavailable = errors.New("store: operational sample unavailable")

type OperationalSnapshot struct {
	At                                                                  time.Time
	FilePending, FileRetry, FileLeased, URLPending, URLRetry, URLLeased int64
	FileDiscoveryLag, CommandDiscoveryLag, ProtectedFileJobs            int64
	PoolOpen, PoolInUse, PoolWaits                                      int64
}

// Probe is intentionally cheap and cancellable; it is not a full integrity
// scan and never creates lazy tables or writes application state.
func (s *Store) Probe(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var version int
	if err := s.db.QueryRowContext(ctx, "SELECT version FROM schema_migrations LIMIT 1").Scan(&version); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrOperationalUnavailable
	}
	return nil
}

// OperationalSnapshot is for the once-per-minute aggregate sampler, never a
// request handler. Its result is fixed scalars and its queries honor a budget.
func (s *Store) OperationalSnapshot(ctx context.Context) (out OperationalSnapshot, result error) {
	if err := ctx.Err(); err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	defer func() {
		if result != nil {
			if ctx.Err() != nil {
				result = ctx.Err()
			} else {
				result = ErrOperationalUnavailable
			}
		}
	}()
	if !s.captureMu.TryLock() {
		return out, ErrOperationalUnavailable
	}
	policy := s.capturePolicy
	s.captureMu.Unlock()
	if err := s.Probe(ctx); err != nil {
		return out, err
	}
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(state='pending'),0),COALESCE(SUM(state='retry'),0),COALESCE(SUM(state='leased'),0) FROM capture_file_jobs WHERE state IN ('pending','retry','leased')`).Scan(&out.FilePending, &out.FileRetry, &out.FileLeased)
	if err != nil {
		return out, err
	}
	err = s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(status='pending' AND attempt_count<5),0),COALESCE(SUM(status='failed' AND attempt_count<5),0),COALESCE(SUM(status='capturing'),0) FROM artifacts WHERE origin='quarantine_fetch' AND status IN ('pending','failed','capturing')`).Scan(&out.URLPending, &out.URLRetry, &out.URLLeased)
	if err != nil {
		return out, err
	}
	var high int64
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(id),0) FROM events").Scan(&high); err != nil {
		return out, err
	}
	for _, item := range []struct {
		enabled bool
		key     string
		out     *int64
	}{{policy.FilesEnabled, fileCaptureDiscoveryPath, &out.FileDiscoveryLag}, {policy.CommandsEnabled, "command-artifacts-v1", &out.CommandDiscoveryLag}} {
		if !item.enabled {
			continue
		}
		var checkpoint int64
		err := s.db.QueryRowContext(ctx, "SELECT offset FROM ingest_state WHERE source='capture' AND path=?", item.key).Scan(&checkpoint)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return out, err
		}
		if checkpoint < 0 {
			return out, ErrOperationalUnavailable
		}
		*item.out = max(high-checkpoint, 0)
	}
	stats := s.db.Stats()
	out.PoolOpen = int64(stats.OpenConnections)
	out.PoolInUse = int64(stats.InUse)
	out.PoolWaits = stats.WaitCount
	out.ProtectedFileJobs = out.FilePending + out.FileRetry + out.FileLeased
	out.At = time.Now().UTC()
	return out, nil
}
