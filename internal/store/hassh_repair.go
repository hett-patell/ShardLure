package store

import (
	"database/sql"
	"time"
)

// canonicalHASSHRepairUpdate repairs one id range; the stored cursor is kept
// up with ingest, so the range is normally a tick's worth of new rows. The
// unary + on source is load-bearing: without it the planner answers
// source='cowrie' from idx_events_session and walks every Cowrie row to find
// that range (~10% of a core at idle on a 1.7M-event DB, every 5s tick).
const canonicalHASSHRepairUpdate = `UPDATE events SET hassh=(SELECT h.hassh FROM cowrie_session_hassh h WHERE h.session_id=events.session_id)
WHERE id>? AND id<=? AND +source='cowrie' AND COALESCE(hassh,'')=''
 AND EXISTS(SELECT 1 FROM cowrie_session_hassh h WHERE h.session_id=events.session_id AND h.hassh<>'' AND events.actor_id='cowrie:'||h.hassh)`

// RepairCanonicalHASSHBatch backfills the old reconciliation's missing HASSH
// only when its actor ID already agrees with the durable session binding. It
// does not guess identity or rebuild aggregates from retention-limited rows.
// The primary-key scan and cursor commit are bounded and restart-safe; newly
// reconciled sessions are stamped by ReconcileSessionHASSH itself.
func (s *Store) RepairCanonicalHASSHBatch(limit int) (int, error) {
	if limit <= 0 || limit > 2000 {
		limit = 2000
	}
	if err := s.ensureSessionHASSHIndex(); err != nil {
		return 0, err
	}
	changed := 0
	err := s.WithTx(func(tx *sql.Tx) error {
		const key = "canonical-hassh-v1"
		var cursor int64
		err := tx.QueryRow(`SELECT offset FROM ingest_state WHERE source='repair' AND path=?`, key).Scan(&cursor)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		var end int64
		if err := tx.QueryRow(`SELECT COALESCE(MAX(id),0) FROM (SELECT id FROM events WHERE id>? ORDER BY id LIMIT ?)`, cursor, limit).Scan(&end); err != nil {
			return err
		}
		if end == 0 {
			return nil
		}
		result, err := tx.Exec(canonicalHASSHRepairUpdate, cursor, end)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		changed = int(n)
		_, err = tx.Exec(`INSERT INTO ingest_state(source,path,inode,offset,head_sig,updated_at) VALUES('repair',?,0,?,'',?)
ON CONFLICT(source,path) DO UPDATE SET offset=excluded.offset,updated_at=excluded.updated_at`, key, end, time.Now().UTC().Format(time.RFC3339Nano))
		return err
	})
	if err != nil {
		return 0, err
	}
	return changed, nil
}
