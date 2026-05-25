package store

import (
	"database/sql"
	"time"
)

// JournalIPStats is the persisted per-IP roll-up the in-memory live
// collector hydrates from when an evicted IP returns. Returned values
// reflect the row that the previous live tail upserted at the moment
// it last ran for this IP; the caller is expected to fold any newly
// observed events on top of these counters before the next upsert.
//
// Returned First/Last are zero only when the IP has never been seen.
// UserCounts is allocated but possibly empty when no rows exist in
// actor_users for the IP's actor.
type JournalIPStats struct {
	Count      int
	First      time.Time
	Last       time.Time
	UserCounts map[string]int
}

// LoadJournalIPStats returns the persisted counters for a journal
// source IP. Used by the live collector to recover state for an IP
// that was evicted from its in-memory LRU. Returns a zero-value
// struct (Count == 0, empty UserCounts) when the IP has no row yet;
// returns an error only on a true SQL failure.
//
// Cost: two indexed lookups (one on actor_ips by ip, one on
// actor_users by actor_id). Cheap relative to the rest of the
// SyncJournalEvent path.
func (s *Store) LoadJournalIPStats(ip string) (JournalIPStats, error) {
	out := JournalIPStats{UserCounts: map[string]int{}}
	// We don't need the actors row itself — actor_ips carries the
	// counters this IP contributed and actor_users keys off actor_id.
	var actorID string
	var first, last string
	err := s.db.QueryRow(`
SELECT actor_id, count, first_seen, last_seen
FROM actor_ips
WHERE ip=?
ORDER BY last_seen DESC
LIMIT 1`, ip).Scan(&actorID, &out.Count, &first, &last)
	if err == sql.ErrNoRows {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.First, _ = parseTime(first)
	out.Last, _ = parseTime(last)

	rows, err := s.db.Query(`SELECT username, count FROM actor_users WHERE actor_id=?`, actorID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var u string
		var c int
		if err := rows.Scan(&u, &c); err != nil {
			return out, err
		}
		out.UserCounts[u] = c
	}
	return out, rows.Err()
}
