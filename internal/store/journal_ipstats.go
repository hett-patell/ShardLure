package store

import (
	"database/sql"
	"time"
)

// JournalIPStats is the persisted per-actor/IP roll-up the in-memory
// live collector hydrates from when an evicted IP returns. Returned
// values reflect the row that the previous live tail upserted at the
// moment it last ran for this actor/IP pair; the caller is expected to
// fold any newly observed events on top of these counters before the
// next upsert.
//
// Returned First/Last are zero when the requested actor/IP pair has
// no row, even if another actor has seen the IP. UserCounts is
// allocated but possibly empty when the pair is absent or no rows
// exist in actor_users for the requested actor.
type JournalIPStats struct {
	Count      int
	First      time.Time
	Last       time.Time
	UserCounts map[string]int
}

// LoadJournalIPStats returns the persisted counters for one journal
// actor and source IP. Used by the live collector to recover state
// for an IP that was evicted from its in-memory LRU. Returns a
// zero-value struct (Count == 0, empty UserCounts) when the requested
// actor/IP pair has no row yet; returns an error only on a true SQL
// failure.
//
// Cost: two indexed lookups (actor_ips by its composite primary key,
// then actor_users by the actor_id prefix of its primary key). Cheap
// relative to the rest of the SyncJournalEvent path.
func (s *Store) LoadJournalIPStats(actorID, ip string) (JournalIPStats, error) {
	out := JournalIPStats{UserCounts: map[string]int{}}
	// We don't need the actors row itself — actor_ips carries the
	// counters this IP contributed and actor_users keys off actor_id.
	var first, last string
	err := s.db.QueryRow(`
SELECT count, first_seen, last_seen
FROM actor_ips
WHERE actor_id=? AND ip=?`, actorID, ip).Scan(&out.Count, &first, &last)
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
