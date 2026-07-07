package store

import (
	"time"
)

// TunnelTarget is one forwarding destination attackers tried to pivot to
// THROUGH the honeypot, aggregated across cowrie direct-tcpip events. It
// powers the "Proxy Targets" red-team widget and the tunnel IOC export.
type TunnelTarget struct {
	DstIP        string    `json:"dstIp"`
	DstPort      int       `json:"dstPort"`
	Hits         int       `json:"hits"`
	UniqueActors int       `json:"uniqueActors"`
	FirstSeen    time.Time `json:"firstSeen"`
	LastSeen     time.Time `json:"lastSeen"`
}

// TopTunnelTargets returns the most-hit proxy/pivot destinations seen since
// the given time, newest window first by hit count. Only kind='tunnel' events
// carry a dst_ip (toEvent gates the columns on that kind), so the WHERE clause
// both restricts to forwarding events and drops the empty-dst rows that would
// otherwise collapse into a bogus ":0" bucket.
//
// A zero `since` means "all time". limit<=0 falls back to a generous cap so a
// crafted flood of unique dst targets can't pull an unbounded result set into
// memory (mirrors topCounts).
func (s *Store) TopTunnelTargets(since time.Time, limit int) ([]TunnelTarget, error) {
	const defaultLimit = 500
	if limit <= 0 {
		limit = defaultLimit
	}
	args := []interface{}{}
	where := `kind='tunnel' AND dst_ip IS NOT NULL AND dst_ip != ''`
	if !since.IsZero() {
		where += ` AND ts >= ?`
		args = append(args, since.UTC().Format(time.RFC3339Nano))
	}
	args = append(args, limit)
	rows, err := s.db.Query(`
SELECT dst_ip, dst_port,
       COUNT(*)                       AS hits,
       COUNT(DISTINCT actor_id)       AS uniq_actors,
       MIN(ts)                        AS first_seen,
       MAX(ts)                        AS last_seen
FROM events
WHERE `+where+`
GROUP BY dst_ip, dst_port
ORDER BY hits DESC, last_seen DESC
LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TunnelTarget
	for rows.Next() {
		var t TunnelTarget
		var first, last string
		if err := rows.Scan(&t.DstIP, &t.DstPort, &t.Hits, &t.UniqueActors, &first, &last); err != nil {
			return nil, err
		}
		t.FirstSeen, _ = parseTime(first)
		t.LastSeen, _ = parseTime(last)
		out = append(out, t)
	}
	return out, rows.Err()
}
