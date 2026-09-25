package store

import (
	"fmt"
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

// tunnelTargetWindow is the row filter shared by TopTunnelTargets and
// CountTunnelTargetsSince. It lives in one place because the two must select
// the SAME population: a count taken over different criteria than the page it
// describes is worse than no count at all. Only kind='tunnel' events carry a
// dst_ip (toEvent gates the columns on that kind), so it both restricts to
// forwarding events and drops the empty-dst rows that would otherwise collapse
// into a bogus ":0" bucket.
//
// A zero `since` means "all time".
func tunnelTargetWindow(since time.Time) (string, []any) {
	var cutoff *time.Time
	if !since.IsZero() {
		cutoff = &since
	}
	return globalEventTimeBranches("dst_ip,dst_port,actor_id", cutoff,
		"kind='tunnel' AND dst_ip IS NOT NULL AND dst_ip != ''", nil)
}

// CountTunnelTargetsSince returns the TRUE number of distinct (dst_ip, dst_port)
// destinations in the window. TopTunnelTargets applies a row LIMIT, so its len()
// is the page size, not the population — the proxy-targets widget reported that
// as its total and so said "3 destinations" when three were requested and nine
// existed, hiding six pivot destinations with nothing on screen to hint at it.
//
// Counting distinct pairs needs the subquery: COUNT(DISTINCT dst_ip) would
// under-count a host probed on several ports, which is exactly the port-sweep
// shape this widget exists to show.
func (s *Store) CountTunnelTargetsSince(since time.Time) (int, error) {
	window, args := tunnelTargetWindow(since)
	var n int
	err := s.db.QueryRow("WITH tunnel_events AS ("+window+") "+`
SELECT COUNT(*) FROM (
  SELECT dst_ip, dst_port FROM tunnel_events
  GROUP BY dst_ip, dst_port
)`, args...).Scan(&n)
	return n, err
}

// TopTunnelTargets returns the most-hit proxy/pivot destinations seen since
// the given time, newest window first by hit count.
//
// A zero `since` means "all time". limit<=0 falls back to a generous cap so a
// crafted flood of unique dst targets can't pull an unbounded result set into
// memory (mirrors topCounts). Callers that display a total must take it from
// CountTunnelTargetsSince, not from len() of this result.
func (s *Store) TopTunnelTargets(since time.Time, limit int) ([]TunnelTarget, error) {
	const defaultLimit = 500
	if limit <= 0 {
		limit = defaultLimit
	}
	window, args := tunnelTargetWindow(since)
	args = append(args, limit)
	rows, err := s.db.Query("WITH tunnel_events AS ("+window+") "+`
SELECT dst_ip, dst_port,
       COUNT(*)                       AS hits,
       COUNT(DISTINCT actor_id)       AS uniq_actors,
       MIN(exact_ts)                  AS first_seen,
       MAX(exact_ts)                  AS last_seen
FROM tunnel_events
GROUP BY dst_ip, dst_port
ORDER BY hits DESC, last_seen DESC, dst_ip ASC, dst_port ASC
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
		var err error
		if t.FirstSeen, err = parseTime(first); err != nil {
			return nil, fmt.Errorf("tunnel first seen: invalid timestamp")
		}
		if t.LastSeen, err = parseTime(last); err != nil {
			return nil, fmt.Errorf("tunnel last seen: invalid timestamp")
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
