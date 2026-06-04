package store

import (
	"database/sql"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// SessionSummary is one cowrie session rolled up to the columns the
// timeline list needs. Light enough to load 500 of them and render
// instantly; for the full play-by-play call SessionEvents.
type SessionSummary struct {
	ID         string
	SrcIP      string
	Username   string // a non-empty username on the session (alphabetical-max; the detail modal resolves the true chronological one)
	HASSH      string
	SSHClient  string
	StartTS    time.Time
	EndTS      time.Time
	EventCount int
	CmdCount   int
	ActorID    string
}

// ListSessions returns cowrie sessions whose latest event falls within
// the given window, ordered most-recent first. limit caps the result so
// the dashboard list stays bounded.
//
// Only cowrie events are considered: journal events have no session id
// (per the design decision in the slice planning question) — a bare
// SSH attempt isn't a session.
// CountSessionsSince returns the TRUE number of distinct cowrie sessions in the
// window. ListSessions caps at the newest `limit`, so the rendered row count
// (always == limit on a busy box) is not the population; the dashboard now
// shows "newest N of <this> sessions".
func (s *Store) CountSessionsSince(since time.Time) (int, error) {
	var n int
	err := s.db.QueryRow(`
SELECT COUNT(DISTINCT session_id) FROM events
WHERE source='cowrie' AND session_id != '' AND ts >= ?`,
		since.UTC().Format(time.RFC3339Nano)).Scan(&n)
	return n, err
}

func (s *Store) ListSessions(since time.Time, limit int) ([]SessionSummary, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.Query(`
SELECT
  session_id,
  MAX(src_ip)                                       AS src_ip,
  -- Alphabetical-max non-empty username. NOT chronologically "most recent" —
  -- a correlated per-session ORDER BY ts subquery here made this endpoint take
  -- ~110s over a 30d window (tens of thousands of session groups). In practice
  -- a session re-authing to a *different* username is vanishingly rare (zero on
  -- live data), so MAX is a safe, fast approximation; the detail modal shows
  -- the true chronological user.
  COALESCE(MAX(CASE WHEN username != '' THEN username END), '') AS username,
  MAX(hassh)                                        AS hassh,
  MAX(ssh_client)                                   AS ssh_client,
  MIN(ts)                                           AS start_ts,
  MAX(ts)                                           AS end_ts,
  COUNT(*)                                          AS n,
  SUM(CASE WHEN command != '' THEN 1 ELSE 0 END)    AS n_cmd,
  COALESCE(MAX(actor_id), '')                       AS actor_id
FROM events
WHERE source='cowrie' AND session_id != '' AND ts >= ?
GROUP BY session_id
ORDER BY end_ts DESC
LIMIT ?`, since.UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionSummary
	for rows.Next() {
		var s SessionSummary
		var startTS, endTS string
		if err := rows.Scan(&s.ID, &s.SrcIP, &s.Username, &s.HASSH, &s.SSHClient,
			&startTS, &endTS, &s.EventCount, &s.CmdCount, &s.ActorID); err != nil {
			return nil, err
		}
		s.StartTS, _ = parseTime(startTS)
		s.EndTS, _ = parseTime(endTS)
		out = append(out, s)
	}
	return out, rows.Err()
}

// ShellSessionSummary is a SessionSummary plus the first shell command
// observed in that session. It surfaces the most interesting honeypot rows
// -- sessions where an attacker actually executed something -- to the
// landing dashboard.
type ShellSessionSummary struct {
	SessionSummary
	FirstCommand string
}

// RecentShellSessions returns up to `limit` cowrie sessions whose latest
// event is within `since`, restricted to sessions that produced at least
// one cowrie.command.input event. Results are ordered most-recent first
// and include the earliest command observed (for the dashboard sample
// column).
func (s *Store) RecentShellSessions(since time.Time, limit int) ([]ShellSessionSummary, error) {
	if limit <= 0 {
		limit = 30
	}
	rows, err := s.db.Query(`
WITH first_cmds AS (
  SELECT session_id, command,
    ROW_NUMBER() OVER (PARTITION BY session_id ORDER BY ts ASC) AS rn
  FROM events
  WHERE source = 'cowrie' AND kind = 'command' AND command != ''
)
SELECT
  s.session_id,
  MAX(s.src_ip)                                            AS src_ip,
  COALESCE(MAX(CASE WHEN s.username != '' THEN s.username END), '') AS username,
  MAX(s.hassh)                                             AS hassh,
  MAX(s.ssh_client)                                        AS ssh_client,
  MIN(s.ts)                                                AS start_ts,
  MAX(s.ts)                                                AS end_ts,
  COUNT(*)                                                 AS n,
  SUM(CASE WHEN s.kind='command' THEN 1 ELSE 0 END)        AS n_cmd,
  COALESCE(MAX(s.actor_id), '')                            AS actor_id,
  COALESCE(MAX(fc.command), '')                            AS first_cmd
FROM events s
LEFT JOIN first_cmds fc ON fc.session_id = s.session_id AND fc.rn = 1
WHERE s.source='cowrie' AND s.session_id != '' AND s.ts >= ?
GROUP BY s.session_id
HAVING n_cmd > 0
ORDER BY end_ts DESC
LIMIT ?`, since.UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ShellSessionSummary
	for rows.Next() {
		var sum ShellSessionSummary
		var startTS, endTS string
		var firstCmd sql.NullString
		if err := rows.Scan(&sum.ID, &sum.SrcIP, &sum.Username, &sum.HASSH, &sum.SSHClient,
			&startTS, &endTS, &sum.EventCount, &sum.CmdCount, &sum.ActorID, &firstCmd); err != nil {
			return nil, err
		}
		sum.StartTS, _ = parseTime(startTS)
		sum.EndTS, _ = parseTime(endTS)
		if firstCmd.Valid {
			sum.FirstCommand = firstCmd.String
		}
		out = append(out, sum)
	}
	return out, rows.Err()
}

// SessionEvents returns every event in a session in chronological order.
// Used to render the play-by-play terminal-style timeline.
func (s *Store) SessionEvents(sessionID string) ([]*models.Event, error) {
	rows, err := s.db.Query(`
SELECT id, ts, source, kind, src_ip, src_port, username, password, session_id, hassh, ssh_client, ja4, command, sha256, filename, actor_id
FROM events WHERE session_id=? ORDER BY ts ASC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.Event
	for rows.Next() {
		e := &models.Event{}
		var ts, source, kind string
		if err := rows.Scan(&e.ID, &ts, &source, &kind, &e.SrcIP, &e.SrcPort, &e.Username,
			&e.Password, &e.SessionID, &e.HASSH, &e.SSHClient, &e.JA4, &e.Command,
			&e.SHA256, &e.Filename, &e.ActorID); err != nil {
			return nil, err
		}
		e.TS, _ = parseTime(ts)
		e.Source = models.Source(source)
		e.Kind = models.EventKind(kind)
		out = append(out, e)
	}
	return out, rows.Err()
}
