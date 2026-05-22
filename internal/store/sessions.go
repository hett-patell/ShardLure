package store

import (
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// SessionSummary is one cowrie session rolled up to the columns the
// timeline list needs. Light enough to load 500 of them and render
// instantly; for the full play-by-play call SessionEvents.
type SessionSummary struct {
	ID         string
	SrcIP      string
	Username   string // most-recent non-empty username on the session
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
func (s *Store) ListSessions(since time.Time, limit int) ([]SessionSummary, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.Query(`
SELECT
  session_id,
  MAX(src_ip)                                       AS src_ip,
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
