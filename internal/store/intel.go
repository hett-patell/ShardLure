package store

import (
	"database/sql"
	"strings"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// HourlyKindCell is one cell in an hour × event-kind heatmap.
type HourlyKindCell struct {
	Hour time.Time
	Kind string
	Hits int
}

// LabelCount is a grouped count (playbook, intent, kind, etc.).
type LabelCount struct {
	Label string
	Hits  int
}

// CommandEvent is a cowrie/journal event with command detail for the intel view.
type CommandEvent struct {
	TS        time.Time
	Kind      models.EventKind
	SrcIP     string
	Username  string
	ActorID   string
	Command   string
	SessionID string
	SHA256    string
	Filename  string
	Source    models.Source
}

func (s *Store) HourlyEventCountsByKind(limitHours int) ([]HourlyKindCell, error) {
	if limitHours <= 0 {
		limitHours = 72
	}
	cutoff := time.Now().UTC().Add(-time.Duration(limitHours) * time.Hour).Format(time.RFC3339Nano)
	rows, err := s.db.Query(`
SELECT substr(ts, 1, 13) AS hour, kind, COUNT(*) AS hits
FROM events
WHERE ts >= ?
GROUP BY hour, kind
ORDER BY hour ASC, kind ASC`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []HourlyKindCell
	for rows.Next() {
		var hour string
		var c HourlyKindCell
		if err := rows.Scan(&hour, &c.Kind, &c.Hits); err != nil {
			return nil, err
		}
		c.Hour, _ = time.Parse("2006-01-02T15", hour)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) CountsByKind() ([]LabelCount, error) {
	return s.labelCounts(`SELECT kind, COUNT(*) AS hits FROM events GROUP BY kind ORDER BY hits DESC`)
}

func (s *Store) CountsByIntent() ([]LabelCount, error) {
	return s.labelCounts(`SELECT intent, COUNT(*) AS hits FROM actors WHERE intent != '' GROUP BY intent ORDER BY hits DESC`)
}

func (s *Store) CountsByPlaybook() ([]LabelCount, error) {
	return s.labelCounts(`SELECT playbook, COUNT(*) AS hits FROM actors WHERE playbook != '' GROUP BY playbook ORDER BY hits DESC`)
}

func (s *Store) CountsBySource() ([]LabelCount, error) {
	return s.labelCounts(`SELECT source, COUNT(*) AS hits FROM events GROUP BY source ORDER BY hits DESC`)
}

func (s *Store) labelCounts(query string) ([]LabelCount, error) {
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LabelCount
	for rows.Next() {
		var c LabelCount
		if err := rows.Scan(&c.Label, &c.Hits); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) RecentCommands(limit int) ([]CommandEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT ts, kind, src_ip, username, actor_id, command, session_id, sha256, filename, source
FROM events WHERE command IS NOT NULL AND command != '' ORDER BY ts DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CommandEvent
	for rows.Next() {
		var e CommandEvent
		var ts string
		var kind, source string
		if err := rows.Scan(&ts, &kind, &e.SrcIP, &e.Username, &e.ActorID, &e.Command,
			&e.SessionID, &e.SHA256, &e.Filename, &source); err != nil {
			return nil, err
		}
		e.TS, _ = parseTime(ts)
		e.Kind = models.EventKind(kind)
		e.Source = models.Source(source)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Cowrie stamps username on login/auth events, not on command.input —
	// fill empty usernames from the session's login row so the intel
	// "Recent commands" User column isn't permanently "—".
	if err := s.fillSessionUsernames(out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) EventsByActor(actorID string, limit int) ([]CommandEvent, error) {
	q := `SELECT ts, kind, src_ip, username, actor_id, command, session_id, sha256, filename, source
FROM events WHERE actor_id=? ORDER BY ts DESC`
	args := []any{actorID}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CommandEvent
	for rows.Next() {
		var e CommandEvent
		var ts string
		var kind, source string
		if err := rows.Scan(&ts, &kind, &e.SrcIP, &e.Username, &e.ActorID, &e.Command,
			&e.SessionID, &e.SHA256, &e.Filename, &source); err != nil {
			return nil, err
		}
		e.TS, _ = parseTime(ts)
		e.Kind = models.EventKind(kind)
		e.Source = models.Source(source)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := s.fillSessionUsernames(out); err != nil {
		return nil, err
	}
	return out, nil
}

// fillSessionUsernames backfills empty Username fields from the session's
// login/auth events. Cowrie only writes username on accepted/failed_password
// rows; command/file_* events leave it blank. Batched in one IN-query over
// the distinct session_ids that still need a user.
func (s *Store) fillSessionUsernames(events []CommandEvent) error {
	need := make(map[string]struct{})
	for _, e := range events {
		if e.Username == "" && e.SessionID != "" {
			need[e.SessionID] = struct{}{}
		}
	}
	if len(need) == 0 {
		return nil
	}
	ids := make([]string, 0, len(need))
	for id := range need {
		ids = append(ids, id)
	}
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}
	q := `SELECT session_id,
  COALESCE(
    MAX(CASE WHEN kind = 'accepted' AND username != '' THEN username END),
    MAX(CASE WHEN username != '' THEN username END)
  )
FROM events
WHERE session_id IN (` + strings.Join(placeholders, ",") + `)
GROUP BY session_id`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	bySess := make(map[string]string, len(ids))
	for rows.Next() {
		var sid string
		var user sql.NullString
		if err := rows.Scan(&sid, &user); err != nil {
			return err
		}
		if user.Valid && user.String != "" {
			bySess[sid] = user.String
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range events {
		if events[i].Username == "" && events[i].SessionID != "" {
			if u, ok := bySess[events[i].SessionID]; ok {
				events[i].Username = u
			}
		}
	}
	return nil
}

// LastCommandByActor returns the most recent non-empty command for an actor.
func (s *Store) LastCommandByActor(actorID string) (string, error) {
	var cmd string
	err := s.db.QueryRow(`
SELECT command FROM events
WHERE actor_id=? AND command IS NOT NULL AND command != ''
ORDER BY ts DESC LIMIT 1`, actorID).Scan(&cmd)
	return cmd, err
}

// LastCommandsForActors returns the most recent non-empty command per actor
// for a batch of actor IDs in ONE query — so the /api/intel actor list can
// fill its "Last cmd" column without an N+1 (or leaving it permanently blank,
// which it was: handleIntel never called the per-actor version). Mirrors
// ActorUsersForActors' window-function approach; actors with no command event
// are simply absent from the map. Uses idx_events_actor_ts for the ordering.
func (s *Store) LastCommandsForActors(ids []string) (map[string]string, error) {
	out := make(map[string]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}
	q := `
SELECT actor_id, command FROM (
  SELECT actor_id, command,
         ROW_NUMBER() OVER (PARTITION BY actor_id ORDER BY ts DESC) AS rn
  FROM events
  WHERE actor_id IN (` + strings.Join(placeholders, ",") + `)
    AND command IS NOT NULL AND command != ''
) WHERE rn = 1`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, cmd string
		if err := rows.Scan(&id, &cmd); err != nil {
			return nil, err
		}
		out[id] = cmd
	}
	return out, rows.Err()
}
