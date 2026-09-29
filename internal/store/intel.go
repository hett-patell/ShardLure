package store

import (
	"database/sql"
	"fmt"
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
	cutoff := time.Now().UTC().Add(-time.Duration(limitHours) * time.Hour)
	window, args := eventTimeBranches("kind", &cutoff, "", nil)
	rows, err := s.db.Query("WITH hourly_events AS ("+window+") "+`
SELECT substr(exact_ts, 1, 13) AS hour, kind, COUNT(*) AS hits
FROM hourly_events
GROUP BY hour, kind
ORDER BY hour ASC, kind ASC`, args...)
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
		if c.Hour, err = time.Parse("2006-01-02T15", hour); err != nil {
			return nil, fmt.Errorf("hourly event kinds: invalid timestamp")
		}
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
	return s.labelCounts("SELECT label,COUNT(*) AS hits FROM (SELECT " + actorVisiblePlaybookSQL + " AS label FROM actors) WHERE label<>'' GROUP BY label ORDER BY hits DESC,label")
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

// RecentCommands returns the newest `limit` command-bearing events (exact
// time, ties by id), newest first.
//
// It used to be orderedGlobalEventQuery over every migrated row: with no index
// that can skip rows without a command, the native branch visited the whole
// table to find the ~1% with one, ~260 ms per /api/intel request on a
// 640k-event database. The native branch now reads idx_events_cmd_ts (v26,
// partial over command rows) newest-first and stops after `limit` rows; ts is
// canonical fixed-width text for migrated rows and rowid breaks ties in index
// order, so its first `limit` rows are exactly its newest. The legacy branch
// stays on the pinned, shrinking idx_events_legacy_ts, as every global mixed
// read does, and the merge re-applies the exact-time order and the limit.
func (s *Store) RecentCommands(limit int) ([]CommandEvent, error) {
	query, args := recentCommandsQuery(limit)
	return s.commandEvents(query, args)
}

func recentCommandsQuery(limit int) (string, []any) {
	if limit <= 0 {
		limit = 50
	}
	const pred = "command IS NOT NULL AND command != ''"
	query := `SELECT * FROM (SELECT ` + commandEventColumns + `,ts AS exact_ts FROM events INDEXED BY idx_events_cmd_ts
WHERE ` + pred + ` AND ts_unix_ns IS NOT NULL ORDER BY ts DESC, id DESC LIMIT ?)
UNION ALL SELECT ` + commandEventColumns + `,` + legacyEventTimeSQL + ` AS exact_ts FROM events INDEXED BY idx_events_legacy_ts
WHERE ts_unix_ns IS NULL AND (` + pred + `)
ORDER BY exact_ts DESC, id DESC LIMIT ?`
	return query, []any{limit, limit}
}

func (s *Store) EventsByActor(actorID string, limit int) ([]CommandEvent, error) {
	query, args := orderedEventQuery(commandEventColumns, nil, "actor_id=?", []any{actorID}, true, limit)
	return s.commandEvents(query, args)
}

const commandEventColumns = `id,ts,kind,COALESCE(src_ip,''),COALESCE(username,''),COALESCE(actor_id,''),COALESCE(command,''),COALESCE(session_id,''),COALESCE(sha256,''),COALESCE(filename,''),source`

func (s *Store) commandEvents(query string, args []any) ([]CommandEvent, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CommandEvent
	for rows.Next() {
		var e CommandEvent
		var id int64
		var ts, exact string
		var kind, source string
		if err := rows.Scan(&id, &ts, &kind, &e.SrcIP, &e.Username, &e.ActorID, &e.Command,
			&e.SessionID, &e.SHA256, &e.Filename, &source, &exact); err != nil {
			return nil, err
		}
		if e.TS, err = parseTime(ts); err != nil {
			return nil, fmt.Errorf("event %d: invalid timestamp", id)
		}
		e.Kind = models.EventKind(kind)
		e.Source = models.Source(source)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Release this reader before the second lookup, even with a one-connection
	// test pool. Cowrie command events normally inherit their user from login.
	if err := rows.Close(); err != nil {
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
	query, args := orderedEventQuery("id,command", nil,
		"actor_id=? AND command IS NOT NULL AND command != ''", []any{actorID}, true, 1)
	var cmd string
	err := s.db.QueryRow("SELECT command FROM ("+query+")", args...).Scan(&cmd)
	return cmd, err
}

// lastCommandNativeQuery / lastCommandLegacyQuery read ONE actor's newest
// command through partial (actor_id, ts) indexes over command-bearing rows
// only (schema v26).
//
// The native branch walks idx_events_actor_cmd newest-first (ts is canonical
// fixed-width text for migrated rows, and rowid breaks ties in index order)
// and stops at the first migrated row.
//
// The legacy branch reads idx_events_actor_cmd_legacy, whose predicate also
// requires ts_unix_ns IS NULL. On idx_events_actor_cmd the legacy filter
// could only be checked after a table lookup, so every call visited ALL of
// the actor's command rows, converted or not (~9.5 ms for one actor with 19k
// command rows under C SQLite, more under modernc on ARM), on every uncached
// /api/intel poll. On the legacy-only index it visits just the actor's
// unconverted command rows, ordered by the exact parsed time, and that index
// really does shrink to nothing: the backfill sets ts_unix_ns, which removes
// the row from it. Actor-scoped, never the global legacy index (see
// eventTimeBranches).
const (
	lastCommandNativeQuery = `SELECT command, ts, id FROM events INDEXED BY idx_events_actor_cmd
WHERE actor_id=? AND command IS NOT NULL AND command != '' AND ts_unix_ns IS NOT NULL ORDER BY ts DESC, id DESC LIMIT 1`
	lastCommandLegacyQuery = `SELECT command, ` + legacyEventTimeSQL + ` AS exact_ts, id FROM events INDEXED BY idx_events_actor_cmd_legacy
WHERE actor_id=? AND command IS NOT NULL AND command != '' AND ts_unix_ns IS NULL ORDER BY exact_ts DESC, id DESC LIMIT 1`
)

// LastCommandsForActors returns the most recent non-empty command per actor
// (latest exact event time, ties by event id), so the /api/intel actor list
// can fill its "Last cmd" column. Actors with no command event are absent.
//
// It used to rank every command event of each actor's whole history in one
// window-function query through idx_events_actor_ts. That index cannot skip
// the rows without a command, so every command-less actor - most of them:
// handshake scanners - was walked end to end on every /api/intel poll: 0.87 s
// of CPU per request on a 640k-event database, 97% of the handler. Two
// LIMIT 1 reads per actor through the partial command index touch only
// command rows, and a command-less actor costs one empty index seek.
func (s *Store) LastCommandsForActors(ids []string) (map[string]string, error) {
	out := make(map[string]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	native, err := s.db.Prepare(lastCommandNativeQuery)
	if err != nil {
		return nil, err
	}
	defer native.Close()
	legacy, err := s.db.Prepare(lastCommandLegacyQuery)
	if err != nil {
		return nil, err
	}
	defer legacy.Close()
	type hit struct {
		command, ts string
		id          int64
		ok          bool
	}
	read := func(stmt *sql.Stmt, actor string) (hit, error) {
		var h hit
		err := stmt.QueryRow(actor).Scan(&h.command, &h.ts, &h.id)
		if err == sql.ErrNoRows {
			return h, nil
		}
		h.ok = err == nil
		return h, err
	}
	for _, actor := range ids {
		n, err := read(native, actor)
		if err != nil {
			return nil, err
		}
		l, err := read(legacy, actor)
		if err != nil {
			return nil, err
		}
		// Both times are the fixed-width UTC form (formatFixedUTC), so they
		// compare as strings; the id breaks a tie, as the ranking did.
		best := n
		if l.ok && (!n.ok || l.ts > n.ts || (l.ts == n.ts && l.id > n.id)) {
			best = l
		}
		if best.ok {
			out[actor] = best.command
		}
	}
	return out, nil
}
