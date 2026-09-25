package store

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
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
	// DurationMs is cowrie's authoritative session length (cowrie.session.closed),
	// 0 when not observed — the API then falls back to EndTS-StartTS. Arch is the
	// negotiated client arch (cowrie.session.params), "" when not observed. Both
	// are stamped from cowrie_session_meta after the group-by, not joined.
	DurationMs int64
	Arch       string
}

// SessionListOptions narrows WHICH sessions ListSessions and
// CountSessionsSince consider. Variadic and zero-valued by default, so existing
// callers keep the unfiltered behaviour (mirrors abuseipdb.VetOptions).
//
// It exists because the replay generator needs *replayable* sessions, and
// filtering after the LIMIT is not the same thing as filtering before it. The
// replay dropdown used to fetch the newest 200 sessions and discard the
// command-less ones in JavaScript. On the reference deployment ~99.5% of
// sessions are bare connects, so 200 rows yielded 8 selectable sessions out of
// 1,876 that actually had commands — and when a batch of 200 happened to contain
// none, the panel said "no sessions with commands in window", which is a
// different and false claim from "none in the newest 200".
type SessionListOptions struct {
	// MinCommands requires the session to carry at least this many command
	// events. 0 (or negative) means no requirement.
	MinCommands int
}

func firstSessionOpts(opts []SessionListOptions) SessionListOptions {
	if len(opts) > 0 {
		return opts[0]
	}
	return SessionListOptions{}
}

// sessionWindow is the cowrie-session slice of the exact-time event branches.
// The legacy branch MUST stay pinned to the partial legacy-timestamp index
// (globalEventTimeBranches): with an unpinned legacy branch SQLite evaluated the
// Go timestamp function on every cowrie row, not just unconverted ones (about
// seven Go allocations per event in the window). The native branch remains
// bounded by the ts index.
func sessionWindow(since time.Time) (string, []any) {
	return globalEventTimeBranches("id,session_id,src_ip,username,hassh,ssh_client,actor_id,command,kind", &since,
		"source='cowrie' AND session_id<>''", nil)
}

// sessionSummariesSince aggregates sessions whose events fall in the window,
// newest end time first, entirely inside SQLite, returning at most limit rows
// (limit <= 0 means all). It used to stream EVERY event in the window through
// Go and aggregate in a map, twice per request (list + count): on the 1.75M-
// event prod database /api/intel/sessions at 30d/90d never answered. The
// per-column MAX choices match the previous Go accumulator exactly.
func (s *Store) sessionSummariesSince(since time.Time, minCommands, limit int) ([]ShellSessionSummary, error) {
	out, _, err := s.sessionSummaryPage(since, minCommands, limit)
	return out, err
}

// sessionSummaryPage is sessionSummariesSince plus the total number of
// matching sessions, computed in the same pass (COUNT(*) OVER () over the
// grouped rows, before LIMIT). Grouping the window a second time just to count
// doubled the cost of the slowest intel panel on prod.
func (s *Store) sessionSummaryPage(since time.Time, minCommands, limit int) ([]ShellSessionSummary, int, error) {
	window, args := sessionWindow(since)
	query := `WITH w AS (` + window + `)
SELECT session_id, MAX(src_ip), COALESCE(MAX(CASE WHEN username<>'' THEN username END),''),
  COALESCE(MAX(hassh),''), COALESCE(MAX(ssh_client),''), COALESCE(MAX(actor_id),''),
  MIN(exact_ts), MAX(exact_ts), COUNT(*), SUM(CASE WHEN COALESCE(command,'')<>'' THEN 1 ELSE 0 END),
  COUNT(*) OVER ()
FROM w GROUP BY session_id`
	// HAVING, not WHERE: "has commands" is a property of the whole session.
	// Filtering rows would drop its login/connect events and corrupt every
	// other aggregate (event count, start time, username).
	if minCommands > 0 {
		query += ` HAVING SUM(CASE WHEN COALESCE(command,'')<>'' THEN 1 ELSE 0 END) >= ?`
		args = append(args, minCommands)
	}
	query += ` ORDER BY MAX(exact_ts) DESC, session_id ASC`
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []ShellSessionSummary
	total := 0
	for rows.Next() {
		var sum SessionSummary
		var srcIP sql.NullString
		var startTS, endTS string
		if err := rows.Scan(&sum.ID, &srcIP, &sum.Username, &sum.HASSH, &sum.SSHClient, &sum.ActorID,
			&startTS, &endTS, &sum.EventCount, &sum.CmdCount, &total); err != nil {
			return nil, 0, err
		}
		sum.SrcIP = srcIP.String
		if sum.StartTS, err = time.Parse(time.RFC3339Nano, startTS); err != nil {
			return nil, 0, fmt.Errorf("session %s event time: %w", sum.ID, err)
		}
		if sum.EndTS, err = time.Parse(time.RFC3339Nano, endTS); err != nil {
			return nil, 0, fmt.Errorf("session %s event time: %w", sum.ID, err)
		}
		out = append(out, ShellSessionSummary{SessionSummary: sum})
	}
	return out, total, rows.Err()
}

// countSessionsSince counts the same population sessionSummariesSince lists,
// without returning rows.
func (s *Store) countSessionsSince(since time.Time, minCommands int) (int, error) {
	window, args := sessionWindow(since)
	query := `WITH w AS (` + window + `) SELECT COUNT(*) FROM (SELECT session_id FROM w GROUP BY session_id`
	if minCommands > 0 {
		query += ` HAVING SUM(CASE WHEN COALESCE(command,'')<>'' THEN 1 ELSE 0 END) >= ?`
		args = append(args, minCommands)
	}
	query += `)`
	var n int
	err := s.db.QueryRow(query, args...).Scan(&n)
	return n, err
}

// stampFirstCommands fills FirstCommand for the (bounded) returned sessions:
// the earliest in-window kind=command event, ties broken by event id.
func (s *Store) stampFirstCommands(since time.Time, sums []ShellSessionSummary) error {
	if len(sums) == 0 {
		return nil
	}
	placeholders := make([]string, len(sums))
	ids := make([]any, len(sums))
	index := make(map[string]int, len(sums))
	for i := range sums {
		placeholders[i] = "?"
		ids[i] = sums[i].ID
		index[sums[i].ID] = i
	}
	// Pinned legacy branch for the same reason as sessionWindow.
	window, args := globalEventTimeBranches("id,session_id,command", &since,
		"source='cowrie' AND kind='command' AND COALESCE(command,'')<>'' AND session_id IN ("+strings.Join(placeholders, ",")+")", ids)
	rows, err := s.db.Query(`WITH w AS (`+window+`)
SELECT session_id, command FROM (
  SELECT session_id, command, ROW_NUMBER() OVER (PARTITION BY session_id ORDER BY exact_ts ASC, id ASC) AS rn FROM w
) WHERE rn=1`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, command string
		if err := rows.Scan(&id, &command); err != nil {
			return err
		}
		if i, ok := index[id]; ok {
			sums[i].FirstCommand = command
		}
	}
	return rows.Err()
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
//
// opts must match whatever ListSessions was given, or the total describes a
// different population than the rows.
func (s *Store) CountSessionsSince(since time.Time, opts ...SessionListOptions) (int, error) {
	return s.countSessionsSince(since, firstSessionOpts(opts).MinCommands)
}

// ListSessionsWithTotal is ListSessions plus the true matching-session total
// (CountSessionsSince) from a single aggregation pass.
func (s *Store) ListSessionsWithTotal(since time.Time, limit int, opts ...SessionListOptions) ([]SessionSummary, int, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, total, err := s.sessionSummaryPage(since, firstSessionOpts(opts).MinCommands, limit)
	if err != nil {
		return nil, 0, err
	}
	out := make([]SessionSummary, len(rows))
	for i := range rows {
		out[i] = rows[i].SessionSummary
	}
	if err := s.stampSessionMeta(out); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (s *Store) ListSessions(since time.Time, limit int, opts ...SessionListOptions) ([]SessionSummary, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.sessionSummariesSince(since, firstSessionOpts(opts).MinCommands, limit)
	if err != nil {
		return nil, err
	}
	out := make([]SessionSummary, len(rows))
	for i := range rows {
		out[i] = rows[i].SessionSummary
	}
	if err := s.stampSessionMeta(out); err != nil {
		return nil, err
	}
	return out, nil
}

// stampSessionMeta fills DurationMs/Arch on each summary from the
// cowrie_session_meta side-channel in one batched lookup. A missing binding
// leaves the zero values (the API falls back to the ts-delta / "unknown").
func (s *Store) stampSessionMeta(sums []SessionSummary) error {
	if len(sums) == 0 {
		return nil
	}
	ids := make([]string, 0, len(sums))
	for i := range sums {
		if sums[i].ID != "" {
			ids = append(ids, sums[i].ID)
		}
	}
	meta, err := s.SessionMetaForSessions(ids)
	if err != nil {
		return err
	}
	for i := range sums {
		if m, ok := meta[sums[i].ID]; ok {
			sums[i].DurationMs = m.DurationMs
			sums[i].Arch = m.Arch
		}
	}
	return nil
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
	out, err := s.sessionSummariesSince(since, 1, limit)
	if err != nil {
		return nil, err
	}
	if err := s.stampFirstCommands(since, out); err != nil {
		return nil, err
	}
	// Stamp duration/arch from the side-channel. ShellSessionSummary embeds
	// SessionSummary by value, so mutate through the embedded field in place.
	ids := make([]string, 0, len(out))
	for i := range out {
		if out[i].ID != "" {
			ids = append(ids, out[i].ID)
		}
	}
	meta, err := s.SessionMetaForSessions(ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if m, ok := meta[out[i].ID]; ok {
			out[i].DurationMs = m.DurationMs
			out[i].Arch = m.Arch
		}
	}
	return out, nil
}

// SessionEvents returns every event in a session in chronological order.
// Used to render the play-by-play terminal-style timeline.
func (s *Store) SessionEvents(sessionID string) ([]*models.Event, error) {
	// source='cowrie' lets the planner use idx_events_session(source,
	// session_id, ts): without it the session_id predicate can't lead any
	// index and every session-detail click full-scanned the events table.
	// Sessions are cowrie-only, so this doesn't drop rows.
	rows, err := s.db.Query(`
SELECT id, ts, source, kind, COALESCE(src_ip,''), COALESCE(src_port,0), COALESCE(username,''), COALESCE(password,''), COALESCE(session_id,''), COALESCE(hassh,''), COALESCE(ssh_client,''), COALESCE(command,''), COALESCE(sha256,''), COALESCE(filename,''), COALESCE(dst_ip,''), COALESCE(dst_port,0), COALESCE(actor_id,'')
FROM events WHERE source='cowrie' AND session_id=?`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.Event
	for rows.Next() {
		e := &models.Event{}
		var ts, source, kind string
		if err := rows.Scan(&e.ID, &ts, &source, &kind, &e.SrcIP, &e.SrcPort, &e.Username,
			&e.Password, &e.SessionID, &e.HASSH, &e.SSHClient, &e.Command,
			&e.SHA256, &e.Filename, &e.DstIP, &e.DstPort, &e.ActorID); err != nil {
			return nil, err
		}
		parsed, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return nil, fmt.Errorf("event %d ts: %w", e.ID, err)
		}
		e.TS = parsed
		e.Source = models.Source(source)
		e.Kind = models.EventKind(kind)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].TS.Equal(out[j].TS) {
			return out[i].TS.Before(out[j].TS)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// CountSessions returns the all-time number of distinct cowrie sessions.
// Companion to CountSessionsSince for the dashboard's Summary tiles, which are
// all-time figures — using the 24h-windowed count there would sit inconsistently
// beside all-time events/actors/IPs, and using len(RecentShellSessions) would be
// worse still: that slice is LIMITed to 30, so the tile would read "30" forever
// once a honeypot passed 30 sessions.
func (s *Store) CountSessions() (int, error) {
	var n int
	err := s.db.QueryRow(`
SELECT COUNT(DISTINCT session_id) FROM events
WHERE source='cowrie' AND session_id != ''`).Scan(&n)
	return n, err
}
