package store

import (
	"fmt"
	"sort"
	"strconv"
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

// having renders the aggregate filter shared by the list and count queries, so
// the count always describes the same population as the page it labels.
//
// It has to be HAVING rather than WHERE: "sessions with commands" is a property
// of the whole session group, not of an individual row — restricting rows to
// those with a non-empty command would drop the login/connect events and corrupt
// every other aggregate on the summary (event counts, start time, username).
//
// (Described in prose rather than as SQL on purpose: a doc comment containing a
// pair of single quotes around nothing gets rewritten to a curly quote by
// gofmt's doc-comment pass, which then fails CI's gofmt gate.)
func (o SessionListOptions) having() string {
	if o.MinCommands <= 0 {
		return ""
	}
	return "\nHAVING SUM(CASE WHEN command != '' THEN 1 ELSE 0 END) >= " +
		strconv.Itoa(o.MinCommands)
}

func firstSessionOpts(opts []SessionListOptions) SessionListOptions {
	if len(opts) > 0 {
		return opts[0]
	}
	return SessionListOptions{}
}

type sessionAccumulator struct {
	summary        SessionSummary
	firstCommand   string
	firstCommandTS time.Time
	firstCommandID int64
}

func (s *Store) sessionSummariesSince(since time.Time, minCommands int) ([]ShellSessionSummary, error) {
	byID := make(map[string]*sessionAccumulator)
	err := s.IterateEventsSince(since, func(event *models.Event) error {
		if event.Source != models.SourceCowrie || event.SessionID == "" {
			return nil
		}
		acc := byID[event.SessionID]
		if acc == nil {
			acc = &sessionAccumulator{summary: SessionSummary{ID: event.SessionID, StartTS: event.TS, EndTS: event.TS}}
			byID[event.SessionID] = acc
		}
		sum := &acc.summary
		if event.TS.Before(sum.StartTS) {
			sum.StartTS = event.TS
		}
		if event.TS.After(sum.EndTS) {
			sum.EndTS = event.TS
		}
		if event.SrcIP > sum.SrcIP {
			sum.SrcIP = event.SrcIP
		}
		if event.Username != "" && event.Username > sum.Username {
			sum.Username = event.Username
		}
		if event.HASSH > sum.HASSH {
			sum.HASSH = event.HASSH
		}
		if event.SSHClient > sum.SSHClient {
			sum.SSHClient = event.SSHClient
		}
		if event.ActorID > sum.ActorID {
			sum.ActorID = event.ActorID
		}
		sum.EventCount++
		if event.Command != "" {
			sum.CmdCount++
			if event.Kind == models.KindCommand && (acc.firstCommandTS.IsZero() || event.TS.Before(acc.firstCommandTS) ||
				(event.TS.Equal(acc.firstCommandTS) && event.ID < acc.firstCommandID)) {
				acc.firstCommand = event.Command
				acc.firstCommandTS = event.TS
				acc.firstCommandID = event.ID
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]ShellSessionSummary, 0, len(byID))
	for _, acc := range byID {
		if acc.summary.CmdCount < minCommands {
			continue
		}
		out = append(out, ShellSessionSummary{SessionSummary: acc.summary, FirstCommand: acc.firstCommand})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].EndTS.Equal(out[j].EndTS) {
			return out[i].EndTS.After(out[j].EndTS)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
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
	o := firstSessionOpts(opts)
	rows, err := s.sessionSummariesSince(since, o.MinCommands)
	return len(rows), err
}

func (s *Store) ListSessions(since time.Time, limit int, opts ...SessionListOptions) ([]SessionSummary, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.sessionSummariesSince(since, firstSessionOpts(opts).MinCommands)
	if err != nil {
		return nil, err
	}
	if len(rows) > limit {
		rows = rows[:limit]
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
	out, err := s.sessionSummariesSince(since, 1)
	if err != nil {
		return nil, err
	}
	if len(out) > limit {
		out = out[:limit]
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
