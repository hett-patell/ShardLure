package store

import (
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// EventsSince returns events with TS >= since. Includes all columns the
// classifier and exporters need (kind, command, src_ip, actor_id,
// session_id, hashes, source). limit caps the rows scanned so analysts
// can't accidentally walk an entire 30-day log file from a UI fetch.
//
// Pass limit=0 (or any non-positive value) to use the default cap of
// 5000 rows. Pass an explicit positive limit if you want fewer; there
// is no way to request "all rows" - this method is intentionally
// bounded. For unbounded streaming, use IterateEventsBySource.
//
// Use this for read-only analytics. Streaming ingest paths should
// continue to call IterateEventsBySource so they can consume
// arbitrarily large slices without buffering everything in memory.
func (s *Store) EventsSince(since time.Time, limit int) ([]*models.Event, error) {
	if limit <= 0 {
		limit = 5000
	}
	rows, err := s.db.Query(`
SELECT id, ts, source, kind, src_ip, src_port, username, password, session_id, hassh, ssh_client, command, sha256, filename, COALESCE(dst_ip,'') AS dst_ip, dst_port, actor_id
FROM events WHERE ts >= ? ORDER BY ts DESC LIMIT ?`,
		since.UTC().Format(time.RFC3339Nano), limit)
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
		e.TS, _ = parseTime(ts)
		e.Source = models.Source(source)
		e.Kind = models.EventKind(kind)
		out = append(out, e)
	}
	return out, rows.Err()
}

// IterateEventsSince streams every event with TS >= since (no row cap), in
// ts ASC order, invoking fn per event. Unlike EventsSince — which caps at the
// most-recent 5000 rows and was silently truncating every windowed analytic
// (a "30d" view actually saw ~7.5h) — this covers the FULL window without
// buffering the whole result set in memory, so MITRE/TTP/IOC/graph/deobf can
// classify the entire window on a small VPS. fn must not retain e across calls.
func (s *Store) IterateEventsSince(since time.Time, fn func(*models.Event) error) error {
	rows, err := s.db.Query(`
SELECT id, ts, source, kind, src_ip, src_port, username, password, session_id, hassh, ssh_client, command, sha256, filename, COALESCE(dst_ip,'') AS dst_ip, dst_port, actor_id
FROM events WHERE ts >= ? ORDER BY ts ASC`,
		since.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		e := &models.Event{}
		var ts, source, kind string
		if err := rows.Scan(&e.ID, &ts, &source, &kind, &e.SrcIP, &e.SrcPort, &e.Username,
			&e.Password, &e.SessionID, &e.HASSH, &e.SSHClient, &e.Command,
			&e.SHA256, &e.Filename, &e.DstIP, &e.DstPort, &e.ActorID); err != nil {
			return err
		}
		e.TS, _ = parseTime(ts)
		e.Source = models.Source(source)
		e.Kind = models.EventKind(kind)
		if err := fn(e); err != nil {
			return err
		}
	}
	return rows.Err()
}

// EventsSinceAll returns every event in the window (full window, no silent
// cap), backed by IterateEventsSince. Use this for the windowed analytic
// endpoints whose collectors take a []*Event slice. The result is the true
// window population — a "30d" request returns 30 days of events, not the last
// 5000.
//
// Prefer EventsSinceCapped for anything reachable from a UI poll: this method
// materializes the ENTIRE window into a slice, which on a multi-million-row DB
// is a full scan plus a multi-hundred-MB allocation held in cache.
func (s *Store) EventsSinceAll(since time.Time) ([]*models.Event, error) {
	var out []*models.Event
	err := s.IterateEventsSince(since, func(e *models.Event) error {
		out = append(out, e)
		return nil
	})
	return out, err
}

// EventsSinceCapped returns at most limit events from the window (the most
// recent, newest-first) along with total — the true count of events in the
// window regardless of the cap. This is the bounded counterpart to
// EventsSinceAll: it never materializes more than limit rows in memory, but
// unlike the old silently-truncating EventsSince it also reports the full
// window size so callers can disclose "analyzed N of M" instead of quietly
// classifying a fraction. limit<=0 uses defaultWindowEventCap.
//
// The events are returned newest-first (ts DESC LIMIT), matching what a capped
// view should show — the most recent activity — while total comes from a cheap
// COUNT that rides idx_events_ts.
func (s *Store) EventsSinceCapped(since time.Time, limit int) (events []*models.Event, total int, err error) {
	if limit <= 0 {
		limit = defaultWindowEventCap
	}
	sinceStr := since.UTC().Format(time.RFC3339Nano)
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE ts >= ?`, sinceStr).Scan(&total); err != nil {
		return nil, 0, err
	}
	events, err = s.EventsSince(since, limit)
	return events, total, err
}

// defaultWindowEventCap bounds the events any single windowed-analytics fetch
// pulls into memory. 200k rows of the Event struct is on the order of tens of
// MB — enough that the MITRE/TTP/IOC/wordlist collectors see a representative
// window on any real honeypot, but a hard ceiling so a wide window over a huge
// DB can't OOM the process or pin a giant slice in the window cache. When the
// window holds more than this, the handlers report total > returned so the UI
// can disclose the truncation.
const defaultWindowEventCap = 200_000
