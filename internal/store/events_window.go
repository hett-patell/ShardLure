package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

const eventWindowColumns = `id, ts, source, kind, COALESCE(src_ip,''), COALESCE(src_port,0), COALESCE(username,''), COALESCE(password,''), COALESCE(session_id,''), COALESCE(hassh,''), COALESCE(ssh_client,''), COALESCE(command,''), COALESCE(sha256,''), COALESCE(filename,''), COALESCE(dst_ip,''), COALESCE(dst_port,0), COALESCE(actor_id,'')`

func readWindowEvents(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, since time.Time, limit int) ([]*models.Event, error) {
	query, args := orderedEventQuery(eventWindowColumns, &since, "", nil, true, limit)
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	var out []*models.Event
	err = iterateOrderedEventRows(rows, false, func(e *models.Event) error { out = append(out, e); return nil })
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) collectEventsSince(since time.Time, limit int) ([]*models.Event, int, error) {
	// Count and page share a read snapshot even when ingest/backfill is active.
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	query, args := eventWindowCountQuery(since)
	var total int
	if err := tx.QueryRowContext(ctx, query, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	events, err := readWindowEvents(ctx, tx, since, limit)
	if err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	return events, total, nil
}

func (s *Store) iterateEventsSinceExactContext(ctx context.Context, since time.Time, descending bool, fn func(*models.Event) error) error {
	query, args := orderedEventQuery(eventWindowColumns, &since, "", nil, descending, 0)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	return iterateOrderedEventRows(rows, false, fn)
}

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
	return readWindowEvents(context.Background(), s.db, since, limit)
}

// IterateEventsSince streams every event with TS >= since (no row cap), in
// ts ASC order, invoking fn per event. Unlike EventsSince — which caps at the
// most-recent 5000 rows and was silently truncating every windowed analytic
// (a "30d" view actually saw ~7.5h) — this covers the FULL window without
// buffering the whole result set in memory, so MITRE/TTP/IOC/graph/deobf can
// classify the entire window on a small VPS. fn must not retain e across calls.
func (s *Store) IterateEventsSince(since time.Time, fn func(*models.Event) error) error {
	return s.IterateEventsSinceContext(context.Background(), since, fn)
}

// IterateEventsSinceContext is the cancellable form used by report and web
// paths whose callers may disconnect during a large legacy window scan.
func (s *Store) IterateEventsSinceContext(ctx context.Context, since time.Time, fn func(*models.Event) error) error {
	return s.iterateEventsSinceExactContext(ctx, since, false, fn)
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
// Indexed migrated rows and exactly parsed legacy rows are merged newest-first
// before SQL LIMIT. A separate scalar count in the same snapshot reports the
// full window size without decoding discarded event bodies.
func (s *Store) EventsSinceCapped(since time.Time, limit int) (events []*models.Event, total int, err error) {
	if limit <= 0 {
		limit = defaultWindowEventCap
	}
	return s.collectEventsSince(since, limit)
}

// defaultWindowEventCap bounds the events any single windowed-analytics fetch
// pulls into memory. 200k rows of the Event struct is on the order of tens of
// MB — enough that the MITRE/TTP/IOC/wordlist collectors see a representative
// window on any real honeypot, but a hard ceiling so a wide window over a huge
// DB can't OOM the process or pin a giant slice in the window cache. When the
// window holds more than this, the handlers report total > returned so the UI
// can disclose the truncation.
const defaultWindowEventCap = 200_000
