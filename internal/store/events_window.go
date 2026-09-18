package store

import (
	"container/heap"
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

const eventWindowColumns = `id, ts, source, kind, COALESCE(src_ip,''), COALESCE(src_port,0), COALESCE(username,''), COALESCE(password,''), COALESCE(session_id,''), COALESCE(hassh,''), COALESCE(ssh_client,''), COALESCE(command,''), COALESCE(sha256,''), COALESCE(filename,''), COALESCE(dst_ip,''), COALESCE(dst_port,0), COALESCE(actor_id,'')`

const eventTimeBucketSQL = `CASE
WHEN ts_unix_ns IS NOT NULL THEN ts_unix_ns / 1000000
ELSE CAST((julianday(ts) - 2440587.5) * 86400000 AS INTEGER)
END`

type recentEventHeap []*models.Event

func (h recentEventHeap) Len() int { return len(h) }
func (h recentEventHeap) Less(i, j int) bool {
	if !h[i].TS.Equal(h[j].TS) {
		return h[i].TS.Before(h[j].TS)
	}
	return h[i].ID < h[j].ID
}
func (h recentEventHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *recentEventHeap) Push(x any)   { *h = append(*h, x.(*models.Event)) }
func (h *recentEventHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

func eventAfter(a, b *models.Event) bool {
	return a.TS.After(b.TS) || (a.TS.Equal(b.TS) && a.ID > b.ID)
}

func (s *Store) collectEventsSince(since time.Time, limit int) ([]*models.Event, int, error) {
	recent := &recentEventHeap{}
	heap.Init(recent)
	total := 0
	err := s.iterateEventsSinceExactContext(context.Background(), since, false, func(e *models.Event) error {
		total++
		if recent.Len() < limit {
			heap.Push(recent, e)
		} else if eventAfter(e, (*recent)[0]) {
			heap.Pop(recent)
			heap.Push(recent, e)
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	out := append([]*models.Event(nil), (*recent)...)
	sort.Slice(out, func(i, j int) bool { return eventAfter(out[i], out[j]) })
	return out, total, nil
}

func (s *Store) iterateEventsSinceExactContext(ctx context.Context, since time.Time, descending bool, fn func(*models.Event) error) error {
	direction := "ASC"
	if descending {
		direction = "DESC"
	}
	// RFC3339 permits offsets through +/-14h. Widen the legacy text-index
	// prefilter by 15h, then enforce the exact cutoff after parsing in Go.
	legacyFloor := formatFixedUTC(since.Add(-15 * time.Hour))
	query := "SELECT " + eventTimeBucketSQL + " AS time_bucket," + eventWindowColumns +
		" FROM events WHERE (ts_unix_ns >= ? OR (ts_unix_ns IS NULL AND ts >= ?))" +
		" ORDER BY time_bucket " + direction + ", id " + direction
	rows, err := s.db.QueryContext(ctx, query, since.UnixNano(), legacyFloor)
	if err != nil {
		return err
	}
	defer rows.Close()

	type bucketedEvent struct {
		bucket sql.NullInt64
		event  *models.Event
	}
	var group []bucketedEvent
	flush := func() error {
		sort.Slice(group, func(i, j int) bool {
			a, b := group[i].event, group[j].event
			if !a.TS.Equal(b.TS) {
				if descending {
					return a.TS.After(b.TS)
				}
				return a.TS.Before(b.TS)
			}
			if descending {
				return a.ID > b.ID
			}
			return a.ID < b.ID
		})
		for _, item := range group {
			if item.event.TS.Before(since) {
				continue
			}
			if err := fn(item.event); err != nil {
				return err
			}
		}
		group = group[:0]
		return nil
	}
	equalBucket := func(a, b sql.NullInt64) bool {
		return a.Valid == b.Valid && (!a.Valid || a.Int64 == b.Int64)
	}
	for rows.Next() {
		var item bucketedEvent
		item.event = &models.Event{}
		var ts, source, kind string
		if err := rows.Scan(&item.bucket, &item.event.ID, &ts, &source, &kind,
			&item.event.SrcIP, &item.event.SrcPort, &item.event.Username, &item.event.Password,
			&item.event.SessionID, &item.event.HASSH, &item.event.SSHClient, &item.event.Command,
			&item.event.SHA256, &item.event.Filename, &item.event.DstIP, &item.event.DstPort,
			&item.event.ActorID); err != nil {
			return err
		}
		parsed, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return fmt.Errorf("event %d ts: %w", item.event.ID, err)
		}
		item.event.TS = parsed
		item.event.Source = models.Source(source)
		item.event.Kind = models.EventKind(kind)
		if len(group) > 0 && !equalBucket(group[0].bucket, item.bucket) {
			if err := flush(); err != nil {
				return err
			}
		}
		group = append(group, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return flush()
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
	out, _, err := s.collectEventsSince(since, limit)
	return out, err
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
// The events are returned newest-first (ts DESC LIMIT), matching what a capped
// view should show — the most recent activity — while total comes from a cheap
// COUNT that rides idx_events_ts.
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
