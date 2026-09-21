package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
	"modernc.org/sqlite"
)

func init() {
	// Legacy timestamps can have offsets and variable fractional widths. SQLite's
	// julianday loses precision; this connection-local function preserves all nine
	// digits. No schema/index depends on it, so ordinary sqlite3 can still open DBs.
	sqlite.MustRegisterDeterministicScalarFunction("shardlure_event_time", 2, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		raw, ok := args[0].(string)
		if !ok {
			return nil, fmt.Errorf("event %v: invalid timestamp", args[1])
		}
		ts, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return nil, fmt.Errorf("event %v: invalid timestamp", args[1])
		}
		return formatFixedUTC(ts), nil
	})
}

const legacyEventTimeSQL = "shardlure_event_time(ts,id)"

// eventTimeBranches splits migrated and legacy rows in one SQLite snapshot.
// The left branch retains the normal ts/actor/session indexes. The right branch
// visits only unconverted rows through a partial index that empties as backfill
// progresses. Parsing/sorting legacy rows stays in SQLite, never a Go time bucket.
func eventTimeBranches(columns string, since *time.Time, predicate string, predicateArgs []any) (string, []any) {
	nativeWhere := "ts_unix_ns IS NOT NULL"
	legacyWhere := "ts_unix_ns IS NULL"
	legacyFrom := "events INDEXED BY idx_events_legacy_ts"
	var nativeArgs, legacyArgs []any
	if predicate != "" {
		// Scoped reads must retain actor/source index seeks; forcing the global
		// legacy index makes one actor lookup scan every unconverted row.
		legacyFrom = "events"
		nativeWhere += " AND (" + predicate + ")"
		legacyWhere += " AND (" + predicate + ")"
		nativeArgs = append(nativeArgs, predicateArgs...)
		legacyArgs = append(legacyArgs, predicateArgs...)
	}
	if since != nil {
		nativeWhere += " AND ts>=?"
		legacyWhere += " AND " + legacyEventTimeSQL + ">=?"
		nativeArgs = append(nativeArgs, formatFixedUTC(*since))
		legacyArgs = append(legacyArgs, formatFixedUTC(*since))
	}
	return "SELECT " + columns + ",ts AS exact_ts FROM events WHERE " + nativeWhere +
			" UNION ALL SELECT " + columns + "," + legacyEventTimeSQL + " AS exact_ts FROM " + legacyFrom + " WHERE " + legacyWhere,
		append(nativeArgs, legacyArgs...)
}

func orderedEventQuery(columns string, since *time.Time, predicate string, predicateArgs []any, descending bool, limit int) (string, []any) {
	query, args := eventTimeBranches(columns, since, predicate, predicateArgs)
	direction := "ASC"
	if descending {
		direction = "DESC"
	}
	query += " ORDER BY exact_ts " + direction + ", id " + direction
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	return query, args
}

func scanOrderedEvent(rows *sql.Rows, full bool) (*models.Event, error) {
	e := &models.Event{}
	var ts, sortTS string
	args := []any{&e.ID, &ts, &e.Source, &e.Kind, &e.SrcIP, &e.SrcPort, &e.Username, &e.Password, &e.SessionID, &e.HASSH, &e.SSHClient, &e.Command, &e.SHA256, &e.Filename, &e.DstIP, &e.DstPort}
	if full {
		args = append(args, &e.Raw)
	}
	args = append(args, &e.ActorID, &sortTS)
	if err := rows.Scan(args...); err != nil {
		return nil, err
	}
	parsed, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return nil, fmt.Errorf("event %d: invalid timestamp", e.ID)
	}
	e.TS = parsed
	return e, nil
}

func iterateOrderedEventRows(rows *sql.Rows, full bool, fn func(*models.Event) error) error {
	defer rows.Close()
	for rows.Next() {
		e, err := scanOrderedEvent(rows, full)
		if err != nil {
			return err
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return rows.Err()
}

// latestEventQuery lets the normal branch stop after one index entry. Only
// pre-v20 rows need exact parsing; even corrupt legacy rows fail closed instead
// of being hidden by LIMIT. MAX retains constant Go memory.
const latestEventQuery = "SELECT ts FROM (SELECT ts FROM events INDEXED BY idx_events_ts WHERE ts_unix_ns IS NOT NULL ORDER BY ts DESC LIMIT 1)" +
	" UNION ALL SELECT MAX(" + legacyEventTimeSQL + ") FROM events INDEXED BY idx_events_legacy_ts WHERE ts_unix_ns IS NULL"

func latestEventTime(ctx context.Context, db *sql.DB) (time.Time, error) {
	rows, err := db.QueryContext(ctx, latestEventQuery)
	if err != nil {
		return time.Time{}, err
	}
	defer rows.Close()
	var latest time.Time
	for rows.Next() {
		var text sql.NullString
		if err := rows.Scan(&text); err != nil {
			return time.Time{}, err
		}
		if !text.Valid {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, text.String)
		if err != nil {
			return time.Time{}, fmt.Errorf("latest event: invalid timestamp")
		}
		if latest.IsZero() || t.After(latest) {
			latest = t
		}
	}
	return latest, rows.Err()
}

// Ensure SQL count paths do not retain event bodies or order a whole window.
func eventWindowCountQuery(since time.Time) (string, []any) {
	key := formatFixedUTC(since)
	return "SELECT (SELECT COUNT(*) FROM events WHERE ts_unix_ns IS NOT NULL AND ts>=?) + (SELECT COUNT(*) FROM events INDEXED BY idx_events_legacy_ts WHERE ts_unix_ns IS NULL AND " + legacyEventTimeSQL + ">=?)", []any{key, key}
}
