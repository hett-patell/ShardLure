package store

import (
	"time"
)

// WindowActivity is recent-activity telemetry for the threat gauge.
//
// It exists because the gauge used to score whole-table cumulative totals,
// which is a ratchet: events only ever accumulate, so the volume and diversity
// factors saturated their caps within the first weeks and the score then sat at
// a constant (52, for months, on the reference deployment). A threat level has
// to describe the CURRENT situation, so every field here is bounded to a window.
type WindowActivity struct {
	Since     time.Time
	Events    int // all events in the window
	UniqueIPs int // distinct source IPs in the window
	Accepted  int // successful honeypot logins: the attacker got a shell
	Commands  int // shell commands run
	Downloads int // file_download + file_upload
}

// WindowActivitySince aggregates the window in ONE pass.
//
// Every field is a conditional SUM over the same `ts >= ?` restriction, so the
// planner uses the ts index once rather than once per metric. Measured at 16ms
// for a 24h window on a 670k-row database, which is why this is safe to put
// behind the 5s poll path (cached above, but cheap even cold).
//
// `since` is formatted with the same RFC3339Nano layout the ts column stores.
// Do not switch this to SQLite's datetime(): that renders a SPACE between date
// and time while ts uses 'T', and since these are TEXT comparisons the mismatch
// silently shifts the window boundary by up to a day.
func (s *Store) WindowActivitySince(since time.Time) (WindowActivity, error) {
	out := WindowActivity{Since: since}
	row := s.db.QueryRow(`
		SELECT COUNT(*),
		       COUNT(DISTINCT src_ip),
		       SUM(CASE WHEN kind = 'accepted' THEN 1 ELSE 0 END),
		       SUM(CASE WHEN kind = 'command' THEN 1 ELSE 0 END),
		       SUM(CASE WHEN kind IN ('file_download','file_upload') THEN 1 ELSE 0 END)
		FROM events
		WHERE ts >= ?`,
		since.UTC().Format(time.RFC3339Nano),
	)
	// The SUMs are NULL when the window is empty, so they are scanned as
	// nullable and defaulted rather than failing the whole gauge on a quiet box.
	var accepted, commands, downloads *int
	if err := row.Scan(&out.Events, &out.UniqueIPs, &accepted, &commands, &downloads); err != nil {
		return out, err
	}
	if accepted != nil {
		out.Accepted = *accepted
	}
	if commands != nil {
		out.Commands = *commands
	}
	if downloads != nil {
		out.Downloads = *downloads
	}
	return out, nil
}
