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
// The native branch retains its timestamp index; only legacy rows need parsing.
// Every metric uses the same exact window, without retaining event bodies in Go.
func (s *Store) WindowActivitySince(since time.Time) (WindowActivity, error) {
	out := WindowActivity{Since: since}
	window, args := eventTimeBranches("src_ip,kind", &since, "", nil)
	row := s.db.QueryRow("WITH activity_events AS ("+window+") "+`
		SELECT COUNT(*),
		       COUNT(DISTINCT src_ip),
		       SUM(CASE WHEN kind = 'accepted' THEN 1 ELSE 0 END),
		       SUM(CASE WHEN kind = 'command' THEN 1 ELSE 0 END),
		       SUM(CASE WHEN kind IN ('file_download','file_upload') THEN 1 ELSE 0 END)
		FROM activity_events`, args...)
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
