package store

import (
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// Recent (windowed) attack rates per actor.
//
// # WHY THESE EXIST
//
// models.Actor.AttemptsPerHour is a LIFETIME average: EventCount divided by the
// whole FirstSeen..LastSeen span. That is the wrong quantity for anything that
// claims to describe how hard an actor is hitting right now, because a long-
// lived actor's active burst is averaged against however many weeks it spent
// idle. Measured on a 39-day-old deployment, comparing the stored value against
// the same actors' true 24h rate:
//
//	91.92.42.227     stored 316.7/h   actual 661.4/h   understated 2.1x
//	47.77.182.54     stored   2.2/h   actual   7.6/h   understated 3.5x
//	57.128.225.99    stored 167.4/h   actual 107.3/h   overstated  1.6x
//
// So it both hides escalation and flatters actors that have calmed down, and the
// Brute-Force Radar - which advertises "most aggressive" - was ranking and
// displaying that number.
//
// The rate is computed from events at READ time rather than being tracked at
// ingest, deliberately: events are the source of truth, so there is no new
// column, no migration, and no stale value to re-derive. It costs one indexed
// GROUP BY over the window.
//
// ProbeScore deliberately still uses the lifetime average. Its rate tiers are
// coarse (20/60/120 per hour) and measurement showed only 3 of 245 currently
// active actors change tier under a windowed rate - all three overstated - which
// does not justify tracking new per-actor state through ingest and the live
// collector's eviction/rehydration path.
const RecentRateWindow = 24 * time.Hour

// ReportPoolMaxAge bounds how far past the window ActorsForReporting's
// lifetime-ranked half may reach. That half ignores `since` by design (so an
// actor that was loud once stays offerable), which left it unbounded: it
// re-admitted actors dormant for months into the abuse-report pool.
//
// Deliberately wider than RecentRateWindow — a weekly cron must still be able to
// report last weekend's campaign, and an actor pausing a day mid-campaign is
// still current. It only excludes what no longer describes present activity.
// abuseipdb.Vet applies the authoritative staleness gate; this just keeps the
// query from hauling in rows that would be rejected downstream anyway.
const ReportPoolMaxAge = 7 * 24 * time.Hour

// ActorRate pairs an actor with its rate over a bounded window. It is a distinct
// type rather than an Actor with AttemptsPerHour overwritten, so a caller can
// never mistake the windowed figure for the stored lifetime one.
type ActorRate struct {
	Actor models.Actor
	// PerHour is events in the window divided by the window length in hours.
	PerHour float64
	// Events is the raw count in the window, for callers that want to say how
	// much evidence the rate rests on.
	Events int
}

// RecentRatesByActor returns events-per-hour for every actor with activity in
// the window, in ONE query. Actors absent from the map had no events: that is
// meaningfully different from a rate of zero and callers decide what to do.
func (s *Store) RecentRatesByActor(since time.Time) (map[string]float64, error) {
	hours := time.Since(since).Hours()
	if hours <= 0 {
		hours = RecentRateWindow.Hours()
	}
	rows, err := s.db.Query(`
		SELECT actor_id, COUNT(*)
		FROM events
		WHERE ts >= ? AND actor_id IS NOT NULL AND actor_id <> ''
		GROUP BY actor_id`,
		since.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]float64)
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = float64(n) / hours
	}
	return out, rows.Err()
}

// TopActorsByRecentRate ranks actors by how hard they are hitting IN THE WINDOW,
// which is what the Brute-Force Radar claims to show.
//
// It replaces ORDER BY attempts_per_hour, which ordered by lifetime average: an
// actor mid-escalation sorted below one that was briefly loud a month ago.
func (s *Store) TopActorsByRecentRate(since time.Time, limit int) ([]ActorRate, error) {
	if limit <= 0 {
		limit = 8
	}
	hours := time.Since(since).Hours()
	if hours <= 0 {
		hours = RecentRateWindow.Hours()
	}
	// Ranked in SQL, actors loaded in a second pass. Selecting actorColumns plus
	// an extra column would need its own scanner, and a second copy of that
	// column list is exactly how a scan silently drifts from the schema.
	rows, err := s.db.Query(`
		SELECT actor_id, COUNT(*) AS n
		FROM events
		WHERE ts >= ? AND actor_id IS NOT NULL AND actor_id <> ''
		GROUP BY actor_id
		ORDER BY n DESC
		LIMIT ?`,
		since.UTC().Format(time.RFC3339Nano), limit,
	)
	if err != nil {
		return nil, err
	}
	type hit struct {
		id string
		n  int
	}
	var hits []hit
	for rows.Next() {
		var h hit
		if err := rows.Scan(&h.id, &h.n); err != nil {
			rows.Close()
			return nil, err
		}
		hits = append(hits, h)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	out := make([]ActorRate, 0, len(hits))
	for _, h := range hits {
		a, err := s.GetActor(h.id)
		if err != nil || a == nil {
			// An actor row can legitimately be missing: purge removes actors
			// whose events aged out while a concurrent window still counted
			// them. Skip rather than fail the whole radar.
			continue
		}
		out = append(out, ActorRate{Actor: *a, PerHour: float64(h.n) / hours, Events: h.n})
	}
	return out, nil
}

// ActorsForReporting returns the candidate pool for abuse reporting and
// suggestions: every actor with activity in the window, UNIONED with the highest
// lifetime-rate actors.
//
// The pool used to be `ORDER BY attempts_per_hour DESC LIMIT 1000`. Because that
// column is a lifetime average, on a 39-day-old deployment the 1000-row cutoff
// sat at 8.0/h and excluded 229 of the 245 actors active in the last 24h -
// including 4 of the 8 that would have passed every vetting floor. Half the
// reportable, currently-active brute-forcers could not be seen by the batch
// reporter at all, because they were filtered out before Vet ever ran.
//
// The union deliberately keeps the old lifetime-ordered set as a floor, so an
// actor that was offered before is still offered: this widens the pool, it does
// not trade one blind spot for another. An actor that last attacked just outside
// the window is still reachable through the lifetime half of the union.
//
// That lifetime half is bounded by ReportPoolMaxAge, and must be. It ignores
// `since` by design, so unbounded it re-admitted actors dormant for MONTHS:
// measured on the reference deployment, 868 of the top 1000 by lifetime rate had
// been silent for over a week (79 with this bound applied — all 7-8 days old,
// left for abuseipdb.Vet to refuse, since the bound is relative to `since` and so
// necessarily one window wider than the gate), and all 6 IPs the suggestions
// widget offered were 31-50 days stale — every one already reported the day
// before — while the actor attacking at that moment was nowhere in the list.
//
// The bound is generous relative to `since` (a week against 24h) precisely so it
// still does its original job of surfacing a big attacker that paused; it only
// excludes the month-old rows that no longer describe current activity.
// abuseipdb.Vet enforces its own staleness gate on top of this — the pool is a
// query optimisation, not the policy — so tightening here cannot loosen there.
func (s *Store) ActorsForReporting(since time.Time, limit int) ([]models.Actor, error) {
	if limit <= 0 {
		limit = 1000
	}
	// Bound the lifetime half relative to `since` rather than the wall clock, so
	// a caller passing an older window widens both halves consistently and the
	// query stays a pure function of its arguments (testable without freezing
	// time).
	poolFloor := since.Add(-ReportPoolMaxAge)
	return s.queryActors(`SELECT `+actorColumns+`
FROM actors a
WHERE a.id IN (
        SELECT actor_id FROM events
        WHERE ts >= ? AND actor_id IS NOT NULL AND actor_id <> ''
      )
   OR a.id IN (
        SELECT id FROM actors WHERE attempts_per_hour > 0 AND last_seen >= ?
        ORDER BY attempts_per_hour DESC LIMIT ?
      )
ORDER BY a.attempts_per_hour DESC`,
		since.UTC().Format(time.RFC3339Nano),
		poolFloor.UTC().Format(time.RFC3339Nano), limit)
}
