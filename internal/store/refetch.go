package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// NextRefetch is the Phase C re-fetch schedule, measured from the URL's
// first sighting: hourly for the first 24 h, every 6 h until day 7, then
// stop — except that 6 consecutive failures make the URL "offline", checked
// daily, and nothing is checked after day 10 (MalwareBazaar accepts samples
// up to 10 days old; a later capture could never be shared).
func NextRefetch(firstSeen, now time.Time, failures int) (time.Time, string) {
	age := now.Sub(firstSeen)
	if age >= 10*24*time.Hour {
		return time.Time{}, "done"
	}
	var next time.Time
	state := "active"
	switch {
	case failures >= 6:
		state = "offline"
		next = now.Add(24 * time.Hour)
	case age < 24*time.Hour:
		next = now.Add(time.Hour)
	case age < 7*24*time.Hour:
		next = now.Add(6 * time.Hour)
	default:
		// Past day 7 an online URL is no longer re-fetched on schedule.
		return time.Time{}, "done"
	}
	if next.Sub(firstSeen) >= 10*24*time.Hour {
		return time.Time{}, "done"
	}
	return next, state
}

// refetchableURL reports whether a URL may enter the re-fetch schedule. Only
// real http(s) URLs can be fetched again; the capture runner's
// cowrie-download:/cowrie-event: dedup pseudo-keys name no server.
func refetchableURL(u string) bool {
	l := strings.ToLower(u)
	return (strings.HasPrefix(l, "http://") && len(l) > len("http://")) ||
		(strings.HasPrefix(l, "https://") && len(l) > len("https://"))
}

// SeedRefetch schedules a URL that has served a payload for re-fetching.
// INSERT OR IGNORE: a URL's schedule is anchored on its first sighting, so a
// second seed (a re-capture, a duplicate completion) never resets it.
func (s *Store) SeedRefetch(url string, firstSeen time.Time, sha string) error {
	if !refetchableURL(url) {
		return nil
	}
	now := time.Now().UTC()
	return s.WithTx(func(tx *sql.Tx) error { return seedRefetchTx(tx, url, firstSeen, now, sha) })
}

// seedRefetchTx schedules from the seed time, not from the first sighting:
// the capture that seeds the row has just fetched the payload, so the next
// check is one schedule step after now. A capture completing on day 7-10
// is therefore not re-fetched minutes later, and one completing on or after
// day 10 is seeded done (a later capture could never be shared).
func seedRefetchTx(tx *sql.Tx, url string, firstSeen, now time.Time, sha string) error {
	if !refetchableURL(url) {
		return nil
	}
	next, state := NextRefetch(firstSeen, now, 0)
	if state == "done" {
		// A done row keeps a NOT NULL next_check_at: the seed time.
		next = now
	}
	var last any
	if sha != "" {
		last = sha
	}
	_, err := tx.Exec(`INSERT OR IGNORE INTO refetch_schedule(url, first_seen_at, next_check_at, state, last_sha256)
VALUES(?,?,?,?,?)`, url, captureTime(firstSeen), captureTime(next), state, last)
	return err
}

// RefetchJob is one leased re-fetch. Checks is the fencing token: completion
// succeeds only while the row's checks still equals it and this claim's
// lease is the live one.
type RefetchJob struct {
	URL       string
	Checks    int
	FirstSeen time.Time

	// lease is the lease_until this claim wrote. It fences against a
	// reclaim after expiry, which leaves checks unchanged. A job built
	// outside ClaimRefetch has none and is always refused (fail closed).
	lease string
}

// refetchMaxAge is the schedule's hard stop: nothing is fetched at or after
// day 10 from first sighting (MalwareBazaar's freshness window). NextRefetch
// applies it when a row advances; ClaimRefetch applies it again at claim time,
// because a row that never advanced (re-fetch disabled, daemon down) can sit
// overdue for weeks.
const refetchMaxAge = 10 * 24 * time.Hour

// refetchSettleChunk bounds how many overdue rows one claim settles, so a
// large backlog (re-fetch turned back on after weeks) costs each 30 s tick a
// bounded write. The claim itself never returns an overdue row, so a backlog
// still being settled is never fetched.
const refetchSettleChunk = 500

// RefetchMaxNewPayloads caps the distinct new payloads one URL may yield by
// re-fetch (final review I3). The fourth new hash settles the schedule done.
const RefetchMaxNewPayloads = 4

// RefetchReleaseDelay is how far ReleaseRefetch pushes a busy host's job: one
// re-fetch worker tick, so the next claim takes another host's due row first.
const RefetchReleaseDelay = 30 * time.Second

// ClaimRefetch leases the most overdue re-fetch, or returns nil, nil when
// nothing is due. done rows are never claimed.
//
// Rows whose first sighting is 10 or more days old are settled to done in the
// same transaction (at most refetchSettleChunk per call) and are never
// returned: an active row seeded while capture.refetch was off, or left
// overdue while the daemon was down, would otherwise be fetched once more on
// re-enable, weeks after any capture could be shared (final review I1). The
// claim query repeats the age bound, so a row the settle has not reached yet
// (or one whose first_seen_at does not parse: julianday NULL) is skipped, not
// fetched. A row under a live lease is left to its holder, whose completion
// settles it through NextRefetch.
func (s *Store) ClaimRefetch(now time.Time, lease time.Duration) (*RefetchJob, error) {
	if lease <= 0 {
		return nil, errors.New("refetch lease must be positive")
	}
	nowS := captureTime(now)
	leaseS := captureTime(now.Add(lease))
	maxAgeDays := refetchMaxAge.Hours() / 24
	var job *RefetchJob
	err := s.WithTx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE refetch_schedule SET state='done', next_check_at=?, lease_until=NULL
WHERE rowid IN (
  SELECT rowid FROM refetch_schedule
  WHERE state IN ('active','offline')
    AND julianday(?) - julianday(first_seen_at) >= ?
    AND (lease_until IS NULL OR julianday(lease_until) <= julianday(?))
  LIMIT ?)`, nowS, nowS, maxAgeDays, nowS, refetchSettleChunk); err != nil {
			return err
		}
		var url, first string
		var checks int
		err := tx.QueryRow(`SELECT url, first_seen_at, checks FROM refetch_schedule
WHERE state IN ('active','offline')
  AND julianday(next_check_at) <= julianday(?)
  AND (lease_until IS NULL OR julianday(lease_until) <= julianday(?))
  AND julianday(?) - julianday(first_seen_at) < ?
ORDER BY julianday(next_check_at), url
LIMIT 1`, nowS, nowS, nowS, maxAgeDays).Scan(&url, &first, &checks)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		firstSeen, err := parseTime(first)
		if err != nil {
			return err
		}
		if now.Sub(firstSeen) >= refetchMaxAge {
			// julianday and Go disagree only at the exact boundary; Go wins
			// and the row is left for the next settle.
			return nil
		}
		res, err := tx.Exec(`UPDATE refetch_schedule SET lease_until=?
WHERE url=? AND checks=? AND state IN ('active','offline')
  AND (lease_until IS NULL OR julianday(lease_until) <= julianday(?))`, leaseS, url, checks, nowS)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil
		}
		job = &RefetchJob{URL: url, Checks: checks, FirstSeen: firstSeen.UTC(), lease: leaseS}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return job, nil
}

// RefetchOutcome is what a re-fetch found. OK means a payload was fetched
// and hashed; anything else counts toward the offline streak.
type RefetchOutcome struct {
	OK                        bool
	SHA256, LocalPath, Detail string
	Size                      int64
}

// CompleteRefetch records a re-fetch in one transaction. A payload already
// held for this URL (a fetched row at any epoch with the same sha) only sets
// that row's last_refetch_at (never last_successful_fetch_at, which share
// freshness reads); a new sha becomes a new artifacts row at
// the URL's next epoch, carrying epoch 0's provenance, and returns true.
// The schedule then advances by NextRefetch. ErrClaimStale when the job's
// checks moved or its lease is no longer the live one.
func (s *Store) CompleteRefetch(job RefetchJob, now time.Time, out RefetchOutcome) (newPayload bool, err error) {
	if out.OK && out.SHA256 == "" {
		return false, errors.New("refetch outcome OK without a sha256")
	}
	if job.lease == "" {
		// Only a job ClaimRefetch returned carries its lease; a hand-built
		// one could otherwise complete over another holder's live lease.
		return false, ErrClaimStale
	}
	if err := s.ensureArtifactsTable(); err != nil {
		return false, err
	}
	nowS := captureTime(now)
	err = s.WithTx(func(tx *sql.Tx) error {
		newPayload = false
		var first string
		var failures int
		err := tx.QueryRow(`SELECT first_seen_at, consecutive_failures FROM refetch_schedule
WHERE url=? AND checks=? AND lease_until IS NOT NULL AND julianday(lease_until) > julianday(?)
  AND lease_until=?`, job.URL, job.Checks, nowS, job.lease).Scan(&first, &failures)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrClaimStale
		}
		if err != nil {
			return err
		}
		firstSeen, err := parseTime(first)
		if err != nil {
			return err
		}
		var lastSHA any
		if out.OK {
			failures = 0
			lastSHA = out.SHA256
			// Only the re-fetch liveness clock moves. ts, first_observed_at
			// and last_seen_at record attacker sightings: discovery drops a
			// sighting older than last_seen_at and retention ages rows on
			// it. last_successful_fetch_at is write-once (the row's first
			// fetch): MalwareBazaar freshness, the share pool and the funnel
			// read it as when the sample was captured, so a re-fetch moving
			// it kept an old sample looking fresh (final review C1). Our own
			// fetch cadence must never touch any of them.
			res, err := tx.Exec(`UPDATE artifacts SET last_refetch_at=?
WHERE url=? AND status='fetched' AND sha256=?`, nowS, job.URL, out.SHA256)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				// A LEFT JOIN so a URL whose artifact rows retention already
				// purged still records the payload: provenance stays empty
				// and first_observed_at falls back to the schedule's
				// first_seen_at (the URL's first sighting), never to now,
				// which would re-anchor the sample's freshness.
				if _, err := tx.Exec(`INSERT INTO artifacts(ts, src_ip, session_id, actor_id, url, local_path, sha256, size_bytes,
  origin, status, detail, created_at, attempt_count, first_observed_at, last_seen_at,
  last_fetch_attempt_at, last_successful_fetch_at, fetch_epoch, parent_sha256, depth)
SELECT ?, a.src_ip, a.session_id, a.actor_id, ?, ?, ?, ?,
  'quarantine_fetch', 'fetched', ?, ?, 1, COALESCE(a.first_observed_at, ?), ?,
  ?, ?, (SELECT COALESCE(MAX(fetch_epoch), -1) + 1 FROM artifacts WHERE url=?), a.parent_sha256, COALESCE(a.depth, 0)
FROM (SELECT 1) LEFT JOIN artifacts a ON a.url=? AND a.fetch_epoch=0`,
					nowS, job.URL, out.LocalPath, out.SHA256, out.Size,
					out.Detail, nowS, captureTime(firstSeen), nowS,
					nowS, nowS, job.URL, job.URL); err != nil {
					return err
				}
				newPayload = true
			}
		} else {
			failures++
		}
		next, state := NextRefetch(firstSeen, now, failures)
		if newPayload && state != "done" {
			// A URL that has minted RefetchMaxNewPayloads distinct payloads
			// by re-fetch (epochs 1..N) is a server returning a new body on
			// every check, not a rotating build: stop, so it cannot fill
			// the evidence disk one 50 MiB "sample" per check.
			var rotated int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM artifacts WHERE url=? AND fetch_epoch>0`, job.URL).Scan(&rotated); err != nil {
				return err
			}
			if rotated >= RefetchMaxNewPayloads {
				state = "done"
			}
		}
		if state == "done" {
			// A finished row keeps its last check time (next_check_at is
			// NOT NULL) and is never claimed again.
			next = now
		}
		res, err := tx.Exec(`UPDATE refetch_schedule
SET checks=checks+1, last_check_at=?, last_sha256=COALESCE(?, last_sha256),
    consecutive_failures=?, next_check_at=?, state=?, lease_until=NULL
WHERE url=? AND checks=?`, nowS, lastSHA, failures, captureTime(next), state, job.URL, job.Checks)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrClaimStale
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return newPayload, nil
}

// ReleaseRefetch hands a claimed job back without checking it: the lease is
// cleared and next_check_at moves to now + RefetchReleaseDelay (checks and
// failures stay). The re-fetch worker uses it when the URL's host is busy
// with another fetch. Without the push the same row, still the most overdue,
// was claimed first on every tick while its host stayed busy, and every other
// host's due re-fetches waited behind it (final review M1). Fenced exactly
// like CompleteRefetch: only the live lease this claim wrote may be released,
// so a holder whose lease lapsed and was reclaimed cannot free the new
// holder's lease, and a hand-built job (no lease token) is refused.
func (s *Store) ReleaseRefetch(job RefetchJob, now time.Time) error {
	if job.lease == "" {
		return ErrClaimStale
	}
	next := captureTime(now.Add(RefetchReleaseDelay))
	return s.WithTx(func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE refetch_schedule SET lease_until=NULL, next_check_at=?
WHERE url=? AND checks=? AND lease_until=?`, next, job.URL, job.Checks, job.lease)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrClaimStale
		}
		return nil
	})
}

// purgeRefetchSchedule deletes schedule rows retention no longer needs:
//   - done rows whose last check (or, never checked, first sighting) is older
//     than the retention cutoff;
//   - rows in any state first seen more than 10 days ago and before the
//     cutoff. Such a row can never be fetched again (ClaimRefetch settles it),
//     but one seeded while capture.refetch was off is never claimed either, so
//     without this it would stay active forever (final review I1).
//
// Bounded chunks, each its own transaction, so writeMu is released between
// them. A row with an unparsable time has a NULL julianday and is kept (fail
// closed; ClaimRefetch never fetches it either).
func (s *Store) purgeRefetchSchedule(ctx context.Context, cutoff time.Time) error {
	const chunk = 5000
	cut := captureTime(cutoff)
	nowS := captureTime(time.Now().UTC())
	maxAgeDays := refetchMaxAge.Hours() / 24
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var n int64
		err := s.WithTx(func(tx *sql.Tx) error {
			res, err := tx.Exec(`DELETE FROM refetch_schedule WHERE rowid IN (
  SELECT rowid FROM refetch_schedule
  WHERE (state='done' AND julianday(COALESCE(last_check_at, first_seen_at)) < julianday(?))
     OR (julianday(first_seen_at) < julianday(?) AND julianday(?) - julianday(first_seen_at) > ?)
  LIMIT ?)`, cut, cut, nowS, maxAgeDays, chunk)
			if err != nil {
				return err
			}
			n, err = res.RowsAffected()
			return err
		})
		if err != nil {
			return err
		}
		if n < chunk {
			return nil
		}
	}
}
