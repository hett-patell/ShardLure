package store

import (
	"database/sql"
	"log"
	"time"
)

// URLhausStatusAlreadyListed is the ledger status for a URL URLhaus's own
// read-only lookup found already on record. It is terminal for dedup (later
// runs skip the URL without a network round trip) but is not a submission of
// ours, so the funnel's shared_urlhaus count and the panel's submitted total
// exclude it, exactly as bazaar excludes file_already_known. Mirrors
// urlhaus.StatusAlreadyListed — store never imports the intel packages, so the
// literal is the contract.
const URLhausStatusAlreadyListed = "already_listed"

// URLhausStatusAlreadyQueued is the ledger status builds before the duplicate
// pre-check wrote for the submission API's plaintext already_queued answer.
// Current Share normalises that answer to URLhausStatusAlreadyListed; both
// statuses stay out of the "submitted" figures so historical rows are not
// counted as contributions of ours.
const URLhausStatusAlreadyQueued = "already_queued"

// urlhausNotSubmittedWhere is the SQL predicate for ledger rows that are not a
// submission of ours (a listing check, a resolved dedup note). Private
// constants only, never caller input.
const urlhausNotSubmittedWhere = "status NOT IN ('" + URLhausStatusAlreadyListed + "','" + URLhausStatusAlreadyQueued + "')"

// URLhausSubmission records what the ledger knows about one URL: a submission
// of ours (status "ok"/"submitted") or a duplicate pre-check that found it
// already listed (already_listed). The URL is the natural key: URLhaus dedupes
// on it. Since v27 one URL may own several artifact rows (one per payload it
// served), so the candidate queries pick one row per URL
// (urlhausCandidateWhere) to match the ledger.
type URLhausSubmission struct {
	URL         string
	SubmittedAt time.Time
	Status      string
}

// ensureURLhausTable creates the submissions table on first use. Same lazy
// sync.Once pattern as the other side tables so the DDL never runs under
// writeMu on a hot path.
func (s *Store) ensureURLhausTable() error {
	s.onceURLhaus.Do(func() {
		s.errURLhaus = s.WithTx(func(tx *sql.Tx) error { return ensureLedgerTimeSchema(tx, urlhausLedger) })
	})
	return s.errURLhaus
}

// URLhausSubmitted reports whether the ledger already settled this URL —
// submitted by us, or found already listed upstream — so a repeat run neither
// re-POSTs it nor repeats the lookup. Satisfies urlhaus.SubmitRecorder.
func (s *Store) URLhausSubmitted(url string) (bool, error) {
	if url == "" {
		return false, nil
	}
	if err := s.ensureURLhausTable(); err != nil {
		return false, err
	}
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM urlhaus_submissions WHERE url=?`, url).Scan(&n)
	return n > 0, err
}

// RecordURLhausSubmission upserts the row for a URL that was submitted or
// found already listed. Network failures and auth rejections are left
// unrecorded so the next run retries them, matching RecordBazaarUpload.
//
// An already_listed write never updates an existing row: the CLI and a
// dashboard button can check the ledger concurrently, and without the guard a
// listing check could overwrite a real "ok" submission (and decrement the
// funnel's shared count and the submitted total).
func (s *Store) RecordURLhausSubmission(url, status string, at time.Time) error {
	if url == "" {
		return nil
	}
	if err := s.ensureURLhausTable(); err != nil {
		return err
	}
	if at.IsZero() {
		at = time.Now()
	}
	ts := at.UTC().Format(time.RFC3339Nano)
	if _, err := parseLedgerTimestamp(ts); err != nil {
		return err
	}
	_, err := s.execWrite(`
INSERT INTO urlhaus_submissions (url, submitted_at, status, submitted_at_key)
VALUES (?, ?, ?, ?)
ON CONFLICT(url) DO UPDATE SET
  submitted_at=excluded.submitted_at,
  submitted_at_key=excluded.submitted_at_key,
  status=excluded.status
WHERE excluded.status <> ?`,
		url, ts, status, formatFixedUTC(at), URLhausStatusAlreadyListed)
	return err
}

// URLhausStats holds aggregate counts for the URLhaus sharing widget.
// TotalSubmitted and LastSubmittedAt cover submissions of ours only: rows
// recorded as already listed (a duplicate pre-check, or a historical
// plaintext already_queued answer) are excluded.
type URLhausStats struct {
	TotalSubmitted  int
	Pending         int
	LastSubmittedAt time.Time
}

// URLhausSubmissionStats returns aggregate sharing metrics.
//
// Pending counts artifacts that would plausibly pass the vetting gate but
// haven't been submitted. It deliberately mirrors only the cheap, SQL-able
// parts of urlhaus.Vet (real fetched URL, has a payload, big enough, recent) —
// the authoritative decision stays in Vet. Treat this as an upper bound for
// the UI, not a promise.
func (s *Store) URLhausSubmissionStats(activeDays int) (URLhausStats, error) {
	if err := s.ensureURLhausTable(); err != nil {
		return URLhausStats{}, err
	}
	if err := s.ensureArtifactsTable(); err != nil {
		return URLhausStats{}, err
	}
	var st URLhausStats
	var lastTS sql.NullString
	// already_listed/already_queued rows are URLhaus's own records, not
	// submissions of ours: they keep URLs out of the candidate list but must
	// not inflate the total or move the "last submitted" clock.
	if err := s.db.QueryRow("SELECT COUNT(*), ("+latestLedgerTimeSQL(urlhausLedger, urlhausNotSubmittedWhere)+") FROM urlhaus_submissions WHERE "+urlhausNotSubmittedWhere).Scan(&st.TotalSubmitted, &lastTS); err != nil {
		return st, err
	}
	if lastTS.Valid {
		var err error
		if st.LastSubmittedAt, err = parseLedgerTimestamp(lastTS.String); err != nil {
			return st, err
		}
	}
	if err := s.db.QueryRow(`
SELECT COUNT(*)
FROM artifacts a`+urlhausCandidateWhere, urlhausCandidateArgs(activeDays, time.Now())...).Scan(&st.Pending); err != nil {
		log.Printf("urlhaus pending count: %v (defaulting to 0)", err)
	}
	return st, nil
}

// ListURLhausSubmissions returns recorded submissions, newest first.
// Bounded by limit; pass 0 for no cap.
func (s *Store) ListURLhausSubmissions(limit int) ([]URLhausSubmission, error) {
	if err := s.ensureURLhausTable(); err != nil {
		return nil, err
	}
	q, args := orderedLedgerQuery(urlhausLedger, "url,submitted_at,status", limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []URLhausSubmission
	for rows.Next() {
		var u URLhausSubmission
		var ts, key string
		if err := rows.Scan(&u.URL, &ts, &u.Status, &key); err != nil {
			return nil, err
		}
		if u.SubmittedAt, err = parseLedgerRowTimestamp(ts, key); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// urlhausCandidateArgs binds urlhausCandidateWhere. The one-hour future
// tolerance is urlhaus.Vet's clock-skew bound (store must not import it).
func urlhausCandidateArgs(activeDays int, now time.Time) []any {
	if activeDays <= 0 {
		activeDays = 3
	}
	now = now.UTC()
	cutoff := now.Add(-time.Duration(activeDays) * 24 * time.Hour).Format(time.RFC3339Nano)
	notAfter := now.Add(time.Hour).Format(time.RFC3339Nano)
	return []any{cutoff, cutoff, notAfter}
}

// urlhausCandidateWhere is the single WHERE clause shared by URLhausCandidates
// and the Pending count in URLhausSubmissionStats. CLAUDE.md requires the two
// to stay identical (they drifted once and the UI count disagreed with the
// CLI's list); sharing one constant makes that structural.
//
// URLhaus is keyed by URL, but since v27 a URL can own several artifact rows
// (a rotated payload gets the next fetch_epoch). The correlated subquery keeps
// exactly one row per URL — the eligible one fetched most recently, id as the
// tie-break — so a URL that served two binaries is one candidate and one
// pending, not two. The subquery repeats the outer predicate on b so the row
// it picks is itself eligible; the NOT IN is URL-level and need not repeat.
// Rows fetched more than an hour in the future (the third parameter) rank
// last: urlhaus.Vet refuses those as clock skew, so picking one would hide an
// older row Vet accepts and the URL would be offered nowhere. They are ranked,
// not excluded, so a URL whose only row is future-dated still appears and the
// panel shows Vet's rejection reason instead of silently dropping it.
//
// Parameters, in order: cutoff, cutoff, notAfter (urlhausCandidateArgs).
const urlhausCandidateWhere = `
WHERE a.origin = 'quarantine_fetch'
  AND a.status = 'fetched'
  AND a.sha256 IS NOT NULL AND a.sha256 != ''
  AND a.size_bytes >= 64
  AND (a.url LIKE 'http://%' OR a.url LIKE 'https://%')
  AND julianday(a.last_successful_fetch_at) >= julianday(?)
  AND a.url NOT IN (SELECT url FROM urlhaus_submissions)
  AND a.id = (
    SELECT b.id FROM artifacts b
    WHERE b.url = a.url
      AND b.origin = 'quarantine_fetch'
      AND b.status = 'fetched'
      AND b.sha256 IS NOT NULL AND b.sha256 != ''
      AND b.size_bytes >= 64
      AND julianday(b.last_successful_fetch_at) >= julianday(?)
    ORDER BY julianday(b.last_successful_fetch_at) <= julianday(?) DESC,
      julianday(b.last_successful_fetch_at) DESC, b.id DESC
    LIMIT 1)`

// URLhausCandidateRow is an artifact considered for URL submission, shaped for
// the urlhaus.Candidate conversion done by the caller (cmd/web). Keeping the
// query here and the struct conversion in the caller preserves the rule that
// intel packages never import store.
type URLhausCandidateRow struct {
	URL       string
	SHA256    string
	SizeBytes int64
	Origin    string
	Status    string
	FetchedAt time.Time
	LocalPath string
	// Depth > 0 marks a URL harvested from a fetched script rather than
	// named by the attacker; the gate refuses it (final review I2).
	Depth int
}

// URLhausCandidates returns artifacts that could be submitted, newest first.
// The SQL applies only the cheap structural filters; urlhaus.Vet remains the
// authoritative policy gate (it also needs the classifier's file kind, which
// requires reading the file off disk).
//
// The WHERE clause is kept deliberately IDENTICAL to the Pending subquery in
// URLhausSubmissionStats — including the size floor, which mirrors
// urlhaus.minPayloadBytes. When the two drifted apart, the UI reported a
// pending count that didn't match the list the CLI would actually offer.
// Both now read the one urlhausCandidateWhere constant.
func (s *Store) URLhausCandidates(activeDays, limit int) ([]URLhausCandidateRow, error) {
	if err := s.ensureURLhausTable(); err != nil {
		return nil, err
	}
	if err := s.ensureArtifactsTable(); err != nil {
		return nil, err
	}
	q := `
SELECT a.url, COALESCE(a.sha256,''), COALESCE(a.size_bytes,0), a.origin, a.status,
       a.last_successful_fetch_at, COALESCE(a.local_path,''), COALESCE(a.depth,0)
FROM artifacts a` + urlhausCandidateWhere + `
ORDER BY julianday(a.last_successful_fetch_at) DESC`
	args := urlhausCandidateArgs(activeDays, time.Now())
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []URLhausCandidateRow
	for rows.Next() {
		var r URLhausCandidateRow
		var ts string
		if err := rows.Scan(&r.URL, &r.SHA256, &r.SizeBytes, &r.Origin, &r.Status, &ts, &r.LocalPath, &r.Depth); err != nil {
			return nil, err
		}
		if t, perr := time.Parse(time.RFC3339Nano, ts); perr == nil {
			r.FetchedAt = t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
