package store

import (
	"database/sql"
	"errors"
	"time"
)

// PayloadIntel is a cached third-party verdict about a captured payload,
// keyed by its sha256.
//
// Why a separate table from ip_enrichment: that table is keyed by IP and its
// rows expire on a 24h TTL because an address's reputation genuinely changes.
// A FILE hash is immutable, and so is the verdict about it in any practical
// sense, so payload verdicts get their own table with a much longer TTL. That
// matters here because VirusTotal's free tier allows only 4 requests/minute —
// re-asking on a 24h cycle for every payload on the dashboard would exhaust
// the quota and return nothing useful.
type PayloadIntel struct {
	SHA256    string
	Source    string
	Payload   string
	FetchedAt time.Time
}

// ensurePayloadIntelTable creates the table on first use, following the same
// lazy sync.Once pattern as the other side tables so DDL never runs under
// writeMu on a hot path.
func (s *Store) ensurePayloadIntelTable() error {
	s.oncePayloadIntel.Do(func() {
		_, s.errPayloadIntel = s.execWrite(`
CREATE TABLE IF NOT EXISTS payload_intel (
  sha256     TEXT NOT NULL,
  source     TEXT NOT NULL,
  payload    TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  PRIMARY KEY (sha256, source)
);
CREATE INDEX IF NOT EXISTS idx_payload_intel_fetched ON payload_intel(fetched_at);
`)
	})
	return s.errPayloadIntel
}

// EnsurePayloadIntelTable exposes the lazy creation so callers batching several
// writes can create the table BEFORE opening a transaction. ensure* helpers
// take writeMu via execWrite and writeMu is not reentrant, so ensuring inside a
// transaction deadlocks (see RecordSessionBindings for the same hazard).
func (s *Store) EnsurePayloadIntelTable() error {
	return s.ensurePayloadIntelTable()
}

// GetPayloadIntel returns the cached verdict for (sha256, source).
func (s *Store) GetPayloadIntel(sha, source string) (PayloadIntel, bool, error) {
	if sha == "" || source == "" {
		return PayloadIntel{}, false, nil
	}
	if err := s.ensurePayloadIntelTable(); err != nil {
		return PayloadIntel{}, false, err
	}
	var rec PayloadIntel
	var ts string
	err := s.db.QueryRow(`
SELECT sha256, source, payload, fetched_at
FROM payload_intel WHERE sha256=? AND source=?`, sha, source).
		Scan(&rec.SHA256, &rec.Source, &rec.Payload, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return PayloadIntel{}, false, nil
	}
	if err != nil {
		return PayloadIntel{}, false, err
	}
	if t, perr := time.Parse(time.RFC3339Nano, ts); perr == nil {
		rec.FetchedAt = t
	}
	return rec, true, nil
}

// PutPayloadIntel upserts a verdict. Callers must only store SUCCESSFUL
// lookups: caching an error would mean a transient rate-limit response
// suppressed a real verdict for the whole TTL.
func (s *Store) PutPayloadIntel(sha, source, payload string) error {
	if sha == "" || source == "" {
		return nil
	}
	if err := s.ensurePayloadIntelTable(); err != nil {
		return err
	}
	_, err := s.execWrite(`
INSERT INTO payload_intel (sha256, source, payload, fetched_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(sha256, source) DO UPDATE SET
  payload=excluded.payload,
  fetched_at=excluded.fetched_at`,
		sha, source, payload, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// PayloadIntelBySource returns every cached verdict for one source, keyed by
// sha256. Used by the payload panel to decorate a page of payloads in ONE
// query instead of a point lookup per row (the N+1 the bazaar join already
// had to fix once).
func (s *Store) PayloadIntelBySource(source string, shas []string) (map[string]PayloadIntel, error) {
	out := map[string]PayloadIntel{}
	if source == "" || len(shas) == 0 {
		return out, nil
	}
	if err := s.ensurePayloadIntelTable(); err != nil {
		return nil, err
	}
	// Build a bounded IN list. The caller pages the payload panel, so this is
	// tens of hashes, not thousands.
	const maxIn = 500
	if len(shas) > maxIn {
		shas = shas[:maxIn]
	}
	q := `SELECT sha256, source, payload, fetched_at FROM payload_intel WHERE source=? AND sha256 IN (`
	args := []any{source}
	for i, sha := range shas {
		if i > 0 {
			q += ","
		}
		q += "?"
		args = append(args, sha)
	}
	q += ")"

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var rec PayloadIntel
		var ts string
		if err := rows.Scan(&rec.SHA256, &rec.Source, &rec.Payload, &ts); err != nil {
			return nil, err
		}
		if t, perr := time.Parse(time.RFC3339Nano, ts); perr == nil {
			rec.FetchedAt = t
		}
		out[rec.SHA256] = rec
	}
	return out, rows.Err()
}

// PurgePayloadIntelBefore deletes cached verdicts older than cutoff. Called by
// MaintenancePurge so the cache can't grow without bound on a long-lived
// honeypot.
func (s *Store) PurgePayloadIntelBefore(cutoff time.Time) (int64, error) {
	if err := s.ensurePayloadIntelTable(); err != nil {
		return 0, err
	}
	res, err := s.execWrite(`DELETE FROM payload_intel WHERE fetched_at < ?`,
		cutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
