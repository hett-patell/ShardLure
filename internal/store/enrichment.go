package store

import (
	"database/sql"
	"time"
)

// EnrichmentRecord is one cached threat-intel lookup for (ip, source).
// Payload is the raw JSON body returned by the provider, stored as
// TEXT so we can deserialise into whatever provider-specific shape
// the API handler prefers without locking the schema to one version
// of the upstream response.
type EnrichmentRecord struct {
	IP        string
	Source    string
	Payload   string
	FetchedAt time.Time
}

func (s *Store) EnsureEnrichmentTable() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS ip_enrichment (
  ip TEXT NOT NULL,
  source TEXT NOT NULL,
  payload TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  PRIMARY KEY (ip, source)
)`)
	return err
}

// GetEnrichment returns the cached record for (ip, source) along with
// whether the record exists. Callers decide on staleness using the
// FetchedAt timestamp; the store doesn't enforce TTL so analysts can
// see stale-but-known data while a refresh is in flight.
func (s *Store) GetEnrichment(ip, source string) (*EnrichmentRecord, bool, error) {
	if err := s.EnsureEnrichmentTable(); err != nil {
		return nil, false, err
	}
	row := s.db.QueryRow(`SELECT ip, source, payload, fetched_at FROM ip_enrichment WHERE ip=? AND source=?`, ip, source)
	var r EnrichmentRecord
	var fetched string
	if err := row.Scan(&r.IP, &r.Source, &r.Payload, &fetched); err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		// Genuine DB error (corruption, locked file, schema drift):
		// don't pretend it's just a cache miss. The resolver decides
		// whether to fail open or surface the error to the UI.
		return nil, false, err
	}
	r.FetchedAt, _ = parseTime(fetched)
	return &r, true, nil
}

// PutEnrichment upserts a cached lookup. Pass payload="" to record a
// negative cache entry (provider returned nothing useful); the
// fetched_at still gates re-querying so we don't hammer rate limits.
func (s *Store) PutEnrichment(ip, source, payload string) error {
	if err := s.EnsureEnrichmentTable(); err != nil {
		return err
	}
	_, err := s.db.Exec(`
INSERT INTO ip_enrichment (ip, source, payload, fetched_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(ip, source) DO UPDATE SET
  payload    = excluded.payload,
  fetched_at = excluded.fetched_at`,
		ip, source, payload, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
