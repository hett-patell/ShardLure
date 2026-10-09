package store

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// Second-stage harvesting (payload yield Phase C). A fetched dropper script
// names the binaries it would download; the capture runner reads the script
// as text and queues those URLs here as ordinary epoch-0 quarantine_fetch
// rows, which the ArtifactWorker later fetches through SafeFetcher. Nothing
// in this file fetches or interprets anything.
const (
	harvestCursorKey = "harvest-v1"
	// HarvestMaxScriptBytes is the largest fetched file read as a script.
	HarvestMaxScriptBytes = 1 << 20
	// HarvestMaxDepth bounds recursion: command/Cowrie payloads are depth 0,
	// URLs harvested from them depth 1, from those depth 2; a depth-2 payload
	// is never harvested.
	HarvestMaxDepth = 2
	// harvestMaxURLBytes matches command discovery's per-URL bound.
	harvestMaxURLBytes = 65536
)

// HarvestSource is one fetched artifact that may be a script.
type HarvestSource struct {
	ID                                           int64
	SHA256, LocalPath, SrcIP, SessionID, ActorID string
	Depth                                        int
}

// harvestInFlight is the predicate of a row the capture worker may still
// complete (exactly DueArtifactCaptures' status set). A later completion does
// not change the row's id, so the cursor must never pass such a row or the
// script it fetches would never be harvested.
const harvestInFlight = `fetch_epoch=0 AND origin='quarantine_fetch' AND status IN ('pending','capturing','failed')`

// HarvestCandidates returns up to limit fetched artifacts past the harvest
// cursor, ordered by id. Rows at or beyond the oldest still in-flight capture
// are held back (see harvestInFlight) so the cursor only ever moves over
// settled rows.
func (s *Store) HarvestCandidates(ctx context.Context, limit int) ([]HarvestSource, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	if err := s.ensureArtifactsTable(); err != nil {
		return nil, err
	}
	var cursor int64
	err := s.db.QueryRowContext(ctx, "SELECT offset FROM ingest_state WHERE source='capture' AND path=?", harvestCursorKey).Scan(&cursor)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, COALESCE(sha256,''), COALESCE(local_path,''), COALESCE(src_ip,''),
  COALESCE(session_id,''), COALESCE(actor_id,''), depth
FROM artifacts
WHERE id>? AND id<COALESCE((SELECT MIN(id) FROM artifacts WHERE `+harvestInFlight+`), 9223372036854775807)
  AND status='fetched' AND size_bytes BETWEEN 1 AND ?
  AND origin IN ('quarantine_fetch','cowrie_download','cowrie_file_download')
  AND depth<?
ORDER BY id LIMIT ?`, cursor, HarvestMaxScriptBytes, HarvestMaxDepth, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HarvestSource
	for rows.Next() {
		var h HarvestSource
		if err := rows.Scan(&h.ID, &h.SHA256, &h.LocalPath, &h.SrcIP, &h.SessionID, &h.ActorID, &h.Depth); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// advanceHarvestCursorTx moves the cursor forward to id, never back.
func advanceHarvestCursorTx(ctx context.Context, tx *sql.Tx, id int64, now string) error {
	if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO ingest_state(source,path,inode,offset,head_sig,updated_at) VALUES('capture',?,0,0,'',?)", harvestCursorKey, now); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "UPDATE ingest_state SET offset=MAX(offset,?),updated_at=? WHERE source='capture' AND path=?", id, now, harvestCursorKey)
	return err
}

// AdvanceHarvestCursor records that source id needs no harvesting (not a
// script, or its file is gone).
func (s *Store) AdvanceHarvestCursor(ctx context.Context, id int64) error {
	if err := s.ensureArtifactsTable(); err != nil {
		return err
	}
	return s.WithTxContext(ctx, func(tx *sql.Tx) error {
		return advanceHarvestCursorTx(ctx, tx, id, captureTime(time.Now()))
	})
}

// harvestHostKey is the per-host cap's key: the URL's hostname, lowercased,
// one trailing dot removed, IP literals canonical (IPv4-mapped unmapped). It
// mirrors capture's hostGateKey; store cannot import capture.
func harvestHostKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Unmap().String()
	}
	return h
}

// QueueHarvestedURLs queues the URLs harvested from src in one transaction
// and advances the harvest cursor to src.ID, also when nothing was queued.
// Each URL becomes an epoch-0 quarantine_fetch pending row (INSERT OR IGNORE:
// a URL already known is left alone) with parent_sha256=src.SHA256,
// depth=src.Depth+1 and src's provenance. A host that already has
// perHostDaily harvested rows (depth>0) created in the last 24 h gets no
// more: one script cannot turn the honeypot into a crawler of one server.
func (s *Store) QueueHarvestedURLs(ctx context.Context, src HarvestSource, urls []string, now time.Time, perHostDaily int) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if src.Depth < 0 || src.Depth >= HarvestMaxDepth {
		return 0, errors.New("harvest: source depth out of range")
	}
	if err := s.ensureArtifactsTable(); err != nil {
		return 0, err
	}
	s.captureMu.Lock()
	defer s.captureMu.Unlock()
	queued := 0
	err := s.WithTxContext(ctx, func(tx *sql.Tx) error {
		queued = 0
		nowS := captureTime(now)
		counts := map[string]int{}
		if len(urls) > 0 {
			// Every depth>0 epoch-0 row is written here with captureTime, so the
			// fixed-width string compare is exact and uses idx_artifacts_created.
			// Bounded by the cap itself: at most perHostDaily rows per host per
			// day can exist through this path.
			rows, err := tx.QueryContext(ctx, `SELECT url FROM artifacts
WHERE created_at > ? AND depth>0 AND fetch_epoch=0`, captureTime(now.Add(-24*time.Hour)))
			if err != nil {
				return err
			}
			for rows.Next() {
				var u string
				if err := rows.Scan(&u); err != nil {
					rows.Close()
					return err
				}
				if h := harvestHostKey(u); h != "" {
					counts[h]++
				}
			}
			if err := rows.Close(); err != nil {
				return err
			}
		}
		for _, u := range urls {
			if err := ctx.Err(); err != nil {
				return err
			}
			if u == "" || len(u) > harvestMaxURLBytes || strings.ContainsRune(u, 0) || !utf8.ValidString(u) {
				continue
			}
			host := harvestHostKey(u)
			if host == "" || counts[host] >= perHostDaily {
				continue
			}
			res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO artifacts(ts,src_ip,session_id,actor_id,url,origin,status,created_at,first_observed_at,last_seen_at,parent_sha256,depth)
VALUES(?,?,?,?,?,'quarantine_fetch','pending',?,?,?,?,?)`, nowS, src.SrcIP, src.SessionID, src.ActorID, u, nowS, nowS, nowS, src.SHA256, src.Depth+1)
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return err
			}
			if n > 0 {
				queued++
				counts[host]++
			}
		}
		return advanceHarvestCursorTx(ctx, tx, src.ID, nowS)
	})
	if err != nil {
		return 0, err
	}
	return queued, nil
}
