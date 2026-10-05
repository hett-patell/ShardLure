package store

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// FunnelCounts is one time window of the payload funnel: how many Cowrie
// sessions reached each stage, how many distinct payloads were captured, how
// many of those were seen for the first time, and how many submissions each
// sharing ledger recorded. It exists so every payload-yield change (re-fetch,
// second-stage harvesting, realism fixes) reports a measured before/after
// instead of an impression (payload-yield spec, Phase 0).
type FunnelCounts struct {
	Connected, LoggedIn, RanCommands, DownloadAttempt int64
	Captured, NewPayloads                             int64
	SharedBazaar, SharedURLhaus, SharedThreatFox      int64
}

// funnelDownloadPredicate marks a session as having attempted a download: a
// Cowrie file transfer, or a command naming a remote URL or /dev/tcp target.
// It approximates capture.ExtractURLs in SQL (store must not import capture);
// tftp/ftp are included because Mirai-style loaders use them. The match is
// case-sensitive on the scheme, like capture's reHTTP.
//
// This is an *attempt* stage and is deliberately wider than what capture acts
// on: capture never fetches ftp:// or tftp, so a gap between DownloadAttempt and
// Captured is partly by construction. Don't "fix" that gap by blaming capture
// or by narrowing this predicate — it measures attacker intent, not our reach.
const funnelDownloadPredicate = `kind IN ('file_download','file_upload') OR (kind='command' AND (instr(command,'http://')>0 OR instr(command,'https://')>0 OR instr(command,'ftp://')>0 OR instr(command,'tftp ')>0 OR instr(command,'tftp'||char(9))>0 OR instr(lower(command),'/dev/tcp/')>0))`

// funnelLedgerCountSQL counts one submission ledger's rows at or after a
// fixed-width UTC key. It reads the v22 exact time keys the same way
// orderedLedgerQuery does — the indexed native key, plus shardlure_time_key
// over the shrinking legacy rows — instead of julianday(raw): julianday turns a
// malformed timestamp into NULL, which silently drops the row, and rounds near
// the boundary. shardlure_time_key errors on a malformed value instead, so the
// funnel fails closed exactly like the ledgers' own Stats. extra is an optional
// AND-ed filter on a private constant, never caller input.
func funnelLedgerCountSQL(ledger submissionLedger, extra string) string {
	d := submissionLedgers[ledger]
	if extra != "" {
		extra = " AND (" + extra + ")"
	}
	return "SELECT (SELECT COUNT(*) FROM " + d.table + " INDEXED BY idx_" + d.prefix + "_time_key WHERE " + d.key + " IS NOT NULL AND " + d.key + ">=?" + extra +
		") + (SELECT COUNT(*) FROM " + d.table + " INDEXED BY idx_" + d.prefix + "_legacy_time WHERE " + d.key + " IS NULL AND shardlure_time_key(" + d.timestamp + ")>=?" + extra + ")"
}

// PayloadFunnel counts the funnel for events and payloads at or after since.
//
// Session stages are Cowrie-only and count distinct non-empty session ids
// (journal has no session ids and its "accepted" is a real-sshd login).
//
// Captured is the distinct sha256s with a shareable row (the MalwareBazaar
// candidate predicate: status fetched, sha256 set, size and origin from pol)
// whose last successful fetch falls in the window — the same pool
// ArtifactsForShare sees, so the funnel never claims payloads
// the share path would refuse. A zero SharePolicy selects nothing, failing
// closed like ArtifactsForShare.
//
// NewPayloads is a subset of Captured by construction: a captured hash is new
// when *no* row of that hash, under any origin or status, was first observed
// before since. Judging over every row (not only shareable or in-window ones)
// is deliberate: a payload first seen last month as an observation-only or
// differently-originated row is not new just because a shareable fetch
// arrived today. Observation-only rows (RecordArtifactObservation: fetched but
// no fetch time) can therefore make a hash "old" but never make one captured.
//
// All queries run in one read-only transaction so the stages are one database
// snapshot; without it live ingest and sharing between queries could, for
// example, count an upload against a capture count read a moment earlier.
func (s *Store) PayloadFunnel(ctx context.Context, since time.Time, pol SharePolicy) (FunnelCounts, error) {
	var out FunnelCounts
	// The lazy tables are created before the transaction opens: ensure* takes
	// writeMu (not reentrant) and may run DDL, so it must never run inside one.
	for _, ensure := range []func() error{s.ensureArtifactsTable, s.ensureBazaarUploadsTable, s.ensureURLhausTable, s.ensureThreatFoxTable} {
		if err := ensure(); err != nil {
			return out, err
		}
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()

	window, args := globalEventTimeBranches("session_id,kind,command", &since,
		"source='cowrie' AND session_id<>'' AND kind IN ('connect','accepted','command','file_download','file_upload')", nil)
	query := `WITH w AS (` + window + `) SELECT
  COUNT(DISTINCT CASE WHEN kind='connect' THEN session_id END),
  COUNT(DISTINCT CASE WHEN kind='accepted' THEN session_id END),
  COUNT(DISTINCT CASE WHEN kind='command' THEN session_id END),
  COUNT(DISTINCT CASE WHEN ` + funnelDownloadPredicate + ` THEN session_id END)
FROM w`
	if err := tx.QueryRowContext(ctx, query, args...).Scan(&out.Connected, &out.LoggedIn, &out.RanCommands, &out.DownloadAttempt); err != nil {
		return out, err
	}

	if pol.MinBytes > 0 && len(pol.Origins) > 0 {
		sinceText := since.UTC().Format(time.RFC3339Nano)
		// Bind order follows the text: NOT EXISTS cutoff, size, origins, fetch cutoff.
		ph := make([]string, len(pol.Origins))
		qargs := []any{sinceText, pol.MinBytes}
		for i, o := range pol.Origins {
			ph[i] = "?"
			qargs = append(qargs, o)
		}
		qargs = append(qargs, sinceText)
		// Artifact times are julianday-compared like every other artifact
		// window (legacy rows are not fixed-width); the table is small.
		q := `SELECT COUNT(*), COALESCE(SUM(NOT EXISTS (
    SELECT 1 FROM artifacts o WHERE o.sha256=c.sha256
      AND julianday(COALESCE(NULLIF(o.first_observed_at,''),o.created_at))<julianday(?))),0)
FROM (SELECT DISTINCT sha256 FROM artifacts
  WHERE status='fetched' AND sha256 IS NOT NULL AND sha256<>'' AND size_bytes>=?
    AND origin IN (` + strings.Join(ph, ",") + `)
    AND julianday(last_successful_fetch_at)>=julianday(?)) c`
		if err := tx.QueryRowContext(ctx, q, qargs...).Scan(&out.Captured, &out.NewPayloads); err != nil {
			return out, err
		}
	}

	key := formatFixedUTC(since)
	// A duplicate MalwareBazaar answer contributed nothing new to the
	// community, so it is not counted as shared. The ledgers are upserts, so a
	// row counts at its latest submission time.
	ledgers := []struct {
		dst   *int64
		query string
	}{
		{&out.SharedBazaar, funnelLedgerCountSQL(bazaarLedger, "COALESCE(response_status,'')<>'file_already_known'")},
		{&out.SharedURLhaus, funnelLedgerCountSQL(urlhausLedger, "")},
		{&out.SharedThreatFox, funnelLedgerCountSQL(threatfoxLedger, "")},
	}
	for _, l := range ledgers {
		if err := tx.QueryRowContext(ctx, l.query, key, key).Scan(l.dst); err != nil {
			return out, err
		}
	}
	return out, tx.Commit()
}
