package store

import (
	"context"
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
// tftp/ftp are included because Mirai-style loaders use them.
const funnelDownloadPredicate = `kind IN ('file_download','file_upload') OR (kind='command' AND (instr(command,'http://')>0 OR instr(command,'https://')>0 OR instr(command,'ftp://')>0 OR instr(command,'tftp ')>0 OR instr(lower(command),'/dev/tcp/')>0))`

// PayloadFunnel counts the funnel for events and payloads at or after since.
// Session stages are Cowrie-only (journal has no session ids and its
// "accepted" is a real-sshd login). Payload stages use the same predicate as
// the MalwareBazaar candidate pool (status fetched, sha256 set, size and
// origin from pol), so the funnel can never claim payloads the share path
// would refuse; a zero SharePolicy selects nothing, failing closed like
// ArtifactsForShare. The ledgers are small, never-purged tables, so a
// julianday() scan is cheaper than maintaining another index.
func (s *Store) PayloadFunnel(ctx context.Context, since time.Time, pol SharePolicy) (FunnelCounts, error) {
	var out FunnelCounts
	// The lazy tables are created before any query: ensure* takes writeMu, so
	// it must never run inside a transaction (none is open here).
	for _, ensure := range []func() error{s.ensureArtifactsTable, s.ensureBazaarUploadsTable, s.ensureURLhausTable, s.ensureThreatFoxTable} {
		if err := ensure(); err != nil {
			return out, err
		}
	}
	window, args := globalEventTimeBranches("session_id,kind,command", &since,
		"source='cowrie' AND session_id<>'' AND kind IN ('connect','accepted','command','file_download','file_upload')", nil)
	query := `WITH w AS (` + window + `) SELECT
  COUNT(DISTINCT CASE WHEN kind='connect' THEN session_id END),
  COUNT(DISTINCT CASE WHEN kind='accepted' THEN session_id END),
  COUNT(DISTINCT CASE WHEN kind='command' THEN session_id END),
  COUNT(DISTINCT CASE WHEN ` + funnelDownloadPredicate + ` THEN session_id END)
FROM w`
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&out.Connected, &out.LoggedIn, &out.RanCommands, &out.DownloadAttempt); err != nil {
		return out, err
	}

	sinceText := since.UTC().Format(time.RFC3339Nano)
	if pol.MinBytes > 0 && len(pol.Origins) > 0 {
		ph := make([]string, len(pol.Origins))
		base := []any{pol.MinBytes}
		for i, o := range pol.Origins {
			ph[i] = "?"
			base = append(base, o)
		}
		shareable := `status='fetched' AND sha256 IS NOT NULL AND sha256<>'' AND size_bytes>=? AND origin IN (` + strings.Join(ph, ",") + `)`
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT sha256) FROM artifacts WHERE `+shareable+
			` AND julianday(last_successful_fetch_at)>=julianday(?)`, append(append([]any{}, base...), sinceText)...).Scan(&out.Captured); err != nil {
			return out, err
		}
		// "New" = the hash's earliest observation falls in the window, so a
		// payload re-fetched today but first seen last month is captured, not new.
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT sha256 FROM artifacts WHERE `+shareable+
			` GROUP BY sha256 HAVING julianday(MIN(COALESCE(NULLIF(first_observed_at,''),created_at)))>=julianday(?))`,
			append(append([]any{}, base...), sinceText)...).Scan(&out.NewPayloads); err != nil {
			return out, err
		}
	}

	// A duplicate MalwareBazaar answer contributed nothing new to the
	// community, so it is not counted as shared.
	ledgers := []struct {
		dst   *int64
		query string
	}{
		{&out.SharedBazaar, `SELECT COUNT(*) FROM bazaar_uploads WHERE julianday(uploaded_at)>=julianday(?) AND COALESCE(response_status,'')<>'file_already_known'`},
		{&out.SharedURLhaus, `SELECT COUNT(*) FROM urlhaus_submissions WHERE julianday(submitted_at)>=julianday(?)`},
		{&out.SharedThreatFox, `SELECT COUNT(*) FROM threatfox_submissions WHERE julianday(submitted_at)>=julianday(?)`},
	}
	for _, l := range ledgers {
		if err := s.db.QueryRowContext(ctx, l.query, sinceText).Scan(l.dst); err != nil {
			return out, err
		}
	}
	return out, nil
}
