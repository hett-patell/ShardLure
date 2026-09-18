package store

import (
	"context"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// IterateReportEvidence reads only first-hand observations of the named IP
// and source, inside the reporting window. The IP index bounds the scan;
// julianday handles legacy offset and variable-precision timestamps.
// Rows are grouped by case-sensitive username so consumers need only retain
// the previous username to accumulate exact distinct-user signals. SQLite's
// sorter can spill to disk; no username index adds write overhead to ingest.
func (s *Store) IterateReportEvidence(source models.Source, ip string, since, until time.Time, fn func(*models.Event)) error {
	return s.IterateReportEvidenceContext(context.Background(), source, ip, since, until, fn)
}

func (s *Store) IterateReportEvidenceContext(ctx context.Context, source models.Source, ip string, since, until time.Time, fn func(*models.Event)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, ts, kind, COALESCE(username,''), COALESCE(ssh_client,''), COALESCE(command,'')
FROM events WHERE src_ip=? AND source=? AND COALESCE(actor_id,'')<>''
AND julianday(ts)>=julianday(?) AND julianday(ts)<=julianday(?)
ORDER BY COALESCE(username,'') COLLATE BINARY, id`, ip, source, captureTime(since), captureTime(until))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		e := &models.Event{Source: source, SrcIP: ip}
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Kind, &e.Username, &e.SSHClient, &e.Command); err != nil {
			return err
		}
		e.TS, err = parseTime(ts)
		if err != nil {
			return err
		}
		if !e.TS.Before(since) && !e.TS.After(until) {
			fn(e)
			if err := ctx.Err(); err != nil {
				return err
			}
		}
	}
	return rows.Err()
}
