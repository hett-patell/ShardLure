package store

import (
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func (s *Store) EventsByIP(ip string, limit int) ([]*models.Event, error) {
	q := `SELECT id, ts, source, kind, src_ip, src_port, username, password, session_id, hassh, ssh_client, ja4, command, sha256, filename, raw, actor_id
FROM events WHERE src_ip=? ORDER BY ts ASC`
	args := []any{ip}
	if limit > 0 {
		q += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.Event
	for rows.Next() {
		var e models.Event
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Source, &e.Kind, &e.SrcIP, &e.SrcPort, &e.Username, &e.Password,
			&e.SessionID, &e.HASSH, &e.SSHClient, &e.JA4, &e.Command, &e.SHA256, &e.Filename, &e.Raw, &e.ActorID); err != nil {
			return nil, err
		}
		e.TS, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, &e)
	}
	return out, rows.Err()
}
