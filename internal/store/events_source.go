package store

import (
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func (s *Store) EventExists(e *models.Event) (bool, error) {
	var n int
	err := s.db.QueryRow(`
SELECT COUNT(1) FROM events
WHERE source=? AND kind=? AND ts=? AND src_ip=? AND session_id=? AND username=? AND command=?`,
		e.Source, e.Kind, e.TS.UTC().Format(time.RFC3339Nano), e.SrcIP, e.SessionID, e.Username, e.Command).Scan(&n)
	return n > 0, err
}

func (s *Store) EventRawExists(raw string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM events WHERE raw=?`, raw).Scan(&n)
	return n > 0, err
}

func (s *Store) EventsBySource(source models.Source) ([]*models.Event, error) {
	rows, err := s.db.Query(`SELECT id, ts, source, kind, src_ip, src_port, username, password, session_id, hassh, ssh_client, ja4, command, sha256, filename, raw, actor_id
FROM events WHERE source=? ORDER BY ts ASC`, source)
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

func (s *Store) DeleteActorsBySource(source models.Source) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM actor_ips WHERE actor_id IN (SELECT id FROM actors WHERE source=?)`, source); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DELETE FROM actor_users WHERE actor_id IN (SELECT id FROM actors WHERE source=?)`, source); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DELETE FROM actors WHERE source=?`, source); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Store) ClearBySource(source models.Source) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM actor_ips WHERE actor_id IN (SELECT id FROM actors WHERE source=?)`, source); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DELETE FROM actor_users WHERE actor_id IN (SELECT id FROM actors WHERE source=?)`, source); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DELETE FROM actors WHERE source=?`, source); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DELETE FROM events WHERE source=?`, source); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
