package store

import (
	"strings"
)

// cowrie emits a client's HASSH fingerprint only on the cowrie.client.kex
// event, but clustering (and the "same actor across N IPs" premise) needs
// that fingerprint on the session's login/command events too. The cowrie
// ingest records the session->hassh binding from the kex line here, then
// stamps it onto the rest of that session's events — including across
// incremental-tail batches, where the kex arrived in an earlier tick than
// the commands. Mirrors the cowrie_tty_index pattern.

func (s *Store) ensureSessionHASSHIndex() error {
	s.onceSessHASSH.Do(func() {
		_, s.errSessHASSH = s.execWrite(`
CREATE TABLE IF NOT EXISTS cowrie_session_hassh (
  session_id TEXT PRIMARY KEY,
  hassh      TEXT NOT NULL
)`)
	})
	return s.errSessHASSH
}

// RecordSessionHASSH binds a cowrie session id to its client HASSH. Safe to
// call repeatedly; the first non-empty hassh for a session wins (a session
// only performs one key exchange, so re-binds would carry the same value).
func (s *Store) RecordSessionHASSH(sessionID, hassh string) error {
	sessionID = strings.TrimSpace(sessionID)
	hassh = strings.TrimSpace(hassh)
	if sessionID == "" || hassh == "" {
		return nil
	}
	if err := s.ensureSessionHASSHIndex(); err != nil {
		return err
	}
	_, err := s.execWrite(`
INSERT INTO cowrie_session_hassh (session_id, hassh) VALUES (?, ?)
ON CONFLICT(session_id) DO UPDATE SET hassh=excluded.hassh`,
		sessionID, hassh)
	return err
}

// HASSHForSessions returns the session_id->hassh map for the given session
// ids (only sessions with a recorded binding appear in the result). Chunked
// to stay under SQLite's bound-parameter limit.
func (s *Store) HASSHForSessions(ids []string) (map[string]string, error) {
	out := make(map[string]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	if err := s.ensureSessionHASSHIndex(); err != nil {
		return nil, err
	}
	const chunk = 400
	for i := 0; i < len(ids); i += chunk {
		end := i + chunk
		if end > len(ids) {
			end = len(ids)
		}
		batch := ids[i:end]
		placeholders := make([]string, len(batch))
		args := make([]any, len(batch))
		for j, id := range batch {
			placeholders[j] = "?"
			args[j] = id
		}
		q := "SELECT session_id, hassh FROM cowrie_session_hassh WHERE session_id IN (" +
			strings.Join(placeholders, ",") + ")"
		if err := s.QueryRows(q, args, func(scan func(...any) error) error {
			var sid, h string
			if err := scan(&sid, &h); err != nil {
				return err
			}
			out[sid] = h
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return out, nil
}
