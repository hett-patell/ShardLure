package store

import (
	"strings"
)

// cowrie carries a session's real end-of-life facts on eventids that make poor
// events themselves: cowrie.session.closed reports the authoritative
// duration_ms (better than MAX(ts)-MIN(ts), which misses the idle tail before
// disconnect), and cowrie.session.params reports the negotiated client arch
// ("linux-x64-lsb"). Neither is in mapKind, so — exactly like the
// session->hassh binding — we capture them as a side-channel keyed by session
// id and LEFT JOIN them onto the sessions view at read time. Mirrors the
// cowrie_session_hassh pattern.

// SessionMeta is the per-session enrichment persisted from the closed/params
// events. Zero values mean "not observed" (duration 0 / empty arch), which the
// sessions view treats as "fall back to the ts-delta / unknown".
type SessionMeta struct {
	DurationMs int64
	Arch       string
}

func (s *Store) ensureSessionMetaTable() error {
	s.onceSessMeta.Do(func() {
		_, s.errSessMeta = s.execWrite(`
CREATE TABLE IF NOT EXISTS cowrie_session_meta (
  session_id  TEXT PRIMARY KEY,
  duration_ms INTEGER DEFAULT 0,
  arch        TEXT
)`)
	})
	return s.errSessMeta
}

// RecordSessionDuration binds a session id to its cowrie-reported duration
// (milliseconds). Safe to call repeatedly; the row is upserted. A non-positive
// duration is ignored so a malformed/absent value can't overwrite a real one.
func (s *Store) RecordSessionDuration(sessionID string, durationMs int64) error {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" || durationMs <= 0 {
		return nil
	}
	if err := s.ensureSessionMetaTable(); err != nil {
		return err
	}
	// Preserve any arch already recorded for this session: INSERT sets arch to
	// its column default (NULL) and the ON CONFLICT clause only touches
	// duration_ms, so a prior params row's arch survives a later closed row.
	_, err := s.execWrite(`
INSERT INTO cowrie_session_meta (session_id, duration_ms) VALUES (?, ?)
ON CONFLICT(session_id) DO UPDATE SET duration_ms=excluded.duration_ms`,
		sessionID, durationMs)
	return err
}

// RecordSessionArch binds a session id to its negotiated client arch. Safe to
// call repeatedly; empty arch is ignored.
func (s *Store) RecordSessionArch(sessionID, arch string) error {
	sessionID = strings.TrimSpace(sessionID)
	arch = strings.TrimSpace(arch)
	if sessionID == "" || arch == "" {
		return nil
	}
	if err := s.ensureSessionMetaTable(); err != nil {
		return err
	}
	_, err := s.execWrite(`
INSERT INTO cowrie_session_meta (session_id, arch) VALUES (?, ?)
ON CONFLICT(session_id) DO UPDATE SET arch=excluded.arch`,
		sessionID, arch)
	return err
}

// SessionMetaForSessions returns the session_id->SessionMeta map for the given
// ids (only sessions with a recorded binding appear). Chunked to stay under
// SQLite's bound-parameter limit. Mirrors HASSHForSessions.
func (s *Store) SessionMetaForSessions(ids []string) (map[string]SessionMeta, error) {
	out := make(map[string]SessionMeta, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	if err := s.ensureSessionMetaTable(); err != nil {
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
		q := "SELECT session_id, COALESCE(duration_ms,0), COALESCE(arch,'') FROM cowrie_session_meta WHERE session_id IN (" +
			strings.Join(placeholders, ",") + ")"
		if err := s.QueryRows(q, args, func(scan func(...any) error) error {
			var sid string
			var m SessionMeta
			if err := scan(&sid, &m.DurationMs, &m.Arch); err != nil {
				return err
			}
			out[sid] = m
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return out, nil
}
