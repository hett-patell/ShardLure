package store

import (
	"database/sql"
	"strings"
	"time"
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

// SessionBinding is one session's side-channel facts from a single parse pass,
// as produced by the cowrie ingester. Empty/zero fields are skipped. Passed to
// RecordSessionBindings so a tick's worth of bindings commit in ONE transaction
// instead of one writeMu acquisition per (binding × table).
type SessionBinding struct {
	SessionID  string
	HASSH      string
	Arch       string
	DurationMs int64
	// TTYSHA/TTYTS bind a ttylog sha to this session (cowrie_tty_index). Empty
	// TTYSHA skips the tty write.
	TTYSHA string
	TTYTS  time.Time
}

// RecordSessionBindings persists a batch of per-session side-channel bindings
// (hassh, duration, arch, ttylog-sha) in a single write transaction. It is the
// batched form of calling RecordSessionHASSH / RecordSessionDuration /
// RecordSessionArch / RecordCowrieTTYBinding per item: on a tick with many new
// sessions that was N separate writeMu acquisitions ahead of the main event
// insert; this collapses them to one. Semantics per column are identical to the
// singular methods (same ON CONFLICT clauses, same skip-empty rules).
//
// Tables are ensured BEFORE opening the transaction: the ensure* helpers take
// writeMu via execWrite, and writeMu is not reentrant, so calling them inside
// WithTx (which holds writeMu) would deadlock.
func (s *Store) RecordSessionBindings(bindings []SessionBinding) error {
	if len(bindings) == 0 {
		return nil
	}
	needMeta, needHASSH, needTTY := false, false, false
	for _, b := range bindings {
		if strings.TrimSpace(b.SessionID) == "" {
			continue
		}
		if strings.TrimSpace(b.HASSH) != "" {
			needHASSH = true
		}
		if strings.TrimSpace(b.Arch) != "" || b.DurationMs > 0 {
			needMeta = true
		}
		if strings.TrimSpace(b.TTYSHA) != "" {
			needTTY = true
		}
	}
	if needHASSH {
		if err := s.ensureSessionHASSHIndex(); err != nil {
			return err
		}
	}
	if needMeta {
		if err := s.ensureSessionMetaTable(); err != nil {
			return err
		}
	}
	if needTTY {
		if err := s.ensureCowrieTTYIndex(); err != nil {
			return err
		}
	}
	if !needHASSH && !needMeta && !needTTY {
		return nil
	}
	return s.WithTx(func(tx *sql.Tx) error {
		for _, b := range bindings {
			sid := strings.TrimSpace(b.SessionID)
			if sid == "" {
				continue
			}
			if h := strings.TrimSpace(b.HASSH); h != "" {
				if _, err := tx.Exec(`
INSERT INTO cowrie_session_hassh (session_id, hassh) VALUES (?, ?)
ON CONFLICT(session_id) DO UPDATE SET hassh=excluded.hassh`, sid, h); err != nil {
					return err
				}
			}
			if b.DurationMs > 0 {
				if _, err := tx.Exec(`
INSERT INTO cowrie_session_meta (session_id, duration_ms) VALUES (?, ?)
ON CONFLICT(session_id) DO UPDATE SET duration_ms=excluded.duration_ms`, sid, b.DurationMs); err != nil {
					return err
				}
			}
			if a := strings.TrimSpace(b.Arch); a != "" {
				if _, err := tx.Exec(`
INSERT INTO cowrie_session_meta (session_id, arch) VALUES (?, ?)
ON CONFLICT(session_id) DO UPDATE SET arch=excluded.arch`, sid, a); err != nil {
					return err
				}
			}
			if sha := strings.TrimSpace(strings.ToLower(b.TTYSHA)); sha != "" {
				ts := b.TTYTS
				if ts.IsZero() {
					ts = time.Now().UTC()
				}
				if _, err := tx.Exec(`
INSERT INTO cowrie_tty_index (sha256, session_id, ts) VALUES (?, ?, ?)
ON CONFLICT(sha256) DO UPDATE SET session_id=excluded.session_id, ts=excluded.ts`,
					sha, sid, ts.UTC().Format(time.RFC3339Nano)); err != nil {
					return err
				}
			}
		}
		return nil
	})
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
