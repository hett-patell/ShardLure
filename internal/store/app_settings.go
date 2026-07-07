package store

import (
	"database/sql"
	"time"
)

// app_settings is a simple key/value store for operator-editable runtime
// settings and API keys managed from the dashboard Settings panel. Values —
// including provider API keys — are stored PLAINTEXT: the DB file is already
// chmod 0600 (see Open) and can hold attacker-supplied passwords, so it is
// treated as a loaded gun regardless. An at-rest obfuscation layer here would
// be security theatre without an external key-management story. Callers must
// never log these values.
//
// The mutable runtime cache with env-var fallback lives one layer up in
// internal/settings.Keystore; this file is dumb persistence only, mirroring
// ingest_state.go.

// GetAppSetting returns the stored value for key and whether a row exists.
func (s *Store) GetAppSetting(key string) (string, bool, error) {
	row := s.db.QueryRow(`SELECT value FROM app_settings WHERE key=?`, key)
	var v string
	if err := row.Scan(&v); err != nil {
		if err == sql.ErrNoRows {
			return "", false, nil
		}
		return "", false, err
	}
	return v, true, nil
}

// AllAppSettings returns every stored key/value pair. Used to seed the runtime
// keystore at startup.
func (s *Store) AllAppSettings() (map[string]string, error) {
	out := make(map[string]string)
	err := s.QueryRows(`SELECT key, value FROM app_settings`, nil, func(scan func(...any) error) error {
		var k, v string
		if err := scan(&k, &v); err != nil {
			return err
		}
		out[k] = v
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SetAppSetting upserts a key/value pair. Same idempotent pattern as
// SetIngestState.
func (s *Store) SetAppSetting(key, value string) error {
	_, err := s.execWrite(`
INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?)
ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		key, value, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// DeleteAppSetting removes a key. A missing key is not an error (DELETE of zero
// rows succeeds), so callers can Clear unconditionally.
func (s *Store) DeleteAppSetting(key string) error {
	_, err := s.execWrite(`DELETE FROM app_settings WHERE key=?`, key)
	return err
}
