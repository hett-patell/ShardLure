package store

import "database/sql"

// v25: campaigns and script fingerprints. Evidence and scripts are per
// session so a HASSH re-key moves them with the session's events.
const campaignsSchema = `
CREATE TABLE IF NOT EXISTS session_script_lines (
  session_id TEXT NOT NULL,
  event_id INTEGER NOT NULL,
  line TEXT NOT NULL,
  PRIMARY KEY (session_id, event_id)
);
CREATE TABLE IF NOT EXISTS session_scripts (
  session_id TEXT PRIMARY KEY,
  actor_id TEXT NOT NULL DEFAULT '',
  src_ip TEXT NOT NULL DEFAULT '',
  line_count INTEGER NOT NULL DEFAULT 0,
  bytes INTEGER NOT NULL DEFAULT 0,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  settled_at TEXT NOT NULL DEFAULT '',
  fingerprint TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_session_scripts_fp ON session_scripts(fingerprint);
CREATE INDEX IF NOT EXISTS idx_session_scripts_actor ON session_scripts(actor_id);
CREATE INDEX IF NOT EXISTS idx_session_scripts_last_seen ON session_scripts(last_seen);
CREATE INDEX IF NOT EXISTS idx_session_scripts_pending ON session_scripts(last_seen) WHERE settled_at='' OR updated_at>settled_at;
CREATE TABLE IF NOT EXISTS scripts (
  fingerprint TEXT PRIMARY KEY,
  normalized TEXT NOT NULL,
  display TEXT NOT NULL,
  command_count INTEGER NOT NULL,
  distinctive INTEGER NOT NULL,
  family TEXT NOT NULL DEFAULT '',
  family_distance REAL NOT NULL DEFAULT 0,
  token_count INTEGER NOT NULL DEFAULT 0,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scripts_family ON scripts(family);
CREATE TABLE IF NOT EXISTS script_families (
  family TEXT PRIMARY KEY,
  display TEXT NOT NULL,
  variants TEXT NOT NULL,
  sessions INTEGER NOT NULL,
  actors INTEGER NOT NULL,
  ips INTEGER NOT NULL,
  command_count INTEGER NOT NULL,
  distinctive INTEGER NOT NULL,
  links INTEGER NOT NULL,
  reason TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS campaign_evidence (
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  session_id TEXT NOT NULL,
  actor_id TEXT NOT NULL DEFAULT '',
  src_ip TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  PRIMARY KEY (kind, value, session_id)
);
CREATE INDEX IF NOT EXISTS idx_campaign_evidence_actor ON campaign_evidence(actor_id);
CREATE INDEX IF NOT EXISTS idx_campaign_evidence_session ON campaign_evidence(session_id);
CREATE INDEX IF NOT EXISTS idx_campaign_evidence_last_seen ON campaign_evidence(last_seen);
CREATE TABLE IF NOT EXISTS campaign_ids (
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  campaign_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  PRIMARY KEY (kind, value)
);
CREATE INDEX IF NOT EXISTS idx_campaign_ids_campaign ON campaign_ids(campaign_id);
CREATE TABLE IF NOT EXISTS campaign_aliases (
  old_id TEXT PRIMARY KEY,
  new_id TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS campaigns (
  id TEXT PRIMARY KEY,
  anchor_kind TEXT NOT NULL DEFAULT '',
  anchor_value TEXT NOT NULL DEFAULT '',
  suggested_name TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL DEFAULT '',
  last_seen TEXT NOT NULL DEFAULT '',
  actors INTEGER NOT NULL DEFAULT 0,
  ips INTEGER NOT NULL DEFAULT 0,
  sessions INTEGER NOT NULL DEFAULT 0,
  kinds TEXT NOT NULL DEFAULT '',
  search TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS campaign_members (
  campaign_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  sessions INTEGER NOT NULL,
  ips INTEGER NOT NULL,
  reasons TEXT NOT NULL,
  PRIMARY KEY (campaign_id, actor_id)
);
CREATE INDEX IF NOT EXISTS idx_campaign_members_actor ON campaign_members(actor_id);
CREATE TABLE IF NOT EXISTS campaign_edits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  campaign_id TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  arg TEXT NOT NULL DEFAULT '',
  who TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
-- A normaliser version change re-encodes every script (ResetScriptsForVersion)
-- and keeps each session's old fingerprint here until the sessions have
-- settled again, so script assignments in campaign_ids can be carried to the
-- new fingerprints (released by ScriptRebuildHold). Empty outside a rebuild.
CREATE TABLE IF NOT EXISTS script_version_carry (
  session_id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL
);
-- GetCampaign reads a campaign's edits with campaign_id IN (...); the
-- history is never purged, so an unindexed filter grows without bound.
CREATE INDEX IF NOT EXISTS idx_campaign_edits_campaign ON campaign_edits(campaign_id);`

func (s *Store) migrateCampaigns(now string) error {
	return s.WithTx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(campaignsSchema); err != nil {
			return err
		}
		_, err := tx.Exec("INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(25,?)", now)
		return err
	})
}
