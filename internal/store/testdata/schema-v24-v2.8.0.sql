-- sqlite_master of a database created by the shipped v2.8.0 (commit 0108fa0) (schema v24),
-- dumped from that build's own store.Open on an empty file. Test fixture for
-- released_schema_test.go: the current binary must migrate it to the latest
-- schema. Do not edit by hand; regenerate from the release commit.
-- table abuseipdb_reports (abuseipdb_reports)
CREATE TABLE abuseipdb_reports (
  ip          TEXT PRIMARY KEY,
  reported_at TEXT NOT NULL,
  status      TEXT NOT NULL,
  categories  TEXT,
  abuse_score INTEGER DEFAULT 0
);
-- table actor_ips (actor_ips)
CREATE TABLE actor_ips (
  actor_id TEXT,
  ip TEXT,
  first_seen TEXT,
  last_seen TEXT,
  count INTEGER,
  PRIMARY KEY (actor_id, ip)
);
-- table actor_users (actor_users)
CREATE TABLE actor_users (
  actor_id TEXT,
  username TEXT,
  count INTEGER,
  PRIMARY KEY (actor_id, username)
);
-- table actors (actors)
CREATE TABLE actors (
  id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  primary_ip TEXT,
  playbook TEXT,
  intent TEXT,
  confidence INTEGER,
  first_seen TEXT,
  last_seen TEXT,
  event_count INTEGER,
  unique_users INTEGER,
  attempts_per_hour REAL,
  hassh TEXT,
  ssh_client TEXT,
  username_hash TEXT,
  campaigns TEXT,
  probe_score INTEGER,
  notes TEXT
, flags INTEGER NOT NULL DEFAULT 0, generated_notes TEXT NOT NULL DEFAULT '');
-- table app_settings (app_settings)
CREATE TABLE app_settings (
  -- Operator-editable runtime key/value store backing the dashboard Settings
  -- panel (API keys, AbuseIPDB reporting knobs, geo/home). Values are plaintext
  -- in an already-0600 DB; see internal/store/app_settings.go for the rationale.
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
-- table artifacts (artifacts)
CREATE TABLE artifacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  src_ip TEXT,
  session_id TEXT,
  actor_id TEXT,
  url TEXT NOT NULL,
  local_path TEXT,
  sha256 TEXT,
  size_bytes INTEGER DEFAULT 0,
  origin TEXT NOT NULL,
  status TEXT NOT NULL,
  detail TEXT,
  created_at TEXT NOT NULL, attempt_count INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT, first_observed_at TEXT, last_seen_at TEXT, last_fetch_attempt_at TEXT, last_successful_fetch_at TEXT, lease_until TEXT,
  UNIQUE(url)
);
-- table bazaar_uploads (bazaar_uploads)
CREATE TABLE bazaar_uploads (
  sha256          TEXT PRIMARY KEY,
  uploaded_at     TEXT NOT NULL,
  response_status TEXT NOT NULL,
  mb_url          TEXT
, uploaded_at_key TEXT);
-- table capture_discovery_errors (capture_discovery_errors)
CREATE TABLE capture_discovery_errors(
 event_id INTEGER PRIMARY KEY,kind TEXT NOT NULL,
 reason TEXT NOT NULL CHECK(reason IN ('invalid_timestamp','invalid_metadata','too_many_urls')),
 created_at TEXT NOT NULL
);
-- table capture_file_jobs (capture_file_jobs)
CREATE TABLE capture_file_jobs(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 event_id INTEGER NOT NULL UNIQUE,
 source_name TEXT NOT NULL DEFAULT '', delivery_url TEXT NOT NULL DEFAULT '',
 src_ip TEXT NOT NULL DEFAULT '',session_id TEXT NOT NULL DEFAULT '',actor_id TEXT NOT NULL DEFAULT '',
 expected_sha256 TEXT NOT NULL DEFAULT '',observed_at TEXT,
 state TEXT NOT NULL CHECK(state IN ('pending','retry','leased','archived','rejected','failed')),
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0 AND attempts<=5),
 next_attempt_at TEXT NOT NULL,lease_started_at TEXT,lease_until TEXT,last_clock_at TEXT,
 lease_token INTEGER NOT NULL DEFAULT 0,
 result_sha256 TEXT NOT NULL DEFAULT '',result_path TEXT NOT NULL DEFAULT '',result_size INTEGER NOT NULL DEFAULT 0,
 reason TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,updated_at TEXT NOT NULL
);
-- table cowrie_session_hassh (cowrie_session_hassh)
CREATE TABLE cowrie_session_hassh (
  session_id  TEXT PRIMARY KEY,
  hassh       TEXT NOT NULL,
  observed_at TEXT NOT NULL DEFAULT ''
);
-- table cowrie_session_meta (cowrie_session_meta)
CREATE TABLE cowrie_session_meta (
  session_id  TEXT PRIMARY KEY,
  duration_ms INTEGER DEFAULT 0,
  arch        TEXT,
  observed_at TEXT NOT NULL DEFAULT ''
);
-- table events (events)
CREATE TABLE events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  -- Fixed-width RFC3339 UTC text plus exact epoch nanoseconds. ts remains for
  -- compatibility/export; ts_unix_ns drives chronological v20+ reads.
  ts TEXT NOT NULL,
  ts_unix_ns INTEGER,
  source TEXT NOT NULL,
  kind TEXT NOT NULL,
  src_ip TEXT,
  src_port INTEGER DEFAULT 0,
  username TEXT,
  -- Honeypot passwords are attacker-supplied telemetry and can still be sensitive.
  password TEXT,
  session_id TEXT,
  hassh TEXT,
  ssh_client TEXT,
  command TEXT,
  sha256 TEXT,
  filename TEXT,
  dst_ip TEXT,
  dst_port INTEGER DEFAULT 0,
  raw TEXT,
  actor_id TEXT
);
-- table ingest_state (ingest_state)
CREATE TABLE ingest_state (
  source TEXT NOT NULL,
  path TEXT NOT NULL,
  inode INTEGER NOT NULL DEFAULT 0,
  offset INTEGER NOT NULL DEFAULT 0,
  -- head_sig fingerprints the file's first bytes to detect copytruncate-style
  -- in-place rotation (same inode, replaced content) and reset the offset.
  head_sig TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (source, path)
);
-- table journal_summaries (journal_summaries)
CREATE TABLE journal_summaries(
 actor_id TEXT PRIMARY KEY,
 corpus_revision INTEGER NOT NULL DEFAULT 0,
 building_revision INTEGER NOT NULL DEFAULT -1,
 completed_revision INTEGER NOT NULL DEFAULT -1,
 user_cursor TEXT NOT NULL DEFAULT '',
 fold_state BLOB,
 status TEXT NOT NULL DEFAULT 'unknown_history' CHECK(status IN ('pending','current','unknown_history'))
);
-- table schema_migrations (schema_migrations)
CREATE TABLE schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);
-- table threatfox_submissions (threatfox_submissions)
CREATE TABLE threatfox_submissions (ioc TEXT PRIMARY KEY, ioc_type TEXT NOT NULL, malware TEXT NOT NULL, submitted_at TEXT NOT NULL, status TEXT NOT NULL, submitted_at_key TEXT);
-- table urlhaus_submissions (urlhaus_submissions)
CREATE TABLE urlhaus_submissions (url TEXT PRIMARY KEY, submitted_at TEXT NOT NULL, status TEXT NOT NULL, submitted_at_key TEXT);
-- trigger bazaar_legacy_time_insert (bazaar_uploads)
CREATE TRIGGER bazaar_legacy_time_insert AFTER INSERT ON bazaar_uploads WHEN NEW.uploaded_at_key IS NULL BEGIN UPDATE ingest_state SET offset=MIN(offset,NEW.rowid-1) WHERE source='migration' AND path='ledger-bazaar-v22'; END;
-- trigger bazaar_legacy_time_update (bazaar_uploads)
CREATE TRIGGER bazaar_legacy_time_update AFTER UPDATE OF uploaded_at,uploaded_at_key ON bazaar_uploads WHEN NEW.uploaded_at_key IS NULL OR (NEW.uploaded_at IS NOT OLD.uploaded_at AND NEW.uploaded_at_key IS OLD.uploaded_at_key) BEGIN UPDATE bazaar_uploads SET uploaded_at_key=NULL WHERE rowid=NEW.rowid AND uploaded_at_key IS NOT NULL;UPDATE ingest_state SET offset=MIN(offset,NEW.rowid-1) WHERE source='migration' AND path='ledger-bazaar-v22'; END;
-- index idx_abuseipdb_reports_ts (abuseipdb_reports)
CREATE INDEX idx_abuseipdb_reports_ts ON abuseipdb_reports(reported_at);
-- index idx_actor_ips_ip (actor_ips)
CREATE INDEX idx_actor_ips_ip ON actor_ips(ip);
-- index idx_actors_event_count (actors)
CREATE INDEX idx_actors_event_count ON actors(event_count);
-- index idx_actors_last_seen (actors)
CREATE INDEX idx_actors_last_seen ON actors(last_seen);
-- index idx_actors_primary_ip (actors)
CREATE INDEX idx_actors_primary_ip ON actors(primary_ip);
-- index idx_actors_rate (actors)
CREATE INDEX idx_actors_rate ON actors(attempts_per_hour);
-- index idx_artifacts_capture_due (artifacts)
CREATE INDEX idx_artifacts_capture_due ON artifacts(origin, status, next_attempt_at);
-- index idx_bazaar_legacy_time (bazaar_uploads)
CREATE INDEX idx_bazaar_legacy_time ON bazaar_uploads(uploaded_at) WHERE uploaded_at_key IS NULL;
-- index idx_bazaar_time_key (bazaar_uploads)
CREATE INDEX idx_bazaar_time_key ON bazaar_uploads(uploaded_at_key DESC,sha256);
-- index idx_bazaar_uploads_ts (bazaar_uploads)
CREATE INDEX idx_bazaar_uploads_ts ON bazaar_uploads(uploaded_at);
-- index idx_cowrie_session_hassh_observed_at (cowrie_session_hassh)
CREATE INDEX idx_cowrie_session_hassh_observed_at ON cowrie_session_hassh(observed_at);
-- index idx_cowrie_session_meta_observed_at (cowrie_session_meta)
CREATE INDEX idx_cowrie_session_meta_observed_at ON cowrie_session_meta(observed_at);
-- index idx_events_actor_ts (events)
CREATE INDEX idx_events_actor_ts ON events(actor_id, ts);
-- index idx_events_command (events)
CREATE INDEX idx_events_command ON events(command);
-- index idx_events_ip (events)
CREATE INDEX idx_events_ip ON events(src_ip);
-- index idx_events_kind_ts (events)
CREATE INDEX idx_events_kind_ts ON events(kind, ts);
-- index idx_events_legacy_ts (events)
CREATE INDEX idx_events_legacy_ts ON events(ts,id) WHERE ts_unix_ns IS NULL;
-- index idx_events_session (events)
CREATE INDEX idx_events_session ON events(source, session_id, ts);
-- index idx_events_sha256 (events)
CREATE INDEX idx_events_sha256 ON events(sha256) WHERE sha256 != '';
-- index idx_events_ts (events)
CREATE INDEX idx_events_ts ON events(ts);
-- index idx_events_unix_ns (events)
CREATE INDEX idx_events_unix_ns ON events(ts_unix_ns, id) WHERE ts_unix_ns IS NOT NULL;
-- index idx_events_username (events)
CREATE INDEX idx_events_username ON events(username);
-- index idx_file_capture_due (capture_file_jobs)
CREATE INDEX idx_file_capture_due ON capture_file_jobs(next_attempt_at,id) WHERE state IN ('pending','retry','leased');
-- index idx_file_capture_lease (capture_file_jobs)
CREATE INDEX idx_file_capture_lease ON capture_file_jobs(lease_until,id) WHERE state='leased';
-- index idx_file_capture_source_live (capture_file_jobs)
CREATE INDEX idx_file_capture_source_live ON capture_file_jobs(source_name) WHERE state IN ('pending','retry','leased');
-- index idx_journal_summary_pending (journal_summaries)
CREATE INDEX idx_journal_summary_pending ON journal_summaries(actor_id) WHERE status='pending';
-- index idx_threatfox_legacy_time (threatfox_submissions)
CREATE INDEX idx_threatfox_legacy_time ON threatfox_submissions(submitted_at) WHERE submitted_at_key IS NULL;
-- index idx_threatfox_time_key (threatfox_submissions)
CREATE INDEX idx_threatfox_time_key ON threatfox_submissions(submitted_at_key DESC,ioc);
-- index idx_urlhaus_legacy_time (urlhaus_submissions)
CREATE INDEX idx_urlhaus_legacy_time ON urlhaus_submissions(submitted_at) WHERE submitted_at_key IS NULL;
-- index idx_urlhaus_time_key (urlhaus_submissions)
CREATE INDEX idx_urlhaus_time_key ON urlhaus_submissions(submitted_at_key DESC,url);
-- trigger journal_summary_actor_delete (actors)
CREATE TRIGGER journal_summary_actor_delete AFTER DELETE ON actors
BEGIN DELETE FROM journal_summaries WHERE actor_id=OLD.id; END;
-- trigger journal_summary_actor_insert (actors)
CREATE TRIGGER journal_summary_actor_insert AFTER INSERT ON actors WHEN NEW.source='journal'
BEGIN INSERT OR IGNORE INTO journal_summaries(actor_id) VALUES(NEW.id); END;
-- trigger journal_summary_counters (actors)
CREATE TRIGGER journal_summary_counters AFTER UPDATE OF event_count,unique_users,first_seen,last_seen ON actors WHEN NEW.source='journal'
BEGIN UPDATE journal_summaries SET status=CASE WHEN status='unknown_history' THEN status ELSE 'pending' END WHERE actor_id=NEW.id; END;
-- trigger journal_summary_user_delete (actor_users)
CREATE TRIGGER journal_summary_user_delete AFTER DELETE ON actor_users
BEGIN UPDATE journal_summaries SET corpus_revision=corpus_revision+1,status=CASE WHEN status='unknown_history' THEN status ELSE 'pending' END WHERE actor_id=OLD.actor_id; END;
-- trigger journal_summary_user_identity (actor_users)
CREATE TRIGGER journal_summary_user_identity AFTER UPDATE OF username,actor_id ON actor_users WHEN NEW.username IS NOT OLD.username OR NEW.actor_id IS NOT OLD.actor_id
BEGIN UPDATE journal_summaries SET corpus_revision=corpus_revision+1,status=CASE WHEN status='unknown_history' THEN status ELSE 'pending' END WHERE actor_id IN (NEW.actor_id,OLD.actor_id); END;
-- trigger journal_summary_user_insert (actor_users)
CREATE TRIGGER journal_summary_user_insert AFTER INSERT ON actor_users
BEGIN UPDATE journal_summaries SET corpus_revision=corpus_revision+1,status=CASE WHEN status='unknown_history' THEN status ELSE 'pending' END WHERE actor_id=NEW.actor_id; END;
-- trigger threatfox_legacy_time_insert (threatfox_submissions)
CREATE TRIGGER threatfox_legacy_time_insert AFTER INSERT ON threatfox_submissions WHEN NEW.submitted_at_key IS NULL BEGIN UPDATE ingest_state SET offset=MIN(offset,NEW.rowid-1) WHERE source='migration' AND path='ledger-threatfox-v22'; END;
-- trigger threatfox_legacy_time_update (threatfox_submissions)
CREATE TRIGGER threatfox_legacy_time_update AFTER UPDATE OF submitted_at,submitted_at_key ON threatfox_submissions WHEN NEW.submitted_at_key IS NULL OR (NEW.submitted_at IS NOT OLD.submitted_at AND NEW.submitted_at_key IS OLD.submitted_at_key) BEGIN UPDATE threatfox_submissions SET submitted_at_key=NULL WHERE rowid=NEW.rowid AND submitted_at_key IS NOT NULL;UPDATE ingest_state SET offset=MIN(offset,NEW.rowid-1) WHERE source='migration' AND path='ledger-threatfox-v22'; END;
-- trigger urlhaus_legacy_time_insert (urlhaus_submissions)
CREATE TRIGGER urlhaus_legacy_time_insert AFTER INSERT ON urlhaus_submissions WHEN NEW.submitted_at_key IS NULL BEGIN UPDATE ingest_state SET offset=MIN(offset,NEW.rowid-1) WHERE source='migration' AND path='ledger-urlhaus-v22'; END;
-- trigger urlhaus_legacy_time_update (urlhaus_submissions)
CREATE TRIGGER urlhaus_legacy_time_update AFTER UPDATE OF submitted_at,submitted_at_key ON urlhaus_submissions WHEN NEW.submitted_at_key IS NULL OR (NEW.submitted_at IS NOT OLD.submitted_at AND NEW.submitted_at_key IS OLD.submitted_at_key) BEGIN UPDATE urlhaus_submissions SET submitted_at_key=NULL WHERE rowid=NEW.rowid AND submitted_at_key IS NOT NULL;UPDATE ingest_state SET offset=MIN(offset,NEW.rowid-1) WHERE source='migration' AND path='ledger-urlhaus-v22'; END;
INSERT INTO schema_migrations(version, applied_at) VALUES (1,'fixture'),(2,'fixture'),(3,'fixture'),(4,'fixture'),(5,'fixture'),(6,'fixture'),(7,'fixture'),(8,'fixture'),(9,'fixture'),(10,'fixture'),(11,'fixture'),(12,'fixture'),(13,'fixture'),(14,'fixture'),(15,'fixture'),(16,'fixture'),(17,'fixture'),(18,'fixture'),(19,'fixture'),(20,'fixture'),(21,'fixture'),(22,'fixture'),(23,'fixture'),(24,'fixture');
