package store

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"regexp"
	"time"

	"modernc.org/sqlite"
)

type submissionLedger int

const (
	bazaarLedger submissionLedger = iota
	urlhausLedger
	threatfoxLedger
)

// Identifiers are private constants, never operator or attacker input.
var submissionLedgers = [...]struct {
	table, timestamp, key, primary, prefix, columns string
}{
	{"bazaar_uploads", "uploaded_at", "uploaded_at_key", "sha256", "bazaar",
		"sha256 TEXT PRIMARY KEY, uploaded_at TEXT NOT NULL, response_status TEXT NOT NULL, mb_url TEXT"},
	{"urlhaus_submissions", "submitted_at", "submitted_at_key", "url", "urlhaus",
		"url TEXT PRIMARY KEY, submitted_at TEXT NOT NULL, status TEXT NOT NULL"},
	{"threatfox_submissions", "submitted_at", "submitted_at_key", "ioc", "threatfox",
		"ioc TEXT PRIMARY KEY, ioc_type TEXT NOT NULL, malware TEXT NOT NULL, submitted_at TEXT NOT NULL, status TEXT NOT NULL"},
}

var errLedgerTimestamp = errors.New("submission ledger: invalid timestamp")

// time.Parse accepts comma fractions, single-digit hours, out-of-range zone
// fields and silently truncates >9 fractional digits. Exact ledger keys must
// not invent an instant from those values. Calendar validity is checked below.
var ledgerTimestampSyntax = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)

func parseLedgerTimestamp(raw string) (time.Time, error) {
	if !ledgerTimestampSyntax.MatchString(raw) {
		return time.Time{}, errLedgerTimestamp
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || len(formatFixedUTC(t)) != 30 {
		return time.Time{}, errLedgerTimestamp
	}
	return t, nil
}

func parseLedgerRowTimestamp(raw, key string) (time.Time, error) {
	t, err := parseLedgerTimestamp(raw)
	if err != nil || formatFixedUTC(t) != key {
		return time.Time{}, errLedgerTimestamp
	}
	return t, nil
}

func init() {
	// The schema uses only ordinary SQL: old binaries/sqlite3 can still write,
	// and invalidation triggers below never depend on this connection function.
	sqlite.MustRegisterDeterministicScalarFunction("shardlure_time_key", 1, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		raw, ok := args[0].(string)
		if !ok {
			return nil, errLedgerTimestamp
		}
		t, err := parseLedgerTimestamp(raw)
		if err != nil {
			return nil, err
		}
		return formatFixedUTC(t), nil
	})
}

func (ledger submissionLedger) backfillPath() string {
	return "ledger-" + submissionLedgers[ledger].prefix + "-v22"
}

func ensureLedgerTimeSchema(tx *sql.Tx, ledger submissionLedger) error {
	d := submissionLedgers[ledger]
	if _, err := tx.Exec("CREATE TABLE IF NOT EXISTS " + d.table + " (" + d.columns + ")"); err != nil {
		return err
	}
	has, err := columnExistsIn(tx, d.table, d.key)
	if err != nil {
		return err
	}
	if !has {
		if _, err := tx.Exec("ALTER TABLE " + d.table + " ADD COLUMN " + d.key + " TEXT"); err != nil {
			return err
		}
	}
	// Retain the original timestamp and every dedup row. Open only adds schema;
	// the bounded worker fills keys later. Reset a repair cursor if an old
	// writer changes an already-visited row, including one diagnosed as invalid.
	// The conditional UPDATE also makes this safe with recursive_triggers=ON.
	reset := "UPDATE ingest_state SET offset=MIN(offset,NEW.rowid-1) WHERE source='migration' AND path='" + ledger.backfillPath() + "';"
	_, err = tx.Exec("CREATE INDEX IF NOT EXISTS idx_" + d.prefix + "_time_key ON " + d.table + "(" + d.key + " DESC," + d.primary + ");" +
		"CREATE INDEX IF NOT EXISTS idx_" + d.prefix + "_legacy_time ON " + d.table + "(" + d.timestamp + ") WHERE " + d.key + " IS NULL;" +
		"CREATE TRIGGER IF NOT EXISTS " + d.prefix + "_legacy_time_insert AFTER INSERT ON " + d.table + " WHEN NEW." + d.key + " IS NULL BEGIN " + reset + " END;" +
		"CREATE TRIGGER IF NOT EXISTS " + d.prefix + "_legacy_time_update AFTER UPDATE OF " + d.timestamp + "," + d.key + " ON " + d.table +
		" WHEN NEW." + d.key + " IS NULL OR (NEW." + d.timestamp + " IS NOT OLD." + d.timestamp + " AND NEW." + d.key + " IS OLD." + d.key + ") BEGIN " +
		"UPDATE " + d.table + " SET " + d.key + "=NULL WHERE rowid=NEW.rowid AND " + d.key + " IS NOT NULL;" + reset + " END;")
	return err
}

func (s *Store) migrateLedgerTimes(now string) error {
	return s.WithTx(func(tx *sql.Tx) error {
		for ledger := range submissionLedgers {
			if err := ensureLedgerTimeSchema(tx, submissionLedger(ledger)); err != nil {
				return err
			}
		}
		_, err := tx.Exec("INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(22,?)", now)
		return err
	})
}

// ORDER BY on the compound query merges the indexed native side with only the
// shrinking legacy sort. Do not wrap both sides in a scalar or sort in Go.
func orderedLedgerQuery(ledger submissionLedger, columns string, limit int) (string, []any) {
	d := submissionLedgers[ledger]
	q := "SELECT " + columns + "," + d.key + " AS exact_time FROM " + d.table + " INDEXED BY idx_" + d.prefix + "_time_key WHERE " + d.key + " IS NOT NULL" +
		" UNION ALL SELECT " + columns + ",shardlure_time_key(" + d.timestamp + ") AS exact_time FROM " + d.table + " INDEXED BY idx_" + d.prefix + "_legacy_time WHERE " + d.key + " IS NULL" +
		" ORDER BY exact_time DESC," + d.primary + " ASC"
	if limit > 0 {
		return q + " LIMIT ?", []any{limit}
	}
	return q, nil
}

// The native latest value is one index lookup, not MAX(scalar(all history)).
// MAX on the legacy side visits every remaining row so malformed values cannot
// disappear behind a LIMIT. Embedded by Stats in the same database snapshot.
func latestLedgerTimeSQL(ledger submissionLedger) string {
	d := submissionLedgers[ledger]
	return "SELECT MAX(exact_time) FROM (SELECT CASE WHEN " + d.key + "=shardlure_time_key(" + d.timestamp + ") THEN " + d.key +
		" ELSE shardlure_time_key(NULL) END AS exact_time FROM (SELECT " + d.timestamp + "," + d.key + " FROM " + d.table +
		" INDEXED BY idx_" + d.prefix + "_time_key WHERE " + d.key + " IS NOT NULL ORDER BY " + d.key + " DESC LIMIT 1)" +
		" UNION ALL SELECT MAX(shardlure_time_key(" + d.timestamp + ")) FROM " + d.table + " INDEXED BY idx_" + d.prefix + "_legacy_time WHERE " + d.key + " IS NULL)"
}
