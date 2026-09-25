package store

import (
	"strings"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// Credential frequency counts, aggregated in SQL.
//
// # WHY THIS IS NOT DONE IN GO OVER A WINDOW OF EVENTS
//
// The wordlist panel used to fetch the window's events and count them in
// memory. That fetch is deliberately capped (defaultWindowEventCap, 200k) to
// keep a poll path from materialising hundreds of MB, so on any deployment with
// more events than the cap the wordlist silently described a SAMPLE while
// presenting itself as the window total. Measured on a 30-day window holding
// 533,647 events:
//
//	root      shown 20,623   actual 51,967   (60% low)
//	admin     shown  4,211   actual 10,311   (59% low)
//	distinct usernames shown 3,800, actual 7,203 - 47% of the vocabulary missing
//
// For a panel whose entire purpose is credential COVERAGE, missing half the
// distinct values is not a rounding error. Counting is exactly what a database
// is for: this is an indexed aggregate over the same window that returns exact
// totals, reads no event bodies, and allocates one row per distinct value
// instead of one struct per event.
//
// Kinds mirror wordlist.isCredentialEvent - the authentication events that
// actually carry a credential. Keep the two in step.
var credentialKinds = []any{
	string(models.KindFailedPass),
	string(models.KindFailedKey),
	string(models.KindInvalidUser),
	string(models.KindAccepted),
}

// CredentialCount is one ranked credential observation.
type CredentialCount struct {
	Username string
	Password string
	Count    int
}

func credentialKindPlaceholders() string {
	return strings.TrimSuffix(strings.Repeat("?,", len(credentialKinds)), ",")
}

// TopUsernamesSince ranks distinct usernames by attempts in the window.
// limit <= 0 returns every distinct value, which is what a wordlist download
// wants; the JSON preview passes a limit.
func (s *Store) TopUsernamesSince(since time.Time, limit int) ([]CredentialCount, error) {
	return s.credentialCounts(`
		SELECT username, '', COUNT(*) AS c
		FROM credential_events
		WHERE COALESCE(username,'') <> '' AND username <> '?'
		GROUP BY username
		ORDER BY c DESC, username ASC`, since, limit)
}

// TopPasswordsSince ranks distinct passwords by attempts in the window.
func (s *Store) TopPasswordsSince(since time.Time, limit int) ([]CredentialCount, error) {
	return s.credentialCounts(`
		SELECT '', password, COUNT(*) AS c
		FROM credential_events
		WHERE COALESCE(password,'') <> ''
		GROUP BY password
		ORDER BY c DESC, password ASC`, since, limit)
}

// TopCombosSince ranks distinct username:password pairs in the window.
func (s *Store) TopCombosSince(since time.Time, limit int) ([]CredentialCount, error) {
	return s.credentialCounts(`
		SELECT username, password, COUNT(*) AS c
		FROM credential_events
		WHERE COALESCE(username,'') <> '' AND username <> '?'
		  AND COALESCE(password,'') <> ''
		GROUP BY username, password
		ORDER BY c DESC, username ASC, password ASC`, since, limit)
}

// DistinctCredentialCount is the true number of distinct values in the window,
// so the UI can report coverage without materialising the whole list.
func (s *Store) DistinctCredentialCount(column string, since time.Time) (int, error) {
	// Whitelisted, never interpolated from user input: the column name cannot be
	// parameterised and this is the only place it is chosen.
	switch column {
	case "username", "password":
	default:
		return 0, nil
	}
	window, args := credentialWindowQuery(since)
	filter := "COALESCE(" + column + ",'') <> ''"
	if column == "username" {
		// '?' represents an unknown username, but is a literal password in
		// TopPasswordsSince/TopCombosSince. The total must count that same pool.
		filter += " AND username <> '?'"
	}
	var n int
	err := s.db.QueryRow(window+`
		SELECT COUNT(DISTINCT `+column+`)
		FROM credential_events
		WHERE `+filter, args...).Scan(&n)
	return n, err
}

// Count in SQLite without materializing events. Both sides of the migration
// share an exact instant boundary, including a whole-second cutoff.
func credentialWindowQuery(since time.Time) (string, []any) {
	query, args := globalEventTimeBranches("username,password", &since,
		"kind IN ("+credentialKindPlaceholders()+")", credentialKinds)
	return "WITH credential_events AS (" + query + ") ", args
}

func (s *Store) credentialCounts(query string, since time.Time, limit int) ([]CredentialCount, error) {
	window, args := credentialWindowQuery(since)
	query = window + query
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CredentialCount
	for rows.Next() {
		var c CredentialCount
		if err := rows.Scan(&c.Username, &c.Password, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
