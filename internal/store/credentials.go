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
		FROM events
		WHERE ts >= ? AND kind IN (`+credentialKindPlaceholders()+`)
		  AND COALESCE(username,'') <> '' AND username <> '?'
		GROUP BY username
		ORDER BY c DESC, username ASC`, since, limit)
}

// TopPasswordsSince ranks distinct passwords by attempts in the window.
func (s *Store) TopPasswordsSince(since time.Time, limit int) ([]CredentialCount, error) {
	return s.credentialCounts(`
		SELECT '', password, COUNT(*) AS c
		FROM events
		WHERE ts >= ? AND kind IN (`+credentialKindPlaceholders()+`)
		  AND COALESCE(password,'') <> ''
		GROUP BY password
		ORDER BY c DESC, password ASC`, since, limit)
}

// TopCombosSince ranks distinct username:password pairs in the window.
func (s *Store) TopCombosSince(since time.Time, limit int) ([]CredentialCount, error) {
	return s.credentialCounts(`
		SELECT username, password, COUNT(*) AS c
		FROM events
		WHERE ts >= ? AND kind IN (`+credentialKindPlaceholders()+`)
		  AND COALESCE(username,'') <> '' AND username <> '?'
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
	args := append([]any{since.UTC().Format(time.RFC3339Nano)}, credentialKinds...)
	var n int
	err := s.db.QueryRow(`
		SELECT COUNT(DISTINCT `+column+`)
		FROM events
		WHERE ts >= ? AND kind IN (`+credentialKindPlaceholders()+`)
		  AND COALESCE(`+column+`,'') <> '' AND `+column+` <> '?'`, args...).Scan(&n)
	return n, err
}

func (s *Store) credentialCounts(query string, since time.Time, limit int) ([]CredentialCount, error) {
	args := append([]any{since.UTC().Format(time.RFC3339Nano)}, credentialKinds...)
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
