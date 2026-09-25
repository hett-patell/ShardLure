package store

import "regexp"

// legacyGeneratedNote matches exactly the two summaries the actor builder wrote
// into the notes column before v23 gave generated text its own column
// ("%d events, %d usernames" for Cowrie, "%d distinct usernames" for journal
// actors). Nothing moves that legacy text out, and the builder rewrote it on
// every rebuild, so on the audited prod database all 6,716 actors carried one.
var legacyGeneratedNote = regexp.MustCompile(`^(?:[0-9]+ events, [0-9]+ usernames|[0-9]+ distinct usernames)$`)

// isOperatorNote reports whether notes holds human annotation that must keep
// an otherwise-orphaned actor alive. Exact legacy builder output does not:
// treating it as annotation stopped retention from ever removing an orphan.
// Any other text, including text that merely contains a builder phrase, is
// preserved as operator work.
func isOperatorNote(notes string) bool {
	return notes != "" && !legacyGeneratedNote.MatchString(notes)
}
