package abuseipdb

import (
	"net"
	"strings"

	"github.com/networkshard/shardlure/internal/netmatch"
)

// AbuseIPDB reporting policy is enforced HERE, in one place, so both the CLI
// `report abuseipdb` command and the dashboard "Report" button obey it. The
// discipline mirrors bazaar.Vet: hard-rejects win over any accept signal, and
// nothing gets reported unless it is a CONFIRMED brute-forcer.
//
// Two account-strike risks drive the hard rejects:
//   - reporting your OWN admin IP (a false accusation against yourself), and
//   - reporting a private/reserved/malformed address (AbuseIPDB rejects these
//     and repeated violations get an account flagged).
//
// Both are checked FIRST, defense-in-depth, even though admin IPs never become
// actors upstream (SyncJournalEvent skips them) — the vet must stand alone.

// ReportCandidate is the minimal, deliberately host-anonymous view of an actor
// the report pipeline needs. It carries the offender SrcIP (the whole point)
// plus attack metadata, but NOTHING identifying the honeypot host or session —
// the same guarantee bazaar.Candidate makes by omission.
type ReportCandidate struct {
	SrcIP           string
	Playbook        string
	ProbeScore      int
	EventCount      int
	UniqueUsers     int
	AttemptsPerHour float64
}

const (
	// minEventFloor / minUserFloor keep one-off scans out: a real brute-force
	// actor makes many attempts across several usernames. A single failed
	// login is not report-worthy.
	minEventFloor = 20
	minUserFloor  = 3
)

// brutePlaybook reports whether the actor's playbook label is a brute-force
// pattern. The classifier emits "*_spray" and "*_enum" for credential attacks
// (fast_dictionary_spray, dictionary_spray, default_credential_spray,
// service_account_enum); those are exactly the actors AbuseIPDB categories
// 18/22 describe.
func brutePlaybook(pb string) bool {
	pb = strings.ToLower(strings.TrimSpace(pb))
	return strings.HasSuffix(pb, "_spray") || strings.HasSuffix(pb, "_enum")
}

// Vet decides whether a candidate may be reported to AbuseIPDB. Returns
// (false, reason) to skip. admin may be nil (no admin IPs configured).
// minProbe is the config ProbeScore floor.
func Vet(c ReportCandidate, admin *netmatch.Set, minProbe int) (bool, string) {
	ip := strings.TrimSpace(c.SrcIP)

	// --- hard rejects (win over any accept signal) --------------------
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false, "malformed IP"
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsUnspecified() ||
		parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() ||
		parsed.IsMulticast() || parsed.IsInterfaceLocalMulticast() {
		return false, "private/reserved IP — reporting it is an account strike"
	}
	if admin != nil && admin.Has(ip) {
		return false, "admin IP — never report our own operators"
	}

	// --- confirmed brute-force signals (accept only if ALL hold) ------
	if !brutePlaybook(c.Playbook) {
		return false, "playbook " + c.Playbook + " is not a brute-force pattern"
	}
	if c.ProbeScore < minProbe {
		return false, "probe score below floor"
	}
	if c.EventCount < minEventFloor || c.UniqueUsers < minUserFloor {
		return false, "below event/user floor for a confirmed brute-forcer"
	}
	return true, ""
}
