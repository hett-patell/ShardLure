package abuseipdb

import (
	"net"
	"strconv"
	"strings"
	"time"

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

	// LastSeen is when this attacker was last observed. It is policy input, not
	// payload: Vet needs it to reject dormant IPs (see maxAge below), and
	// Suggest scores recency from it.
	//
	// It does not weaken the anonymity guarantee above — it describes the
	// ATTACKER's activity, like EventCount and AttemptsPerHour already do, and
	// says nothing about this host. Client.Submit builds the wire form field by
	// field from Submission, so no field added here is transmitted implicitly.
	//
	// Zero means "unknown", which Vet hard-rejects: an undateable observation
	// cannot be defended if the report is challenged.
	LastSeen time.Time
}

// VetOptions tightens reporting policy beyond the hard defaults. Mirrors
// bazaar.VetOptions/urlhaus.VetOptions: an operator may only make the gate
// STRICTER, never looser, so a misconfiguration cannot widen what we report.
type VetOptions struct {
	MaxAgeDays int // 1..6 tightens policy; 0, 7, or invalid = hard default (7)
}

const (
	// minEventFloor / minUserFloor keep one-off scans out: a real brute-force
	// actor makes many attempts across several usernames. A single failed
	// login is not report-worthy.
	minEventFloor = 20
	minUserFloor  = 3

	// defaultMaxAgeDays bounds how stale an observation may be and still be
	// reported. AbuseIPDB is a feed of CURRENT threats — a report says "this IP
	// is attacking", present tense — so an IP dormant for weeks is both
	// low-value to the community and an unverifiable claim against its current
	// operator, who may not even be the same party any more.
	//
	// This gate did not exist, and the reporting pool reaches back past the
	// window by design (ActorsForReporting unions in the top actors by LIFETIME
	// rate, so an actor loud once stays visible). With nothing bounding age, the
	// two combined: measured on the reference deployment, all 6 suggested
	// targets were last seen 31-50 days earlier at a windowed rate of 0/h, every
	// one already reported the previous day, while the actor attacking right then
	// (probe 100, ~302k events, 1895 usernames — identified by those figures and
	// not by IP, since it is a HASSH-clustered actor whose primary_ip rotates
	// every few days) was nowhere in the list. 868 of the top 1000 by lifetime
	// rate were dormant more than 7 days.
	//
	// It was not hypothetical. The last batch run before this fix reported 12 IPs,
	// of which 3 had been silent for 29, 16 and 14 days at the moment they were
	// submitted, plus one at 6 days — wrongful reports against the community feed,
	// and the kind of thing an AbuseIPDB account gets struck for. Re-running the
	// same batch through this gate refuses exactly those.
	//
	// 7 days rather than the 24h report window: an operator running the CLI on a
	// weekly cron must still be able to report last weekend's campaign, and an
	// actor pausing a day or two mid-campaign is still current. It is decisively
	// short of the month-old rows that caused this.
	defaultMaxAgeDays = 7
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
// minProbe is the config ProbeScore floor. now is injected for testability.
func Vet(c ReportCandidate, admin *netmatch.Set, minProbe int, now time.Time, opts ...VetOptions) (bool, string) {
	ip := strings.TrimSpace(c.SrcIP)

	maxAgeDays := defaultMaxAgeDays
	if len(opts) > 0 && opts[0].MaxAgeDays > 0 && opts[0].MaxAgeDays < defaultMaxAgeDays {
		maxAgeDays = opts[0].MaxAgeDays
	}

	// --- hard rejects (win over any accept signal) --------------------
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false, "malformed IP"
	}
	if !netmatch.IsPublicIP(parsed) {
		return false, "private/reserved IP — reporting it is an account strike"
	}
	if admin != nil && admin.Has(ip) {
		return false, "admin IP — never report our own operators"
	}
	// Staleness is a hard reject: a report asserts present-tense activity.
	// Checked before the accept signals so no amount of probe score, volume or
	// breadth can carry a dormant IP through.
	if c.LastSeen.IsZero() {
		return false, "no last-seen timestamp — cannot confirm the attack is current"
	}
	if age := now.Sub(c.LastSeen); age > time.Duration(maxAgeDays)*24*time.Hour {
		return false, "last seen " + strconv.Itoa(int(age.Hours()/24)) + "d ago — dormant, " +
			"AbuseIPDB reports must describe current activity"
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
