package urlhaus

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/netmatch"
)

// URLhaus submission policy (https://urlhaus.abuse.ch/api/, "Submission
// Policy") is enforced HERE, in one place, so both the CLI and any dashboard
// button obey it. Submitting junk gets an abuse.ch account banned, and unlike
// MalwareBazaar a bad URL submission pollutes a dataset other people consume
// as blocklist IOCs — so the bar is deliberately high.
//
// The policy points that map onto honeypot data:
//
//   - ONLY active sites currently serving a payload. We approximate "active
//     and returning 200" with "our SafeFetcher successfully downloaded a
//     payload from it", which is direct first-hand evidence rather than a
//     guess. A failed fetch is proof of the opposite and is rejected.
//   - A payload must be a real file (executable, script, document).
//   - No URL shorteners / pure redirectors.
//   - No adware/PUP, no phishing.
//   - "Automated submissions ... ensure proper URL verification. Please also
//     ensure that you do not submit any private IP addresses (RFC1597) or any
//     IP addresses that are used for any other special purpose (RFC6890)."
//   - Submit the URL "as you see it on the wire".
//
// Like the bazaar gate, hard rejects are evaluated first and always win over
// accept signals.

const (
	// minPayloadBytes floors the payload size. Below this there is no real
	// file behind the URL — empty markers, 1-byte probes, truncated fetches.
	// Matches the bazaar gate's floor for consistency.
	minPayloadBytes = 64

	// defaultActiveDays bounds how long after a successful fetch we still
	// consider a URL "active". URLhaus explicitly does not want dead URLs, and
	// malware-distribution hosts are torn down fast, so anything we last
	// confirmed serving more than this long ago is treated as unproven.
	defaultActiveDays = 3
)

// shortenerHosts are pure redirection services. URLhaus rejects these outright
// because they don't host the payload themselves. Not exhaustive by design —
// it catches the common ones an attacker one-liner actually uses.
var shortenerHosts = map[string]bool{
	"bit.ly": true, "tinyurl.com": true, "goo.gl": true, "t.co": true,
	"ow.ly": true, "is.gd": true, "buff.ly": true, "cutt.ly": true,
	"rb.gy": true, "shorturl.at": true, "rebrand.ly": true, "t.ly": true,
	"tiny.cc": true, "s.id": true, "shorte.st": true, "adf.ly": true,
}

// benignKinds must never be submitted: they are honeypot artefacts or attacker
// key material, not a distributed payload.
var benignKinds = map[string]bool{
	"SSH key": true,
}

// fetchedOrigins are the provenances that mean "we pulled this file from the
// URL ourselves". Only these can prove a URL was serving a payload; the
// cowrie-side origins describe files that arrived by other means (SFTP upload,
// cowrie's own download store) and carry no verified URL.
var fetchedOrigins = map[string]bool{
	"quarantine_fetch": true,
}

// Candidate is one artifact row considered for URL submission.
//
// Deliberately NO SrcIP / SessionID / LocalPath fields: URLhaus needs the URL
// and nothing else, and not carrying honeypot identifiers at all is the
// strongest guarantee that a future tag/comment change cannot leak them. Same
// reasoning as bazaar.Candidate.
type Candidate struct {
	// URL is the attacker-supplied URL exactly as recovered from the session.
	URL string
	// SHA256 of the payload we downloaded from it; empty means we never got
	// a file, which is disqualifying.
	SHA256 string
	// SizeBytes of the downloaded payload.
	SizeBytes int64
	// Origin is the artifact provenance; only quarantine_fetch proves we
	// fetched the URL ourselves.
	Origin string
	// Status is the capture status; only "fetched" proves a 200 + payload.
	Status string
	// FetchedAt is when we last successfully downloaded from this URL. Used
	// for the "still active" window, so the redelivery ts bump keeps
	// long-lived campaigns eligible.
	FetchedAt time.Time
	// FileKind is the classifier's verdict (script / ELF / ...). Used to
	// confirm a real payload and to reject benign content.
	FileKind string
}

// VetOptions holds optional policy overrides.
type VetOptions struct {
	// ActiveDays tightens the "recently confirmed active" window. Values
	// above the default are ignored — callers may only be stricter.
	ActiveDays int
}

// Vet decides whether a single candidate may be submitted to URLhaus.
// Returns (false, reason) to skip. now is injected for testability.
func Vet(c Candidate, now time.Time, opts ...VetOptions) (bool, string) {
	activeDays := defaultActiveDays
	if len(opts) > 0 && opts[0].ActiveDays > 0 && opts[0].ActiveDays < defaultActiveDays {
		activeDays = opts[0].ActiveDays
	}

	// --- hard rejects -------------------------------------------------

	// 1. Must be a real absolute http(s) URL. This also filters the internal
	//    pseudo-keys the capture runner uses for non-URL artifacts
	//    ("cowrie-download:<name>", "cowrie-event:<id>", "cowrie-tty:<name>"),
	//    which are dedup keys, not addresses, and would be garbage upstream.
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil {
		return false, "unparseable URL"
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false, "not an http(s) URL"
	}
	if u.Host == "" {
		return false, "URL has no host"
	}

	// 2. Provenance: we must have fetched it ourselves.
	if !fetchedOrigins[c.Origin] {
		return false, "not a URL we fetched (origin " + c.Origin + ")"
	}

	// 3. Proof it was serving: a successful fetch with a real payload.
	if c.Status != "fetched" {
		return false, "fetch did not succeed (status " + c.Status + ") — URL was not serving a payload"
	}
	if c.SHA256 == "" {
		return false, "no payload hash — nothing was downloaded"
	}
	if c.SizeBytes < minPayloadBytes {
		return false, "payload too small to be a real file"
	}

	// 4. Benign content is never a malware distribution site.
	if benignKinds[c.FileKind] {
		return false, "benign content (" + c.FileKind + ")"
	}

	// 5. Private / reserved / special-purpose addresses. Explicitly required
	//    by the submission policy for automated submitters (RFC1597/RFC6890),
	//    and also stops us publishing a link to a host inside our own network.
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		// netmatch.IsPublicIP is the ONE conservative definition of "public"
		// shared with the capture fetcher and the AbuseIPDB gate. Do not
		// hand-roll this: it covers RFC6890 special-use blocks a naive check
		// misses (AS112, NAT64, 6to4, IETF protocol assignments, benchmarking,
		// documentation), which is exactly what URLhaus's automated-submission
		// policy forbids.
		if !netmatch.IsPublicIP(ip) {
			return false, "private or special-purpose IP address"
		}
	} else if !isSubmittableHostname(host) {
		return false, "non-public hostname"
	}

	// 6. Pure redirectors host no payload.
	if shortenerHosts[strings.ToLower(strings.TrimPrefix(host, "www."))] {
		return false, "URL shortener / redirector, not a payload host"
	}

	// 7. Still active. URLhaus does not want dead URLs.
	if c.FetchedAt.IsZero() {
		return false, "unknown fetch time — cannot confirm the URL is still active"
	}
	if age := now.Sub(c.FetchedAt); age > time.Duration(activeDays)*24*time.Hour {
		return false, fmt.Sprintf("last confirmed serving %s ago (>%dd) — may be offline", age.Round(time.Hour), activeDays)
	}
	// A fetch timestamp in the future means clock skew; refuse rather than
	// submit something we can't reason about.
	if c.FetchedAt.After(now.Add(1 * time.Hour)) {
		return false, "fetch time is in the future (clock skew?)"
	}

	// --- accept -------------------------------------------------------
	// We downloaded a non-benign file of known shape from a public host that
	// returned it within the active window. That is exactly "an active site
	// distributing malware", verified first-hand.
	if c.FileKind == "" || c.FileKind == "unknown" {
		// We have bytes but no idea what they are. Payload definition requires
		// a file that harms once executed; an unclassifiable blob doesn't meet
		// the bar, so stay out of the dataset.
		return false, "payload shape unrecognised — cannot confirm it is malware"
	}
	return true, ""
}

// isSubmittableHostname rejects names that can't be a public payload host:
// bare hostnames with no dot (intranet names), localhost, and .local/.internal
// style private suffixes.
func isSubmittableHostname(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "" || h == "localhost" {
		return false
	}
	if !strings.Contains(h, ".") {
		return false
	}
	for _, suffix := range []string{".local", ".internal", ".localdomain", ".lan", ".home", ".corp", ".test", ".invalid", ".example", ".onion"} {
		if strings.HasSuffix(h, suffix) {
			return false
		}
	}
	return true
}
