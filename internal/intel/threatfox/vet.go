package threatfox

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/intel/intelutil"
)

// ThreatFox submission policy is enforced HERE, in one place, so both the CLI
// and any dashboard button obey it. abuse.ch says "only submit confirmed /
// vetted IOCs" and BANS accounts that submit junk — and this is the SAME
// account that carries MalwareBazaar and URLhaus, so a ThreatFox ban kills all
// three give-back channels. The bar is therefore at least as strict as the
// urlhaus gate, plus one hard extra requirement ThreatFox imposes that URLhaus
// does not: every submission needs a real Malpedia malware-family label, so a
// candidate whose family we cannot confidently resolve is unsubmittable.
//
// Like the bazaar and urlhaus gates, hard rejects are evaluated first and
// always win over accept signals.

const (
	// minPayloadBytes floors the payload size — below this there is no real
	// file behind the URL. Matches the bazaar/urlhaus floor.
	minPayloadBytes = 64

	// defaultActiveDays bounds how long after a successful fetch we still
	// consider the delivery infrastructure "active". Malware-hosting infra is
	// torn down fast; an old fetch is an unproven IOC.
	defaultActiveDays = 3

	// defaultConfidence is the confidence_level we assign a vetted IOC. We
	// downloaded the payload first-hand and the classifier attributed a family,
	// which is strong but not perfect (family match is heuristic), so we assert
	// high-but-not-certain rather than 100.
	defaultConfidence = 75
)

// benignKinds must never be submitted: honeypot artefacts or attacker key
// material, not a distributed payload. Shared meaning with the urlhaus gate.
var benignKinds = map[string]bool{
	"SSH key": true,
}

// fetchedOrigins are the provenances that mean "we pulled this file from the
// URL ourselves" — first-hand proof the URL served that payload.
var fetchedOrigins = map[string]bool{
	"quarantine_fetch": true,
}

// Candidate is one confirmed-fetch artifact considered for IOC submission.
//
// Deliberately NO SrcIP / SessionID / LocalPath fields: ThreatFox needs the
// indicators and nothing else, and not carrying honeypot identifiers at all is
// the strongest guarantee that a future tag/comment change cannot leak them.
// Same reasoning as bazaar.Candidate / urlhaus.Candidate.
type Candidate struct {
	// URL the attacker supplied and we fetched from.
	URL string
	// SHA256 of the payload we downloaded; empty means we never got a file.
	SHA256 string
	// SizeBytes of the downloaded payload.
	SizeBytes int64
	// Origin provenance; only quarantine_fetch proves we fetched it ourselves.
	Origin string
	// Status; only "fetched" proves a 200 + payload.
	Status string
	// FetchedAt is when we last successfully downloaded from this URL.
	FetchedAt time.Time
	// FileKind is the classifier's shape verdict (ELF / script / SSH key ...).
	FileKind string
	// Family is the classifier's malware-family verdict (mirai / gafgyt / ...).
	// Must resolve to a Malpedia label via MalpediaLabel or the candidate is
	// unsubmittable.
	Family string
}

// IOC is one indicator derived from a vetted candidate, ready for submission.
type IOC struct {
	Value      string // the indicator: a URL, "ip:port", a domain, or a sha256
	Type       string // IOCTypeURL / IOCTypeIPPort / IOCTypeDomain / IOCTypeSHA256
	ThreatType string // ThreatPayloadDelivery or ThreatPayload
}

// VetOptions holds optional policy overrides (may only tighten).
type VetOptions struct {
	// ActiveDays tightens the "recently confirmed active" window. Values above
	// the default are ignored — callers may only be stricter.
	ActiveDays int
}

// Vet decides whether a candidate may be submitted and, if so, returns the set
// of IOCs to submit for it (URL + host + sha256) along with the resolved
// Malpedia malware label. Returns ok=false with a human-readable reason to
// skip. now is injected for testability.
//
// The returned malware label is the caller's proof the family resolved; every
// IOC in the returned slice is submitted with that same label.
func Vet(c Candidate, now time.Time, opts ...VetOptions) (ok bool, malware string, iocs []IOC, reason string) {
	activeDays := defaultActiveDays
	if len(opts) > 0 && opts[0].ActiveDays > 0 && opts[0].ActiveDays < defaultActiveDays {
		activeDays = opts[0].ActiveDays
	}

	// --- hard rejects -------------------------------------------------

	// 1. A real absolute http(s) URL. Also filters the capture runner's
	//    internal pseudo-keys ("cowrie-download:", "cowrie-event:", ...) which
	//    are dedup keys, not addresses.
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil {
		return false, "", nil, "unparseable URL"
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false, "", nil, "not an http(s) URL"
	}
	if u.Host == "" {
		return false, "", nil, "URL has no host"
	}
	if u.User != nil {
		return false, "", nil, "URL contains credentials"
	}
	if p := u.Port(); p != "" {
		n, perr := strconv.Atoi(p)
		if perr != nil || n < 1 || n > 65535 {
			return false, "", nil, "invalid port"
		}
	}

	// 2. Provenance: we must have fetched it ourselves.
	if !fetchedOrigins[c.Origin] {
		return false, "", nil, "not a URL we fetched (origin " + c.Origin + ")"
	}

	// 3. Proof it was serving: a successful fetch with a real payload.
	if c.Status != "fetched" {
		return false, "", nil, "fetch did not succeed (status " + c.Status + ") — nothing served"
	}
	if c.SHA256 == "" {
		return false, "", nil, "no payload hash — nothing was downloaded"
	}
	// The hash becomes a first-class sha256_hash IOC, so it must be a real
	// sha256: exactly 64 hex chars. Production always feeds a machine-generated
	// hex.EncodeToString(sha256.Sum) here, but a submission API is the wrong
	// place to trust that — a malformed hash IOC is junk that risks the shared
	// account, so validate rather than assume.
	if !isSHA256Hex(c.SHA256) {
		return false, "", nil, "payload hash is not a well-formed sha256"
	}
	if c.SizeBytes < minPayloadBytes {
		return false, "", nil, "payload too small to be a real file"
	}

	// 4. Benign content is never malware-delivery infrastructure.
	if benignKinds[c.FileKind] {
		return false, "", nil, "benign content (" + c.FileKind + ")"
	}
	if c.FileKind == "" || c.FileKind == "unknown" {
		return false, "", nil, "payload shape unrecognised — cannot confirm it is malware"
	}

	// 5. Malware family MUST resolve to a Malpedia label. This is the extra
	//    ThreatFox requirement: the `malware` field is mandatory and a wrong or
	//    guessed value is exactly the junk that bans the account. A confirmed
	//    malware file we cannot family-attribute stays out of the dataset.
	label, resolved := MalpediaLabel(c.Family)
	if !resolved {
		fam := strings.TrimSpace(c.Family)
		if fam == "" {
			fam = "unclassified"
		}
		return false, "", nil, "no confident Malpedia label for family " + fam + " — not submittable"
	}

	// 6. Host must be a public payload host. Shared classification with the
	//    urlhaus gate (intelutil): identical private-IP / numeric-shorthand /
	//    hostname / shortener rules, so the two gates can never disagree.
	host := intelutil.HostNormalise(u.Hostname())
	hostKind, hostReason := intelutil.PublicHostKind(host)
	if hostReason != "" {
		return false, "", nil, hostReason
	}

	// 7. Still active. Dead infrastructure is an unproven IOC.
	if c.FetchedAt.IsZero() {
		return false, "", nil, "unknown fetch time — cannot confirm the host is still active"
	}
	if age := now.Sub(c.FetchedAt); age > time.Duration(activeDays)*24*time.Hour {
		return false, "", nil, fmt.Sprintf("last confirmed serving %s ago (>%dd) — may be offline", age.Round(time.Hour), activeDays)
	}
	if c.FetchedAt.After(now.Add(1 * time.Hour)) {
		return false, "", nil, "fetch time is in the future (clock skew?)"
	}

	// --- accept: build the IOC set ------------------------------------
	// The URL served the payload (payload_delivery). Submit the URL "as seen on
	// the wire", matching urlhaus's submit-verbatim rule.
	out := []IOC{
		{Value: cleanURL(u), Type: IOCTypeURL, ThreatType: ThreatPayloadDelivery},
	}
	// The host, as its own payload_delivery IOC: an ip:port for an IP host, a
	// domain for a hostname. hostKind is the shared classifier's verdict.
	switch hostKind {
	case "ip":
		out = append(out, IOC{Value: ipPort(u, host), Type: IOCTypeIPPort, ThreatType: ThreatPayloadDelivery})
	case "domain":
		out = append(out, IOC{Value: host, Type: IOCTypeDomain, ThreatType: ThreatPayloadDelivery})
	}
	// The sample hash, as a payload IOC. sha256 is always present here (checked
	// above) and is first-hand — we hashed the bytes we downloaded.
	out = append(out, IOC{Value: strings.ToLower(c.SHA256), Type: IOCTypeSHA256, ThreatType: ThreatPayload})

	return true, label, out, ""
}

// isSHA256Hex reports whether s is exactly 64 lowercase-or-uppercase hex chars.
// (Vet lowercases the value for the IOC; this just validates the shape.)
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

// cleanURL renders the URL for submission: scheme+host+path+query, no userinfo
// (already rejected) and no fragment (never part of a server request). Keeps
// the address ThreatFox will see aligned with what we fetched.
func cleanURL(u *url.URL) string {
	v := *u
	v.Fragment = ""
	return v.String()
}

// ipPort builds the "ip:port" IOC. ThreatFox's ip:port type wants an explicit
// port; default to the scheme's well-known port when the URL omitted one, so
// the indicator is complete and matches how the payload was actually served.
//
// An IPv6 host MUST be bracketed: "2606:4700::1111" + ":80" would render the
// ambiguous, malformed "2606:4700::1111:80" (the trailing :80 reads as another
// hextet). net.JoinHostPort adds the brackets only when needed, so IPv4 stays
// "1.2.3.4:80" and IPv6 becomes "[2606:4700::1111]:80" — the correct wire form
// for both. Submitting the malformed variant is exactly the junk ThreatFox
// bans an account for.
func ipPort(u *url.URL, host string) string {
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(host, port)
}
