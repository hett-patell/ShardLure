package bazaar

import "time"

// MalwareBazaar submission policy (https://bazaar.abuse.ch/, "Submission
// Policy") is enforced HERE, in one place, so both the CLI `share` command
// and the dashboard upload button obey it — and so nothing benign, junk, or
// stale ever reaches the MB API (repeated violations get an account banned):
//
//   - confirmed malware only (no benign / suspicious files)
//   - adware/PUP is not malware
//   - no samples older than 10 days
//   - no file infectors
//
// The design intent (operator's steer): attackers constantly ship NOVEL
// scripts and binaries, so a known-family signature list alone would miss the
// most valuable captures. Vet therefore confirms maliciousness from
// STRUCTURE and PROVENANCE, not just signatures — while still hard-rejecting
// provably-benign content, junk, and stale samples.

const (
	// minSampleBytes floors sample size. Below this it's control-plane noise
	// (empty markers, 1-byte scp probes, truncated fetches), never a real
	// sample. The archive holds literal 1- and 2-byte "downloads".
	minSampleBytes = 64
	// maxFreshness is MB's hard 10-day rule, measured from first observation.
	maxFreshness = 10 * 24 * time.Hour
)

// malwareTags are tags Classify attaches that, on their own, confirm the file
// is malware (structural or family evidence), independent of provenance.
var malwareTags = map[string]bool{
	"elf": true, "exe": true, // any executable dropped on an SSH honeypot
	"miner": true, "dropper": true, "botnet": true,
	"scanner": true, "proxyware": true, "ransomware": true, "rootkit": true,
}

// fetchedOrigins are provenances that mean "the attacker pulled this into the
// honeypot during a session" (curl|sh, wget, sftp/scp upload). A
// script/binary-shaped file arriving this way is confirmed-malicious by
// provenance even when we recognise no family — this is the novel-threat path.
var fetchedOrigins = map[string]bool{
	"quarantine_fetch":     true,
	"cowrie_download":      true,
	"cowrie_file_download": true,
}

// benignKinds are Classify FileKinds that are NOT malware and must never be
// shipped to MB (they're honeypot bait/artefacts or attacker key material,
// not samples).
var benignKinds = map[string]bool{
	"SSH key": true,
}

// Vet decides whether a single candidate may be submitted to MalwareBazaar.
// Returns (false, reason) to skip. now is injected for testability.
//
// Order matters: hard rejects (policy violations / benign / junk) come first
// and win over any malware signal, then the accept signals are evaluated.
func Vet(c Candidate, cls Classification, now time.Time) (bool, string) {
	// --- hard rejects -------------------------------------------------
	if c.Origin == "cowrie_tty" {
		return false, "tty transcript, not a malware sample"
	}
	if c.SizeBytes < minSampleBytes {
		return false, "too small to be a real sample"
	}
	if benignKinds[cls.FileKind] {
		return false, "benign content (" + cls.FileKind + ")"
	}
	// Freshness: MB rejects samples older than 10 days. Measure from first
	// observation in the honeypot, not artifact-registration time. A zero
	// ObservedAt (unknown) is treated as stale — better to skip than risk a
	// policy strike on a sample we can't date.
	if c.ObservedAt.IsZero() || now.Sub(c.ObservedAt) > maxFreshness {
		return false, "stale: older than MB's 10-day freshness policy"
	}

	// --- confirmed-malware signals (accept if ANY) --------------------
	// 1. Structural / signature: Classify tagged it as an executable, a known
	//    family, or a malware behaviour class.
	if cls.Family != "" {
		return true, ""
	}
	for _, t := range cls.Tags {
		if malwareTags[t] {
			return true, ""
		}
	}
	// 2. Behavioural (novel-threat path): a non-benign file the attacker
	//    FETCHED/UPLOADED during a session. Covers brand-new obfuscated
	//    droppers with no recognisable family — malicious by provenance.
	if fetchedOrigins[c.Origin] && cls.FileKind != "" && cls.FileKind != "unknown" {
		return true, ""
	}

	// Everything else: we can't confirm it's malware. Skip rather than risk
	// shipping a benign/suspicious file.
	return false, "unconfirmed: no structural, family, or provenance malware signal"
}
