package actor

import (
	"regexp"
	"strings"
)

// reCNName is a COARSE heuristic, not an identity classifier. It matches
// usernames that share a prefix with extremely common SSH-spray dictionaries
// observed in the wild (predominantly Chinese-origin botnets). It is used
// only as one signal among several to bucket a session into the
// "fast_dictionary_spray" playbook. Treat the playbook label as "this looks
// like a known spray pattern", not as a statement about the operator.
var (
	reCNName     = regexp.MustCompile(`(?i)^(zhang|chen|wang|li|liu|yang|huang|zhao|wu|zhou|xu|sun|ma|zhu|hu|guo|he|gao|lin|luo|zheng|liang|xie|song|tang|han|feng|yu|dong|wei|ye|shi|weiqq|yaojun|wenshuo)`)
	serviceUsers = map[string]bool{
		"oracle": true, "hadoop": true, "postgres": true, "mysql": true,
		"jenkins": true, "gitlab": true, "ftpuser": true, "redis": true,
	}
	cryptoUsers = map[string]bool{
		"sol": true, "solana": true, "ethereum": true, "miner": true,
	}
	// reScannerTool matches the SSH client banners of mass-scanning and
	// internet-survey tooling observed against honeypot port 22. These actors
	// complete the handshake (so Cowrie records connect + client_version) but
	// rarely send a username, so the username-corpus classifier can never label
	// them — measured on the reference deployment as the 74% "unknown" bucket.
	// The banner is the durable fingerprint: it survives IP churn and is
	// near-unique to the tool. Substring (not prefix) match because banners are
	// versioned ("SSH-2.0-libssh_0.9.6", "SSH-2.0-libssh_0.11.1", ...).
	reScannerTool = regexp.MustCompile(`(?i)libssh|libssh2|nmap|zgrab|zmap|masscan|phpseclib|asyncssh|rawpasswordconnectonly|paramiko|openssh-for-windows|ssh-2\.0-go|recon-ng|hydra|medusa|ncrack`)
)

// Playbook classification thresholds (attempts per hour). These come from
// empirical observation of journalctl traces on small VPS honeypots; they
// are deliberately round numbers, not tuned constants. Adjust if your
// deployment sees very different traffic.
const (
	// Sustained rate above this with a high CN-name ratio looks like a
	// commodity dictionary spray.
	playbookFastSprayAPH = 120.0
	// Service-account enumeration is usually quiet & methodical, not loud.
	playbookServiceAccountMaxAPH = 80.0
	// "default credential" spray (admin/root/test/user) needs both volume
	// and at least two of the canonical default usernames.
	playbookDefaultCredAPH = 40.0
	// Anything above this we just call a generic dictionary spray.
	playbookDictionarySprayAPH = 60.0
	// Below 0.30 in the CN-name ratio is "no signal".
	playbookCNRatioThreshold = 0.30
	// Crypto cluster has to be more than incidental.
	playbookCryptoRatioThreshold = 0.15
	// Two or more ops/CI usernames flips us into the ops-target bucket.
	playbookOpsMinHits = 2
)

// ClassifyPlaybook returns a playbook tag from observed usernames and rate.
func ClassifyPlaybook(usernames []string, attemptsPerHour float64) string {
	var features playbookFeatures
	for _, user := range usernames {
		features.add(user)
	}
	return features.classify(attemptsPerHour)
}

// playbookFeatures holds exact username-corpus signals in constant space.
// Callers add each distinct username once, preserving case-sensitive identity
// while matching the same case-insensitive heuristics as ClassifyPlaybook.
type playbookFeatures struct {
	users, cn, svc, crypto, admin, k8s int
}

func (f *playbookFeatures) add(user string) {
	f.users++
	lu := strings.ToLower(user)
	if serviceUsers[lu] {
		f.svc++
	}
	if cryptoUsers[lu] {
		f.crypto++
	}
	if lu == "admin" || lu == "root" || lu == "user" || lu == "test" {
		f.admin++
	}
	if strings.Contains(lu, "k8s") || lu == "deploy" || lu == "ci" {
		f.k8s++
	}
	if reCNName.MatchString(lu) || len(lu) >= 4 && isMostlyLowerAlpha(lu) {
		f.cn++
	}
}

func (f playbookFeatures) classify(attemptsPerHour float64) string {
	if f.users == 0 {
		return "unknown"
	}
	n := float64(f.users)
	if attemptsPerHour >= playbookFastSprayAPH && float64(f.cn)/n > playbookCNRatioThreshold {
		return "fast_dictionary_spray"
	}
	if f.svc >= 2 && attemptsPerHour < playbookServiceAccountMaxAPH {
		return "service_account_enum"
	}
	// Avoid over-classifying large sprays as crypto campaigns when
	// they only include one incidental "sol/solana" username.
	if f.crypto >= 2 || (f.crypto >= 1 && float64(f.crypto)/n >= playbookCryptoRatioThreshold) {
		return "crypto_target"
	}
	// Two or more k8s/deploy/ci-flavoured usernames signal someone
	// hunting CI/CD or container ops accounts rather than blasting
	// stock credentials.
	if f.k8s >= playbookOpsMinHits {
		return "ops_target"
	}
	if f.admin >= 2 && attemptsPerHour >= playbookDefaultCredAPH {
		return "default_credential_spray"
	}
	if attemptsPerHour >= playbookDictionarySprayAPH {
		return "dictionary_spray"
	}
	return "opportunistic"
}

// ClassifyCowriePlaybook classifies a Cowrie actor using the full event mix,
// not just the username corpus. ClassifyPlaybook only ever sees usernames, so
// a handshake-only actor (connect + client_version, no auth attempt) returns
// "unknown" — and on a live honeypot those scanners dominate: measured as 74%
// of all actors (4,110/5,537) because internet-wide scanners complete the SSH
// handshake to fingerprint the service and never send a login. This function
// is the cowrie-specific overlay that recovers them.
//
// Ordering: real login-driven playbooks win (they have usernames and a higher
// signal-to-noise). The handshake-scan label is applied only when there is
// genuinely nothing else — no auth attempt, no command, no payload, no tunnel.
func ClassifyCowriePlaybook(usernames []string, attemptsPerHour float64, sshClient string, hasAuth, hasCommand, hasTunnel, hasPayload bool) string {
	return cowriePlaybook(ClassifyPlaybook(usernames, attemptsPerHour), sshClient, hasAuth, hasCommand, hasTunnel, hasPayload)
}

func cowriePlaybook(corpusPlaybook, sshClient string, hasAuth, hasCommand, hasTunnel, hasPayload bool) string {
	// A real auth attempt or any post-login action means the actor is doing
	// more than scanning — defer to the username-corpus classifier, which has
	// the richer signal for those.
	if hasAuth || hasCommand || hasTunnel || hasPayload {
		return corpusPlaybook
	}

	// Handshake-only. The client banner is the durable fingerprint of the
	// scanner tooling (libssh/Go/ZGrab/Nmap/...), near-unique and IP-stable.
	if reScannerTool.MatchString(sshClient) {
		return "scanner_tool"
	}
	// Handshake completed, no banner match, no auth attempt: a generic
	// internet-wide scan / service fingerprint probe.
	return "handshake_scan"
}

func isMostlyLowerAlpha(s string) bool {
	if len(s) < 3 {
		return false
	}
	alpha, total := 0, 0
	for _, r := range s {
		total++
		if (r >= 'a' && r <= 'z') || r == '_' {
			alpha++
		}
	}
	// Compare rune counts on both sides: len(s) counts bytes, so a multi-byte
	// UTF-8 username would otherwise get an unfairly low ratio.
	return float64(alpha)/float64(total) > 0.85
}

// ClassifyIntent from event mix (cowrie-rich later).
func ClassifyIntent(hasTunnel, hasPayload, hasProbe, hasDeployCmd bool) string {
	if hasTunnel && (hasPayload || hasDeployCmd) {
		return "mixed"
	}
	if hasProbe && !hasPayload && !hasDeployCmd {
		return "probe"
	}
	if hasTunnel && !hasPayload && !hasDeployCmd {
		return "proxy"
	}
	if hasPayload || hasDeployCmd {
		return "deploy"
	}
	return "unknown"
}
