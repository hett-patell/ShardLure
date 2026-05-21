package actor

import (
	"regexp"
	"strings"
)

var (
	reCNName = regexp.MustCompile(`(?i)^(zhang|chen|wang|li|liu|yang|huang|zhao|wu|zhou|xu|sun|ma|zhu|hu|guo|he|gao|lin|luo|zheng|liang|xie|song|tang|han|feng|yu|dong|wei|ye|shi|weiqq|yaojun|wenshuo)`)
	serviceUsers = map[string]bool{
		"oracle": true, "hadoop": true, "postgres": true, "mysql": true,
		"jenkins": true, "gitlab": true, "ftpuser": true, "redis": true,
	}
	cryptoUsers = map[string]bool{
		"sol": true, "solana": true, "ethereum": true, "miner": true,
	}
)

// ClassifyPlaybook returns a playbook tag from observed usernames and rate.
func ClassifyPlaybook(usernames []string, attemptsPerHour float64) string {
	if len(usernames) == 0 {
		return "unknown"
	}

	cn, svc, crypto, admin, k8s := 0, 0, 0, 0, 0
	for _, u := range usernames {
		lu := strings.ToLower(u)
		if serviceUsers[lu] {
			svc++
		}
		if cryptoUsers[lu] {
			crypto++
		}
		if lu == "admin" || lu == "root" || lu == "user" || lu == "test" {
			admin++
		}
		if strings.Contains(lu, "k8s") || lu == "deploy" || lu == "ci" {
			k8s++
		}
		if reCNName.MatchString(lu) || len(lu) >= 4 && isMostlyLowerAlpha(lu) {
			cn++
		}
	}

	n := float64(len(usernames))
	if attemptsPerHour >= 120 && float64(cn)/n > 0.3 {
		return "fast_dictionary_spray"
	}
	if svc >= 2 && attemptsPerHour < 80 {
		return "service_account_enum"
	}
	// Avoid over-classifying large sprays as crypto campaigns when
	// they only include one incidental "sol/solana" username.
	if crypto >= 2 || (crypto >= 1 && float64(crypto)/n >= 0.15) {
		return "crypto_target"
	}
	if admin >= 2 && attemptsPerHour >= 40 {
		return "default_credential_spray"
	}
	if attemptsPerHour >= 60 {
		return "dictionary_spray"
	}
	return "opportunistic"
}

func isMostlyLowerAlpha(s string) bool {
	if len(s) < 3 {
		return false
	}
	alpha := 0
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || r == '_' {
			alpha++
		}
	}
	return float64(alpha)/float64(len(s)) > 0.85
}

// ClassifyIntent from event mix (cowrie-rich later).
func ClassifyIntent(hasTunnel, hasPayload, hasProbe, hasDeployCmd bool) string {
	if hasProbe && !hasPayload && !hasDeployCmd {
		return "probe"
	}
	if hasTunnel && !hasPayload && !hasDeployCmd {
		return "proxy"
	}
	if hasPayload || hasDeployCmd {
		return "deploy"
	}
	if hasTunnel {
		return "mixed"
	}
	return "unknown"
}
