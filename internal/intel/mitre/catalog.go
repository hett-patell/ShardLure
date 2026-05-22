// Package mitre maps ShardLure events into MITRE ATT&CK techniques.
//
// The mapping is intentionally narrow: only the techniques an SSH
// honeypot can plausibly observe are catalogued, so the coverage grid
// stays honest. If you add a new EventKind or capture a new artefact
// type, append a matcher to defaultCatalog instead of guessing from
// outside the catalogue.
package mitre

import (
	"regexp"
	"strings"

	"github.com/networkshard/shardlure/pkg/models"
)

// Tactic is the column on the ATT&CK grid (Initial Access, Execution, …).
// We keep these as plain strings rather than enums so they can be passed
// straight through to JSON / HTML.
type Tactic string

const (
	TacticInitialAccess    Tactic = "initial-access"
	TacticExecution        Tactic = "execution"
	TacticPersistence      Tactic = "persistence"
	TacticPrivEsc          Tactic = "privilege-escalation"
	TacticDefenseEvasion   Tactic = "defense-evasion"
	TacticCredentialAccess Tactic = "credential-access"
	TacticDiscovery        Tactic = "discovery"
	TacticLateralMovement  Tactic = "lateral-movement"
	TacticCommandControl   Tactic = "command-and-control"
	TacticImpact           Tactic = "impact"
)

// AllTactics returns tactics in the canonical ATT&CK left-to-right order.
// The dashboard renders columns in this exact order.
func AllTactics() []Tactic {
	return []Tactic{
		TacticInitialAccess,
		TacticExecution,
		TacticPersistence,
		TacticPrivEsc,
		TacticDefenseEvasion,
		TacticCredentialAccess,
		TacticDiscovery,
		TacticLateralMovement,
		TacticCommandControl,
		TacticImpact,
	}
}

// Technique describes one cell on the grid.
type Technique struct {
	ID       string // e.g. "T1110.001"
	Name     string
	Tactic   Tactic
	URL      string // MITRE reference, optional
	matchers []matcher
}

// matcher returns true when an event maps to a given technique. The two
// most common patterns are kind-based (cheap O(1) map lookup) and
// command-substring/regex (only evaluated when the event has a non-empty
// Command). Keeping both in one struct lets the classifier walk the
// catalogue once per event.
type matcher struct {
	kinds    map[models.EventKind]struct{}
	substr   []string         // any of (lowercased substring on cmd)
	rx       []*regexp.Regexp // any of (full command)
	allowAll bool             // matches every event, used for connect baseline
}

func techniques() []Technique {
	return defaultCatalog
}

// defaultCatalog is the static knowledge base. Keep it deterministic and
// alphabetically grouped by tactic so PR diffs read cleanly.
var defaultCatalog = []Technique{
	// -------- Initial Access --------
	{
		ID: "T1078", Name: "Valid Accounts", Tactic: TacticInitialAccess,
		URL:      "https://attack.mitre.org/techniques/T1078/",
		matchers: []matcher{{kinds: kindSet(models.KindAccepted)}},
	},
	{
		ID: "T1133", Name: "External Remote Services", Tactic: TacticInitialAccess,
		URL:      "https://attack.mitre.org/techniques/T1133/",
		matchers: []matcher{{kinds: kindSet(models.KindConnect)}},
	},

	// -------- Execution --------
	{
		ID: "T1059.004", Name: "Unix Shell", Tactic: TacticExecution,
		URL:      "https://attack.mitre.org/techniques/T1059/004/",
		matchers: []matcher{{kinds: kindSet(models.KindCommand)}},
	},

	// -------- Persistence --------
	{
		ID: "T1053.003", Name: "Cron", Tactic: TacticPersistence,
		URL: "https://attack.mitre.org/techniques/T1053/003/",
		matchers: []matcher{{
			substr: []string{"crontab", "/etc/cron", "/var/spool/cron"},
		}},
	},
	{
		ID: "T1098.004", Name: "SSH Authorized Keys", Tactic: TacticPersistence,
		URL: "https://attack.mitre.org/techniques/T1098/004/",
		matchers: []matcher{{
			substr: []string{"authorized_keys", ".ssh/authorized"},
		}},
	},

	// -------- Defense Evasion --------
	{
		ID: "T1070.003", Name: "Clear Command History", Tactic: TacticDefenseEvasion,
		URL: "https://attack.mitre.org/techniques/T1070/003/",
		matchers: []matcher{{
			substr: []string{"history -c", ".bash_history", "unset histfile"},
		}},
	},
	{
		ID: "T1562", Name: "Impair Defenses", Tactic: TacticDefenseEvasion,
		URL: "https://attack.mitre.org/techniques/T1562/",
		matchers: []matcher{{
			substr: []string{"iptables -f", "ufw disable", "systemctl stop fail2ban", "chattr -i", "chattr +i"},
		}},
	},

	// -------- Credential Access --------
	{
		ID: "T1110.001", Name: "Password Brute Force", Tactic: TacticCredentialAccess,
		URL:      "https://attack.mitre.org/techniques/T1110/001/",
		matchers: []matcher{{kinds: kindSet(models.KindFailedPass, models.KindInvalidUser)}},
	},
	{
		ID: "T1110.002", Name: "Public-key Brute Force", Tactic: TacticCredentialAccess,
		URL:      "https://attack.mitre.org/techniques/T1110/002/",
		matchers: []matcher{{kinds: kindSet(models.KindFailedKey)}},
	},

	// -------- Discovery --------
	{
		ID: "T1033", Name: "System Owner / User", Tactic: TacticDiscovery,
		URL: "https://attack.mitre.org/techniques/T1033/",
		matchers: []matcher{{
			rx: []*regexp.Regexp{regexp.MustCompile(`(?i)\b(whoami|id|who|w)\b`)},
		}},
	},
	{
		ID: "T1046", Name: "Network Service Discovery", Tactic: TacticDiscovery,
		URL: "https://attack.mitre.org/techniques/T1046/",
		matchers: []matcher{{
			substr: []string{"netstat", "nmap", " ss -", "ss -t", "ss -l"},
		}},
	},
	{
		ID: "T1082", Name: "System Information Discovery", Tactic: TacticDiscovery,
		URL: "https://attack.mitre.org/techniques/T1082/",
		matchers: []matcher{{
			substr: []string{"uname", "/proc/cpuinfo", "/proc/meminfo", "lscpu", "lsb_release", "cat /etc/os-release", "cat /etc/issue"},
		}},
	},
	{
		ID: "T1083", Name: "File and Directory Discovery", Tactic: TacticDiscovery,
		URL: "https://attack.mitre.org/techniques/T1083/",
		matchers: []matcher{{
			rx: []*regexp.Regexp{regexp.MustCompile(`(?i)(^|[\s;|&])(ls|find|pwd|dir)\b`)},
		}},
	},
	{
		ID: "T1087", Name: "Account Discovery", Tactic: TacticDiscovery,
		URL: "https://attack.mitre.org/techniques/T1087/",
		matchers: []matcher{{
			substr: []string{"/etc/passwd", "/etc/shadow", "getent passwd", "compgen -u"},
		}},
	},

	// -------- Command and Control --------
	{
		ID: "T1071.004", Name: "DNS", Tactic: TacticCommandControl,
		URL: "https://attack.mitre.org/techniques/T1071/004/",
		matchers: []matcher{{
			substr: []string{"nslookup ", "dig ", "host ", "getent hosts"},
		}},
	},
	{
		ID: "T1105", Name: "Ingress Tool Transfer", Tactic: TacticCommandControl,
		URL: "https://attack.mitre.org/techniques/T1105/",
		matchers: []matcher{
			{kinds: kindSet(models.KindFileDown, models.KindFileUp)},
			{rx: []*regexp.Regexp{regexp.MustCompile(`(?i)\b(wget|curl|tftp|ftpget|scp|rsync)\b`)}},
		},
	},
	{
		ID: "T1571", Name: "Non-Standard Port", Tactic: TacticCommandControl,
		URL: "https://attack.mitre.org/techniques/T1571/",
		matchers: []matcher{{
			rx: []*regexp.Regexp{regexp.MustCompile(`/dev/tcp/[^/\s]+/(\d+)`)},
		}},
	},

	// -------- Impact --------
	{
		ID: "T1496", Name: "Resource Hijacking", Tactic: TacticImpact,
		URL: "https://attack.mitre.org/techniques/T1496/",
		matchers: []matcher{{
			substr: []string{"xmrig", "cgminer", "minerd", "kdevtmpfsi", "monero", "stratum+tcp"},
		}},
	},
	{
		ID: "T1486", Name: "Data Encrypted for Impact", Tactic: TacticImpact,
		URL: "https://attack.mitre.org/techniques/T1486/",
		matchers: []matcher{{
			substr: []string{"openssl enc -aes", ".locked", "ransom"},
		}},
	},
}

func kindSet(ks ...models.EventKind) map[models.EventKind]struct{} {
	out := make(map[models.EventKind]struct{}, len(ks))
	for _, k := range ks {
		out[k] = struct{}{}
	}
	return out
}

// match returns true if the event satisfies any of the matchers attached
// to a Technique. The two cheap paths (kind and substring) run first.
func (t Technique) match(e *models.Event) bool {
	cmd := strings.ToLower(e.Command)
	for _, m := range t.matchers {
		if m.allowAll {
			return true
		}
		if len(m.kinds) > 0 {
			if _, ok := m.kinds[e.Kind]; ok {
				return true
			}
		}
		if cmd != "" {
			for _, s := range m.substr {
				if strings.Contains(cmd, s) {
					return true
				}
			}
			for _, rx := range m.rx {
				if rx.MatchString(cmd) {
					return true
				}
			}
		}
	}
	return false
}
