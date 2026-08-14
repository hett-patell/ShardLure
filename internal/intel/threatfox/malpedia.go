package threatfox

import "strings"

// Malpedia family labels for ThreatFox's mandatory `malware` submission field.
//
// ThreatFox requires a real Malpedia family label on every submission and bans
// accounts that submit junk — and this is the SAME abuse.ch account that
// carries MalwareBazaar and URLhaus, so a wrong label endangers all three
// channels. Therefore this map is DELIBERATELY tiny: it holds only the families
// ShardLure's classifier (bazaar.Classify) emits that resolve to a single,
// unambiguous Malpedia label, and NOTHING ELSE.
//
// Every entry was verified on 2026-08-14 against the live ThreatFox API
// (`get_label` + the 3,855-entry `malware_list`) using the deployment's
// abuse.ch key:
//
//	mirai   -> elf.mirai      (verified present)
//	gafgyt  -> elf.bashlite   (Malpedia files Gafgyt under Bashlite; elf.gafgyt
//	                           does NOT exist — a naive map would be rejected)
//	redtail -> elf.redtail    (verified present)
//	xmrig   -> elf.xmrig      (verified present)
//
// Families the classifier can emit but which have NO confident Malpedia label
// are intentionally ABSENT and therefore unsubmittable: komari, c3pool,
// traffmonetizer, proxyware (ShardLure-internal names with no Malpedia entry),
// and the generic buckets botnet/miner/coinminer (get_label returns many
// unrelated families — picking one would be a guess, i.e. exactly the junk that
// gets the account banned).
//
// TO ADD A FAMILY: re-verify its label against the live API
// (`{"query":"get_label","malware":"<name>"}` and confirm the label appears in
// `malware_list`) before adding it here. Do not add a guess. malpedia_test.go
// pins the shape of this map and the strict-drop behaviour.
var malpediaLabels = map[string]string{
	"mirai":   "elf.mirai",
	"gafgyt":  "elf.bashlite",
	"redtail": "elf.redtail",
	"xmrig":   "elf.xmrig",
	"mozi":    "elf.mozi",    // verified present in the live malware_list (2026-08-14)
	"tsunami": "elf.tsunami", // verified present; classifier emits "Tsunami"
}

// MalpediaLabel resolves a ShardLure classifier family to its verified Malpedia
// label. ok is false when the family has no confident label — the caller MUST
// then drop the candidate (an unlabelled submission is rejected junk), never
// substitute a generic or guessed value.
func MalpediaLabel(family string) (label string, ok bool) {
	label, ok = malpediaLabels[strings.ToLower(strings.TrimSpace(family))]
	return label, ok
}
