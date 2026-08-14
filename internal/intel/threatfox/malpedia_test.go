package threatfox

import "testing"

// TestMalpediaLabelStrictMapping pins the exact verified map. These four labels
// were confirmed against the live ThreatFox API + the 3,855-entry malware_list
// on 2026-08-14; the test freezes them so a typo or a well-meaning "add more
// families" edit that introduces an UNVERIFIED label fails here rather than
// silently submitting junk that bans the shared abuse.ch account.
func TestMalpediaLabelStrictMapping(t *testing.T) {
	want := map[string]string{
		"mirai":   "elf.mirai",
		"gafgyt":  "elf.bashlite", // NOT elf.gafgyt — that label does not exist in Malpedia
		"redtail": "elf.redtail",
		"xmrig":   "elf.xmrig",
	}
	for fam, label := range want {
		got, ok := MalpediaLabel(fam)
		if !ok {
			t.Errorf("MalpediaLabel(%q) not ok — a verified family lost its label", fam)
			continue
		}
		if got != label {
			t.Errorf("MalpediaLabel(%q) = %q, want %q", fam, got, label)
		}
	}
	// Case/space-insensitive on the family name (the classifier may emit any case).
	if got, ok := MalpediaLabel("  MIRAI "); !ok || got != "elf.mirai" {
		t.Errorf("MalpediaLabel is not case/space-insensitive: got %q ok=%v", got, ok)
	}
}

// TestMalpediaLabelDropsUnverifiedFamilies is the strict-safety half: families
// the classifier CAN emit but which have no confident Malpedia label must be
// unsubmittable (ok=false), never mapped to a guess. gafgyt's absence of an
// elf.gafgyt label is the cautionary case — a naive map would have used it and
// been rejected upstream.
func TestMalpediaLabelDropsUnverifiedFamilies(t *testing.T) {
	// ShardLure-internal names with no Malpedia entry, and generic buckets that
	// get_label resolves to many unrelated families (a guess = junk).
	for _, fam := range []string{
		"komari", "c3pool", "traffmonetizer", "proxyware",
		"botnet", "miner", "coinminer",
		"", "unknown", "elf.gafgyt", "nonsense",
	} {
		if label, ok := MalpediaLabel(fam); ok {
			t.Errorf("MalpediaLabel(%q) resolved to %q, but this family has NO confident "+
				"Malpedia label and must be unsubmittable — a wrong label bans the shared "+
				"abuse.ch account", fam, label)
		}
	}
}
