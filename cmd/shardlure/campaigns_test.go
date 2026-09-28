package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
)

func TestWriteCampaignsAndScripts(t *testing.T) {
	var b bytes.Buffer
	writeCampaigns(&b, []store.CampaignSummary{{ID: "c-0123456789ab", SuggestedName: "Outlaw/Dota", Actors: 3, IPs: 133, Sessions: 162,
		LastSeen: time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC), Kinds: []string{"ssh_key"}}})
	for _, want := range []string{"CAMPAIGN", "c-0123456789ab", "Outlaw/Dota (suggested)", "133", "ssh_key"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q:\n%s", want, b.String())
		}
	}
	b.Reset()
	writeScripts(&b, []store.ScriptFamilyRow{{Family: "abc", Display: "cd ~\nwget <url>", Sessions: 4, Links: true}})
	if !strings.Contains(b.String(), "abc") || !strings.Contains(b.String(), "cd ~") {
		t.Errorf("scripts output:\n%s", b.String())
	}
}

// Script text, key comments, hosts and client versions are attacker bytes.
// Printed raw, an OSC sequence retitles (or worse) the operator's terminal.
func TestCampaignOutputEscapesTerminalControls(t *testing.T) {
	const evil = "\x1b]0;pwned\x07"
	const want = `\x1b]0;pwned\x07`
	var b bytes.Buffer
	writeScripts(&b, []store.ScriptFamilyRow{{Family: "fam" + evil, Display: "echo " + evil + "\nsecond"}})
	writeCampaigns(&b, []store.CampaignSummary{{ID: "c-1", SuggestedName: evil, Kinds: []string{evil}}})
	writeCampaign(&b, store.CampaignDetail{
		CampaignSummary: store.CampaignSummary{ID: "c-1", Name: evil},
		Notes:           evil,
		Members: []store.CampaignMemberDetail{{ActorID: "cowrie:" + evil, PrimaryIP: evil, Playbook: evil,
			Reasons: `[{"kind":"ssh_key","value":"SHA256:x","label":"` + `\u001b]0;pwned\u0007` + `","first_seen":"2026-09-28T00:00:00Z"}]`}},
		HASSHes: []string{evil}, Clients: []string{"SSH-2.0-" + evil}, Hosts: []string{evil},
	})
	out := b.String()
	for _, bad := range []string{"\x1b", "\x07"} {
		if strings.Contains(out, bad) {
			t.Fatalf("raw control byte %q reached the terminal:\n%q", bad, out)
		}
	}
	if n := strings.Count(out, want); n < 10 {
		t.Errorf("escaped form %q appears %d times, want every field escaped:\n%s", want, n, out)
	}
	if !strings.Contains(out, `SHA256:x`) || !strings.Contains(out, "ssh_key") {
		t.Errorf("reason not rendered:\n%s", out)
	}
}

func TestTermSafe(t *testing.T) {
	for in, want := range map[string]string{
		"plain ascii":      "plain ascii",
		"tab\there":        `tab\x09here`,
		"del\x7f":          `del\x7f`,
		"c1\u009b31m":      `c1\u009b31m`,
		"raw c1 \x9b31m":   `raw c1 \x9b31m`, // invalid UTF-8 byte: escaped, never passed through
		"line\nbreak":      `line\x0abreak`,
		"bidi\u202eevil":   `bidi\u202eevil`,
		"unicode ok: café": "unicode ok: café",
	} {
		if got := termSafe(in); got != want {
			t.Errorf("termSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

// Sibling components routinely share a suggested name; the CLI must refuse
// to pick one and point the operator at the IDs instead.
func TestShowCampaignAmbiguousAndUnknown(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	rows := []store.CampaignRow{
		{ID: "c-aaaaaaaaaaaa", SuggestedName: "Outlaw/Dota", FirstSeen: now, LastSeen: now,
			Members: []store.CampaignMemberRow{{ActorID: "cowrie:a", Reasons: "[]"}}},
		{ID: "c-bbbbbbbbbbbb", SuggestedName: "outlaw/dota", FirstSeen: now, LastSeen: now,
			Members: []store.CampaignMemberRow{{ActorID: "cowrie:b", Reasons: "[]"}}},
		{ID: "c-cccccccccccc", Name: "Solo", FirstSeen: now, LastSeen: now,
			Members: []store.CampaignMemberRow{{ActorID: "cowrie:c", Reasons: "[]"}}},
	}
	if err := st.SaveGrouping(ctx, rows, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	err = showCampaign(ctx, st, &b, []string{"show", "Outlaw/Dota"})
	if err == nil || !strings.Contains(err.Error(), "ambiguous") ||
		!strings.Contains(err.Error(), "c-aaaaaaaaaaaa") || !strings.Contains(err.Error(), "c-bbbbbbbbbbbb") {
		t.Fatalf("ambiguous name: err=%v", err)
	}
	if b.Len() != 0 {
		t.Fatalf("ambiguous name printed a campaign:\n%s", b.String())
	}
	if err := showCampaign(ctx, st, &b, []string{"show", "nope"}); err == nil || !strings.Contains(err.Error(), "no such campaign") {
		t.Fatalf("unknown: err=%v", err)
	}
	for _, args := range [][]string{{"show"}, {"show", "Solo", "extra"}, {"list", "Solo"}} {
		if err := showCampaign(ctx, st, &b, args); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("args %q: err=%v, want usage error", args, err)
		}
	}
	if err := showCampaign(ctx, st, &b, []string{"show", "solo"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "c-cccccccccccc") || !strings.Contains(b.String(), "cowrie:c") {
		t.Errorf("detail output:\n%s", b.String())
	}
}
