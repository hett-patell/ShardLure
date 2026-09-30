package main

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
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

// The IDs printed are exactly the store's matches (errors.As on
// *store.AmbiguousCampaignError), not a second, capped lookup: the old
// helper read only the 1,000 newest campaigns, so the oldest match here was
// missing from the list the operator was told to pick from.
func TestShowCampaignAmbiguousListsEveryStoreMatch(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "many.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	base := time.Now().UTC().Add(-2000 * time.Hour)
	var rows []store.CampaignRow
	for i := 0; i < 1001; i++ {
		at := base.Add(time.Duration(i) * time.Hour)
		rows = append(rows, store.CampaignRow{ID: fmt.Sprintf("c-%012d", i), SuggestedName: "Outlaw/Dota", FirstSeen: at, LastSeen: at})
	}
	if err := st.SaveGrouping(ctx, rows, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	err = showCampaign(ctx, st, &b, []string{"show", "outlaw/dota"})
	if err == nil || strings.Count(err.Error(), "c-") != 1001 || !strings.Contains(err.Error(), "c-000000000000") {
		n := 0
		if err != nil {
			n = strings.Count(err.Error(), "c-")
		}
		t.Fatalf("ambiguous error lists %d IDs (want 1001, including the oldest)", n)
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

func TestValidateListLimit(t *testing.T) {
	for _, n := range []int{1, 50, 1000} {
		if err := validateListLimit(n); err != nil {
			t.Errorf("limit %d rejected: %v", n, err)
		}
	}
	// The store silently substitutes 200 for these; the CLI must refuse.
	for _, n := range []int{0, -1, 1001, 5000} {
		err := validateListLimit(n)
		if err == nil || !strings.Contains(err.Error(), "--limit must be 1..1000") {
			t.Errorf("limit %d: err=%v, want range error", n, err)
		}
	}
}

// scripts --rebuild is an action: it deletes the stored normaliser version,
// says a restart is needed, and refuses list flags and stray arguments.
func TestScriptsRebuild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rebuild.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err := st.ResetScriptsForVersion(ctx, 3); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	versionRows := func() int {
		var n int
		if err := raw.QueryRow(`SELECT COUNT(*) FROM ingest_state WHERE source='script_version' AND path='normaliser'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if versionRows() != 1 {
		t.Fatal("precondition: a stored normaliser version")
	}
	var b bytes.Buffer
	if err := runScripts(ctx, st, []string{"--rebuild"}, &b); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(b.String()); got != scriptRebuildMessage ||
		!strings.Contains(got, "every shardlure live and web process") || !strings.Contains(got, "campaign names and IDs are kept") {
		t.Fatalf("output %q", got)
	}
	// The version row is gone: the next worker start sees "no version stored".
	if n := versionRows(); n != 0 {
		t.Fatalf("version row still stored (%d)", n)
	}
	if _, err := st.ResetScriptsForVersion(ctx, 3); err != nil || versionRows() != 1 {
		t.Fatalf("version not re-stored: %v", err)
	}
	for _, args := range [][]string{
		{"--rebuild", "--limit=5"},
		{"--limit=50", "--rebuild"},
		{"--rebuild", "now"},
		{"extra"},
		{"--rebuild=maybe"},
	} {
		b.Reset()
		if err := runScripts(ctx, st, args, &b); err == nil {
			t.Errorf("%v accepted: %q", args, b.String())
		}
		if strings.Contains(b.String(), "rebuild requested") {
			t.Errorf("%v requested a rebuild while refusing", args)
		}
	}
	b.Reset()
	if err := runScripts(ctx, st, []string{"--limit=5"}, &b); err != nil || !strings.Contains(b.String(), "FAMILY") {
		t.Fatalf("listing still works: %v %q", err, b.String())
	}
}

// GetCampaign caps each list at campaignDetailCap but returns the true
// totals; campaign show must disclose "N of M" wherever it prints fewer than
// the total, never a silently cut list (audit I2).
func TestWriteCampaignDisclosesTruncatedLists(t *testing.T) {
	members := make([]store.CampaignMemberDetail, 500)
	for i := range members {
		members[i] = store.CampaignMemberDetail{ActorID: fmt.Sprintf("cowrie:%03d", i)}
	}
	var b bytes.Buffer
	writeCampaign(&b, store.CampaignDetail{
		CampaignSummary: store.CampaignSummary{ID: "c-1", Actors: 600},
		Members:         members, MembersTotal: 600,
		HASSHes: []string{"h1", "h2"}, HASSHesTotal: 7,
		Clients: []string{"SSH-2.0-a"}, ClientsTotal: 3,
		Hosts: []string{"198.51.100.1"}, HostsTotal: 501,
	})
	out := b.String()
	for _, want := range []string{"showing 500 of 600 members", "h1, h2 (showing 2 of 7)", "SSH-2.0-a (showing 1 of 3)", "198.51.100.1 (showing 1 of 501)"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	// A complete list carries no note.
	b.Reset()
	writeCampaign(&b, store.CampaignDetail{
		CampaignSummary: store.CampaignSummary{ID: "c-2"},
		Members:         members[:2], MembersTotal: 2,
		HASSHes: []string{"h1"}, HASSHesTotal: 1,
	})
	if strings.Contains(b.String(), "showing") {
		t.Errorf("complete lists flagged as truncated:\n%s", b.String())
	}
}

// campaign show prints the tail of the edit history the store already
// fetches, escaped: who and arg are operator text that may be pasted from
// attacker bytes (audit M5).
func TestWriteCampaignPrintsRecentEdits(t *testing.T) {
	var edits []store.CampaignEditRow
	for i := range 7 {
		edits = append(edits, store.CampaignEditRow{ID: int64(i + 1), Action: "rename", Arg: fmt.Sprintf("name-%d", i),
			Who: "ops\x1b[31m", CreatedAt: time.Date(2026, 9, 1+i, 12, 0, 0, 0, time.UTC)})
	}
	var b bytes.Buffer
	writeCampaign(&b, store.CampaignDetail{CampaignSummary: store.CampaignSummary{ID: "c-1"}, Edits: edits})
	out := b.String()
	if strings.Contains(out, "\x1b") {
		t.Fatalf("raw ESC in edit history:\n%q", out)
	}
	for _, want := range []string{"EDIT", "name-6", "name-2", `ops\x1b[31m`, "2026-09-07", "showing 5 of 7 edits"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "name-1\n") || strings.Contains(out, "name-0") {
		t.Errorf("older edits beyond the last 5 printed:\n%s", out)
	}
}

// End to end through the store: 501 members, one over campaignDetailCap.
func TestShowCampaignDisclosesStoreCap(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "cap.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	row := store.CampaignRow{ID: "c-000000000501", Name: "Big", FirstSeen: now, LastSeen: now}
	for i := range 501 {
		row.Members = append(row.Members, store.CampaignMemberRow{ActorID: fmt.Sprintf("cowrie:%04d", i), Reasons: "[]"})
	}
	if err := st.SaveGrouping(ctx, []store.CampaignRow{row}, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := showCampaign(ctx, st, &b, []string{"show", "Big"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "(showing 500 of 501 members)") {
		t.Fatalf("store cap not disclosed:\n%s", b.String()[max(0, b.Len()-400):])
	}
}

// campaigns, scripts and actors report a bad flag the same way: the flag
// package prints it once with the usage, exit 2, no second "error:" line;
// --help exits 0; a bad value is an "error:" line, exit 1 (audit M1).
func TestListCommandsReportFlagErrorsOnce(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "f.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	run := map[string]func([]string) error{
		"campaigns": func(a []string) error { return runCampaigns(ctx, st, a, &bytes.Buffer{}) },
		"scripts":   func(a []string) error { return runScripts(ctx, st, a, &bytes.Buffer{}) },
		"actors":    func(a []string) error { _, err := parseActorsArgs(a); return err },
	}
	for name, fn := range run {
		for _, tc := range []struct {
			args   []string
			code   int
			report bool
		}{{[]string{"--bogus"}, 2, false}, {[]string{"-h"}, 0, false}, {[]string{"--limit=-1"}, 1, true}} {
			err := fn(tc.args)
			if err == nil {
				t.Fatalf("%s %v accepted", name, tc.args)
			}
			if code, report := cmdExitStatus(err); code != tc.code || report != tc.report {
				t.Errorf("%s %v: exit %d report=%v, want %d/%v (%v)", name, tc.args, code, report, tc.code, tc.report, err)
			}
		}
	}
}

// Every list command's --limit help states its accepted range, as the
// CLAUDE.md --limit convention requires: scripts -h used to say only "max
// script families to list" while refusing 0 (final audit M2).
func TestListCommandsHelpStatesLimitRange(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	run := map[string]func([]string) error{
		"campaigns": func(a []string) error { return runCampaigns(ctx, st, a, &bytes.Buffer{}) },
		"scripts":   func(a []string) error { return runScripts(ctx, st, a, &bytes.Buffer{}) },
		"actors":    func(a []string) error { _, err := parseActorsArgs(a); return err },
	}
	for name, fn := range run {
		help := captureStderr(t, func() { _ = fn([]string{"-h"}) })
		if !strings.Contains(help, "1..1000") {
			t.Errorf("%s -h does not state the --limit range:\n%s", name, help)
		}
	}
}

// captureStderr returns what fn wrote to os.Stderr, where the flag package
// prints usage. Tests in this package do not run in parallel.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	defer func() { os.Stderr = saved }()
	fn()
	os.Stderr = saved
	w.Close()
	return <-done
}
