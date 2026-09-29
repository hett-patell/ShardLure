package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSaveGroupingAndReads(t *testing.T) {
	s := newTestStore(t, "campaigns.db")
	ctx := context.Background()
	now := time.Now().UTC()
	cowrieEvent(t, s, "s1", "cowrie:a", "command", injector, "", "", now)
	cowrieEvent(t, s, "s2", "cowrie:b", "command", injector, "", "", now)
	if _, err := s.RecordCampaignEvidence(ctx, 1000); err != nil {
		t.Fatal(err)
	}
	ev, err := s.CampaignEvidenceRows(ctx)
	if err != nil || len(ev) != 2 || ev[0].SizeBytes != -1 || ev[0].SessionID == "" || ev[0].IP == "" {
		t.Fatalf("evidence %+v %v", ev, err)
	}
	row := CampaignRow{ID: "c-0123456789ab", AnchorKind: "ssh_key", AnchorValue: ev[0].Value, SuggestedName: "Outlaw/Dota",
		FirstSeen: now, LastSeen: now, Actors: 2, IPs: 1, Sessions: 2, Kinds: "ssh_key", Search: ev[0].Value,
		Members: []CampaignMemberRow{{ActorID: "cowrie:a", Sessions: 1, IPs: 1, Reasons: `[{"kind":"ssh_key"}]`}, {ActorID: "cowrie:b", Sessions: 1, IPs: 1, Reasons: `[{"kind":"ssh_key"}]`}}}
	assign := []CampaignAssignmentRow{{Kind: "ssh_key", Value: ev[0].Value, CampaignID: row.ID, Seq: 1}}
	if err := s.SaveGrouping(ctx, []CampaignRow{row}, assign, map[string]string{"c-old000000000": row.ID}, 0); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListCampaigns(ctx, 50)
	if err != nil || len(list) != 1 || list[0].Actors != 2 || len(list[0].Kinds) != 1 || list[0].Kinds[0] != "ssh_key" {
		t.Fatalf("list %+v %v", list, err)
	}
	d, err := s.GetCampaign(ctx, "c-old000000000") // resolves through the alias
	if err != nil || d.ID != row.ID || len(d.Members) != 2 {
		t.Fatalf("detail %+v %v", d, err)
	}
	if _, err := s.GetCampaign(ctx, "nope"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing campaign err = %v", err)
	}
	if id, ok, err := s.ResolveCampaignID(ctx, "c-old000000000"); err != nil || !ok || id != row.ID {
		t.Fatalf("resolve %q %v %v", id, ok, err)
	}
	if err := s.AppendCampaignEdit(ctx, row.ID, "rename", "Outlaw", "dashboard"); err != nil {
		t.Fatal(err)
	}
	// A grouping computed before that edit must not overwrite the newer state.
	if err := s.SaveGrouping(ctx, nil, nil, nil, 0); !errors.Is(err, ErrStaleGrouping) {
		t.Fatalf("stale save err = %v", err)
	}
	if cs, err := s.CampaignsForActor(ctx, "cowrie:a"); err != nil || len(cs) != 1 {
		t.Fatalf("for actor %+v %v", cs, err)
	}
}

// An empty campaign ID must never be persisted: fed back as an assignment it
// makes the grouping emit a campaign whose ID is "". Each bad input rejects
// the whole save, leaving the previous grouping intact.
func TestSaveGroupingRejectsEmptyIDs(t *testing.T) {
	s := newTestStore(t, "campaigns-empty.db")
	ctx := context.Background()
	now := time.Now().UTC()
	good := CampaignRow{ID: "c-aaaaaaaaaaaa", FirstSeen: now, LastSeen: now,
		Members: []CampaignMemberRow{{ActorID: "cowrie:a", Reasons: "[]"}}}
	goodAssign := []CampaignAssignmentRow{{Kind: "ssh_key", Value: "k", CampaignID: good.ID, Seq: 1}}
	if err := s.SaveGrouping(ctx, []CampaignRow{good}, goodAssign, nil, 0); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		rows    []CampaignRow
		assign  []CampaignAssignmentRow
		aliases map[string]string
	}{
		"empty campaign id":       {rows: []CampaignRow{{ID: ""}}},
		"empty member actor":      {rows: []CampaignRow{{ID: "c-b", Members: []CampaignMemberRow{{ActorID: ""}}}}},
		"empty assignment target": {assign: []CampaignAssignmentRow{{Kind: "ssh_key", Value: "k2", CampaignID: ""}}},
		"empty assignment kind":   {assign: []CampaignAssignmentRow{{Kind: "", Value: "k2", CampaignID: "c-b"}}},
		"empty assignment value":  {assign: []CampaignAssignmentRow{{Kind: "ssh_key", Value: "", CampaignID: "c-b"}}},
		"empty alias source":      {aliases: map[string]string{"": "c-b"}},
		"empty alias target":      {aliases: map[string]string{"c-x": ""}},
	}
	for name, tc := range cases {
		err := s.SaveGrouping(ctx, tc.rows, tc.assign, tc.aliases, 0)
		if !errors.Is(err, ErrInvalidGrouping) {
			t.Fatalf("%s: err = %v, want ErrInvalidGrouping", name, err)
		}
	}
	list, err := s.ListCampaigns(ctx, 10)
	if err != nil || len(list) != 1 || list[0].ID != good.ID {
		t.Fatalf("previous grouping lost: %+v %v", list, err)
	}
	assign, _, err := s.CampaignIdentity(ctx)
	if err != nil || len(assign) != 1 || assign[0].CampaignID != good.ID {
		t.Fatalf("identity %+v %v", assign, err)
	}
}

// Duplicate keys are rejected before the transaction with ErrInvalidGrouping,
// not left to fail as a primary-key constraint error halfway through the
// replace: Group emits each (kind, value) and campaign ID once, so a duplicate
// means a bug upstream, and the caller must be able to tell that from an I/O
// failure.
func TestSaveGroupingRejectsDuplicates(t *testing.T) {
	s := newTestStore(t, "campaigns-dup.db")
	ctx := context.Background()
	c := CampaignRow{ID: "c-a", Members: []CampaignMemberRow{{ActorID: "cowrie:a", Reasons: "[]"}}}
	cases := map[string]struct {
		rows   []CampaignRow
		assign []CampaignAssignmentRow
	}{
		"duplicate assignment": {rows: []CampaignRow{c}, assign: []CampaignAssignmentRow{
			{Kind: "ssh_key", Value: "k", CampaignID: "c-a", Seq: 1}, {Kind: "ssh_key", Value: "k", CampaignID: "c-b", Seq: 2}}},
		"duplicate campaign": {rows: []CampaignRow{c, {ID: "c-a"}}},
		"duplicate member":   {rows: []CampaignRow{{ID: "c-a", Members: []CampaignMemberRow{{ActorID: "cowrie:a"}, {ActorID: "cowrie:a"}}}}},
	}
	for name, tc := range cases {
		if err := s.SaveGrouping(ctx, tc.rows, tc.assign, nil, 0); !errors.Is(err, ErrInvalidGrouping) {
			t.Fatalf("%s: err = %v, want ErrInvalidGrouping", name, err)
		}
	}
	// Same value under another kind is not a duplicate.
	ok := []CampaignAssignmentRow{{Kind: "ssh_key", Value: "v", CampaignID: "c-a"}, {Kind: "payload", Value: "v", CampaignID: "c-a"}}
	if err := s.SaveGrouping(ctx, []CampaignRow{c}, ok, nil, 0); err != nil {
		t.Fatal(err)
	}
}

// Rows written by anything other than SaveGrouping (an older build, a manual
// repair) could still carry an empty target; the reader drops them.
func TestCampaignIdentitySkipsEmptyIDs(t *testing.T) {
	s := newTestStore(t, "campaigns-identity.db")
	ctx := context.Background()
	for _, q := range []string{
		`INSERT INTO campaign_ids(kind,value,campaign_id,seq) VALUES('ssh_key','k1','',1)`,
		`INSERT INTO campaign_ids(kind,value,campaign_id,seq) VALUES('ssh_key','k2','c-good',2)`,
		`INSERT INTO campaign_aliases(old_id,new_id,created_at) VALUES('c-old','','x')`,
		`INSERT INTO campaign_aliases(old_id,new_id,created_at) VALUES('c-old2','c-good','x')`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	assign, aliases, err := s.CampaignIdentity(ctx)
	if err != nil || len(assign) != 1 || assign[0].CampaignID != "c-good" {
		t.Fatalf("assign %+v %v", assign, err)
	}
	if len(aliases) != 1 || aliases["c-old2"] != "c-good" {
		t.Fatalf("aliases %+v", aliases)
	}
}

// The re-stamped sequence is what Group computed; an upsert that kept the old
// seq would feed the next run a stale ordering.
func TestSaveGroupingUpdatesAssignmentSeq(t *testing.T) {
	s := newTestStore(t, "campaigns-seq.db")
	ctx := context.Background()
	a := []CampaignAssignmentRow{{Kind: "ssh_key", Value: "k", CampaignID: "c-1", Seq: 1}}
	if err := s.SaveGrouping(ctx, nil, a, nil, 0); err != nil {
		t.Fatal(err)
	}
	a[0].CampaignID, a[0].Seq = "c-2", 7
	if err := s.SaveGrouping(ctx, nil, a, nil, 0); err != nil {
		t.Fatal(err)
	}
	got, _, err := s.CampaignIdentity(ctx)
	if err != nil || len(got) != 1 || got[0].CampaignID != "c-2" || got[0].Seq != 7 {
		t.Fatalf("identity %+v %v", got, err)
	}
}

// An empty name must not match every campaign whose name is still unset.
func TestGetCampaignEmptyLookupIsNotFound(t *testing.T) {
	s := newTestStore(t, "campaigns-blank.db")
	ctx := context.Background()
	if err := s.SaveGrouping(ctx, []CampaignRow{{ID: "c-1"}}, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetCampaign(ctx, "  "); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("blank lookup err = %v", err)
	}
	if d, err := s.GetCampaign(ctx, "c-1"); err != nil || d.ID != "c-1" {
		t.Fatalf("id lookup %+v %v", d, err)
	}
}

// The stale check compares against the newest edit the grouping read, so an
// edit that arrived after the read blocks the save while a save that saw every
// edit goes through.
func TestSaveGroupingAcceptsCurrentEdits(t *testing.T) {
	s := newTestStore(t, "campaigns-edits.db")
	ctx := context.Background()
	if err := s.AppendCampaignEdit(ctx, "c-1", "rename", "X", "cli"); err != nil {
		t.Fatal(err)
	}
	edits, err := s.CampaignEdits(ctx)
	if err != nil || len(edits) != 1 || edits[0].Who != "cli" || edits[0].CreatedAt.IsZero() {
		t.Fatalf("edits %+v %v", edits, err)
	}
	last := edits[0].ID
	if err := s.SaveGrouping(ctx, []CampaignRow{{ID: "c-1"}}, nil, nil, last); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendCampaignEdit(ctx, "c-1", "notes", "n", "cli"); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveGrouping(ctx, nil, nil, nil, last); !errors.Is(err, ErrStaleGrouping) {
		t.Fatalf("stale err = %v", err)
	}
	if list, _ := s.ListCampaigns(ctx, 10); len(list) != 1 {
		t.Fatalf("stale save changed campaigns: %+v", list)
	}
}

func TestScriptAndArtifactReads(t *testing.T) {
	s := newTestStore(t, "campaigns-scripts.db")
	ctx := context.Background()
	ts := formatFixedUTC(time.Now())
	for _, q := range []string{
		`INSERT INTO scripts(fingerprint,normalized,display,command_count,distinctive,family,first_seen,last_seen) VALUES('fp1','n','d',3,1,'fam','` + ts + `','` + ts + `')`,
		`INSERT INTO session_scripts(session_id,actor_id,src_ip,first_seen,last_seen,updated_at,settled_at,fingerprint) VALUES('s1','cowrie:a','203.0.113.7','` + ts + `','` + ts + `','` + ts + `','` + ts + `','fp1')`,
		`INSERT INTO session_scripts(session_id,actor_id,src_ip,first_seen,last_seen,updated_at,fingerprint) VALUES('s2','cowrie:b','203.0.113.8','` + ts + `','` + ts + `','` + ts + `','')`,
		`INSERT INTO script_families(family,display,variants,sessions,actors,ips,command_count,distinctive,links,reason,first_seen,last_seen) VALUES('fam','d','[]',1,1,1,3,1,0,'r','` + ts + `','` + ts + `')`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	occ, err := s.SettledScriptRows(ctx)
	if err != nil || len(occ) != 1 || !occ[0].Distinctive || occ[0].FirstSeen.IsZero() {
		t.Fatalf("occ %+v %v", occ, err)
	}
	fams, err := s.ListScriptFamilies(ctx, 0)
	if err != nil || len(fams) != 1 || !fams[0].Distinctive || fams[0].Links {
		t.Fatalf("families %+v %v", fams, err)
	}
	d, err := s.GetScript(ctx, "fp1")
	if err != nil || d.Family != "fam" || len(d.Sessions) != 1 || len(d.Actors) != 1 {
		t.Fatalf("script %+v %v", d, err)
	}
	if _, err := s.GetScript(ctx, "missing"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing script err = %v", err)
	}
	if _, ok, err := s.ArtifactPathForSHA256(ctx, "00"); err != nil || ok {
		t.Fatalf("artifact path ok=%v err=%v", ok, err)
	}
	if n, err := s.CowrieActorPopulation(ctx, time.Time{}); err != nil || n != 0 {
		t.Fatalf("population %d %v", n, err)
	}
}

// Group was validated against replace semantics: the next run is fed exactly
// the previous Output.Assignments. A value it left unassigned (an attribution
// tie, a floating value in an unemitted component, a purged value) must not
// survive as a stale ownership claim.
func TestSaveGroupingReplacesAssignments(t *testing.T) {
	s := newTestStore(t, "campaigns-replace.db")
	ctx := context.Background()
	a := CampaignAssignmentRow{Kind: "ssh_key", Value: "A", CampaignID: "c-1", Seq: 1}
	b := CampaignAssignmentRow{Kind: "ssh_key", Value: "B", CampaignID: "c-1", Seq: 2}
	if err := s.SaveGrouping(ctx, nil, []CampaignAssignmentRow{a, b}, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveGrouping(ctx, nil, []CampaignAssignmentRow{a}, nil, 0); err != nil {
		t.Fatal(err)
	}
	got, _, err := s.CampaignIdentity(ctx)
	if err != nil || len(got) != 1 || got[0].Value != "A" {
		t.Fatalf("identity %+v %v", got, err)
	}
}

// Edits are filtered to the campaign's own ID and every alias that resolves
// to it (including chains), never another campaign's.
func TestGetCampaignEditsFollowAliases(t *testing.T) {
	s := newTestStore(t, "campaigns-edit-alias.db")
	ctx := context.Background()
	aliases := map[string]string{"c-old2": "c-old", "c-old": "c-new", "c-else": "c-other"}
	if err := s.SaveGrouping(ctx, []CampaignRow{{ID: "c-new"}, {ID: "c-other"}}, nil, aliases, 0); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"c-new", "c-old", "c-old2", "c-other", "c-else"} {
		if err := s.AppendCampaignEdit(ctx, id, "notes", id, "cli"); err != nil {
			t.Fatal(err)
		}
	}
	d, err := s.GetCampaign(ctx, "c-old2")
	if err != nil || d.ID != "c-new" {
		t.Fatalf("detail %+v %v", d, err)
	}
	var args []string
	for _, e := range d.Edits {
		args = append(args, e.Arg)
	}
	if len(args) != 3 || args[0] != "c-new" || args[1] != "c-old" || args[2] != "c-old2" {
		t.Fatalf("edits %v", args)
	}
	al, err := s.CampaignAliases(ctx)
	if err != nil || len(al) != 3 {
		t.Fatalf("aliases %+v %v", al, err)
	}
}

// actors.last_seen is formatFixedUTC text; a variable-width RFC3339Nano bound
// misorders an actor seen at exactly `since` (".500000000Z" < ".5Z").
func TestCowrieActorPopulationBoundIsExact(t *testing.T) {
	s := newTestStore(t, "campaigns-pop.db")
	ctx := context.Background()
	at := time.Date(2026, 9, 1, 12, 0, 5, 500_000_000, time.UTC)
	if _, err := s.db.Exec(`INSERT INTO actors(id,source,first_seen,last_seen) VALUES('cowrie:a','cowrie',?,?)`,
		formatFixedUTC(at), formatFixedUTC(at)); err != nil {
		t.Fatal(err)
	}
	if n, err := s.CowrieActorPopulation(ctx, at); err != nil || n != 1 {
		t.Fatalf("population %d %v", n, err)
	}
	if n, err := s.CowrieActorPopulation(ctx, at.Add(time.Nanosecond)); err != nil || n != 0 {
		t.Fatalf("population after %d %v", n, err)
	}
}

// A name or suggested name shared by several campaigns (several "Outlaw/Dota"
// components) must be reported as ambiguous, never resolved to the lowest ID.
func TestGetCampaignAmbiguousNameIsReported(t *testing.T) {
	s := newTestStore(t, "campaigns-ambiguous.db")
	ctx := context.Background()
	rows := []CampaignRow{
		{ID: "c-aaaaaaaaaaa1", SuggestedName: "Outlaw/Dota"},
		{ID: "c-aaaaaaaaaaa2", SuggestedName: "outlaw/dota"},
		{ID: "c-aaaaaaaaaaa3", Name: "Outlaw/Dota"},
		{ID: "c-aaaaaaaaaaa4", Name: "Solo", SuggestedName: "Mirai"},
	}
	if err := s.SaveGrouping(ctx, rows, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	_, err := s.GetCampaign(ctx, "OUTLAW/DOTA")
	var amb *AmbiguousCampaignError
	if !errors.Is(err, ErrAmbiguousCampaign) || !errors.As(err, &amb) {
		t.Fatalf("ambiguous lookup err = %v", err)
	}
	if got := strings.Join(amb.IDs, ","); got != "c-aaaaaaaaaaa1,c-aaaaaaaaaaa2,c-aaaaaaaaaaa3" {
		t.Fatalf("ambiguous IDs = %s", got)
	}
	if d, err := s.GetCampaign(ctx, "solo"); err != nil || d.ID != "c-aaaaaaaaaaa4" {
		t.Fatalf("unique name %+v %v", d.ID, err)
	}
	if d, err := s.GetCampaign(ctx, "mirai"); err != nil || d.ID != "c-aaaaaaaaaaa4" {
		t.Fatalf("unique suggested name %+v %v", d.ID, err)
	}
	// An exact ID always wins, even when it also equals some campaign's name.
	if d, err := s.GetCampaign(ctx, "c-aaaaaaaaaaa1"); err != nil || d.ID != "c-aaaaaaaaaaa1" {
		t.Fatalf("id lookup %+v %v", d.ID, err)
	}
}

// GetCampaign filters edits with campaign_id IN (...); without an index that
// is a scan of the whole never-purged edit history on every detail request.
func TestCampaignEditsIndexed(t *testing.T) {
	s := newTestStore(t, "campaigns-edit-index.db")
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_campaign_edits_campaign' AND tbl_name='campaign_edits'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("index count = %d err = %v", n, err)
	}
}

// campaignAliasTarget walks the stored alias map, which is data: the walk is
// bounded by len(aliases)+1 so a legitimate 70-link chain resolves to its
// root while a corrupt cyclic map still terminates.
func TestCampaignAliasTargetFollowsLongChain(t *testing.T) {
	aliases := map[string]string{}
	for i := 0; i < 70; i++ {
		aliases[fmt.Sprintf("c-%03d", i)] = fmt.Sprintf("c-%03d", i+1)
	}
	if got := campaignAliasTarget(aliases, "c-000"); got != "c-070" {
		t.Fatalf("got %s, want the root c-070", got)
	}
	if campaignAliasTarget(map[string]string{"a": "b", "b": "a"}, "a") == "" {
		t.Fatal("a cyclic map must still terminate")
	}
}

// A detail response is bounded: members, HASSHes, clients and hosts are each
// capped at campaignDetailCap, and the true totals travel with them so the UI
// can say "N of M" instead of presenting a truncated list as complete.
func TestGetCampaignBoundsListsAndReportsTotals(t *testing.T) {
	s := newTestStore(t, "campaigns-bounds.db")
	ctx := context.Background()
	old := campaignDetailCap
	campaignDetailCap = 2
	t.Cleanup(func() { campaignDetailCap = old })
	c := CampaignRow{ID: "c-big"}
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("cowrie:m%d", i)
		c.Members = append(c.Members, CampaignMemberRow{ActorID: id, Reasons: "[]"})
		if _, err := s.db.Exec(`INSERT INTO actors(id,source,primary_ip,hassh,ssh_client,first_seen,last_seen) VALUES(?,?,?,?,?,?,?)`,
			id, "cowrie", "203.0.113.1", fmt.Sprintf("h%d", i), fmt.Sprintf("SSH-2.0-c%d", i), formatFixedUTC(time.Now()), formatFixedUTC(time.Now())); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SaveGrouping(ctx, []CampaignRow{c}, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.ensureArtifactsTable(); err != nil {
		t.Fatal(err)
	}
	// Four URLs, three distinct hosts.
	for i, u := range []string{"http://a.example/x", "http://a.example/y", "http://b.example/x", "http://c.example:8080/x"} {
		if _, err := s.db.Exec(`INSERT INTO artifacts(ts,actor_id,url,origin,status,created_at) VALUES(?,?,?,?,?,?)`,
			formatFixedUTC(time.Now()), fmt.Sprintf("cowrie:m%d", i%3), u, "quarantine_fetch", "fetched", formatFixedUTC(time.Now())); err != nil {
			t.Fatal(err)
		}
	}
	d, err := s.GetCampaign(ctx, "c-big")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Members) != 2 || d.MembersTotal != 3 || len(d.HASSHes) != 2 || d.HASSHesTotal != 3 ||
		len(d.Clients) != 2 || d.ClientsTotal != 3 || len(d.Hosts) != 2 || d.HostsTotal != 3 {
		t.Fatalf("members %d/%d hasshes %d/%d clients %d/%d hosts %v/%d", len(d.Members), d.MembersTotal,
			len(d.HASSHes), d.HASSHesTotal, len(d.Clients), d.ClientsTotal, d.Hosts, d.HostsTotal)
	}
	if d.Hosts[0] != "a.example" || d.Hosts[1] != "b.example" {
		t.Fatalf("hosts must be the first in sort order: %v", d.Hosts)
	}
}

// Every matching ID is reported, with no list cap: the operator needs the
// complete set to pick from.
func TestGetCampaignAmbiguousListsEveryID(t *testing.T) {
	s := newTestStore(t, "campaigns-ambiguous-many.db")
	ctx := context.Background()
	var rows []CampaignRow
	for i := 0; i < 1001; i++ {
		rows = append(rows, CampaignRow{ID: fmt.Sprintf("c-%012d", i), SuggestedName: "Outlaw/Dota"})
	}
	if err := s.SaveGrouping(ctx, rows, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	_, err := s.GetCampaign(ctx, "outlaw/dota")
	var amb *AmbiguousCampaignError
	if !errors.As(err, &amb) || len(amb.IDs) != 1001 || amb.IDs[0] != "c-000000000000" {
		t.Fatalf("err = %v", err)
	}
}

// GetCampaign reads one snapshot. A SaveGrouping that commits between its
// summary and member reads (here it re-keys the campaign away) must not leave
// a detail with the old summary and the new grouping's empty member list
// (store-reads audit Minor 2).
func TestGetCampaignReadsOneSnapshot(t *testing.T) {
	s := newTestStore(t, "campaigns-snapshot.db")
	ctx := context.Background()
	old := CampaignRow{ID: "c-1", Members: []CampaignMemberRow{{ActorID: "cowrie:a", Sessions: 1, IPs: 1, Reasons: "[]"}, {ActorID: "cowrie:b", Sessions: 1, IPs: 1, Reasons: "[]"}}}
	if err := s.SaveGrouping(ctx, []CampaignRow{old}, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	var saveErr error
	getCampaignAfterSummary = func() {
		saveErr = s.SaveGrouping(ctx, []CampaignRow{{ID: "c-2", Members: []CampaignMemberRow{{ActorID: "cowrie:c", Sessions: 1, IPs: 1, Reasons: "[]"}}}}, nil, nil, 0)
	}
	t.Cleanup(func() { getCampaignAfterSummary = nil })
	d, err := s.GetCampaign(ctx, "c-1")
	if saveErr != nil {
		t.Fatalf("concurrent save: %v", saveErr)
	}
	if err != nil || d.ID != "c-1" || len(d.Members) != 2 || d.MembersTotal != 2 {
		t.Fatalf("detail = id %q members %d total %d, %v; want c-1 whole from one snapshot", d.ID, len(d.Members), d.MembersTotal, err)
	}
	getCampaignAfterSummary = nil
	if _, err := s.GetCampaign(ctx, "c-1"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("after the save c-1 = %v, want gone", err)
	}
}
