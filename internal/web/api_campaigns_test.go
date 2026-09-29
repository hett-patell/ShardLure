package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

func campaignServer(t *testing.T) (*Server, *http.ServeMux) {
	t.Helper()
	s, st := hasshTestServer(t)
	mux := http.NewServeMux()
	s.registerCampaignRoutes(mux)
	row := store.CampaignRow{ID: "c-0123456789ab", Actors: 2, Members: []store.CampaignMemberRow{{ActorID: "cowrie:a", Reasons: "[]"}, {ActorID: "cowrie:b", Reasons: "[]"}}}
	if err := st.SaveGrouping(context.Background(), []store.CampaignRow{row}, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	return s, mux
}

func TestCampaignRoutesMethods(t *testing.T) {
	_, mux := campaignServer(t)
	for _, p := range []string{"/api/intel/campaigns", "/api/intel/scripts", "/api/intel/campaign?id=c-0123456789ab"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, p, nil))
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") == "" {
			t.Errorf("POST %s = %d", p, rec.Code)
		}
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d", p, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/intel/campaign/edit", nil))
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodPost {
		t.Errorf("GET edit = %d allow=%q", rec.Code, rec.Header().Get("Allow"))
	}
}

func TestCampaignRoutesRequireTokenWhenSet(t *testing.T) {
	s, _ := hasshTestServer(t)
	if err := s.keys.Set(settings.KeyDashToken, "s3cret"); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.registerCampaignRoutes(mux)
	for _, p := range []string{"/api/intel/campaigns", "/api/intel/campaign?id=c-0123456789ab", "/api/intel/scripts", "/api/intel/script?fp=" + strings.Repeat("a", 64)} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("no token %s = %d", p, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/intel/campaign/edit", strings.NewReader("id=c-0123456789ab&action=rename&arg=x")))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("edit without token = %d", rec.Code)
	}
}

func postCampaignEdit(mux *http.ServeMux, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/intel/campaign/edit", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	return rec
}

func TestCampaignEditValidatesAndWakes(t *testing.T) {
	s, mux := campaignServer(t)
	woke := 0
	s.onCampaignEdit = func() { woke++ }
	post := func(form url.Values) int { return postCampaignEdit(mux, form).Code }
	for _, bad := range []url.Values{
		{"id": {"c-0123456789ab"}, "action": {"drop_table"}},
		{"id": {"c-0123456789ab"}, "action": {"rename"}, "arg": {strings.Repeat("x", 201)}},
		{"id": {"c-0123456789ab"}, "action": {"rename"}, "arg": {"a\nb"}},
		{"id": {"c-0123456789ab"}, "action": {"notes"}, "arg": {strings.Repeat("n", 4001)}},
		{"id": {"c-ffffffffffff"}, "action": {"rename"}, "arg": {"x"}}, // unknown campaign
		{"id": {""}, "action": {"rename"}, "arg": {"x"}},               // empty campaign
		{"action": {"ignore_evidence"}, "arg": {"hassh:abc"}},
		{"action": {"ignore_evidence"}, "arg": {"ssh_key:"}},
		{"action": {"ignore_evidence"}, "arg": {"payload"}},
		{"id": {"c-ffffffffffff"}, "action": {"ignore_evidence"}, "arg": {"payload:" + strings.Repeat("a", 64)}},
		// fix-D M2: the ledger is append-only, so a value no evidence can ever
		// carry would be a permanent no-op row. Each kind has one shape.
		{"action": {"ignore_evidence"}, "arg": {"payload:deadbeef"}},
		{"action": {"ignore_evidence"}, "arg": {"payload:" + strings.Repeat("A", 64)}}, // evidence stores lowercase
		{"action": {"ignore_evidence"}, "arg": {"payload:" + strings.Repeat("a", 65)}},
		{"action": {"ignore_evidence"}, "arg": {"script:" + strings.Repeat("g", 64)}},
		{"action": {"ignore_evidence"}, "arg": {"script:SHA256:" + strings.Repeat("A", 43)}},
		{"action": {"ignore_evidence"}, "arg": {"ssh_key:" + strings.Repeat("a", 64)}},
		{"action": {"ignore_evidence"}, "arg": {"ssh_key:SHA256:" + strings.Repeat("A", 42)}},
		{"action": {"ignore_evidence"}, "arg": {"ssh_key:SHA256:" + strings.Repeat("A", 43) + "="}},
		{"action": {"ignore_evidence"}, "arg": {"ssh_key:sha256:" + strings.Repeat("A", 43)}},
		{"id": {"c-0123456789ab"}, "action": {"merge"}, "arg": {"c-0123456789ab"}},
		{"id": {"c-0123456789ab"}, "action": {"merge"}, "arg": {"c-ffffffffffff"}}, // unknown target
		{"id": {"c-0123456789ab"}, "action": {"merge"}, "arg": {""}},
		{"id": {"c-0123456789ab"}, "action": {"remove_actor"}, "arg": {""}},
	} {
		if c := post(bad); c != http.StatusBadRequest {
			t.Errorf("%v = %d", bad, c)
		}
	}
	if c := post(url.Values{"id": {"c-0123456789ab"}, "action": {"notes"}, "arg": {strings.Repeat("n", 70<<10)}}); c != http.StatusBadRequest {
		t.Errorf("oversized body = %d", c)
	}
	if woke != 0 {
		t.Fatalf("a rejected edit woke the worker %d times", woke)
	}
	if c := post(url.Values{"id": {"c-0123456789ab"}, "action": {"rename"}, "arg": {"Outlaw"}}); c != http.StatusOK || woke != 1 {
		t.Fatalf("valid rename = %d woke=%d", c, woke)
	}
	for _, good := range []url.Values{
		{"id": {"c-0123456789ab"}, "action": {"notes"}, "arg": {"line one\r\nline two"}},
		{"id": {"c-0123456789ab"}, "action": {"remove_actor"}, "arg": {"cowrie:a"}},
		{"action": {"ignore_evidence"}, "arg": {"script:" + strings.Repeat("f", 64)}},
		{"id": {"c-0123456789ab"}, "action": {"ignore_evidence"}, "arg": {"payload:" + strings.Repeat("0a", 32)}},
		{"action": {"ignore_evidence"}, "arg": {"ssh_key:SHA256:MkYY9qiVsFGBC5WkjoClCkwEFW5iSjcGQF7m4n4H7Cw"}},
	} {
		if rec := postCampaignEdit(mux, good); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"applying":true`) {
			t.Errorf("%v = %d %s", good, rec.Code, rec.Body.String())
		}
	}
	if woke != 6 {
		t.Fatalf("woke = %d, want 6", woke)
	}
	edits, err := s.st.CampaignEdits(context.Background())
	if err != nil || len(edits) != 6 || edits[0].Who != "dashboard" || edits[0].Arg != "Outlaw" {
		t.Fatalf("edits %+v %v", edits, err)
	}
}

// Edits are recorded literally. Stored aliases include Group's automatic
// bridge aliases, and Group alone interprets IDs (through merge aliases only):
// resolving here would turn "merge T into A" while A is bridged into B into a
// permanent merge into B. Aliases only count as existence.
func TestCampaignEditMergeRecordsLiteralIDs(t *testing.T) {
	s, st := hasshTestServer(t)
	mux := http.NewServeMux()
	s.registerCampaignRoutes(mux)
	const a, b, t0 = "c-000000000001", "c-aaaaaaaaaaaa", "c-bbbbbbbbbbbb" // a is bridge-aliased into b
	rows := []store.CampaignRow{{ID: b}, {ID: t0}}
	if err := st.SaveGrouping(context.Background(), rows, nil, map[string]string{a: b}, 0); err != nil {
		t.Fatal(err)
	}
	if c := postCampaignEdit(mux, url.Values{"id": {b}, "action": {"merge"}, "arg": {b}}).Code; c != http.StatusBadRequest {
		t.Fatalf("literal self-merge = %d", c)
	}
	for _, e := range [][2]string{{t0, a}, {a, b}} { // merge T into A; make the A->B bridge permanent
		if c := postCampaignEdit(mux, url.Values{"id": {e[0]}, "action": {"merge"}, "arg": {e[1]}}).Code; c != http.StatusOK {
			t.Fatalf("merge %s into %s = %d", e[0], e[1], c)
		}
	}
	if c := postCampaignEdit(mux, url.Values{"id": {a}, "action": {"rename"}, "arg": {"X"}}).Code; c != http.StatusOK {
		t.Fatalf("rename via alias source = %d", c)
	}
	edits, err := st.CampaignEdits(context.Background())
	if err != nil || len(edits) != 3 {
		t.Fatalf("edits %+v %v", edits, err)
	}
	want := [][2]string{{t0, a}, {a, b}, {a, "X"}}
	for i, e := range edits {
		if e.CampaignID != want[i][0] || e.Arg != want[i][1] {
			t.Errorf("edit %d recorded %s/%s, want %s/%s", i, e.CampaignID, e.Arg, want[i][0], want[i][1])
		}
	}
}

func TestCampaignDetailContractAndAmbiguity(t *testing.T) {
	s, st := hasshTestServer(t)
	mux := http.NewServeMux()
	s.registerCampaignRoutes(mux)
	rows := []store.CampaignRow{
		{ID: "c-aaaaaaaaaaaa", SuggestedName: "Outlaw/Dota", Kinds: "ssh_key", Members: []store.CampaignMemberRow{{ActorID: "cowrie:a", Reasons: `[{"kind":"ssh_key","value":"k","label":"key","firstSeen":"2026-09-01T00:00:00Z"}]`}}},
		{ID: "c-bbbbbbbbbbbb", SuggestedName: "Outlaw/Dota", Members: []store.CampaignMemberRow{{ActorID: "cowrie:b", Reasons: "not json"}}},
	}
	if err := st.SaveGrouping(context.Background(), rows, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	get := func(p string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		return rec
	}
	// The refusal names every matching ID so the operator can pick one.
	if rec := get("/api/intel/campaign?id=outlaw%2Fdota"); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "ambiguous") ||
		!strings.Contains(rec.Body.String(), "c-aaaaaaaaaaaa, c-bbbbbbbbbbbb") {
		t.Fatalf("ambiguous name = %d %q", rec.Code, rec.Body.String())
	}
	if rec := get("/api/intel/campaign?id=nobody"); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown = %d", rec.Code)
	}
	rec := get("/api/intel/campaign?id=c-aaaaaaaaaaaa")
	if rec.Code != http.StatusOK {
		t.Fatalf("detail = %d", rec.Code)
	}
	var d map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"id", "name", "suggestedName", "actors", "ips", "sessions", "firstSeen", "lastSeen", "kinds", "search", "notes", "anchor", "members", "hasshes", "clients", "hosts", "edits",
		"membersTotal", "hasshesTotal", "clientsTotal", "hostsTotal"} {
		if _, ok := d[k]; !ok {
			t.Errorf("detail missing %q", k)
		}
	}
	// The totals are the store's true counts, not the list lengths.
	if d["membersTotal"] != float64(1) || d["hasshesTotal"] != float64(0) || d["clientsTotal"] != float64(0) || d["hostsTotal"] != float64(0) {
		t.Errorf("totals: %v %v %v %v", d["membersTotal"], d["hasshesTotal"], d["clientsTotal"], d["hostsTotal"])
	}
	m := d["members"].([]any)[0].(map[string]any)
	for _, k := range []string{"actorId", "primaryIp", "playbook", "sessions", "ips", "reasons"} {
		if _, ok := m[k]; !ok {
			t.Errorf("member missing %q", k)
		}
	}
	if r := m["reasons"].([]any)[0].(map[string]any); r["label"] != "key" {
		t.Errorf("reasons not passed through: %+v", r)
	}
	// Invalid stored JSON degrades to an empty list, never breaks the response.
	rec = get("/api/intel/campaign?id=c-bbbbbbbbbbbb")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"reasons":[]`) {
		t.Fatalf("bad reasons = %d %s", rec.Code, rec.Body.String())
	}
	// The list contract.
	rec = get("/api/intel/campaigns")
	var l struct {
		GeneratedAt string           `json:"generatedAt"`
		Campaigns   []map[string]any `json:"campaigns"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &l); err != nil || l.GeneratedAt == "" || len(l.Campaigns) != 2 {
		t.Fatalf("list %s %v", rec.Body.String(), err)
	}
	if k, ok := l.Campaigns[0]["kinds"].([]any); !ok || k == nil {
		t.Errorf("kinds must be an array: %+v", l.Campaigns[0])
	}
}

func TestScriptRoutesContract(t *testing.T) {
	_, mux := campaignServer(t)
	get := func(p string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		return rec
	}
	if c := get("/api/intel/script?fp=nothex").Code; c != http.StatusBadRequest {
		t.Fatalf("bad fp = %d", c)
	}
	if c := get("/api/intel/script?fp=" + strings.Repeat("a", 64)).Code; c != http.StatusNotFound {
		t.Fatalf("unknown fp = %d", c)
	}
	rec := get("/api/intel/scripts")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"families":[]`) {
		t.Fatalf("scripts = %d %s", rec.Code, rec.Body.String())
	}
}

// The actor view carries a campaigns badge; a campaign lookup failure only
// omits it.
func TestActorDetailCarriesCampaigns(t *testing.T) {
	s, st := hasshTestServer(t)
	const id = "journal:198.51.100.3"
	e := &models.Event{TS: time.Now().UTC(), ActorID: id, Source: models.SourceJournal, Kind: models.KindFailedPass, SrcIP: "198.51.100.3", Username: "root"}
	if _, err := st.AppendJournalEventAtomic(e, &store.JournalActorUpdate{Actor: &models.Actor{ID: id}, Username: "root"}); err != nil {
		t.Fatal(err)
	}
	row := store.CampaignRow{ID: "c-0123456789ab", Name: "Outlaw", SuggestedName: "Dota", Members: []store.CampaignMemberRow{{ActorID: id, Reasons: "[]"}}}
	if err := st.SaveGrouping(context.Background(), []store.CampaignRow{row}, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.handleActorDetail(w, httptest.NewRequest(http.MethodGet, "/api/intel/actor?id="+id, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var resp struct {
		Campaigns []map[string]string `json:"campaigns"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Campaigns) != 1 || resp.Campaigns[0]["id"] != row.ID || resp.Campaigns[0]["name"] != "Outlaw" || resp.Campaigns[0]["suggestedName"] != "Dota" {
		t.Fatalf("campaigns badge %+v", resp.Campaigns)
	}
}
