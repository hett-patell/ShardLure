package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
)

// listTotalsServer is a server over a scratch store plus a raw handle to seed
// the materialised script_families table directly.
func listTotalsServer(t *testing.T) (*Server, *http.ServeMux, *store.Store, *sql.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "totals.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	s := New(st, keys, "127.0.0.1:0")
	mux := http.NewServeMux()
	s.registerCampaignRoutes(mux)
	return s, mux, st, raw
}

func seedScriptFamily(t *testing.T, raw *sql.DB, family string, sessions int, variants string) {
	t.Helper()
	const ts = "2026-09-20T00:00:00.000000000Z"
	if _, err := raw.Exec(`INSERT INTO script_families(family,display,variants,sessions,actors,ips,command_count,distinctive,links,reason,first_seen,last_seen)
VALUES(?,?,?,?,1,1,3,1,0,'r',?,?)`, family, "cd /tmp", variants, sessions, ts, ts); err != nil {
		t.Fatal(err)
	}
}

func getJSON(t *testing.T, mux *http.ServeMux, p string, v any) {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d %s", p, rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("GET %s: %v", p, err)
	}
}

// Final audit M1: the Campaigns and Scripts lists are capped (200 by default)
// and the header read the capped length as the whole. Each list response now
// carries the true total beside the capped rows.
func TestCampaignAndScriptListsCarryTotals(t *testing.T) {
	_, mux, st, raw := listTotalsServer(t)
	var rows []store.CampaignRow
	for i := 0; i < 3; i++ {
		rows = append(rows, store.CampaignRow{ID: fmt.Sprintf("c-00000000000%d", i),
			Members: []store.CampaignMemberRow{{ActorID: fmt.Sprintf("cowrie:%d", i), Reasons: "[]"}}})
	}
	if err := st.SaveGrouping(context.Background(), rows, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		seedScriptFamily(t, raw, strings.Repeat(fmt.Sprint(i), 64), 10-i, "[]")
	}
	var c struct {
		Campaigns []any `json:"campaigns"`
		Total     *int  `json:"total"`
	}
	getJSON(t, mux, "/api/intel/campaigns?limit=2", &c)
	if len(c.Campaigns) != 2 || c.Total == nil || *c.Total != 3 {
		t.Fatalf("campaigns: %d rows, total %v; want 2 of 3", len(c.Campaigns), c.Total)
	}
	var f struct {
		Families []any `json:"families"`
		Total    *int  `json:"total"`
	}
	getJSON(t, mux, "/api/intel/scripts?limit=2", &f)
	if len(f.Families) != 2 || f.Total == nil || *f.Total != 3 {
		t.Fatalf("scripts: %d rows, total %v; want 2 of 3", len(f.Families), f.Total)
	}
	// Uncapped: the total equals the rows.
	getJSON(t, mux, "/api/intel/scripts", &f)
	if len(f.Families) != 3 || *f.Total != 3 {
		t.Fatalf("scripts uncapped: %d rows, total %d", len(f.Families), *f.Total)
	}
}
