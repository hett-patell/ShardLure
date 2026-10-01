package web

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
)

// During a script-rebuild hold (after an upgrade that changes the script
// normaliser) the worker records edits but does not regroup, so the dialog
// sat on "applying..." for 10+ minutes with no explanation. The list and the
// edit response now carry a read-only "regroup" block saying why and until
// when.
func TestCampaignResponsesCarryRegroupHold(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hold.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatal(err)
	}
	s := New(st, keys, "127.0.0.1:0")
	mux := http.NewServeMux()
	s.registerCampaignRoutes(mux)
	row := store.CampaignRow{ID: "c-0123456789ab", Members: []store.CampaignMemberRow{{ActorID: "cowrie:a", Reasons: "[]"}}}
	if err := st.SaveGrouping(t.Context(), []store.CampaignRow{row}, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	type regroup struct {
		Held     bool    `json:"held"`
		Phase    string  `json:"phase"`
		Progress float64 `json:"progress"`
		Until    string  `json:"until"`
	}
	list := func() regroup {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/intel/campaigns", nil))
		var d struct {
			Regroup *regroup `json:"regroup"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil || d.Regroup == nil {
			t.Fatalf("list %s %v", rec.Body.String(), err)
		}
		return *d.Regroup
	}
	if g := list(); g.Held {
		t.Fatalf("no hold, got %+v", g)
	}

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	set := func(source, p string, v int64) {
		if _, err := raw.Exec(`INSERT INTO ingest_state(source,path,inode,offset,head_sig,updated_at) VALUES(?,?,0,?,'','x')
ON CONFLICT(source,path) DO UPDATE SET offset=excluded.offset`, source, p, v); err != nil {
			t.Fatal(err)
		}
	}
	// Event 400 exists: since fb814fd the recording target is the mark
	// lowered to MAX(events.id), so a mark above every event would read as
	// already recorded.
	if _, err := raw.Exec(`INSERT INTO events(id,ts,source,kind) VALUES(400,'2026-09-01T00:00:00Z','cowrie','connect')`); err != nil {
		t.Fatal(err)
	}
	set("script_version", "hold_hwm", 400)
	set("campaign", "evidence-v1", 100)
	if g := list(); !g.Held || g.Phase != "recording" || g.Progress != 0.25 || g.Until != "" {
		t.Fatalf("recording = %+v", g)
	}
	until := time.Now().Add(20 * time.Minute).Unix()
	set("campaign", "evidence-v1", 400)
	set("script_version", "hold_deadline", until)
	if g := list(); !g.Held || g.Phase != "settling" || g.Until != time.Unix(until, 0).UTC().Format(time.RFC3339) {
		t.Fatalf("settling = %+v", g)
	}
	rec := postCampaignEdit(mux, url.Values{"id": {"c-0123456789ab"}, "action": {"notes"}, "arg": {"x"}})
	var e struct {
		Applying bool     `json:"applying"`
		Regroup  *regroup `json:"regroup"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil || !e.Applying || e.Regroup == nil || !e.Regroup.Held || e.Regroup.Phase != "settling" {
		t.Fatalf("edit response %s %v", rec.Body.String(), err)
	}
}

// The scripts list carries the same regroup block as the campaigns list:
// ResetScriptsForVersion empties script_families and the first regroup after
// the hold refills it, so an empty list during a rebuild needs the reason.
func TestScriptsResponseCarriesRegroupHold(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hold_scripts.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatal(err)
	}
	s := New(st, keys, "127.0.0.1:0")
	mux := http.NewServeMux()
	s.registerCampaignRoutes(mux)
	type regroup struct {
		Held     bool    `json:"held"`
		Phase    string  `json:"phase"`
		Progress float64 `json:"progress"`
	}
	list := func() (regroup, int) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/intel/scripts", nil))
		var d struct {
			Families []json.RawMessage `json:"families"`
			Regroup  *regroup          `json:"regroup"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil || d.Regroup == nil || d.Families == nil {
			t.Fatalf("scripts %s %v", rec.Body.String(), err)
		}
		return *d.Regroup, len(d.Families)
	}
	if g, n := list(); g.Held || n != 0 {
		t.Fatalf("no hold, got %+v with %d families", g, n)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	// Event 400 exists (see TestCampaignResponsesCarryRegroupHold).
	if _, err := raw.Exec(`INSERT INTO events(id,ts,source,kind) VALUES(400,'2026-09-01T00:00:00Z','cowrie','connect')`); err != nil {
		t.Fatal(err)
	}
	for _, row := range [][3]any{{"script_version", "hold_hwm", 400}, {"campaign", "evidence-v1", 100}} {
		if _, err := raw.Exec(`INSERT INTO ingest_state(source,path,inode,offset,head_sig,updated_at) VALUES(?,?,0,?,'','x')
ON CONFLICT(source,path) DO UPDATE SET offset=excluded.offset`, row[0], row[1], row[2]); err != nil {
			t.Fatal(err)
		}
	}
	if g, n := list(); !g.Held || g.Phase != "recording" || g.Progress != 0.25 || n != 0 {
		t.Fatalf("recording = %+v with %d families", g, n)
	}
}
