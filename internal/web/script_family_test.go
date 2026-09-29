package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
)

// TestScriptDetailDisclosesFamily pins fix-D I1. A Scripts row counts every
// variant of a family, but the dialog it opens (GET /api/intel/script) listed
// only the representative's own sessions and never named the other variants,
// so they could not be opened and the dialog's counts disagreed with the row.
// The detail now carries the family totals and every variant (fingerprint and
// session count), and this fingerprint's true session total beside its capped
// list, so the dialog can say "this variant: N of M family sessions" and open
// each variant.
func TestScriptDetailDisclosesFamily(t *testing.T) {
	path := filepath.Join(t.TempDir(), "family.db")
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

	rep, variant := strings.Repeat("a", 64), strings.Repeat("b", 64)
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	const ts = "2026-09-20T00:00:00.000000000Z"
	for _, fp := range []string{rep, variant} {
		if _, err := raw.Exec(`INSERT INTO scripts(fingerprint,normalized,display,command_count,distinctive,family,family_distance,token_count,first_seen,last_seen)
VALUES(?,?,?,6,1,?,0,6,?,?)`, fp, "n", "cd /tmp", rep, ts, ts); err != nil {
			t.Fatal(err)
		}
	}
	for i, row := range [][3]string{{"s1", "cowrie:a", rep}, {"s2", "cowrie:b", variant}, {"s3", "cowrie:c", variant}} {
		if _, err := raw.Exec(`INSERT INTO session_scripts(session_id,actor_id,src_ip,first_seen,last_seen,updated_at,settled_at,fingerprint)
VALUES(?,?,?,?,?,?,?,?)`, row[0], row[1], "198.51.100."+string(rune('1'+i)), ts, ts, ts, ts, row[2]); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.RebuildScriptFamilies(context.Background(), 100); err != nil {
		t.Fatal(err)
	}

	var d struct {
		Fingerprint    string `json:"fingerprint"`
		Sessions       []any  `json:"sessions"`
		SessionsTotal  int    `json:"sessionsTotal"`
		FamilySessions int    `json:"familySessions"`
		FamilyActors   int    `json:"familyActors"`
		Variants       []struct {
			Fingerprint string `json:"fingerprint"`
			Sessions    int    `json:"sessions"`
		} `json:"variants"`
	}
	for _, fp := range []string{rep, variant} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/intel/script?fp="+fp, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("script %s = %d %s", fp[:4], rec.Code, rec.Body.String())
		}
		d.Variants = nil
		if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
			t.Fatal(err)
		}
		want := map[string]int{rep: 1, variant: 2}[fp]
		if len(d.Sessions) != want || d.SessionsTotal != want {
			t.Errorf("%s: sessions %d total %d, want %d", fp[:4], len(d.Sessions), d.SessionsTotal, want)
		}
		if d.FamilySessions != 3 || d.FamilyActors != 3 {
			t.Errorf("%s: family %d sessions %d actors, want 3/3", fp[:4], d.FamilySessions, d.FamilyActors)
		}
		sum := 0
		got := map[string]int{}
		for _, v := range d.Variants {
			got[v.Fingerprint] = v.Sessions
			sum += v.Sessions
		}
		if got[rep] != 1 || got[variant] != 2 || sum != d.FamilySessions {
			t.Errorf("%s: variants %v do not add up to the family's %d sessions", fp[:4], got, d.FamilySessions)
		}
	}
}
