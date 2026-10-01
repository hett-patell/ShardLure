package web

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
)

// TestMeasureIntelHeavyUsernames times a warm /api/intel on a database whose
// 80 listed actors hold 20,000 usernames each (brute-force shaped, like prod's
// actor_users). Opt-in: SHARDLURE_MEASURE_INTEL=1. It logs the median of 15
// warm requests; it never fails on timing.
func TestMeasureIntelHeavyUsernames(t *testing.T) {
	if os.Getenv("SHARDLURE_MEASURE_INTEL") == "" {
		t.Skip("set SHARDLURE_MEASURE_INTEL=1 to measure")
	}
	path := filepath.Join(t.TempDir(), "heavy.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for a := 0; a < 80; a++ {
		id := fmt.Sprintf("journal:198.51.%d.%d", a/250, a%250)
		if _, err := raw.Exec(`INSERT INTO actors(id,source,primary_ip,playbook,intent,confidence,first_seen,last_seen,event_count,unique_users,attempts_per_hour,probe_score,hassh,ssh_client,username_hash,campaigns,notes)
VALUES(?,'journal',?,'fast_dictionary_spray','credential_access',50,?,?,20000,20000,100,80,'','','','','')`, id, id[8:], now, now); err != nil {
			t.Fatal(err)
		}
		// 20,000 usernames per actor, generated in SQL (one statement each).
		if _, err := raw.Exec(`WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i < 19999)
INSERT INTO actor_users(actor_id,username,count) SELECT ?, printf('user%05d', i), (i*7919)%997+1 FROM n`, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.ListActors(80); err != nil {
		t.Fatalf("ListActors: %v", err)
	}
	if _, err := st.ActorUsersForActors([]string{"x"}, 8); err != nil {
		t.Fatalf("ActorUsersForActors: %v", err)
	}
	if _, err := st.RecentCommands(120); err != nil {
		t.Fatalf("RecentCommands: %v", err)
	}
	raw.Close()
	keys, _ := settings.Load(st)
	s := New(st, keys, "127.0.0.1:0")
	req := func() time.Duration {
		rec := httptest.NewRecorder()
		t0 := time.Now()
		s.handleIntel(rec, httptest.NewRequest(http.MethodGet, "/api/intel", nil))
		d := time.Since(t0)
		if rec.Code != http.StatusOK {
			t.Fatalf("intel = %d", rec.Code)
		}
		return d
	}
	cold := req()
	var ds []time.Duration
	for i := 0; i < 15; i++ {
		ds = append(ds, req())
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	t.Logf("80 actors x 20k usernames: cold %v, warm median %v (min %v, max %v)", cold, ds[len(ds)/2], ds[0], ds[len(ds)-1])
	// The per-request store calls still in handleIntel, timed on their own.
	actors, _ := st.ListActors(80)
	ids := make([]string, 0, len(actors))
	for _, a := range actors {
		ids = append(ids, a.ID)
	}
	timeIt := func(name string, fn func()) {
		var ts []time.Duration
		for i := 0; i < 9; i++ {
			t0 := time.Now()
			fn()
			ts = append(ts, time.Since(t0))
		}
		sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
		t.Logf("  %-28s median %v", name, ts[len(ts)/2])
	}
	timeIt("ListActors(80)", func() { _, _ = st.ListActors(80) })
	timeIt("LastCommandsForActors", func() { _, _ = st.LastCommandsForActors(ids) })
	timeIt("RecentCommands(120)", func() { _, _ = st.RecentCommands(120) })
	timeIt("ActorUsersForActors (uncached)", func() { _, _ = st.ActorUsersForActors(ids, 8) })
}
