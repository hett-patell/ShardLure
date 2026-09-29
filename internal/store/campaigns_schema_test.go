package store

import "testing"

func TestSchemaV25(t *testing.T) {
	s := newTestStore(t, "v25.db")
	var v int
	if err := s.db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&v); err != nil || v < 25 {
		t.Fatalf("schema %d %v", v, err)
	}
	// script_version_carry is registered at 26, not 25: the rc1 v25 shipped
	// without it and the v26 rung creates it (released_schema_test.go).
	since := map[string]int{"script_version_carry": 26}
	for _, tbl := range []string{"session_script_lines", "session_scripts", "scripts", "script_families", "campaign_evidence",
		"campaign_ids", "campaign_aliases", "campaigns", "campaign_members", "campaign_edits", "script_version_carry"} {
		want := 25
		if v, ok := since[tbl]; ok {
			want = v
		}
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, tbl).Scan(&n); err != nil {
			t.Fatalf("%s: %v", tbl, err)
		}
		if n != 1 {
			t.Errorf("missing table %s", tbl)
		}
		found := false
		for _, st := range snapshotTables {
			if st.name == tbl && st.since == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s not in snapshotTables at version %d", tbl, want)
		}
	}
}
