package store

import (
	"testing"
	"time"
)

// I2: a sha held at depth 0 by one row and depth 1 by another is judged at
// depth 0 (the attacker fetched it directly), whichever row is picked; a sha
// held only at depth 1 stays at depth 1.
func TestGetArtifactForShareBySHAUsesMinimumDepth(t *testing.T) {
	st := newTestStore(t, "i2depth.db")
	if err := st.ensureArtifactsTable(); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ins := func(u, sha, local string, depth int, fetched time.Time) {
		t.Helper()
		if _, err := st.db.Exec(`INSERT INTO artifacts(ts,url,local_path,sha256,size_bytes,origin,status,created_at,last_successful_fetch_at,depth)
VALUES(?,?,?,?,4096,'quarantine_fetch','fetched',?,?,?)`, captureTime(fetched), u, local, sha, captureTime(fetched), captureTime(fetched), depth); err != nil {
			t.Fatal(err)
		}
	}
	// The newer row (picked) is the harvested one; the attacker's own
	// fetch of the same bytes is older and has lost its file.
	ins("http://198.51.100.1/typed", "mixed", "", 0, now.Add(-3*time.Hour))
	ins("http://198.51.100.2/named-in-script", "mixed", "/e/q/mixed", 1, now.Add(-time.Hour))
	ins("http://198.51.100.3/only-harvested", "harv", "/e/q/harv", 2, now.Add(-time.Hour))
	pol := sharePolicyForTest()
	a, err := st.GetArtifactForShareBySHA("mixed", pol)
	if err != nil {
		t.Fatal(err)
	}
	if a.URL != "http://198.51.100.2/named-in-script" || a.Depth != 0 {
		t.Fatalf("mixed: url=%s depth=%d, want the file row judged at depth 0", a.URL, a.Depth)
	}
	if a, err := st.GetArtifactForShareBySHA("harv", pol); err != nil || a.Depth != 2 {
		t.Fatalf("harvested-only: %+v %v", a, err)
	}
	// The pool and the URLhaus/ThreatFox rows carry each row's own depth.
	pool, err := st.ArtifactsForShare(now.Add(-24*time.Hour), pol)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pool {
		if p.SHA256 == "harv" && p.Depth != 2 {
			t.Fatalf("pool row depth=%d", p.Depth)
		}
	}
	uh, err := st.URLhausCandidates(3, 0)
	if err != nil {
		t.Fatal(err)
	}
	tf, err := st.ThreatFoxCandidates(3, 0)
	if err != nil {
		t.Fatal(err)
	}
	depths := map[string]int{}
	for _, r := range uh {
		depths["uh "+r.URL] = r.Depth
	}
	for _, r := range tf {
		depths["tf "+r.URL] = r.Depth
	}
	for _, k := range []string{"uh ", "tf "} {
		if d, ok := depths[k+"http://198.51.100.3/only-harvested"]; !ok || d != 2 {
			t.Fatalf("%scandidate depth=%d present=%v", k, d, ok)
		}
		if d, ok := depths[k+"http://198.51.100.1/typed"]; !ok || d != 0 {
			t.Fatalf("%styped candidate depth=%d present=%v", k, d, ok)
		}
	}
}
