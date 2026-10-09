package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/intel/threatfox"
	"github.com/networkshard/shardlure/internal/intel/urlhaus"
	"github.com/networkshard/shardlure/internal/store"
)

// The CLI builders carry each row's second-stage depth into the candidate, so
// `share bazaar|urlhaus|threatfox` judge a harvested URL or sample exactly as
// the dashboard does (final review I2). A builder that dropped Depth would
// hand Vet a zero, the attacker-typed value, and the gate would not fire.
func TestCLIShareCandidatesCarryDepth(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "depth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	u := "http://203.0.113.70/bins/named-in-script"
	if n, err := st.QueueHarvestedURLs(context.Background(), store.HarvestSource{SHA256: "parent", Depth: 0}, []string{u}, now, 32); err != nil || n != 1 {
		t.Fatalf("queue: %d %v", n, err)
	}
	if err := st.ClaimArtifactCapture(u, now, now.Add(time.Minute), 0); err != nil {
		t.Fatal(err)
	}
	if err := st.CompleteArtifactCapture(u, 1, "fetched", "", "/fixture/h", "harvsha", 4096, nil); err != nil {
		t.Fatal(err)
	}

	bz, err := collectShareCandidates(st, "", 24*time.Hour)
	if err != nil || len(bz) != 1 || bz[0].Depth != 1 {
		t.Fatalf("bazaar candidates=%+v err=%v", bz, err)
	}
	if one, err := collectShareCandidates(st, "harvsha", 24*time.Hour); err != nil || len(one) != 1 || one[0].Depth != 1 {
		t.Fatalf("bazaar --sha candidate=%+v err=%v", one, err)
	}

	uhRows, err := st.URLhausCandidates(3, 0)
	if err != nil || len(uhRows) != 1 {
		t.Fatalf("urlhaus rows=%+v err=%v", uhRows, err)
	}
	uh := urlhausCandidateFromRow(uhRows[0])
	if uh.Depth != 1 {
		t.Fatalf("urlhaus candidate depth=%d", uh.Depth)
	}
	if ok, reason := urlhaus.Vet(uh, now); ok || reason != urlhaus.ReasonHarvestedURL {
		t.Fatalf("urlhaus Vet: ok=%v reason=%q", ok, reason)
	}

	tfRows, err := st.ThreatFoxCandidates(3, 0)
	if err != nil || len(tfRows) != 1 {
		t.Fatalf("threatfox rows=%+v err=%v", tfRows, err)
	}
	tf := threatfoxCandidateFromRow(tfRows[0])
	if tf.Depth != 1 {
		t.Fatalf("threatfox candidate depth=%d", tf.Depth)
	}
	if ok, _, _, reason := threatfox.Vet(tf, now); ok || reason != threatfox.ReasonHarvestedURL {
		t.Fatalf("threatfox Vet: ok=%v reason=%q", ok, reason)
	}
}
