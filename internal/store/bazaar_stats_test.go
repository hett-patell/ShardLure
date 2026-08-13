package store

import (
	"testing"
	"time"
)

// TestBazaarPendingMatchesSharePolicy pins the pending stat to the same policy
// and window as candidate selection. The old private filter (`size_bytes >
// 1024 AND origin LIKE '%download%'`, no freshness window) failed in all three
// directions this fixture covers: it excluded quarantine_fetch payloads and
// small droppers that ARE offerable, and included stale samples that are not —
// live it claimed 148 pending against a real pool of 30.
func TestBazaarPendingMatchesSharePolicy(t *testing.T) {
	st := newTestStore(t, "bazaar-stats.db")
	now := time.Now().UTC()
	pol := SharePolicy{MinBytes: 64, Origins: []string{"cowrie_download", "quarantine_fetch"}}

	seed := []struct {
		sha, origin string
		size        int64
		age         time.Duration
	}{
		{"aa01", "cowrie_download", 4096, 24 * time.Hour},      // pending: classic case
		{"aa02", "quarantine_fetch", 4096, 24 * time.Hour},     // pending: old filter's LIKE missed this origin
		{"aa03", "cowrie_download", 389, 24 * time.Hour},       // pending: old filter's >1024 floor dropped this dropper
		{"aa04", "cowrie_download", 4096, 30 * 24 * time.Hour}, // NOT pending: stale — old filter counted it
		{"aa05", "tty_transcript", 4096, 24 * time.Hour},       // NOT pending: origin outside policy
		{"aa06", "cowrie_download", 32, 24 * time.Hour},        // NOT pending: below the policy floor
		{"aa07", "cowrie_download", 4096, 24 * time.Hour},      // NOT pending: already shared (below)
	}
	for _, r := range seed {
		if err := st.RecordArtifact(Artifact{
			URL: "http://malhost.example/" + r.sha, SHA256: r.sha, SizeBytes: r.size,
			Origin: r.origin, Status: "fetched", LocalPath: "/evidence/" + r.sha,
			TS: now.Add(-r.age),
		}); err != nil {
			t.Fatalf("seed %s: %v", r.sha, err)
		}
		// RecordArtifact stamps created_at with the wall clock; backdate it so the
		// stale row is stale by the same COALESCE(created_at, ts) the query (and
		// ArtifactsForShare) windows on.
		if _, err := st.db.Exec(`UPDATE artifacts SET created_at=? WHERE sha256=?`,
			now.Add(-r.age).Format("2006-01-02T15:04:05.999999999Z"), r.sha); err != nil {
			t.Fatalf("backdate %s: %v", r.sha, err)
		}
	}
	if err := st.RecordBazaarUpload(BazaarUpload{SHA256: "aa07", UploadedAt: now, ResponseStatus: "inserted"}); err != nil {
		t.Fatalf("record upload: %v", err)
	}

	stats, err := st.BazaarUploadStats(now.Add(-10*24*time.Hour), pol)
	if err != nil {
		t.Fatalf("BazaarUploadStats: %v", err)
	}
	if stats.Pending != 3 {
		t.Fatalf("pending = %d, want 3 (aa01 classic, aa02 quarantine_fetch, aa03 small dropper; "+
			"stale/off-policy/shared excluded) — a mismatch means the stats query drifted from "+
			"SharePolicy again", stats.Pending)
	}

	// Fail-closed: a zero policy pends nothing, mirroring ArtifactsForShare.
	zero, err := st.BazaarUploadStats(now.Add(-10*24*time.Hour), SharePolicy{})
	if err != nil {
		t.Fatalf("BazaarUploadStats(zero): %v", err)
	}
	if zero.Pending != 0 {
		t.Fatalf("zero-value SharePolicy pending = %d, want 0 (fail closed)", zero.Pending)
	}
}
