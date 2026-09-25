package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
)

func TestSingleSHAShareUsesSuccessfulPayloadNotNewestObservation(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "share.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	for _, a := range []store.Artifact{
		{URL: "https://example.com/fresh", SHA256: "samehash", TS: now.Add(-time.Hour), Origin: "quarantine_fetch", Status: "fetched", LocalPath: "/fixture/fresh", SizeBytes: 128},
		{URL: "https://example.com/stale", SHA256: "samehash", TS: now.Add(-time.Minute), LastSuccessfulFetchAt: now.Add(-30 * 24 * time.Hour), Origin: "quarantine_fetch", Status: "fetched", LocalPath: "/fixture/stale", SizeBytes: 128},
		{URL: "cowrie-tty://samehash", SHA256: "samehash", TS: now, Origin: "cowrie_tty", Status: "fetched", LocalPath: "/fixture/tty", SizeBytes: 128},
	} {
		if err := st.RecordArtifact(a); err != nil {
			t.Fatal(err)
		}
	}
	got, err := collectShareCandidates(st, "samehash", 24*time.Hour)
	if err != nil || len(got) != 1 {
		t.Fatalf("candidates=%+v err=%v", got, err)
	}
	if got[0].LocalPath != "/fixture/fresh" || !got[0].ObservedAt.Equal(now.Add(-time.Hour)) {
		t.Fatalf("wrong evidence chosen: %+v", got[0])
	}
}
