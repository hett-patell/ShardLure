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

// TestBulkShareRePicksTheRowWithAFile pins that bulk `share bazaar` judges the
// same row per sha as `--sha`, the dashboard upload handler and the panel
// (GetArtifactForShareBySHA): a sha whose newest qualifying row has no local
// file, but whose older in-window row does, must reach Share with the file
// row. Taking the newest pooled row skipped it as "file gone" while the panel
// called it eligible — a selection tighter than Vet.
func TestBulkShareRePicksTheRowWithAFile(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "share.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	for _, a := range []store.Artifact{
		{URL: "https://example.com/older", SHA256: "pathhash", TS: now.Add(-2 * time.Hour), Origin: "cowrie_download", Status: "fetched", LocalPath: "/fixture/on-disk", SizeBytes: 128},
		{URL: "https://example.com/newer", SHA256: "pathhash", TS: now.Add(-time.Hour), Origin: "quarantine_fetch", Status: "fetched", LocalPath: "", SizeBytes: 128},
	} {
		if err := st.RecordArtifact(a); err != nil {
			t.Fatal(err)
		}
	}
	got, err := collectShareCandidates(st, "", 24*time.Hour)
	if err != nil || len(got) != 1 {
		t.Fatalf("candidates=%+v err=%v", got, err)
	}
	if got[0].LocalPath != "/fixture/on-disk" || got[0].Origin != "cowrie_download" {
		t.Fatalf("bulk selection kept the file-less newest row: %+v", got[0])
	}
}
