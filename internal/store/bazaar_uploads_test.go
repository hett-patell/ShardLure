package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func TestListBazaarUploadsWithArtifactsSrcIPFromEvents(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "bazaar.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	sha := "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
	now := time.Now().UTC()

	if err := st.RecordArtifact(Artifact{
		TS: now, URL: "cowrie-download:payload.bin", SHA256: sha,
		SizeBytes: 4096, Origin: "cowrie_download", Status: "fetched",
		// SrcIP intentionally empty — mirrors syncCowrieDownloads.
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertEvent(&models.Event{
		TS: now, Source: models.SourceCowrie, Kind: models.KindFileDown,
		SrcIP: "203.0.113.55", SessionID: "sess-bz", SHA256: sha,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordBazaarUpload(BazaarUpload{
		SHA256: sha, UploadedAt: now, ResponseStatus: "inserted",
		MBURL: "https://bazaar.abuse.ch/sample/" + sha + "/",
	}); err != nil {
		t.Fatal(err)
	}

	rows, err := st.ListBazaarUploadsWithArtifacts(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].SrcIP != "203.0.113.55" {
		t.Fatalf("SrcIP = %q, want 203.0.113.55 (backfilled from events.sha256)", rows[0].SrcIP)
	}
}

func TestListBazaarUploadsWithArtifactsSrcIPFromSession(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "bazaar2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	sha := "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
	now := time.Now().UTC()

	if err := st.RecordArtifact(Artifact{
		TS: now, URL: "cowrie-download:other.bin", SHA256: sha,
		SessionID: "sess-only", SizeBytes: 2048,
		Origin: "cowrie_download", Status: "fetched",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertEvent(&models.Event{
		TS: now, Source: models.SourceCowrie, Kind: models.KindConnect,
		SrcIP: "198.51.100.7", SessionID: "sess-only",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordBazaarUpload(BazaarUpload{
		SHA256: sha, UploadedAt: now, ResponseStatus: "inserted",
	}); err != nil {
		t.Fatal(err)
	}

	rows, err := st.ListBazaarUploadsWithArtifacts(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].SrcIP != "198.51.100.7" {
		t.Fatalf("SrcIP = %q, want 198.51.100.7 (backfilled from events.session_id)", rows[0].SrcIP)
	}
}
