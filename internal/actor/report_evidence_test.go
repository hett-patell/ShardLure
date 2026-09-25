package actor

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

func TestReportEvidencePreservesLargeUsernameCorpus(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "large-corpus.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC()
	a := &models.Actor{ID: "journal:8.8.8.8", Source: models.SourceJournal, PrimaryIP: "8.8.8.8"}
	var events []*models.Event
	for i := 0; i < 12000; i++ {
		for j := 0; j < 2; j++ {
			events = append(events, &models.Event{TS: now.Add(-time.Minute), Source: a.Source,
				SrcIP: a.PrimaryIP, ActorID: a.ID, Kind: models.KindFailedPass, Username: fmt.Sprint(i)})
		}
	}
	for _, user := range []string{"solana", "ethereum", "", "?"} {
		events = append(events, &models.Event{TS: now.Add(-time.Minute), Source: a.Source,
			SrcIP: a.PrimaryIP, ActorID: a.ID, Kind: models.KindFailedPass, Username: user})
	}
	if err := st.AppendEventsAndUpsertActorsAgg(events, nil); err != nil {
		t.Fatal(err)
	}
	got, err := ReportEvidenceForIP(st, a, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.EventCount != 24004 || got.UniqueUsers != 12002 || got.Playbook != "crypto_target" || got.ProbeScore != 95 {
		t.Fatalf("username corpus was truncated, sampled, or counted per event: %+v", got)
	}
}

func TestReportEvidenceRecentRateDoesNotFlatterDormantBurst(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC()
	a := &models.Actor{ID: "journal:8.8.8.8", Source: models.SourceJournal, PrimaryIP: "8.8.8.8"}
	var events []*models.Event
	for i := 0; i < 400; i++ {
		events = append(events, &models.Event{TS: now.Add(-48*time.Hour - time.Duration(i)*time.Second),
			Source: a.Source, ActorID: a.ID, SrcIP: a.PrimaryIP, Kind: models.KindFailedPass,
			Username: []string{"root", "admin", "postgres", "oracle"}[i%4]})
	}
	if err := st.AppendEventsAndUpsertActorsAgg(events, nil); err != nil {
		t.Fatal(err)
	}
	got, err := ReportEvidenceForIP(st, a, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.AttemptsPerHour != 0 {
		t.Fatalf("quiet 24h window reports rate %g, want 0", got.AttemptsPerHour)
	}
	if got.EventCount != 400 || got.UniqueUsers != 4 || got.Playbook != "fast_dictionary_spray" || got.ProbeScore != 85 {
		t.Fatalf("recent-rate metadata must not erase confirmed seven-day evidence: %+v", got)
	}
	var fresh []*models.Event
	for i := 0; i < 24; i++ {
		fresh = append(fresh, &models.Event{TS: now.Add(-time.Hour - time.Duration(i)*time.Second),
			Source: a.Source, ActorID: a.ID, SrcIP: a.PrimaryIP, Kind: models.KindFailedPass, Username: "root"})
	}
	if err := st.AppendEventsAndUpsertActorsAgg(fresh, nil); err != nil {
		t.Fatal(err)
	}
	got, err = ReportEvidenceForIP(st, a, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.AttemptsPerHour != 1 || got.EventCount != 424 {
		t.Fatalf("rate must count only target events in last 24h: %+v", got)
	}
}
