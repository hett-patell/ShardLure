package store

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func TestReportEvidenceGroupsUsernamesForStreaming(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "ordered.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	for _, user := range []string{"root", "admin", "root", "?", "", "Root", "admin"} {
		if err := st.InsertEvent(&models.Event{TS: now, SrcIP: "8.8.8.8", Source: models.SourceJournal,
			ActorID: "journal:8.8.8.8", Kind: models.KindFailedPass, Username: user}); err != nil {
			t.Fatal(err)
		}
	}
	var users []string
	err = st.IterateReportEvidenceContext(context.Background(), models.SourceJournal, "8.8.8.8", now.Add(-time.Hour), now, func(e *models.Event) {
		users = append(users, e.Username)
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"", "?", "Root", "admin", "admin", "root", "root"}; !reflect.DeepEqual(users, want) {
		t.Fatalf("username groups must be contiguous with case-sensitive identity: %q", users)
	}
}

func TestReportEvidenceCancellationReleasesConnection(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "cancel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.db.SetMaxOpenConns(1)
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		if err := st.InsertEvent(&models.Event{TS: now, SrcIP: "8.8.8.8", Source: models.SourceJournal,
			ActorID: "journal:8.8.8.8", Kind: models.KindFailedPass, Username: "root"}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	seen := 0
	err = st.IterateReportEvidenceContext(ctx, models.SourceJournal, "8.8.8.8", now.Add(-time.Hour), now, func(*models.Event) {
		seen++
		cancel()
	})
	if !errors.Is(err, context.Canceled) || seen != 1 {
		t.Fatalf("cancel after first row: seen=%d err=%v", seen, err)
	}
	probe, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := st.db.PingContext(probe); err != nil {
		t.Fatalf("reader did not release sole connection: %v", err)
	}
	seen = 0
	err = st.IterateReportEvidenceContext(ctx, models.SourceJournal, "8.8.8.8", now.Add(-time.Hour), now, func(*models.Event) { seen++ })
	if !errors.Is(err, context.Canceled) || seen != 0 {
		t.Fatalf("already cancelled scan: seen=%d err=%v", seen, err)
	}
}
