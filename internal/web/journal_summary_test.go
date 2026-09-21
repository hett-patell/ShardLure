package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/actor"
	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

func TestIntelActorDisclosesJournalDerivationStatus(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "summary.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatal(err)
	}
	s := New(st, keys, "127.0.0.1:0")
	const id = "journal:198.51.100.3"
	e := &models.Event{TS: time.Now().UTC(), ActorID: id, Source: models.SourceJournal, Kind: models.KindFailedPass, SrcIP: "198.51.100.3", Username: "root"}
	if _, err := s.st.AppendJournalEventAtomic(e, &store.JournalActorUpdate{Actor: &models.Actor{ID: id}, Username: "root"}); err != nil {
		t.Fatal(err)
	}
	for _, current := range []bool{false, true} {
		if current {
			if done, err := s.st.AdvanceJournalSummary(context.Background(), id, 10, actor.NewJournalSummaryCodec()); err != nil || !done {
				t.Fatalf("derive=%v err=%v", done, err)
			}
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/intel/actor?id="+id, nil)
		s.handleActorDetail(w, r)
		if w.Code != 200 {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		var response map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		row, ok := response["actor"].(map[string]any)
		if !ok {
			t.Fatalf("missing actor: %+v", response)
		}
		if value, exists := row["derivedCurrent"]; !exists || value != current {
			t.Errorf("missing/wrong derivation state: %+v", row)
		}
		if note, ok := row["generatedNotes"].(string); !ok || note == "" {
			t.Errorf("missing generated summary: %+v", row)
		}
	}
}
