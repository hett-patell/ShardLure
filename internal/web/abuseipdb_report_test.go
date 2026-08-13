package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

func TestAbuseIPDBReportAllFirstRateLimitIsNotSuccess(t *testing.T) {
	var posts atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"errors":[{"detail":"Daily rate limit"}]}`))
	}))
	defer upstream.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "report-all.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatalf("settings.Load: %v", err)
	}
	if err := keys.Set(settings.KeyAbuseIPDB, "test-key"); err != nil {
		t.Fatalf("set AbuseIPDB key: %v", err)
	}

	now := time.Now().UTC()
	// UpsertJournalActorAtomic, not UpsertActor: the staleness gate reads the
	// PRIMARY IP's own last-seen from actor_ips, and an actor without that row
	// is (correctly) refused as undateable before any POST is attempted.
	if err := st.UpsertJournalActorAtomic(&models.Actor{
		ID: "journal:8.8.8.8", Source: models.SourceJournal, PrimaryIP: "8.8.8.8",
		Playbook: "dictionary_spray", ProbeScore: 90, EventCount: 400,
		UniqueUsers: 30, AttemptsPerHour: 500,
		FirstSeen: now.Add(-time.Hour), LastSeen: now,
	}, "8.8.8.8", now.Add(-time.Hour), now, 400, "root", 300); err != nil {
		t.Fatalf("UpsertJournalActorAtomic: %v", err)
	}

	s := New(st, keys, "127.0.0.1:0", Options{
		AbuseReportEnabled: true,
		AbuseEndpoint:      upstream.URL,
		AbuseMinProbe:      60,
		AbuseRewindowHours: 24,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/intel/abuseipdb/report-all", nil)
	s.handleAbuseIPDBReportAll(rec, req)

	var got reportAllResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response (%d %q): %v", rec.Code, rec.Body.String(), err)
	}
	if got.Status != "rate_limited" {
		t.Fatalf("status = %q, want rate_limited; response=%s", got.Status, rec.Body.String())
	}
	if got.Reported != 0 || got.Skipped != 0 {
		t.Fatalf("counts = (%d reported, %d skipped), want (0, 0)", got.Reported, got.Skipped)
	}
	if !strings.Contains(strings.ToLower(got.Error), "rate limit") {
		t.Fatalf("error = %q, want useful rate-limit message", got.Error)
	}
	if gotPosts := posts.Load(); gotPosts != 1 {
		t.Fatalf("upstream POSTs = %d, want 1", gotPosts)
	}
}
