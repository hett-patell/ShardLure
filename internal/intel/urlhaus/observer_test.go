package urlhaus

import (
	"context"
	"errors"
	"github.com/networkshard/shardlure/internal/observability"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type observerLedger struct{}

func (observerLedger) URLhausSubmitted(string) (bool, error) { return false, nil }
func (observerLedger) RecordURLhausSubmission(string, string, time.Time) error {
	return errors.New("inert ledger failure")
}

func TestObserverClassifiesActualResponses(t *testing.T) {
	for _, tc := range []struct {
		code int
		body string
		want observability.Outcome
	}{{401, "no", observability.Unauthorized}, {429, "no", observability.RateLimited}, {200, "not-json", observability.InvalidResponse}, {200, `{"query_status":"invalid_auth_key"}`, observability.Unauthorized}} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.code); _, _ = w.Write([]byte(tc.body)) }))
		m := observability.New(time.Now, 0)
		ctx := observability.WithMonitor(context.Background(), m)
		_, _ = NewClient(server.URL).Submit(ctx, "inert", []Entry{{URL: "http://8.8.8.8/inert"}}, false)
		server.Close()
		if m.Snapshot().ProviderRequests[observability.URLhaus][observability.Submit][tc.want] != 1 {
			t.Fatalf("response outcome %d %v", tc.code, tc.want)
		}
	}
}

func TestObserverSeparatesUpstreamAndDurableOutcomes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer server.Close()
	m := observability.New(time.Now, 0)
	ctx := observability.WithMonitor(context.Background(), m)
	candidate := Candidate{URL: "http://8.8.8.8/inert", SHA256: strings.Repeat("a", 64), SizeBytes: 128, Origin: "quarantine_fetch", Status: "fetched", FetchedAt: time.Now(), FileKind: "script"}
	sent, _, err := Share(ctx, observerLedger{}, []Candidate{candidate}, Options{APIKey: "inert", Endpoint: server.URL})
	if err == nil || sent != 0 {
		t.Fatal("failed ledger reported success")
	}
	s := m.Snapshot()
	if s.ProviderRequests[observability.URLhaus][observability.Submit][observability.Success] != 1 || s.DurableShares[observability.URLhaus][observability.Success] != 0 || s.DurableShares[observability.URLhaus][observability.StorageError] != 1 {
		t.Fatalf("incorrect accounting: %+v", s.DurableShares[observability.URLhaus])
	}
	before := m.Snapshot().ProviderRequests
	if _, _, err := Share(ctx, observerLedger{}, []Candidate{candidate}, Options{DryRun: true}); err != nil {
		t.Fatal(err)
	}
	if m.Snapshot().ProviderRequests != before {
		t.Fatal("dry run counted upstream traffic")
	}
}
