package urlhaus

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSubmitRejectsMalformedSuccessResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("provider-secret-not-json"))
	}))
	defer srv.Close()

	res, err := NewClient(srv.URL).Submit(context.Background(), "key", []Entry{{URL: "https://example.test/a", Threat: ThreatMalwareDownload}}, false)
	if err == nil {
		t.Fatal("malformed 2xx response must fail closed")
	}
	if res != nil {
		t.Fatalf("malformed response returned result: %+v", res)
	}
	if strings.Contains(err.Error(), "provider-secret-not-json") {
		t.Fatalf("provider body leaked into error: %v", err)
	}
}

func TestSubmitAcceptsPlaintextOKResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res, err := NewClient(srv.URL).Submit(context.Background(), "key", []Entry{{URL: "https://example.test/a", Threat: ThreatMalwareDownload}}, false)
	if err != nil || res == nil || res.Status != "ok" {
		t.Fatalf("plaintext ok result=%+v error=%v", res, err)
	}
}

func TestSubmitRejectsPlaintextNoData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		_, _ = w.Write([]byte("no_data"))
	}))
	defer srv.Close()

	res, err := NewClient(srv.URL).Submit(context.Background(), "key", []Entry{{URL: "https://example.test/a", Threat: ThreatMalwareDownload}}, false)
	if err == nil || res != nil {
		t.Fatalf("plaintext no_data result=%+v error=%v", res, err)
	}
	if strings.Contains(err.Error(), "no_data") {
		t.Fatalf("provider token leaked into error: %v", err)
	}
}

func TestSubmitRejectsNonOKStatusWithoutProviderText(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{\"query_status\":\"future_provider_status\",\"message\":\"token-secret\"}"))
	}))
	defer srv.Close()

	res, err := NewClient(srv.URL).Submit(context.Background(), "key", []Entry{{URL: "https://example.test/a", Threat: ThreatMalwareDownload}}, false)
	if err == nil {
		t.Fatal("non-ok provider status must fail closed")
	}
	if res == nil || res.Status != "unknown" {
		t.Fatalf("result = %+v, want sanitized unknown status", res)
	}
	if strings.Contains(err.Error(), "future_provider_status") || strings.Contains(err.Error(), "token-secret") {
		t.Fatalf("provider text leaked into error: %v", err)
	}
}

func TestSubmitDoesNotAcceptBatchWithRejectedEntries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{\"query_status\":\"ok\",\"rejected\":[{\"url\":\"https://example.test/a\",\"reason\":\"provider-secret\"}]}"))
	}))
	defer srv.Close()

	res, err := NewClient(srv.URL).Submit(context.Background(), "key", []Entry{{URL: "https://example.test/a", Threat: ThreatMalwareDownload}}, false)
	if err == nil {
		t.Fatal("batch containing rejected entries must not be accepted")
	}
	if res == nil || res.Status != "rejected" || res.Rejected != 1 {
		t.Fatalf("result = %+v, want sanitized rejected count", res)
	}
	if strings.Contains(err.Error(), "provider-secret") || strings.Contains(err.Error(), "https://example.test/a") {
		t.Fatalf("rejection detail leaked into error: %v", err)
	}
}

func TestSubmitSurfacesBodyReadErrorWithoutText(t *testing.T) {
	c := NewClient("https://endpoint.example.test/api?key=endpoint-secret")
	c.hc.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(errorReader{}), Header: make(http.Header)}, nil
	})

	_, err := c.Submit(context.Background(), "key", []Entry{{URL: "https://example.test/a", Threat: ThreatMalwareDownload}}, false)
	if err == nil {
		t.Fatal("body read failure must be returned")
	}
	if strings.Contains(err.Error(), "endpoint-secret") || strings.Contains(err.Error(), "body-reader-secret") {
		t.Fatalf("sensitive diagnostics leaked: %v", err)
	}
}

func TestSubmitPreservesCancellationIdentity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := NewClient("https://endpoint.example.test/api?key=endpoint-secret").Submit(ctx, "key", []Entry{{URL: "https://example.test/a", Threat: ThreatMalwareDownload}}, false)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if strings.Contains(err.Error(), "endpoint-secret") {
		t.Fatalf("endpoint leaked into cancellation error: %v", err)
	}
}

func TestSubmitResponseSizeBoundary(t *testing.T) {
	const limit = 256 << 10
	valid := `{"query_status":"ok"}`
	for _, tc := range []struct {
		name    string
		size    int
		wantErr bool
	}{
		{name: "exact limit", size: limit},
		{name: "one byte over", size: limit + 1, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := valid + strings.Repeat(" ", tc.size-len(valid))
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()

			res, err := NewClient(srv.URL).Submit(context.Background(), "key", []Entry{{URL: "https://example.test/a", Threat: ThreatMalwareDownload}}, false)
			if tc.wantErr {
				if err == nil || res != nil {
					t.Fatalf("oversized response returned result=%+v error=%v", res, err)
				}
				if !strings.Contains(err.Error(), "too large") {
					t.Fatalf("error = %v, want sanitized size error", err)
				}
				return
			}
			if err != nil || res == nil || res.Status != "ok" {
				t.Fatalf("exact-limit response result=%+v error=%v", res, err)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("body-reader-secret") }
