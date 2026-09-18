package threatfox

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

	res, err := NewClient(srv.URL).Submit(context.Background(), "key", Submission{IOC: "https://example.test/a"})
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

func TestSubmitRejectsOKWithoutValidOutcome(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{\"query_status\":\"ok\",\"data\":{}}"))
	}))
	defer srv.Close()

	res, err := NewClient(srv.URL).Submit(context.Background(), "key", Submission{IOC: "https://example.test/a"})
	if err == nil {
		t.Fatal("ok response without an outcome must fail closed")
	}
	if res != nil {
		t.Fatalf("invalid outcome returned result: %+v", res)
	}
}

func TestSubmitRejectsMalformedOutcomeEntries(t *testing.T) {
	const expectedIOC = "https://example.test/a"
	tests := []struct {
		name string
		data string
	}{
		{name: "null", data: `{"ok":[null],"ignored":[],"duplicated":[]}`},
		{name: "wrong type", data: `{"ok":[42],"ignored":[],"duplicated":[]}`},
		{name: "multiple", data: `{"ok":["https://example.test/a","https://example.test/b"],"ignored":[],"duplicated":[]}`},
		{name: "mismatched IOC", data: `{"ok":["https://example.test/b"],"ignored":[],"duplicated":[]}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("{\"query_status\":\"ok\",\"data\":" + tc.data + "}"))
			}))
			defer srv.Close()

			res, err := NewClient(srv.URL).Submit(context.Background(), "key", Submission{IOC: expectedIOC})
			if err == nil || res != nil {
				t.Fatalf("malformed outcome returned result=%+v error=%v", res, err)
			}
			if !strings.Contains(err.Error(), "invalid submission response") {
				t.Fatalf("error = %v, want sanitized invalid-response error", err)
			}
		})
	}
}

func TestSubmitSanitizesUnknownStatusAndBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{\"query_status\":\"future_provider_status\",\"message\":\"token-secret\"}"))
	}))
	defer srv.Close()

	res, err := NewClient(srv.URL).Submit(context.Background(), "key", Submission{IOC: "https://example.test/a"})
	if err == nil {
		t.Fatal("unknown non-ok status must fail closed")
	}
	if res != nil {
		t.Fatalf("unknown status returned result: %+v", res)
	}
	if strings.Contains(err.Error(), "future_provider_status") || strings.Contains(err.Error(), "token-secret") {
		t.Fatalf("provider text leaked into error: %v", err)
	}
}

func TestSubmitSurfacesBodyReadErrorWithoutText(t *testing.T) {
	c := NewClient("https://endpoint.example.test/api?key=endpoint-secret")
	c.hc.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(errorReader{}), Header: make(http.Header)}, nil
	})

	_, err := c.Submit(context.Background(), "key", Submission{IOC: "https://example.test/a"})
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

	_, err := NewClient("https://endpoint.example.test/api?key=endpoint-secret").Submit(ctx, "key", Submission{IOC: "https://example.test/a"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if strings.Contains(err.Error(), "endpoint-secret") {
		t.Fatalf("endpoint leaked into cancellation error: %v", err)
	}
}

func TestSubmitResponseSizeBoundary(t *testing.T) {
	const limit = 256 << 10
	valid := `{"query_status":"ok","data":{"ok":["https://example.test/a"],"ignored":[],"duplicated":[],"reward":1}}`
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

			res, err := NewClient(srv.URL).Submit(context.Background(), "key", Submission{IOC: "https://example.test/a"})
			if tc.wantErr {
				if err == nil || res != nil {
					t.Fatalf("oversized response returned result=%+v error=%v", res, err)
				}
				if !strings.Contains(err.Error(), "too large") {
					t.Fatalf("error = %v, want sanitized size error", err)
				}
				return
			}
			if err != nil || res == nil || !res.Accepted {
				t.Fatalf("exact-limit response result=%+v error=%v", res, err)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("body-reader-secret") }
