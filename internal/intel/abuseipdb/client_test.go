package abuseipdb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientRejectsUnconfirmedSuccess(t *testing.T) {
	for _, body := range []string{"{}", "null", `{"data":null}`, `{"data":{}}`,
		`{"data":{"abuseConfidenceScore":null}}`, `{"data":{"abuseConfidenceScore":101}}`,
		`{"data":{"abuseConfidenceScore":-1}}`} {
		t.Run(body, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, body)
			}))
			defer upstream.Close()
			result, err := NewClient(upstream.URL).Submit(context.Background(), "key", Submission{IP: "8.8.8.8", Categories: []int{18, 22}})
			if err == nil || result != nil {
				t.Fatalf("unconfirmed success could enter the report ledger: result=%+v err=%v", result, err)
			}
		})
	}
}

func TestClientErrorsDoNotExposeProviderOrEndpointSecrets(t *testing.T) {
	const secret = "sensitive-provider-token-1234"
	for _, status := range []int{http.StatusBadRequest, http.StatusOK} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = io.WriteString(w, secret)
			}))
			defer upstream.Close()
			_, err := NewClient(upstream.URL).Submit(context.Background(), secret, Submission{IP: "8.8.8.8", Categories: []int{18}})
			if err == nil || strings.Contains(err.Error(), secret) {
				t.Fatalf("provider body escaped into diagnostics: %v", err)
			}
		})
	}
	for _, transportErr := range []error{errors.New(secret), fmt.Errorf("%s: %w", secret, context.Canceled)} {
		client := NewClient("https://provider.invalid/report?token=" + secret)
		client.hc.Transport = errorTransport{err: transportErr}
		_, err := client.Submit(context.Background(), secret, Submission{IP: "8.8.8.8", Categories: []int{18}})
		if err == nil || strings.Contains(fmt.Sprintf("%+v", err), secret) {
			t.Fatalf("transport/endpoint secrets escaped into diagnostics: %v", err)
		}
		if errors.Is(transportErr, context.Canceled) && !errors.Is(err, context.Canceled) {
			t.Fatalf("redaction must preserve cancellation identity: %v", err)
		}
	}
}

type errorTransport struct{ err error }

func (t errorTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, t.err }
