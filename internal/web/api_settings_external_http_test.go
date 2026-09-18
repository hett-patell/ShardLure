package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/networkshard/shardlure/internal/settings"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestIPAPITestTransportErrorDoesNotExposeCredentialBearingURL(t *testing.T) {
	const secret = "ip-api-secret-that-must-not-leak"
	s := newIntelTestServer(t, map[string]string{settings.KeyIPAPI: secret})
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, &url.Error{
			Op:  "Get",
			URL: r.URL.String(),
			Err: errors.New("connection refused"),
		}
	})}

	ok, msg := s.testIPAPIWithClient(context.Background(), "1.1.1.1", client)
	if ok {
		t.Fatal("transport failure reported success")
	}
	if want := "unreachable: transport error"; msg != want {
		t.Fatalf("message = %q, want %q", msg, want)
	}
	for _, forbidden := range []string{secret, "pro.ip-api.com", "/json/1.1.1.1", "?key="} {
		if strings.Contains(msg, forbidden) {
			t.Errorf("message leaked %q: %q", forbidden, msg)
		}
	}
}

func TestSettingsTestMessageDoesNotEchoExternalResponseBody(t *testing.T) {
	const secret = "provider-response-secret"
	got := safeSettingsTestMessage("provider error: upstream rejected key=" + secret)
	if want := "provider returned an error"; got != want {
		t.Fatalf("message = %q, want %q", got, want)
	}
	if strings.Contains(got, secret) {
		t.Errorf("message leaked upstream response body: %q", got)
	}
}
