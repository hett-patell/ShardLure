package vt

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

type privateFailureTransport struct{}

func (privateFailureTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("/inert/private/path token=inert-secret")
}
func TestDiagnosticPrivacyTransport(t *testing.T) {
	c := NewClient("http://example.test/?token=inert-secret&sha=")
	c.hc.Transport = privateFailureTransport{}
	_, err := c.Lookup(context.Background(), "inert-key", strings.Repeat("a", 64))
	if err == nil || strings.Contains(err.Error(), "inert-secret") || strings.Contains(err.Error(), "/inert/private/path") {
		t.Fatalf("private transport diagnostic escaped: %v", err)
	}
}
