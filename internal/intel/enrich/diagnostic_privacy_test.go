package enrich

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
	_, err := httpJSON(context.Background(), &http.Client{Transport: privateFailureTransport{}}, "http://example.test/?token=inert-secret", nil, nil)
	if err == nil || strings.Contains(err.Error(), "inert-secret") || strings.Contains(err.Error(), "/inert/private/path") {
		t.Fatalf("private transport diagnostic escaped: %v", err)
	}
}
