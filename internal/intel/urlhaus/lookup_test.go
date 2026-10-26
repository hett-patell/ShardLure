package urlhaus

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// lookupServer answers the read-only URL query endpoint and records what it saw.
type lookupServer struct {
	*httptest.Server
	status  int
	reply   string
	authKey string
	formURL string
	method  string
	hits    int
}

func newLookupServer(t *testing.T, reply string) *lookupServer {
	t.Helper()
	ls := &lookupServer{status: http.StatusOK, reply: reply}
	ls.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ls.hits++
		ls.method = r.Method
		ls.authKey = r.Header.Get("Auth-Key")
		_ = r.ParseForm()
		ls.formURL = r.PostFormValue("url")
		w.WriteHeader(ls.status)
		_, _ = w.Write([]byte(ls.reply))
	}))
	t.Cleanup(ls.Close)
	return ls
}

// The lookup is the duplicate pre-check: "ok" means URLhaus already lists the
// URL, "no_results" means it does not. Both are answers, not errors.
func TestListedReportsListedAndUnknownURLs(t *testing.T) {
	listed := newLookupServer(t, `{"query_status":"ok","url_status":"online"}`)
	c := NewClientWithLookup("", listed.URL)
	got, err := c.Listed(context.Background(), "key", "http://evil.tld/a")
	if err != nil {
		t.Fatalf("Listed(listed): %v", err)
	}
	if !got {
		t.Error("query_status=ok must report listed")
	}
	if listed.method != http.MethodPost {
		t.Errorf("method = %q, want POST", listed.method)
	}
	if listed.authKey != "key" {
		t.Errorf("Auth-Key = %q, want key", listed.authKey)
	}
	if listed.formURL != "http://evil.tld/a" {
		t.Errorf("url form field = %q", listed.formURL)
	}

	unknown := newLookupServer(t, `{"query_status":"no_results"}`)
	c = NewClientWithLookup("", unknown.URL)
	got, err = c.Listed(context.Background(), "key", "http://evil.tld/b")
	if err != nil {
		t.Fatalf("Listed(unknown): %v", err)
	}
	if got {
		t.Error("query_status=no_results must report not listed")
	}
}

// An auth failure is a sentinel so Share can stop the run; every other bad
// answer is an error so the candidate is skipped, never assumed unknown.
func TestListedRejectsAuthFailuresAndBadAnswers(t *testing.T) {
	authJSON := newLookupServer(t, `{"query_status":"invalid_auth_key"}`)
	if _, err := NewClientWithLookup("", authJSON.URL).Listed(context.Background(), "key", "http://evil.tld/a"); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("invalid_auth_key error = %v, want ErrUnauthorized", err)
	}

	unauthorized := newLookupServer(t, "")
	unauthorized.status = http.StatusUnauthorized
	if _, err := NewClientWithLookup("", unauthorized.URL).Listed(context.Background(), "key", "http://evil.tld/a"); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("HTTP 401 error = %v, want ErrUnauthorized", err)
	}

	failing := newLookupServer(t, "")
	failing.status = http.StatusServiceUnavailable
	if _, err := NewClientWithLookup("", failing.URL).Listed(context.Background(), "key", "http://evil.tld/a"); err == nil {
		t.Error("HTTP 503 must be an error")
	}

	// An unrecognised status word is an error, and the raw word must not be
	// able to smuggle a URL or markup into the error text.
	weird := newLookupServer(t, `{"query_status":"already_queued:http://evil.tld/a"}`)
	_, err := NewClientWithLookup("", weird.URL).Listed(context.Background(), "key", "http://evil.tld/a")
	if err == nil {
		t.Fatal("unknown query_status must fail closed")
	}
	if strings.Contains(err.Error(), "evil.tld") {
		t.Errorf("provider status word leaked into error: %v", err)
	}

	notJSON := newLookupServer(t, "provider-secret-not-json")
	_, err = NewClientWithLookup("", notJSON.URL).Listed(context.Background(), "key", "http://evil.tld/a")
	if err == nil {
		t.Fatal("malformed 2xx response must fail closed")
	}
	if strings.Contains(err.Error(), "provider-secret-not-json") {
		t.Errorf("provider body leaked into error: %v", err)
	}
}

func TestListedRejectsEmptyInputs(t *testing.T) {
	c := NewClientWithLookup("", "http://127.0.0.1:1/unused")
	if _, err := c.Listed(context.Background(), "", "http://evil.tld/a"); !errors.Is(err, ErrMissingAPIKey) {
		t.Errorf("empty key error = %v, want ErrMissingAPIKey", err)
	}
	if _, err := c.Listed(context.Background(), "key", " "); !errors.Is(err, ErrMissingURL) {
		t.Errorf("empty URL error = %v, want ErrMissingURL", err)
	}
}

func TestClientDefaultsLookupEndpoint(t *testing.T) {
	if got := NewClient("").lookupEndpoint; got != DefaultLookupEndpoint {
		t.Errorf("lookup endpoint = %q, want default", got)
	}
}

// A provider failure must be summarisable for the operator log without a URL,
// key or upstream free text.
func TestFailureSummaryNamesOnlySafeCategories(t *testing.T) {
	if got := FailureSummary(ErrUnauthorized); got != "abuse.ch rejected the Auth-Key" {
		t.Errorf("auth summary = %q", got)
	}
	if got := FailureSummary(&ProviderError{Operation: "submit", Kind: ProviderErrorHTTP, HTTPStatus: 503}); got != "URLhaus returned HTTP 503" {
		t.Errorf("http summary = %q", got)
	}
	if got := FailureSummary(&ProviderError{Operation: "submit", Kind: ProviderErrorRejected}); got != "URLhaus rejected the submission" {
		t.Errorf("rejected summary = %q", got)
	}
	if got := FailureSummary(&ProviderError{Operation: "submit", Kind: ProviderErrorInvalidResponse}); got != "URLhaus returned an unreadable response" {
		t.Errorf("invalid summary = %q", got)
	}
	// A listing-check failure must not read as if a submission failed.
	if got := FailureSummary(&ProviderError{Operation: "lookup", Kind: ProviderErrorHTTP, HTTPStatus: 503}); got != "the listing check returned HTTP 503" {
		t.Errorf("lookup http summary = %q", got)
	}
	if got := FailureSummary(&ProviderError{Operation: "lookup", Kind: ProviderErrorRejected}); got != "URLhaus rejected the listing check" {
		t.Errorf("lookup rejected summary = %q", got)
	}
	if got := FailureSummary(context.Canceled); got != "request was canceled" {
		t.Errorf("canceled summary = %q", got)
	}
	if got := FailureSummary(errors.New("inert-private-key /inert/private/path")); got != "local storage error" {
		t.Errorf("local summary = %q", got)
	}
}
