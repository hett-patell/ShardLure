package urlhaus

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/intel/intelutil"
	"github.com/networkshard/shardlure/internal/observability"
)

// DefaultLookupEndpoint is URLhaus's read-only URL query API. It is a
// different host and path from DefaultEndpoint (bulk submission): the lookup
// answers whether a URL is already on record, which is how Share avoids
// submitting duplicates. A batch containing URLs another reporter already
// listed came back in a shape the submission parser refuses — the whole batch
// failed and nothing was recorded (2026-10 production run: 31 of 32
// candidates were already listed).
const DefaultLookupEndpoint = "https://urlhaus-api.abuse.ch/v1/url/"

// ErrMissingURL is returned when a lookup is asked about an empty URL.
var ErrMissingURL = errors.New("urlhaus: missing URL")

// lookupTimeout bounds one read-only query. The shared client's 30 s is meant
// for a submission; a stale lookup endpoint must not add 30 s per candidate to
// a batch.
const lookupTimeout = 10 * time.Second

// lookupFailureIsSystemic reports whether a failed listing check means the
// endpoint (or our reachability of it) is failing, rather than this one URL.
// The query API answers a per-URL rejection for a URL it cannot parse
// (invalid_url or an unknown query_status); three of those at the head of the
// newest-first candidate list must not block every later candidate. Transport
// failures, unreadable or oversized responses, per-lookup timeouts, HTTP 429
// and 5xx are endpoint failures; other 4xx answers are treated as per-URL
// (401/403 never reach here — Share stops the run on auth failures).
func lookupFailureIsSystemic(err error) bool {
	var pe *ProviderError
	if errors.As(err, &pe) {
		switch pe.Kind {
		case ProviderErrorTransport, ProviderErrorInvalidResponse:
			return true
		case ProviderErrorHTTP:
			return pe.HTTPStatus == http.StatusTooManyRequests || pe.HTTPStatus >= 500
		default:
			return false
		}
	}
	return errors.Is(err, intelutil.ErrResponseTooLarge) ||
		errors.Is(err, context.DeadlineExceeded)
}

// Listed reports whether URLhaus already has targetURL on record. It is a
// read-only query (POST url=...), never a submission.
//
// The documented replies are query_status "ok" (the URL is listed) and
// "no_results" (it is not). Anything else — an auth failure, an HTTP error, an
// unknown status word, an unparseable body — is returned as an error so the
// caller fails closed: a URL we could not check is not submitted, because one
// duplicate is what made the submission batch unreadable.
func (c *Client) Listed(ctx context.Context, apiKey, targetURL string) (listed bool, resultErr error) {
	ctx, trace := observability.TraceRequest(ctx, observability.URLhaus, observability.Lookup)
	defer func() {
		// A 200 body carrying invalid_auth_key is still an auth failure; say
		// so in the metric instead of classifying it as an invalid response.
		if errors.Is(resultErr, ErrUnauthorized) {
			trace.Finish(resultErr, observability.Unauthorized)
			return
		}
		trace.Finish(resultErr)
	}()
	if strings.TrimSpace(apiKey) == "" {
		return false, ErrMissingAPIKey
	}
	if strings.TrimSpace(targetURL) == "" {
		return false, ErrMissingURL
	}
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	form := url.Values{"url": {targetURL}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.lookupEndpoint, strings.NewReader(form))
	if err != nil {
		return false, errors.New("urlhaus: invalid lookup endpoint")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Auth-Key", apiKey)
	req.Header.Set("Accept", "application/json")

	observability.StartHTTP(ctx)
	resp, err := c.hc.Do(req)
	observability.HTTPResult(ctx, resp, err)
	if err != nil {
		serr := intelutil.SafeRequestError("urlhaus", "lookup", err)
		if errors.Is(serr, context.Canceled) || errors.Is(serr, context.DeadlineExceeded) {
			return false, serr
		}
		return false, &ProviderError{Operation: "lookup", Kind: ProviderErrorTransport}
	}
	defer resp.Body.Close()

	raw, err := intelutil.ReadBoundedResponse("urlhaus", resp.Body, 256<<10)
	if err != nil {
		if errors.Is(err, intelutil.ErrResponseTooLarge) ||
			errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return false, err
		}
		return false, &ProviderError{Operation: "lookup", Kind: ProviderErrorTransport}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return false, ErrUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return false, &ProviderError{Operation: "lookup", Kind: ProviderErrorHTTP, HTTPStatus: resp.StatusCode}
	}

	var parsed struct {
		QueryStatus string `json:"query_status"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return false, &ProviderError{Operation: "lookup", Kind: ProviderErrorInvalidResponse}
	}
	status := strings.ToLower(strings.TrimSpace(parsed.QueryStatus))
	switch status {
	case "ok":
		return true, nil
	case "no_results":
		return false, nil
	case "invalid_auth_key", "unauthorized", "illegal_auth_key", "no_auth_key":
		return false, ErrUnauthorized
	default:
		return false, &ProviderError{Operation: "lookup", Kind: ProviderErrorRejected}
	}
}
