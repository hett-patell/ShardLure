// Package enrich provides cached threat-intelligence lookups for IPv4
// addresses observed in the honeypot. Seven providers are supported:
//
//   - AbuseIPDB (key required: SHARDLURE_ABUSEIPDB_KEY)
//   - VirusTotal (key required: SHARDLURE_VT_KEY)
//   - GreyNoise community (no key needed; SHARDLURE_GREYNOISE_KEY may
//     be set to use the paid endpoint instead)
//   - Shodan InternetDB (no key needed; open ports / CPEs / vulns / tags)
//   - AlienVault OTX (key required: SHARDLURE_OTX_KEY; pulse reputation)
//   - IPQualityScore (key required: SHARDLURE_IPQS_KEY; fraud score + proxy/VPN/TOR)
//   - IPinfo (key required: SHARDLURE_IPINFO_KEY; ASN/geo + privacy flags)
//
// All keys are read from environment variables. The package is
// fail-open: missing keys, network errors and non-2xx responses
// produce an empty Result with a populated Error string so callers
// can degrade gracefully rather than 500-ing the whole panel.
//
// Results are cached for 24h in the SQLite ip_enrichment table to
// avoid burning the (small) free-tier rate limits these providers
// give. Callers go through Resolver.Get which transparently uses the
// cache and refreshes lazily when stale.
package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/networkshard/shardlure/internal/store"
)

// CacheTTL is how long a successful lookup stays fresh. Negative
// results re-attempt after the same interval so a transient outage
// doesn't permanently hide intel.
const CacheTTL = 24 * time.Hour

// Result is the normalised per-provider answer rendered in the UI.
// Raw is the unredacted provider JSON so a future enrichment-rules
// engine can drill in without us having to keep extending this struct.
type Result struct {
	Source     string          `json:"source"`
	Configured bool            `json:"configured"`
	Cached     bool            `json:"cached"`
	Stale      bool            `json:"stale"`
	FetchedAt  time.Time       `json:"fetchedAt,omitempty"`
	Score      *int            `json:"score,omitempty"`   // 0-100 where applicable
	Verdict    string          `json:"verdict,omitempty"` // "malicious", "benign", "unknown"…
	ASN        string          `json:"asn,omitempty"`
	ASOwner    string          `json:"asOwner,omitempty"`
	Country    string          `json:"country,omitempty"`
	Tags       []string        `json:"tags,omitempty"`
	Summary    string          `json:"summary,omitempty"`
	URL        string          `json:"url,omitempty"` // link back to provider's web UI
	Error      string          `json:"error,omitempty"`
	Raw        json.RawMessage `json:"raw,omitempty"`
}

// Provider names used in the cache key + UI.
const (
	ProviderAbuseIPDB  = "abuseipdb"
	ProviderVirusTotal = "virustotal"
	ProviderGreyNoise  = "greynoise"
	ProviderShodan     = "shodan"
	ProviderOTX        = "otx"
	ProviderIPQS       = "ipqualityscore"
	ProviderIPinfo     = "ipinfo"
)

// KeyLookup is the minimal contract the Resolver needs to source provider API
// keys. *settings.Keystore satisfies it. Declared here (rather than importing
// settings) so enrich stays a leaf that imports only store — dodging any import
// cycle and preserving the t.Setenv-based tests, which run with Keys == nil.
type KeyLookup interface {
	Get(key string) string
}

// Resolver coordinates cached lookups across all providers.
type Resolver struct {
	St   *store.Store
	HTTP *http.Client
	Now  func() time.Time
	// Keys sources provider API keys at request time so a key saved from the
	// dashboard takes effect without a restart. When nil, providers fall back
	// to os.Getenv via envKey (the historical behaviour, still used by tests).
	Keys KeyLookup
}

// NewResolver returns a Resolver bound to the given event store. The
// HTTP client has a tight per-request timeout; we'd rather degrade
// to "no enrichment" than block a dashboard fetch for 30s on a slow
// provider.
func NewResolver(st *store.Store) *Resolver {
	return &Resolver{
		St:   st,
		HTTP: &http.Client{Timeout: 6 * time.Second},
		Now:  time.Now,
	}
}

// LookupAll fans out to every provider and returns one Result per
// provider, in a stable order. Missing keys yield Configured=false
// results rather than being elided so the UI can prompt the operator
// to add them.
// safeForEnrichment reports whether ip is a well-formed public IP that is safe
// to hand to an outbound provider lookup. This makes the package self-defending
// rather than trusting each caller to validate first: a non-parseable string
// (which could carry path/query-injection like "1.2.3.4/../x" into providers
// that concatenate it into a URL) or an internal/reserved address is rejected
// here, at the single choke point every provider call passes through.
func safeForEnrichment(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsUnspecified() ||
		parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() ||
		parsed.IsMulticast() || parsed.IsInterfaceLocalMulticast() {
		return false
	}
	return true
}

func (r *Resolver) LookupAll(ctx context.Context, ip string) []Result {
	// Self-defense: never issue an outbound provider request for a malformed or
	// internal address, regardless of whether the caller validated. See MED-4.
	parsed := net.ParseIP(ip)
	if parsed == nil || !safeForEnrichment(ip) {
		return []Result{{Source: "enrich", Error: "invalid or non-public IP"}}
	}
	// Canonicalize: providers concatenate this into request URLs, and the cache
	// keys on it. net.IP.String() only ever yields hex/dot/colon characters, so
	// this guarantees no path/query-injection reaches a provider even though
	// several build URLs by string concatenation.
	ip = parsed.String()
	// Run providers concurrently rather than sequentially: each has its own
	// timeout, so seven in series could take ~7×timeout (~42s worst case) for a
	// single enrichment request. Results are written into fixed indices so the
	// returned order stays stable (the dashboard renders them in this order).
	out := make([]Result, len(providers))
	var wg sync.WaitGroup
	wg.Add(len(providers))
	keyFn := r.keyFunc()
	for i, p := range providers {
		go func(i int, p provider) {
			defer wg.Done()
			// Bind the spec + key source into a fetchFn so lookup stays
			// agnostic of how a key is resolved (and remains test-injectable).
			out[i] = r.lookup(ctx, ip, p.source, func(ctx context.Context, hc *http.Client, ip string) (Result, error) {
				return p.spec.fetch(ctx, hc, ip, keyFn)
			})
		}(i, p)
	}
	wg.Wait()
	return out
}

// provider pairs a cache/UI source name with its declarative spec. Adding
// provider #8 is one spec in its own file plus one row here — the fetch
// pipeline, key gating, 404 handling and caching are all shared.
type provider struct {
	source string
	spec   providerSpec
}

var providers = []provider{
	{ProviderAbuseIPDB, abuseIPDBSpec},
	{ProviderVirusTotal, virusTotalSpec},
	{ProviderGreyNoise, greyNoiseSpec},
	{ProviderShodan, shodanSpec},
	{ProviderOTX, otxSpec},
	{ProviderIPQS, ipqsSpec},
	{ProviderIPinfo, ipinfoSpec},
}

// keyFunc returns the API-key resolver for this Resolver: the injected keystore
// when present, else envKey (os.Getenv) so nil-Keys callers and tests behave as
// before.
func (r *Resolver) keyFunc() func(string) string {
	if r.Keys != nil {
		return r.Keys.Get
	}
	return envKey
}

// lookup is the shared cache-then-fetch path for any provider.
func (r *Resolver) lookup(ctx context.Context, ip, source string, fetch fetchFn) Result {
	// Try the cache first regardless of TTL: if the fetch fails later
	// we want to fall back to the cached value, even if stale.
	cached, hit, cacheErr := r.St.GetEnrichment(ip, source)
	if cacheErr != nil {
		// Cache is broken (DB corruption, locked file, schema
		// drift). Don't silently bypass the cache - that turns one
		// DB error into a flood of live API calls. Return a
		// fail-open Result so the UI can show "cache error" once.
		return Result{Source: source, Error: "cache: " + cacheErr.Error()}
	}
	now := r.Now()
	if hit {
		fresh := now.Sub(cached.FetchedAt) < CacheTTL
		if fresh && cached.Payload != "" {
			res := decodeResult(cached.Payload)
			res.Source = source
			res.Cached = true
			res.Stale = false
			res.FetchedAt = cached.FetchedAt
			return res
		}
	}

	// Fetch live.
	res, err := fetch(ctx, r.HTTP, ip)
	res.Source = source
	if err != nil {
		// Surface the failure but keep the panel alive. If we have
		// stale cached data, return that with Stale=true so the UI
		// can show "last seen at X".
		if hit && cached.Payload != "" {
			fallback := decodeResult(cached.Payload)
			fallback.Source = source
			fallback.Cached = true
			fallback.Stale = true
			fallback.FetchedAt = cached.FetchedAt
			fallback.Error = err.Error()
			return fallback
		}
		res.Error = err.Error()
		return res
	}

	// Persist to cache only for genuine, configured, error-free answers.
	//   - !Configured (no API key): caching it pins "not configured" for the
	//     full TTL, so setting a key would have no effect for 24h. The no-key
	//     path costs nothing to recompute, so skip it.
	//   - res.Error != "" (provider-level failure, e.g. IPQS success:false or a
	//     malformed-JSON parse): caching an error as "fresh" hides recovery for
	//     24h. Let the next lookup retry.
	if res.Configured && res.Error == "" {
		if encoded, err := json.Marshal(res); err == nil {
			_ = r.St.PutEnrichment(ip, source, string(encoded))
		}
	}
	res.Cached = false
	res.FetchedAt = now
	return res
}

func decodeResult(payload string) Result {
	var r Result
	_ = json.Unmarshal([]byte(payload), &r)
	return r
}

type fetchFn func(ctx context.Context, hc *http.Client, ip string) (Result, error)

// providerSpec declaratively describes one IP-reputation provider so the
// shared fetch pipeline below can drive all seven identically:
// env-key gate → build request → HTTP GET → status handling (incl. the
// 404-means-no-data special case) → parse. Each provider file supplies a
// spec plus a pure parse function, keeping every provider unit-testable
// without a network round-trip.
type providerSpec struct {
	// envVar names the environment variable holding the provider's API
	// key. "" means the endpoint is keyless (community/free) and the
	// provider is always "configured".
	envVar string
	// keyOptional marks providers whose endpoint works without a key but
	// will use one when present (GreyNoise community). Such providers are
	// always 'configured': Configured=true signals "we can query this
	// provider" rather than "you've supplied a key".
	keyOptional bool
	// buildReq returns the request URL and headers for one lookup. key is
	// "" for keyless providers or when an optional key is unset.
	buildReq func(ip, key string) (url string, headers map[string]string)
	// parse maps a raw 2xx response body onto a Result.
	parse func(raw []byte, ip string) Result
	// notFound, when non-nil, converts a 404 response into a clean Result
	// for providers where 404 means "no data for this IP", not an error.
	notFound func(ip string) Result
}

// fetch is the shared provider pipeline. keyFn resolves the provider's API key
// (from the runtime keystore or os.Getenv); it is never nil (lookup supplies
// envKey as the fallback).
func (s providerSpec) fetch(ctx context.Context, hc *http.Client, ip string, keyFn func(string) string) (Result, error) {
	var key string
	if s.envVar != "" {
		key = strings.TrimSpace(keyFn(s.envVar))
		if key == "" && !s.keyOptional {
			// Missing required key: report "not configured" without ever
			// touching the network, so the UI can prompt the operator to
			// add one.
			return Result{Configured: false, Verdict: "unknown"}, nil
		}
	}
	url, headers := s.buildReq(ip, key)
	// out=nil: spec.parse owns the decode (httpJSON skips the unmarshal),
	// avoiding a redundant double-decode of the body.
	raw, err := httpJSON(ctx, hc, url, headers, nil)
	if err != nil {
		if s.notFound != nil && isHTTPStatus(err, http.StatusNotFound) {
			return s.notFound(ip), nil
		}
		return Result{Configured: true}, err
	}
	return s.parse(raw, ip), nil
}

// helpers shared across providers --------------------------------

// statusError carries the HTTP status code from a non-2xx response so callers
// can branch on the numeric code (e.g. 404 = "no data") rather than matching
// the upstream-supplied, non-canonical reason phrase string.
type statusError struct {
	Code   int
	Status string
}

func (e *statusError) Error() string { return e.Status }

// isHTTPStatus reports whether err is a statusError with the given code.
func isHTTPStatus(err error, code int) bool {
	var se *statusError
	if errors.As(err, &se) {
		return se.Code == code
	}
	return false
}

// httpJSON does a GET with the provided headers and returns the
// decoded body, or an error suitable for surfacing in Result.Error.
// Any non-2xx is reported as a typed error so callers can fall back
// to cached data without trying to parse the response.
func httpJSON(ctx context.Context, hc *http.Client, url string, headers map[string]string, out any) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "ShardLure/0.1 (+honeypot-enrichment)")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return body, &statusError{Code: resp.StatusCode, Status: resp.Status}
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return body, err
		}
	}
	return body, nil
}

// envKey returns the configured API key for a provider or "" if unset.
// Centralised here so tests can stub via t.Setenv.
func envKey(name string) string {
	return os.Getenv(name)
}

// TestProvider performs a one-shot live lookup against a single provider using
// keys as the API-key source, bypassing the 24h cache entirely (it calls the
// provider's fetch directly, never touching the store). It is the backend of
// the dashboard's per-provider "Test connection" button: it validates that the
// currently-configured key is accepted, using a benign public test IP.
//
// Returns (ok, message). ok is true when the provider is reachable AND, for
// keyed providers, the key is accepted (Configured && no error). message is a
// short human-readable status that NEVER contains the key. keys may be nil, in
// which case os.Getenv is used.
func TestProvider(ctx context.Context, hc *http.Client, keys KeyLookup, source, testIP string) (bool, string) {
	var spec *providerSpec
	for i := range providers {
		if providers[i].source == source {
			spec = &providers[i].spec
			break
		}
	}
	if spec == nil {
		return false, "unknown provider"
	}
	if testIP == "" {
		testIP = "1.1.1.1"
	}
	if !safeForEnrichment(testIP) {
		return false, "invalid test IP"
	}
	if hc == nil {
		hc = &http.Client{Timeout: 6 * time.Second}
	}
	keyFn := envKey
	if keys != nil {
		keyFn = keys.Get
	}

	res, err := spec.fetch(ctx, hc, testIP, keyFn)
	if err != nil {
		return false, "unreachable: " + err.Error()
	}
	if !res.Configured {
		return false, "no API key configured"
	}
	if res.Error != "" {
		return false, "provider error: " + res.Error
	}
	return true, "key accepted; provider reachable"
}

// intPtr is a tiny helper so providers can pass a literal count
// without ceremony into Result.Score.
func intPtr(v int) *int { return &v }
