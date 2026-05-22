// Package enrich provides cached threat-intelligence lookups for IPv4
// addresses observed in the honeypot. Three providers are supported:
//
//   - AbuseIPDB (key required: SHARDLURE_ABUSEIPDB_KEY)
//   - VirusTotal (key required: SHARDLURE_VT_KEY)
//   - GreyNoise community (no key needed; SHARDLURE_GREYNOISE_KEY may
//     be set to use the paid endpoint instead)
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
	"net/http"
	"os"
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
	Score      *int            `json:"score,omitempty"`     // 0-100 where applicable
	Verdict    string          `json:"verdict,omitempty"`   // "malicious", "benign", "unknown"…
	ASN        string          `json:"asn,omitempty"`
	ASOwner    string          `json:"asOwner,omitempty"`
	Country    string          `json:"country,omitempty"`
	Tags       []string        `json:"tags,omitempty"`
	Summary    string          `json:"summary,omitempty"`
	URL        string          `json:"url,omitempty"`     // link back to provider's web UI
	Error      string          `json:"error,omitempty"`
	Raw        json.RawMessage `json:"raw,omitempty"`
}

// Provider names used in the cache key + UI.
const (
	ProviderAbuseIPDB  = "abuseipdb"
	ProviderVirusTotal = "virustotal"
	ProviderGreyNoise  = "greynoise"
)

// Resolver coordinates cached lookups across all providers.
type Resolver struct {
	St     *store.Store
	HTTP   *http.Client
	Now    func() time.Time
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
func (r *Resolver) LookupAll(ctx context.Context, ip string) []Result {
	return []Result{
		r.lookup(ctx, ip, ProviderAbuseIPDB, fetchAbuseIPDB),
		r.lookup(ctx, ip, ProviderVirusTotal, fetchVirusTotal),
		r.lookup(ctx, ip, ProviderGreyNoise, fetchGreyNoise),
	}
}

// lookup is the shared cache-then-fetch path for any provider.
func (r *Resolver) lookup(ctx context.Context, ip, source string, fetch fetchFn) Result {
	// Try the cache first regardless of TTL: if the fetch fails later
	// we want to fall back to the cached value, even if stale.
	cached, hit, _ := r.St.GetEnrichment(ip, source)
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

	// Persist to cache only if we got a non-error response. Negative
	// results (configured=false / no data) are still worth caching so
	// repeated lookups don't keep hitting an unconfigured provider.
	if encoded, err := json.Marshal(res); err == nil {
		_ = r.St.PutEnrichment(ip, source, string(encoded))
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

// helpers shared across providers --------------------------------

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
		return body, errors.New(resp.Status)
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

// intPtr is a tiny helper so providers can pass a literal count
// without ceremony into Result.Score.
func intPtr(v int) *int { return &v }
