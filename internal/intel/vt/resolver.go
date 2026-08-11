package vt

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// Cache is the slice of *store.Store this package needs. Declared as an
// interface so vt never imports store, matching the decoupling used by
// bazaar (UploadRecorder) and abuseipdb (ReportRecorder).
type Cache interface {
	GetPayloadIntel(sha, source string) (payload string, fetchedAt time.Time, found bool, err error)
	PutPayloadIntel(sha, source, payload string) error
}

// KeyLookup resolves the API key at request time so a key saved in the
// dashboard Settings panel takes effect without a restart.
type KeyLookup interface {
	Get(key string) string
}

// KeyEnvVar is the settings/env key holding the VirusTotal API key. Shared
// with the IP-side enrichment provider: one VT account covers both.
const KeyEnvVar = "SHARDLURE_VT_KEY"

// Resolver is the cache-then-fetch entry point used by the web layer.
type Resolver struct {
	Cache    Cache
	Keys     KeyLookup
	Client   *Client
	Now      func() time.Time
	inflight sync.Map // sha -> *sync.Once, collapses concurrent lookups
}

// NewResolver builds a Resolver with sane defaults.
func NewResolver(cache Cache, keys KeyLookup, endpoint string) *Resolver {
	return &Resolver{
		Cache:  cache,
		Keys:   keys,
		Client: NewClient(endpoint),
		Now:    time.Now,
	}
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Configured reports whether an API key is available. The UI uses this to
// show an "add a VirusTotal key" prompt instead of an error.
func (r *Resolver) Configured() bool {
	return r.Keys != nil && r.Keys.Get(KeyEnvVar) != ""
}

// Cached returns a cached verdict without ever touching the network. The web
// layer uses this to decorate a list of payloads: with only ~4 requests/minute
// available, a list view must never trigger live lookups.
func (r *Resolver) Cached(sha string) (Verdict, bool) {
	if r.Cache == nil {
		return Verdict{}, false
	}
	payload, fetchedAt, found, err := r.Cache.GetPayloadIntel(sha, Source)
	if err != nil || !found || payload == "" {
		return Verdict{}, false
	}
	var v Verdict
	if err := json.Unmarshal([]byte(payload), &v); err != nil {
		return Verdict{}, false
	}
	// Self-heal a stale cache FORMAT. A row written by an older field naming
	// still decodes cleanly (encoding/json ignores unknown keys) but yields an
	// empty Verdict — which would render as a blank badge forever, since the
	// TTL is 30 days. Treating that as a miss re-fetches once and rewrites the
	// row in the current format, so no migration is needed.
	if v.Verdict == "" {
		return Verdict{}, false
	}
	if v.FetchedAt.IsZero() {
		v.FetchedAt = fetchedAt
	}
	v.Cached = true
	return v, true
}

// Lookup returns the verdict for one hash, preferring a fresh cache entry.
//
// On a live-fetch error a STALE cached verdict is returned instead of the
// error: a transient rate-limit must not blank out a verdict the analyst
// already had. Only successful lookups are written to the cache, so a 429
// never poisons it for the whole TTL.
func (r *Resolver) Lookup(ctx context.Context, sha string) (Verdict, error) {
	if cached, ok := r.Cached(sha); ok && !Expired(cached, r.now()) {
		return cached, nil
	}
	if !r.Configured() {
		return Verdict{}, ErrMissingAPIKey
	}

	// Collapse concurrent lookups of the same hash (two analysts opening the
	// same payload) into one API call — the quota is far too small to waste.
	onceAny, _ := r.inflight.LoadOrStore(sha, &sync.Once{})
	once := onceAny.(*sync.Once)
	var (
		fresh *Verdict
		ferr  error
		ran   bool
	)
	once.Do(func() {
		ran = true
		defer r.inflight.Delete(sha)
		fresh, ferr = r.Client.Lookup(ctx, r.Keys.Get(KeyEnvVar), sha)
		if ferr == nil && fresh != nil && r.Cache != nil {
			if payload, mErr := json.Marshal(fresh); mErr == nil {
				// A cache-write failure is deliberately non-fatal: we already
				// spent one of the ~4 requests/minute and hold a good verdict,
				// so returning it beats failing the lookup over a DB hiccup.
				// The only cost is that the next lookup re-fetches.
				_ = r.Cache.PutPayloadIntel(sha, Source, string(payload))
			}
		}
	})
	if !ran {
		// Another goroutine performed the fetch; read what it stored.
		if cached, ok := r.Cached(sha); ok {
			return cached, nil
		}
	}
	if ferr != nil {
		// Fall back to a stale cached value rather than surfacing a transient
		// failure as "no data".
		if cached, ok := r.Cached(sha); ok {
			cached.Cached = true
			return cached, nil
		}
		return Verdict{}, ferr
	}
	if fresh == nil {
		return Verdict{}, errors.New("vt: empty verdict")
	}
	return *fresh, nil
}
