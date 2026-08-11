package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/intel/vt"
	"github.com/networkshard/shardlure/internal/store"
)

// vtCacheAdapter bridges *store.Store's PayloadIntel API to the narrower
// interface the vt package declares, keeping vt free of a store import (the
// same pattern as bazaarRecorderAdapter in cmd).
type vtCacheAdapter struct{ st *store.Store }

func (a vtCacheAdapter) GetPayloadIntel(sha, source string) (string, time.Time, bool, error) {
	rec, found, err := a.st.GetPayloadIntel(sha, source)
	return rec.Payload, rec.FetchedAt, found, err
}

func (a vtCacheAdapter) PutPayloadIntel(sha, source, payload string) error {
	return a.st.PutPayloadIntel(sha, source, payload)
}

// vtResolver lazily builds the resolver on first use. Lazy because building it
// touches the keystore, and the server is constructed before settings are
// necessarily seeded.
//
// Note the deliberate asymmetry with bazaar/urlhaus: those expose an endpoint
// override in Settings, VirusTotal does NOT. s.vtEndpoint is a test-only seam.
// An operator-settable endpoint for a service we send an API key to is a
// key-exfiltration path (point it at attacker-controlled host, receive the
// x-apikey header), and unlike the abuse.ch endpoints there is no operational
// reason to ever change it.
func (s *Server) vtResolver() *vt.Resolver {
	s.vtOnce.Do(func() {
		s.vt = vt.NewResolver(vtCacheAdapter{st: s.st}, s.keys, s.vtEndpoint)
	})
	return s.vt
}

// vtVerdictResponse is the single-hash lookup response.
type vtVerdictResponse struct {
	GeneratedAt string `json:"generatedAt"`
	Configured  bool   `json:"configured"`
	// Verdict is omitted when Configured is false or the lookup failed.
	Verdict *vt.Verdict `json:"verdict,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// handleIntelPayloadVT looks up ONE payload hash on VirusTotal.
//
// This is an explicitly on-demand endpoint (analyst opens a payload), never
// called from a poll loop: VirusTotal's free tier allows roughly 4 requests
// per minute, so a background sweep would burn the quota and return nothing.
// Verdicts are cached for 30 days (7 for "not found"), which is safe because a
// file hash is immutable.
func (s *Server) handleIntelPayloadVT(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	sha := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sha")))
	if sha == "" {
		httpError(w, "api_vt", errors.New("missing sha parameter"), http.StatusBadRequest)
		return
	}

	res := s.vtResolver()
	out := vtVerdictResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Configured:  res.Configured(),
	}

	// cache=1 returns only what's already stored, never spending quota. The UI
	// uses this when merely rendering a row.
	if r.URL.Query().Get("cache") == "1" {
		if v, ok := res.Cached(sha); ok {
			out.Verdict = &v
		}
		_ = json.NewEncoder(w).Encode(out)
		return
	}

	if !out.Configured {
		out.Error = "no VirusTotal API key configured"
		_ = json.NewEncoder(w).Encode(out)
		return
	}

	// Bound the live call so a slow upstream can't pin a dashboard request.
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	v, err := res.Lookup(ctx, sha)
	if err != nil {
		// Report the failure in-band with HTTP 200: the panel wants to render
		// "rate limited, try later" next to the payload, not a broken widget.
		switch {
		case errors.Is(err, vt.ErrRateLimited):
			out.Error = "rate limited by VirusTotal (free tier ~4 requests/minute) — try again shortly"
		case errors.Is(err, vt.ErrUnauthorized):
			out.Error = "VirusTotal rejected the API key"
		case errors.Is(err, vt.ErrBadHash):
			out.Error = "not a sha256 hash"
		case errors.Is(err, vt.ErrMissingAPIKey):
			out.Error = "no VirusTotal API key configured"
		default:
			out.Error = err.Error()
		}
		_ = json.NewEncoder(w).Encode(out)
		return
	}
	out.Verdict = &v
	_ = json.NewEncoder(w).Encode(out)
}

// vtBulkResponse maps sha256 -> cached verdict.
type vtBulkResponse struct {
	GeneratedAt string                `json:"generatedAt"`
	Configured  bool                  `json:"configured"`
	Verdicts    map[string]vt.Verdict `json:"verdicts"`
}

// handleIntelPayloadsVTCached decorates a page of payloads with verdicts that
// are ALREADY cached. Deliberately cache-only and single-query: it exists so
// the payload list can show VT badges without either an N+1 of point lookups
// or any live API traffic. Populating the cache is the single-hash endpoint's
// job, driven by an analyst clicking a row.
func (s *Server) handleIntelPayloadsVTCached(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	raw := r.URL.Query().Get("shas")
	var shas []string
	for _, part := range strings.Split(raw, ",") {
		if p := strings.ToLower(strings.TrimSpace(part)); p != "" {
			shas = append(shas, p)
		}
	}
	out := vtBulkResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Configured:  s.vtResolver().Configured(),
		Verdicts:    map[string]vt.Verdict{},
	}
	if len(shas) == 0 {
		_ = json.NewEncoder(w).Encode(out)
		return
	}
	recs, err := s.st.PayloadIntelBySource(vt.Source, shas)
	if err != nil {
		httpError(w, "api_vt", err, http.StatusInternalServerError)
		return
	}
	for sha, rec := range recs {
		var v vt.Verdict
		if err := json.Unmarshal([]byte(rec.Payload), &v); err != nil {
			continue
		}
		if v.FetchedAt.IsZero() {
			v.FetchedAt = rec.FetchedAt
		}
		v.Cached = true
		out.Verdicts[sha] = v
	}
	_ = json.NewEncoder(w).Encode(out)
}
