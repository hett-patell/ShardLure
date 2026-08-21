package web

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/networkshard/shardlure/internal/intel/bazaar"
	"github.com/networkshard/shardlure/internal/intel/urlhaus"
)

// urlhausSubmissionRow is one recorded submission, shaped for the UI.
type urlhausSubmissionRow struct {
	URL         string `json:"url"`
	Status      string `json:"status"`
	SubmittedAt string `json:"submittedAt"`
}

// urlhausCandidateRow is one artifact URL considered for submission, together
// with the vetting gate's decision. Showing the REASON a URL was held back is
// the point: it makes the policy legible instead of silently dropping rows.
type urlhausCandidateRow struct {
	URL       string `json:"url"`
	SHA256    string `json:"sha256,omitempty"`
	SizeBytes int64  `json:"sizeBytes"`
	FileKind  string `json:"fileKind,omitempty"`
	FetchedAt string `json:"fetchedAt,omitempty"`
	Eligible  bool   `json:"eligible"`
	Reason    string `json:"reason,omitempty"`
}

type urlhausResponse struct {
	GeneratedAt string `json:"generatedAt"`
	// Configured reports whether an abuse.ch Auth-Key is available. URLhaus
	// shares the MalwareBazaar key (one key per abuse.ch account), so a
	// bazaar-configured deployment is URLhaus-ready.
	Configured bool `json:"configured"`
	// TotalSubmitted / Pending mirror the bazaar widget's shape. Pending is the
	// SQL-side structural estimate; Eligible below is the authoritative count
	// after the full vetting gate has run.
	TotalSubmitted int `json:"totalSubmitted"`
	Pending        int `json:"pending"`
	Eligible       int `json:"eligible"`
	// ActiveDays is the liveness window used for candidate selection.
	ActiveDays      int                    `json:"activeDays"`
	LastSubmittedAt string                 `json:"lastSubmittedAt,omitempty"`
	Candidates      []urlhausCandidateRow  `json:"candidates"`
	Rows            []urlhausSubmissionRow `json:"rows"`
}

// maxURLhausCandidates bounds how many artifacts we classify per request.
// Classify reads each file's header off disk, so this is the knob that keeps a
// dashboard poll from turning into unbounded IO.
const maxURLhausCandidates = 50

// urlhausCandidates loads artifact rows and runs the real vetting gate over
// them. Shared by the read endpoint and the submit endpoint so the list the
// operator sees is exactly the list that would be submitted.
func (s *Server) urlhausCandidates(activeDays int) ([]urlhaus.Candidate, []urlhausCandidateRow, error) {
	rows, err := s.st.URLhausCandidates(activeDays, maxURLhausCandidates)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	cands := make([]urlhaus.Candidate, 0, len(rows))
	view := make([]urlhausCandidateRow, 0, len(rows))
	for _, r := range rows {
		// The classifier's file kind is required by Vet (it rejects SSH keys
		// and unclassifiable blobs), and it costs a bounded header read.
		kind := ""
		if r.LocalPath != "" {
			if cls, cerr := bazaar.Classify(r.LocalPath); cerr == nil {
				kind = cls.FileKind
			}
		}
		c := urlhaus.Candidate{
			URL:       r.URL,
			SHA256:    r.SHA256,
			SizeBytes: r.SizeBytes,
			Origin:    r.Origin,
			Status:    r.Status,
			FetchedAt: r.FetchedAt,
			FileKind:  kind,
		}
		ok, reason := urlhaus.Vet(c, now, urlhaus.VetOptions{ActiveDays: activeDays})
		vr := urlhausCandidateRow{
			URL:       c.URL,
			SHA256:    c.SHA256,
			SizeBytes: c.SizeBytes,
			FileKind:  kind,
			Eligible:  ok,
			Reason:    reason,
		}
		if !c.FetchedAt.IsZero() {
			vr.FetchedAt = c.FetchedAt.UTC().Format(time.RFC3339)
		}
		view = append(view, vr)
		if ok {
			cands = append(cands, c)
		}
	}
	return cands, view, nil
}

// urlhausActiveDaysFromQuery resolves the liveness window: an explicit
// ?activeDays= query param wins; otherwise the operator-configured Settings
// value (urlhausActiveDaysLive) applies. Previously this hard-defaulted to 3,
// which meant the Settings "Active window (days)" knob was silently ignored —
// an operator tightening it to 1 saw no change in the panel.
func (s *Server) urlhausActiveDaysFromQuery(raw string) int {
	if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 3 {
		return n
	}
	return s.urlhausActiveDaysLive()
}

// handleIntelURLhaus reports URLhaus sharing state: how many malware-
// distribution URLs we've submitted, which are eligible now (with the vetting
// gate's reason for anything held back), and the recent submission log.
// Read-only — it never contacts URLhaus.
func (s *Server) handleIntelURLhaus(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	activeDays := s.urlhausActiveDaysFromQuery(r.URL.Query().Get("activeDays"))
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		if n > 500 {
			n = 500
		}
		limit = n
	}

	stats, err := s.st.URLhausSubmissionStats(activeDays)
	if err != nil {
		httpError(w, "api_urlhaus", err, http.StatusInternalServerError)
		return
	}
	subs, err := s.st.ListURLhausSubmissions(limit)
	if err != nil {
		httpError(w, "api_urlhaus", err, http.StatusInternalServerError)
		return
	}
	eligible, candidateView, err := s.urlhausCandidates(activeDays)
	if err != nil {
		httpError(w, "api_urlhaus", err, http.StatusInternalServerError)
		return
	}

	out := urlhausResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		// One abuse.ch account issues one Auth-Key covering both
		// MalwareBazaar and URLhaus, so this is the same key the bazaar
		// panel reports on.
		Configured:     s.abuseCHKeyLive() != "",
		TotalSubmitted: stats.TotalSubmitted,
		Pending:        stats.Pending,
		Eligible:       len(eligible),
		ActiveDays:     activeDays,
		Candidates:     candidateView,
		Rows:           make([]urlhausSubmissionRow, 0, len(subs)),
	}
	if !stats.LastSubmittedAt.IsZero() {
		out.LastSubmittedAt = stats.LastSubmittedAt.UTC().Format(time.RFC3339)
	}
	for _, u := range subs {
		out.Rows = append(out.Rows, urlhausSubmissionRow{
			URL:         u.URL,
			Status:      u.Status,
			SubmittedAt: u.SubmittedAt.UTC().Format(time.RFC3339),
		})
	}
	_ = json.NewEncoder(w).Encode(out)
}

type urlhausSubmitResponse struct {
	Status    string `json:"status"`
	Submitted int    `json:"submitted"`
	Skipped   int    `json:"skipped"`
	Error     string `json:"error,omitempty"`
}

// handleURLhausSubmit submits every currently-eligible URL to URLhaus.
//
// The vetting gate is NOT re-implemented here: urlhausCandidates() runs the
// same urlhaus.Vet the CLI uses, and urlhaus.Share re-checks dedup, so the
// button can only ever send what `shardlure share urlhaus` would send.
//
// A single URL can be targeted with ?url=... — used by the per-row button.
func (s *Server) handleURLhausSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	apiKey := s.abuseCHKeyLive()
	if apiKey == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(urlhausSubmitResponse{
			Status: "error",
			Error:  "no abuse.ch Auth-Key configured (the MalwareBazaar key in Settings covers URLhaus too)",
		})
		return
	}

	activeDays := s.urlhausActiveDaysFromQuery(r.URL.Query().Get("activeDays"))
	cands, _, err := s.urlhausCandidates(activeDays)
	if err != nil {
		httpError(w, "api_urlhaus", err, http.StatusInternalServerError)
		return
	}

	// Per-row submission: narrow to the requested URL, but only if it passed
	// the gate above — a hand-crafted request can't bypass policy.
	if only := r.URL.Query().Get("url"); only != "" {
		filtered := cands[:0]
		for _, c := range cands {
			if c.URL == only {
				filtered = append(filtered, c)
			}
		}
		cands = filtered
		if len(cands) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(urlhausSubmitResponse{
				Status: "error",
				Error:  "URL is not an eligible candidate (already submitted, stale, or rejected by policy)",
			})
			return
		}
	}

	if len(cands) == 0 {
		_ = json.NewEncoder(w).Encode(urlhausSubmitResponse{Status: "ok", Submitted: 0, Skipped: 0})
		return
	}

	// Guard against concurrent batches (double-click, script loop): a second
	// run would race the dedup ledger and could double-submit.
	if !s.urlhausBatchMu.TryLock() {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(urlhausSubmitResponse{
			Status: "error", Error: "a submission batch is already in progress",
		})
		return
	}
	defer s.urlhausBatchMu.Unlock()

	submitted, skipped, ferr := urlhaus.Share(r.Context(), s.st, cands, urlhaus.Options{
		APIKey:     apiKey,
		Endpoint:   s.urlhausEndpointLive(),
		ExtraTags:  s.urlhausTagsLive(),
		ActiveDays: activeDays,
		Anonymous:  s.urlhausAnonymousLive(),
	})

	resp := urlhausSubmitResponse{Status: "ok", Submitted: submitted, Skipped: skipped}
	switch {
	case errors.Is(ferr, urlhaus.ErrUnauthorized):
		log.Printf("web: urlhaus submit: %v", ferr)
		resp.Status = "error"
		resp.Error = "abuse.ch rejected the Auth-Key"
	case ferr != nil:
		log.Printf("web: urlhaus submit: %v", ferr)
		if submitted > 0 {
			resp.Status = "partial"
		} else {
			resp.Status = "error"
		}
		resp.Error = "some submissions failed — see server logs"
	}
	_ = json.NewEncoder(w).Encode(resp)
}
