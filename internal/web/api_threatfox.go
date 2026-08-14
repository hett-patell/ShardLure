package web

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/networkshard/shardlure/internal/intel/bazaar"
	"github.com/networkshard/shardlure/internal/intel/threatfox"
)

// threatfoxSubmissionRow is one recorded IOC submission, shaped for the UI.
type threatfoxSubmissionRow struct {
	IOC         string `json:"ioc"`
	IOCType     string `json:"iocType"`
	Malware     string `json:"malware"`
	Status      string `json:"status"`
	SubmittedAt string `json:"submittedAt"`
}

// threatfoxCandidateRow is one confirmed-fetch artifact considered for IOC
// submission, together with the vetting gate's decision. Showing the REASON a
// candidate was held back (unmappable family, private host, stale) is the
// point: the policy stays legible instead of silently dropping rows.
type threatfoxCandidateRow struct {
	URL       string `json:"url"`
	SHA256    string `json:"sha256,omitempty"`
	SizeBytes int64  `json:"sizeBytes"`
	FileKind  string `json:"fileKind,omitempty"`
	Family    string `json:"family,omitempty"`
	Malware   string `json:"malware,omitempty"` // resolved Malpedia label, when eligible
	IOCCount  int    `json:"iocCount"`          // number of IOCs this candidate would submit
	FetchedAt string `json:"fetchedAt,omitempty"`
	Eligible  bool   `json:"eligible"`
	Reason    string `json:"reason,omitempty"`
}

type threatfoxResponse struct {
	GeneratedAt string `json:"generatedAt"`
	// Configured: ThreatFox shares the one abuse.ch Auth-Key, so a
	// bazaar-configured deployment is ThreatFox-ready.
	Configured      bool                     `json:"configured"`
	TotalSubmitted  int                      `json:"totalSubmitted"`
	Pending         int                      `json:"pending"`
	Eligible        int                      `json:"eligible"`
	ActiveDays      int                      `json:"activeDays"`
	LastSubmittedAt string                   `json:"lastSubmittedAt,omitempty"`
	Candidates      []threatfoxCandidateRow  `json:"candidates"`
	Rows            []threatfoxSubmissionRow `json:"rows"`
}

// maxThreatFoxCandidates bounds how many artifacts we classify per request
// (each Classify reads the file header off disk).
const maxThreatFoxCandidates = 50

// threatfoxCandidates loads artifact rows and runs the real vetting gate over
// them. Shared by the read and submit endpoints so the list the operator sees
// is exactly the list that would be submitted.
func (s *Server) threatfoxCandidates(activeDays int) ([]threatfox.Candidate, []threatfoxCandidateRow, error) {
	rows, err := s.st.ThreatFoxCandidates(activeDays, maxThreatFoxCandidates)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	cands := make([]threatfox.Candidate, 0, len(rows))
	view := make([]threatfoxCandidateRow, 0, len(rows))
	for _, r := range rows {
		// Classify for BOTH file kind and malware family — the family is
		// ThreatFox's mandatory Malpedia label, and a candidate whose family
		// doesn't resolve is rejected by Vet.
		kind, family := "", ""
		if r.LocalPath != "" {
			if cls, cerr := bazaar.Classify(r.LocalPath); cerr == nil {
				kind = cls.FileKind
				family = cls.Family
			}
		}
		c := threatfox.Candidate{
			URL:       r.URL,
			SHA256:    r.SHA256,
			SizeBytes: r.SizeBytes,
			Origin:    r.Origin,
			Status:    r.Status,
			FetchedAt: r.FetchedAt,
			FileKind:  kind,
			Family:    family,
		}
		ok, malware, iocs, reason := threatfox.Vet(c, now, threatfox.VetOptions{ActiveDays: activeDays})
		vr := threatfoxCandidateRow{
			URL:       c.URL,
			SHA256:    c.SHA256,
			SizeBytes: c.SizeBytes,
			FileKind:  kind,
			Family:    family,
			Malware:   malware,
			IOCCount:  len(iocs),
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

func threatfoxActiveDaysFromQuery(raw string) int {
	if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 3 {
		return n
	}
	return 3
}

// handleIntelThreatFox reports ThreatFox sharing state. Read-only — it never
// contacts ThreatFox.
func (s *Server) handleIntelThreatFox(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	activeDays := threatfoxActiveDaysFromQuery(r.URL.Query().Get("activeDays"))
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		if n > 500 {
			n = 500
		}
		limit = n
	}

	stats, err := s.st.ThreatFoxSubmissionStats(activeDays)
	if err != nil {
		httpError(w, "api_threatfox", err, http.StatusInternalServerError)
		return
	}
	subs, err := s.st.ListThreatFoxSubmissions(limit)
	if err != nil {
		httpError(w, "api_threatfox", err, http.StatusInternalServerError)
		return
	}
	eligible, candidateView, err := s.threatfoxCandidates(activeDays)
	if err != nil {
		httpError(w, "api_threatfox", err, http.StatusInternalServerError)
		return
	}

	out := threatfoxResponse{
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		Configured:     s.abuseCHKeyLive() != "",
		TotalSubmitted: stats.TotalSubmitted,
		Pending:        stats.Pending,
		Eligible:       len(eligible),
		ActiveDays:     activeDays,
		Candidates:     candidateView,
		Rows:           make([]threatfoxSubmissionRow, 0, len(subs)),
	}
	if !stats.LastSubmittedAt.IsZero() {
		out.LastSubmittedAt = stats.LastSubmittedAt.UTC().Format(time.RFC3339)
	}
	for _, u := range subs {
		out.Rows = append(out.Rows, threatfoxSubmissionRow{
			IOC:         u.IOC,
			IOCType:     u.IOCType,
			Malware:     u.Malware,
			Status:      u.Status,
			SubmittedAt: u.SubmittedAt.UTC().Format(time.RFC3339),
		})
	}
	_ = json.NewEncoder(w).Encode(out)
}

type threatfoxSubmitResponse struct {
	Status    string `json:"status"`
	Submitted int    `json:"submitted"`
	Skipped   int    `json:"skipped"`
	Error     string `json:"error,omitempty"`
}

// handleThreatFoxSubmit submits every currently-eligible candidate's IOCs to
// ThreatFox. The gate is NOT re-implemented here: threatfoxCandidates() runs
// the same threatfox.Vet the CLI uses and threatfox.Share re-checks dedup, so
// the button can only send what `shardlure share threatfox` would. A single
// candidate can be targeted with ?url=... for the per-row button.
func (s *Server) handleThreatFoxSubmit(w http.ResponseWriter, r *http.Request) {
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
		_ = json.NewEncoder(w).Encode(threatfoxSubmitResponse{
			Status: "error",
			Error:  "no abuse.ch Auth-Key configured (the MalwareBazaar key in Settings covers ThreatFox too)",
		})
		return
	}

	activeDays := threatfoxActiveDaysFromQuery(r.URL.Query().Get("activeDays"))
	cands, _, err := s.threatfoxCandidates(activeDays)
	if err != nil {
		httpError(w, "api_threatfox", err, http.StatusInternalServerError)
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
			_ = json.NewEncoder(w).Encode(threatfoxSubmitResponse{
				Status: "error",
				Error:  "candidate is not eligible (already submitted, stale, unmappable family, or rejected by policy)",
			})
			return
		}
	}

	if len(cands) == 0 {
		_ = json.NewEncoder(w).Encode(threatfoxSubmitResponse{Status: "ok", Submitted: 0, Skipped: 0})
		return
	}

	if !s.threatfoxBatchMu.TryLock() {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(threatfoxSubmitResponse{
			Status: "error", Error: "a submission batch is already in progress",
		})
		return
	}
	defer s.threatfoxBatchMu.Unlock()

	submitted, skipped, ferr := threatfox.Share(r.Context(), &threatfoxStoreRecorder{st: s.st}, cands, threatfox.Options{
		APIKey:    apiKey,
		ExtraTags: s.bazaarTagsLive(),
	})

	resp := threatfoxSubmitResponse{Status: "ok", Submitted: submitted, Skipped: skipped}
	switch {
	case errors.Is(ferr, threatfox.ErrUnauthorized):
		log.Printf("web: threatfox submit: %v", ferr)
		resp.Status = "error"
		resp.Error = "abuse.ch rejected the Auth-Key"
	case ferr != nil:
		log.Printf("web: threatfox submit: %v", ferr)
		if submitted > 0 {
			resp.Status = "partial"
		} else {
			resp.Status = "error"
		}
		resp.Error = "some submissions failed — see server logs"
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// threatfoxStoreRecorder adapts *store.Store to threatfox.SubmitRecorder.
type threatfoxStoreRecorder struct{ st storeThreatFox }

type storeThreatFox interface {
	ThreatFoxSubmitted(ioc string) (bool, error)
	RecordThreatFoxSubmission(ioc, iocType, malware, status string, at time.Time) error
}

func (a *threatfoxStoreRecorder) ThreatFoxSubmitted(ioc string) (bool, error) {
	return a.st.ThreatFoxSubmitted(ioc)
}
func (a *threatfoxStoreRecorder) RecordThreatFoxSubmission(ioc, iocType, malware, status string, at time.Time) error {
	return a.st.RecordThreatFoxSubmission(ioc, iocType, malware, status, at)
}
