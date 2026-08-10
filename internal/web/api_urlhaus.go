package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// urlhausSubmissionRow is one recorded submission, shaped for the UI.
type urlhausSubmissionRow struct {
	URL         string `json:"url"`
	Status      string `json:"status"`
	SubmittedAt string `json:"submittedAt"`
}

type urlhausResponse struct {
	GeneratedAt string `json:"generatedAt"`
	// Configured reports whether an abuse.ch Auth-Key is available. URLhaus
	// shares the MalwareBazaar key (one key per abuse.ch account), so a
	// bazaar-configured deployment is URLhaus-ready.
	Configured bool `json:"configured"`
	// TotalSubmitted / Pending mirror the bazaar widget's shape.
	TotalSubmitted int `json:"totalSubmitted"`
	Pending        int `json:"pending"`
	// ActiveDays is the liveness window used for the Pending estimate.
	ActiveDays      int                    `json:"activeDays"`
	LastSubmittedAt string                 `json:"lastSubmittedAt,omitempty"`
	Rows            []urlhausSubmissionRow `json:"rows"`
}

// handleIntelURLhaus reports URLhaus sharing state: how many malware-
// distribution URLs we've submitted, how many are eligible but unsent, and the
// recent submission log.
//
// Read-only by design. Submitting is a CLI action (`shardlure share urlhaus`)
// because it publishes to a dataset other people consume as blocklist IOCs —
// that deserves a deliberate operator step, not a dashboard button that could
// be clicked by accident. The vetting gate (urlhaus.Vet) is shared, so if a
// button is ever added it inherits the same policy.
func (s *Server) handleIntelURLhaus(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	activeDays := 3
	if n, err := strconv.Atoi(r.URL.Query().Get("activeDays")); err == nil && n > 0 && n <= 3 {
		activeDays = n
	}
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

	out := urlhausResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		// abuse.ch issues ONE Auth-Key per account covering both
		// MalwareBazaar and URLhaus, so the bazaar key doubles as the
		// URLhaus key rather than asking for the same secret twice.
		Configured:     s.bazaarKeyLive() != "",
		TotalSubmitted: stats.TotalSubmitted,
		Pending:        stats.Pending,
		ActiveDays:     activeDays,
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
