package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type captureResponse struct {
	GeneratedAt string            `json:"generatedAt"`
	Summary     captureSummary    `json:"summary"`
	Artifacts   []captureArtifact `json:"artifacts"`
}

type captureSummary struct {
	Total      int    `json:"total"`
	Fetched    int    `json:"fetched"`
	Capturing  int    `json:"capturing"`
	Failed     int    `json:"failed"`
	TotalBytes int64  `json:"totalBytes"`
	LastAt     string `json:"lastAt,omitempty"`
}

type captureArtifact struct {
	TS        string `json:"ts"`
	CreatedAt string `json:"createdAt"`
	SrcIP     string `json:"srcIp"`
	URL       string `json:"url"`
	Status    string `json:"status"`
	Origin    string `json:"origin"`
	SHA256    string `json:"sha256,omitempty"`
	SizeBytes int64  `json:"sizeBytes"`
	Detail    string `json:"detail,omitempty"`
}

func (s *Server) handleCapture(w http.ResponseWriter, r *http.Request) {
	if !s.requireDashboardAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	sum, err := s.st.CaptureSummary()
	if err != nil {
		httpError(w, "capture", err, http.StatusInternalServerError)
		return
	}
	rows, err := s.st.ListRecentArtifacts(35)
	if err != nil {
		httpError(w, "capture", err, http.StatusInternalServerError)
		return
	}

	resp := captureResponse{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Summary: captureSummary{
			Total:      sum.Total,
			Fetched:    sum.Fetched,
			Capturing:  sum.Capturing,
			Failed:     sum.Failed,
			TotalBytes: sum.TotalBytes,
		},
	}
	if !sum.LastTS.IsZero() {
		resp.Summary.LastAt = sum.LastTS.UTC().Format(time.RFC3339)
	}
	for _, a := range rows {
		url := a.URL
		if strings.HasPrefix(url, "cowrie-download:") {
			url = "cowrie:" + strings.TrimPrefix(url, "cowrie-download:")
		}
		created := a.CreatedAt
		if created.IsZero() {
			created = a.TS
		}
		resp.Artifacts = append(resp.Artifacts, captureArtifact{
			TS:        a.TS.UTC().Format(time.RFC3339),
			CreatedAt: created.UTC().Format(time.RFC3339),
			SrcIP:     a.SrcIP,
			URL:       url,
			Status:    a.Status,
			Origin:    a.Origin,
			SHA256:    a.SHA256,
			SizeBytes: a.SizeBytes,
			Detail:    a.Detail,
		})
	}
	_ = json.NewEncoder(w).Encode(resp)
}
