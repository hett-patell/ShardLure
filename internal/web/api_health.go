package web

import (
	"encoding/json"
	"github.com/networkshard/shardlure/internal/observability"
	"net/http"
)

type operationalHeadWriter struct{ http.ResponseWriter }

func (w operationalHeadWriter) Write(b []byte) (int, error) { return len(b), nil }

func (s *Server) guardOperationalRead(handler http.HandlerFunc) http.HandlerFunc {
	guarded := s.guardDebug(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", 405)
			return
		}
		handler(w, r)
	})
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w = operationalHeadWriter{w}
		}
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Query().Has("token") {
			http.Error(w, "query credentials are not accepted", 401)
			return
		}
		guarded(w, r)
	}
}

func writeOperationalStatus(w http.ResponseWriter, r *http.Request, ok bool, reason string) {
	w.Header().Set("Content-Type", "application/json")
	code := 503
	status := "unavailable"
	if ok {
		code = 200
		status = "ok"
	}
	w.WriteHeader(code)
	if r.Method == http.MethodHead {
		return
	}
	_ = json.NewEncoder(w).Encode(struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}{status, reason})
}
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if s.monitor == nil {
		writeOperationalStatus(w, r, false, "monitor_unavailable")
		return
	}
	snapshot := s.monitor.Snapshot()
	writeOperationalStatus(w, r, snapshot.Phase != observability.Draining, snapshot.Phase.String())
}
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.monitor == nil {
		writeOperationalStatus(w, r, false, "monitor_unavailable")
		return
	}
	ok, reason := s.monitor.Ready()
	writeOperationalStatus(w, r, ok, reason.String())
}
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.monitor == nil {
		writeOperationalStatus(w, r, false, "monitor_unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(200)
	if r.Method == http.MethodHead {
		return
	}
	_ = observability.WritePrometheus(w, s.monitor.Snapshot())
}
