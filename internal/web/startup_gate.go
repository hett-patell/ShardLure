package web

import (
	"github.com/networkshard/shardlure/internal/observability"
	"net/http"
)

// applicationAvailable is checked after authentication. Operational routes and
// embedded public assets deliberately bypass it so startup can be diagnosed.
// A degraded Serving process keeps forensic reads available; readiness is a
// separate contract and not a blanket switch that hides already-collected data.
func (s *Server) applicationAvailable(w http.ResponseWriter, r *http.Request) bool {
	if s.monitor == nil || s.monitor.Snapshot().Phase == observability.Serving {
		return true
	}
	w.Header().Set("Retry-After", "1")
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "application is not ready", http.StatusServiceUnavailable)
	return false
}
