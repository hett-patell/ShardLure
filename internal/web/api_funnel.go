package web

import (
	"encoding/json"
	"net/http"
	"time"
)

type funnelStageJSON struct {
	Stage string `json:"stage"`
	Day   int64  `json:"day"`
	Week  int64  `json:"week"`
}

type funnelJSON struct {
	Available bool              `json:"available"`
	At        string            `json:"at,omitempty"`
	Stages    []funnelStageJSON `json:"stages"`
}

// handleIntelFunnel serves the payload funnel the live sampler last pushed
// into the monitor. It never queries the store: the 7-day funnel costs
// seconds on the ARM sensor, and /metrics already pays for it once every
// five minutes, so a dashboard poll reads that snapshot instead.
func (s *Server) handleIntelFunnel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	out := funnelJSON{Stages: []funnelStageJSON{}}
	if s.monitor != nil {
		f := s.monitor.Snapshot().Funnel
		if !f.At.IsZero() {
			out.Available = f.Valid
			out.At = f.At.UTC().Format(time.RFC3339)
			day, week := f.Day.Stages(), f.Week.Stages()
			for i := range day {
				out.Stages = append(out.Stages, funnelStageJSON{Stage: day[i].Name, Day: day[i].N, Week: week[i].N})
			}
		}
	}
	_ = json.NewEncoder(w).Encode(out)
}
