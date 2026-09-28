package web

import "context"

// WarmCaches fills every cache the landing dashboard reads. Startup calls it
// before reporting ready, so the first request after a restart is answered
// from memory. Filling them on that request took 8-90 s on ARM (1.75M
// events), depending on what else startup was doing.
func (s *Server) WarmCaches(ctx context.Context) error {
	steps := []func(){
		s.refreshHASSHCoverage,
		func() { _, _ = s.summaryStatsCached() },
		func() { _, _ = s.threatBlockCached() },
		func() { s.dashExtraCachedValues() },
		func() { s.topCountriesCached() },
		func() { s.recentRatesCached() },
	}
	for _, step := range steps {
		if err := ctx.Err(); err != nil {
			return err
		}
		step()
	}
	return ctx.Err()
}
