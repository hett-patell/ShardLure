package web

import (
	"sync"
	"time"
)

// radarErrLogEvery bounds how often one polled failure is logged: /api/intel
// is polled every few seconds, and a persistent store error would otherwise
// write a line per poll.
const radarErrLogEvery = 5 * time.Minute

// opLogLimiter logs an operation failure through logOperationError (fixed
// category only, never the raw error) at most once per radarErrLogEvery. The
// zero value is ready to use.
type opLogLimiter struct {
	mu   sync.Mutex
	last time.Time
}

func (l *opLogLimiter) log(operation string, err error) {
	l.mu.Lock()
	now := time.Now()
	if !l.last.IsZero() && now.Sub(l.last) < radarErrLogEvery {
		l.mu.Unlock()
		return
	}
	l.last = now
	l.mu.Unlock()
	logOperationError(operation, err)
}
