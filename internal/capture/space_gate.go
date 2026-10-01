package capture

import (
	"sync"

	"github.com/networkshard/shardlure/internal/safefile"
)

// SpaceGate pauses capture writes while the evidence filesystem has less
// free space than its floor. Every write path asks Allow before it claims
// work, because a write that fails with ENOSPC after claiming burns one of
// the five capture attempts and a full disk would turn every queued URL
// into failed_permanently. Attackers control how much the honeypot
// downloads; on 2026-10-01 the ARM root disk reached 100%.
type SpaceGate struct {
	// OnChange is called once per pause/resume transition (set before use).
	// Calls are serialized and in transition order, because Allow holds the
	// gate's lock while it measures, updates and notifies. OnChange must
	// therefore not call back into the gate (Allow or Paused): that deadlocks.
	// free is the measured free space; on a resume caused by a measurement
	// error (fail-open) it is 0 and carries no meaning.
	OnChange func(paused bool, free uint64)

	dir     string
	minFree uint64
	avail   func(string) (uint64, error)
	mu      sync.Mutex
	paused  bool
}

// NewSpaceGate guards evidenceDir with a floor of minFree bytes; 0 disables it.
func NewSpaceGate(evidenceDir string, minFree uint64) *SpaceGate {
	return &SpaceGate{dir: evidenceDir, minFree: minFree, avail: evidenceAvailable}
}

func evidenceAvailable(dir string) (uint64, error) {
	root, err := safefile.OpenRoot(dir)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	return root.AvailableBytes()
}

// Allow reports whether a capture write may start now. A nil gate, a zero
// floor, or free space that cannot be measured all allow: the floor protects
// the disk, it is not a reason to stop capturing on a platform without
// statfs, and ENOSPC still fails the individual write.
func (g *SpaceGate) Allow() bool {
	if g == nil || g.minFree == 0 {
		return true
	}
	// The runner, the URL worker and the file worker share one gate. Holding
	// the lock across the measurement and the notification keeps a stale
	// reading from overwriting a fresher one and keeps OnChange in order, so
	// an observer never ends on "paused" while the gate is open. A statfs is
	// a few microseconds; serializing three callers costs nothing.
	g.mu.Lock()
	defer g.mu.Unlock()
	free, err := g.avail(g.dir)
	if err != nil {
		free = 0
	}
	paused := err == nil && free < g.minFree
	changed := paused != g.paused
	g.paused = paused
	if changed && g.OnChange != nil {
		g.OnChange(paused, free)
	}
	return !paused
}

// Paused reports the result of the most recent Allow from any of the workers
// sharing the gate, so it can be up to one worker tick stale. It does not
// measure.
func (g *SpaceGate) Paused() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.paused
}
