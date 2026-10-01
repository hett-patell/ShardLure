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
	free, err := g.avail(g.dir)
	paused := err == nil && free < g.minFree
	g.mu.Lock()
	changed := paused != g.paused
	g.paused = paused
	notify := g.OnChange
	g.mu.Unlock()
	if changed && notify != nil {
		notify(paused, free)
	}
	return !paused
}

// Paused reports the result of the last Allow.
func (g *SpaceGate) Paused() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.paused
}
