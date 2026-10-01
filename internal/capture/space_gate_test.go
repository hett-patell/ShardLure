package capture

import (
	"errors"
	"testing"
)

func TestSpaceGatePausesBelowFloorAndResumes(t *testing.T) {
	free := uint64(10)
	g := NewSpaceGate("/inert", 100)
	g.avail = func(string) (uint64, error) { return free, nil }
	var events []bool
	g.OnChange = func(paused bool, _ uint64) { events = append(events, paused) }

	if g.Allow() {
		t.Fatal("10 B free under a 100 B floor must pause")
	}
	if !g.Paused() {
		t.Fatal("Paused must report the pause")
	}
	if g.Allow() {
		t.Fatal("still below the floor")
	}
	free = 500
	if !g.Allow() {
		t.Fatal("above the floor must resume")
	}
	if len(events) != 2 || events[0] != true || events[1] != false {
		t.Fatalf("OnChange must fire once per transition, got %v", events)
	}
}

func TestSpaceGateFailsOpen(t *testing.T) {
	var nilGate *SpaceGate
	if !nilGate.Allow() {
		t.Fatal("a nil gate must allow")
	}
	off := NewSpaceGate("/inert", 0)
	off.avail = func(string) (uint64, error) { return 0, nil }
	if !off.Allow() {
		t.Fatal("a zero floor disables the guard")
	}
	broken := NewSpaceGate("/inert", 100)
	broken.avail = func(string) (uint64, error) { return 0, errors.New("statfs unsupported") }
	if !broken.Allow() {
		t.Fatal("unmeasurable free space must not stop capture; ENOSPC still fails the write itself")
	}
}

func TestPausedArtifactWorkerClaimsNothing(t *testing.T) {
	g := NewSpaceGate("/inert", 100)
	g.avail = func(string) (uint64, error) { return 1, nil }
	cycles := 0
	w := &ArtifactWorker{Space: g, OnCycle: func(begin bool, err error) {
		cycles++
		if err != nil {
			t.Fatalf("a pause must not be reported as a cycle failure: %v", err)
		}
	}}
	// st is nil: reaching DueArtifactCaptures would panic, proving the gate
	// runs before any claim (so a full disk never burns the retry budget).
	if err := w.tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if cycles != 2 {
		t.Fatalf("OnCycle begin+end must still fire while paused (keeps LastProgress fresh), got %d", cycles)
	}
}
