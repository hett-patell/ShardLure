package actor

// resetLiveCollectorForTest clears the process-wide live collector so each
// test starts from a cold state. Lives in a _test.go file so it is compiled
// only for tests.
func resetLiveCollectorForTest() {
	liveCollectorMu.Lock()
	liveCollector = nil
	liveCollectorAdmin = nil
	liveCollectorMu.Unlock()
}
