package actor

// ResetLiveCollectorForTest is the test-only door into the process-
// wide live collector used by SyncJournalEvent. Without it a test
// would inherit accumulated state from earlier tests in the same
// package.
func ResetLiveCollectorForTest() { resetLiveCollectorForTest() }
