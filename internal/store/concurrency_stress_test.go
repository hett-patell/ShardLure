package store

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestConcurrentWritePathsDoNotDeadlockOrRace drives every write path added for
// the intel features simultaneously, alongside readers.
//
// Two specific hazards this guards:
//
//  1. writeMu is NOT reentrant. The ensure* helpers acquire it via execWrite,
//     so a lazy-table creation reached from inside an open transaction
//     deadlocks (the documented RecordSessionBindings trap). Each new writer
//     here touches a different lazily-created table, so an accidental
//     ensure-inside-tx would hang this test rather than fail silently in prod.
//  2. Reads must stay concurrent with the single writer (8-connection WAL
//     pool), so a reader must never be starved into failing.
//
// Run with -race to also catch unsynchronised access to shared store state.
func TestConcurrentWritePathsDoNotDeadlockOrRace(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "stress.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	const workers = 8
	const iterations = 25

	var wg sync.WaitGroup
	errCh := make(chan error, workers*6)
	fail := func(format string, args ...any) {
		select {
		case errCh <- fmt.Errorf(format, args...):
		default:
		}
	}

	now := time.Now().UTC()

	// Writer 1: artifacts + the redelivery timestamp bump.
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				url := fmt.Sprintf("http://evil.tld/w%d-%d", w, i)
				if err := s.RecordArtifact(Artifact{
					TS: now.Add(-time.Duration(i) * time.Minute), URL: url,
					Origin: "quarantine_fetch", Status: "fetched",
					SHA256: fmt.Sprintf("%064d", w*1000+i), SizeBytes: 4096,
				}); err != nil {
					fail("RecordArtifact: %w", err)
					return
				}
				if err := s.TouchArtifactTS(url, now.Add(time.Duration(i)*time.Minute)); err != nil {
					fail("TouchArtifactTS: %w", err)
					return
				}
			}
		}(w)
	}

	// Writer 2: the URLhaus dedup ledger.
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if err := s.RecordURLhausSubmission(
					fmt.Sprintf("http://evil.tld/u%d-%d", w, i), "ok", now); err != nil {
					fail("RecordURLhausSubmission: %w", err)
					return
				}
			}
		}(w)
	}

	// Writer 3: the payload-intel cache.
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if err := s.PutPayloadIntel(
					fmt.Sprintf("%064d", w*1000+i), "virustotal",
					`{"cacheVersion":1,"verdict":"malicious"}`); err != nil {
					fail("PutPayloadIntel: %w", err)
					return
				}
			}
		}(w)
	}

	// Writer 4: settings (a different lazily-used table + the keystore path).
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if err := s.SetAppSetting(fmt.Sprintf("stress.key%d", w),
					fmt.Sprintf("v%d", i)); err != nil {
					fail("SetAppSetting: %w", err)
					return
				}
			}
		}(w)
	}

	// Readers: must never error while the writers hammer writeMu.
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if _, err := s.URLhausSubmissionStats(3); err != nil {
					fail("URLhausSubmissionStats: %w", err)
					return
				}
				if _, err := s.ListURLhausSubmissions(10); err != nil {
					fail("ListURLhausSubmissions: %w", err)
					return
				}
				if _, err := s.PayloadIntelBySource("virustotal",
					[]string{fmt.Sprintf("%064d", i)}); err != nil {
					fail("PayloadIntelBySource: %w", err)
					return
				}
				if _, err := s.URLhausCandidates(3, 10); err != nil {
					fail("URLhausCandidates: %w", err)
					return
				}
			}
		}()
	}

	// A deadlock would hang forever; bound it so the test reports instead.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(90 * time.Second):
		t.Fatal("timed out — likely a writeMu deadlock (ensure* called inside a transaction?)")
	}
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	// Sanity-check the data actually landed.
	subs, err := s.ListURLhausSubmissions(0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(subs) != workers*iterations {
		t.Errorf("urlhaus rows = %d, want %d", len(subs), workers*iterations)
	}
}

// MaintenancePurge holds writeMu across a multi-statement transaction and must
// pre-create every lazy table it deletes from. If a future edit moves an
// ensure* call inside that transaction it deadlocks; running purge concurrently
// with writers is the cheapest way to keep that honest.
func TestMaintenancePurgeConcurrentWithWriters(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "purge-stress.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_ = s.PutPayloadIntel(fmt.Sprintf("%064d", i), "virustotal", `{"cacheVersion":1}`)
			_ = s.RecordURLhausSubmission(fmt.Sprintf("http://x.tld/%d", i), "ok", time.Now())
		}
	}()

	done := make(chan error, 1)
	go func() {
		var perr error
		for i := 0; i < 5; i++ {
			if err := s.MaintenancePurge(90); err != nil {
				perr = err
				break
			}
		}
		done <- perr
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("MaintenancePurge: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("MaintenancePurge timed out — writeMu deadlock")
	}
	close(stop)
	wg.Wait()
}
