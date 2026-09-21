package threatfox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type shareRecordObserver struct {
	*fakeRecorder
	afterRecord func()
}

func (r *shareRecordObserver) RecordThreatFoxSubmission(ioc, kind, malware, status string, at time.Time) error {
	if err := r.fakeRecorder.RecordThreatFoxSubmission(ioc, kind, malware, status, at); err != nil {
		return err
	}
	if r.afterRecord != nil {
		r.afterRecord()
	}
	return nil
}

func TestShareEarlyStopPreservesDurableProgress(t *testing.T) {
	ledgerErr := errors.New("injected ledger write failure")
	for _, tt := range []struct {
		name       string
		stop       string
		durable    int
		previous   bool
		noProgress bool
		wantErr    error
		wantReason string
	}{
		{name: "second ledger write", stop: "ledger", durable: 1, wantErr: ledgerErr, wantReason: "ledger"},
		{name: "third ledger write", stop: "ledger", durable: 2, wantErr: ledgerErr, wantReason: "ledger"},
		{name: "earlier completed candidate", stop: "ledger", durable: 1, previous: true, wantErr: ledgerErr, wantReason: "ledger"},
		{name: "without progress callback", stop: "ledger", durable: 1, noProgress: true, wantErr: ledgerErr},
		{name: "second IOC auth failure", stop: "auth", durable: 1, wantErr: ErrUnauthorized, wantReason: "auth"},
		{name: "third IOC auth failure", stop: "auth", durable: 2, wantErr: ErrUnauthorized, wantReason: "auth"},
		{name: "canceled pacing", stop: "cancel", durable: 1, wantErr: context.Canceled, wantReason: "canceled"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := newOKServer(t)
			rec := &shareRecordObserver{fakeRecorder: newFakeRecorder()}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cand := goodCandidate()
			candidates := []Candidate{cand, freshCandidate(9)}
			wantSubmitted, wantRecorded := 1, tt.durable
			if tt.previous {
				candidates = append([]Candidate{freshCandidate(8)}, candidates...)
				wantSubmitted++
				wantRecorded += 3
			}
			// A preceding dedup error must survive joining the later fatal error.
			if tt.stop != "cancel" {
				failed := freshCandidate(7)
				rec.failOn = failed.URL
				candidates = append([]Candidate{failed}, candidates...)
			}
			rec.afterRecord = func() {
				if rec.count() != wantRecorded {
					return
				}
				switch tt.stop {
				case "ledger":
					rec.recordErr = ledgerErr
				case "auth":
					srv.mu.Lock()
					srv.status = "illegal_auth_key"
					srv.mu.Unlock()
				case "cancel":
					cancel()
				}
			}
			var progressCalls, partialCalls, progressCount int
			var progressSubmitted bool
			var progressReason string
			opts := Options{APIKey: "fixture", Endpoint: srv.URL, RateLimit: -1, Now: vetNow}
			if tt.stop == "cancel" {
				// Cancel immediately after the first durable write; the next pacing
				// wait must exit through ctx.Done(), without a timing-based sleep.
				opts.RateLimit = time.Hour
			}
			if !tt.noProgress {
				opts.OnProgress = func(c Candidate, submitted bool, count int, reason string) {
					progressCalls++
					if c.URL == cand.URL {
						partialCalls++
						progressSubmitted, progressCount, progressReason = submitted, count, reason
					}
				}
			}
			submitted, skipped, err := Share(ctx, rec, candidates, opts)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want errors.Is(_, %v)", err, tt.wantErr)
			}
			if tt.stop != "cancel" && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Errorf("error = %v, lost earlier dedup error", err)
			}
			if submitted != wantSubmitted || skipped != 0 {
				t.Errorf("submitted=%d skipped=%d, want %d/0", submitted, skipped, wantSubmitted)
			}
			wantRequests := wantRecorded + 1
			if tt.stop == "cancel" {
				wantRequests = wantRecorded
			}
			if got := srv.received(); got != wantRequests {
				t.Errorf("server received %d IOCs, want %d before fail-stop", got, wantRequests)
			}
			if got := rec.count(); got != wantRecorded {
				t.Errorf("ledger contains %d IOCs, want %d", got, wantRecorded)
			}
			if !tt.noProgress {
				if progressCalls != wantSubmitted || partialCalls != 1 {
					t.Errorf("progress calls=%d partial calls=%d, want %d/1", progressCalls, partialCalls, wantSubmitted)
				}
				if !progressSubmitted || progressCount != tt.durable || !strings.Contains(progressReason, "partial") || !strings.Contains(progressReason, tt.wantReason) {
					t.Errorf("progress submitted=%v count=%d reason=%q, want true/%d with partial %s reason", progressSubmitted, progressCount, progressReason, tt.durable, tt.wantReason)
				}
			}

			if tt.stop == "ledger" {
				// A retry must skip durable IOCs and finish the unrecorded remainder.
				rec.afterRecord = nil
				rec.recordErr = nil
				opts.OnProgress = nil
				submitted, skipped, err = Share(ctx, rec, []Candidate{cand}, opts)
				if err != nil || submitted != 1 || skipped != 0 {
					t.Errorf("retry submitted=%d skipped=%d err=%v, want 1/0/nil", submitted, skipped, err)
				}
				if got := srv.received() - wantRequests; got != 3-tt.durable {
					t.Errorf("retry sent %d IOCs, want %d unrecorded IOCs", got, 3-tt.durable)
				}
				if got := rec.count(); got != wantRecorded+3-tt.durable {
					t.Errorf("ledger after retry contains %d IOCs, want %d", got, wantRecorded+3-tt.durable)
				}
			}
		})
	}
}

func TestSharePartialSuccessConsumesOneCandidateSlot(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			IOCs []string `json:"iocs"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode submission: %v", err)
			http.Error(w, "invalid submission", http.StatusBadRequest)
			return
		}
		calls++
		if calls == 1 {
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"query_status": "ok",
			"data": map[string]any{
				"ok": body.IOCs, "ignored": []string{}, "duplicated": []string{},
			},
		})
	}))
	t.Cleanup(srv.Close)
	rec := newFakeRecorder()
	var progressCalls, limitCalls, unexamined int
	submitted, skipped, err := Share(context.Background(), rec, []Candidate{goodCandidate(), freshCandidate(1)}, Options{
		APIKey: "fixture", Endpoint: srv.URL, RateLimit: -1, Now: vetNow, MaxSubmissions: 1,
		OnProgress: func(_ Candidate, submitted bool, count int, reason string) {
			progressCalls++
			if !submitted || count != 2 || !strings.Contains(reason, "partial") {
				t.Errorf("progress submitted=%v count=%d reason=%q, want true/2 with partial reason", submitted, count, reason)
			}
		},
		OnLimitReached: func(n int) { limitCalls++; unexamined = n },
	})
	if err == nil || submitted != 1 || skipped != 0 {
		t.Errorf("submitted=%d skipped=%d err=%v, want 1/0 with provider error", submitted, skipped, err)
	}
	if progressCalls != 1 || limitCalls != 1 || unexamined != 1 {
		t.Errorf("progress calls=%d limit calls=%d unexamined=%d, want 1/1/1", progressCalls, limitCalls, unexamined)
	}
	if got := rec.count(); got != 2 {
		t.Errorf("ledger contains %d IOCs, want 2 from first candidate", got)
	}
}
