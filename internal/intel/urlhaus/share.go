package urlhaus

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/intel/intelutil"
)

// SubmitRecorder is the slice of *store.Store this package depends on. Kept
// minimal so urlhaus never imports store (and vice versa) — the same
// decoupling the bazaar and abuseipdb packages use.
type SubmitRecorder interface {
	URLhausSubmitted(url string) (bool, error)
	RecordURLhausSubmission(url, status string, at time.Time) error
}

// Options bundles the runtime knobs for one Share invocation.
type Options struct {
	APIKey     string
	Endpoint   string
	ExtraTags  []string
	ActiveDays int // 1..2 tightens the "still active" window; 0/invalid = 3-day default
	DryRun     bool
	Anonymous  bool // hide the abuse.ch handle on the public record
	BatchSize  int  // URLs per POST; 0 = default
	RateLimit  time.Duration
	OnProgress func(c Candidate, submitted bool, reason string)
}

// defaultBatchSize keeps each POST small. URLhaus accepts a list, but batching
// modestly means one rejected entry can't sink a large batch and progress
// reporting stays granular.
const defaultBatchSize = 25

// ErrEmptyBatch is returned when Share is handed nothing to do.
// (ErrMissingAPIKey / ErrUnauthorized / ErrNoEntries live in client.go.)
var ErrEmptyBatch = errors.New("urlhaus: no candidates to submit")

// sanitiseTags applies abuse.ch's shared tag rule. MalwareBazaar and URLhaus
// use the same validator, so the implementation lives in intelutil rather than
// being copied per destination.
func sanitiseTags(in []string) []string { return intelutil.SanitiseAbuseChTags(in) }

// Share submits each vetted candidate URL to URLhaus. The pipeline:
//
//  1. Skip anything already submitted (URLhausSubmitted).
//  2. Apply the local submission-policy gate (Vet) — the single enforcement
//     point shared with any future dashboard button.
//  3. POST the survivors in batches.
//  4. Record each submitted URL so the next run skips it.
//
// Returns (submitted, skipped, firstErr). As with bazaar.Share, one failing
// batch does not abort the run, but the first error is surfaced so the CLI can
// exit non-zero.
func Share(ctx context.Context, rec SubmitRecorder, candidates []Candidate, opts Options) (submitted, skipped int, firstErr error) {
	if strings.TrimSpace(opts.APIKey) == "" && !opts.DryRun {
		return 0, 0, ErrMissingAPIKey
	}
	if len(candidates) == 0 {
		return 0, 0, ErrEmptyBatch
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = defaultBatchSize
	}
	if opts.RateLimit == 0 {
		opts.RateLimit = 2 * time.Second
	}

	now := time.Now()
	tags := sanitiseTags(opts.ExtraTags)

	// Vet + dedup first, so a dry run reports exactly what a real run would do.
	type pending struct {
		cand  Candidate
		entry Entry
	}
	var queue []pending
	seenURL := map[string]bool{}
	for _, cand := range candidates {
		if ctx.Err() != nil {
			return submitted, skipped, ctx.Err()
		}
		// Collapse duplicates inside one batch: the artifacts table is unique
		// per URL, but a caller could hand us an unfiltered slice.
		if seenURL[cand.URL] {
			skipped++
			continue
		}
		seenURL[cand.URL] = true

		if ok, reason := Vet(cand, now, VetOptions{ActiveDays: opts.ActiveDays}); !ok {
			skipped++
			if opts.OnProgress != nil {
				opts.OnProgress(cand, false, reason)
			}
			continue
		}
		already, err := rec.URLhausSubmitted(cand.URL)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if already {
			skipped++
			if opts.OnProgress != nil {
				opts.OnProgress(cand, false, "already submitted")
			}
			continue
		}
		queue = append(queue, pending{
			cand:  cand,
			entry: Entry{URL: cand.URL, Threat: ThreatMalwareDownload, Tags: tags},
		})
	}

	if len(queue) == 0 {
		return submitted, skipped, firstErr
	}
	if opts.DryRun {
		for _, p := range queue {
			if opts.OnProgress != nil {
				opts.OnProgress(p.cand, true, "dry-run")
			}
			submitted++
		}
		return submitted, skipped, firstErr
	}

	client := NewClient(opts.Endpoint)
	for start := 0; start < len(queue); start += opts.BatchSize {
		if ctx.Err() != nil {
			return submitted, skipped, ctx.Err()
		}
		end := start + opts.BatchSize
		if end > len(queue) {
			end = len(queue)
		}
		batch := queue[start:end]

		entries := make([]Entry, 0, len(batch))
		for _, p := range batch {
			entries = append(entries, p.entry)
		}

		res, err := client.Submit(ctx, opts.APIKey, entries, opts.Anonymous)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			for _, p := range batch {
				if opts.OnProgress != nil {
					opts.OnProgress(p.cand, false, "submit failed: "+err.Error())
				}
			}
			// An auth failure will fail identically for every remaining batch;
			// stop rather than hammering the API with doomed requests.
			if errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrMissingAPIKey) {
				return submitted, skipped, firstErr
			}
			continue
		}

		status := res.Status
		if status == "" {
			status = "submitted"
		}
		for _, p := range batch {
			if err := rec.RecordURLhausSubmission(p.cand.URL, status, time.Now()); err != nil && firstErr == nil {
				firstErr = err
			}
			submitted++
			if opts.OnProgress != nil {
				opts.OnProgress(p.cand, true, status)
			}
		}

		// Be a polite API citizen between batches (abuse.ch fair-use).
		if end < len(queue) {
			select {
			case <-ctx.Done():
				return submitted, skipped, ctx.Err()
			case <-time.After(opts.RateLimit):
			}
		}
	}
	return submitted, skipped, firstErr
}
