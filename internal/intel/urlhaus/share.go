package urlhaus

import (
	"context"
	"errors"
	"github.com/networkshard/shardlure/internal/observability"
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

// Ledger statuses and progress reasons shared with the CLI and dashboard.
const (
	// StatusAlreadyListed is the ledger status Share records for a URL the
	// read-only lookup found already on URLhaus. It is terminal for dedup (a
	// later run skips the URL with no network round trip) but is not a
	// submission of ours: the funnel and the panel's submitted total exclude
	// it. Mirrors store.URLhausStatusAlreadyListed — intel packages never
	// import store, so the literal is the contract.
	StatusAlreadyListed = "already_listed"

	// ReasonAlreadyListed is the OnProgress reason for an already-listed skip.
	// The dashboard matches on it to report the count separately from policy
	// skips.
	ReasonAlreadyListed = "already listed on URLhaus"
)

// defaultLookupRate paces the read-only duplicate checks. URLhaus documents no
// rate limit; this keeps a 30-URL batch polite without making the operator
// wait half a minute.
const defaultLookupRate = 250 * time.Millisecond

// lookupFailStreakLimit bounds a failing lookup endpoint. Each check has a
// 10 s deadline, so continuing through a blackholed host would hang a 30-URL
// batch for five minutes and hammer abuse.ch with requests that cannot
// succeed. Three consecutive ENDPOINT failures stop the checks; a success
// resets the streak, so one transient blip does not. A per-URL answer (the
// query API rejecting that one URL) never counts — three such candidates at
// the head of the newest-first list must not block every later one.
const lookupFailStreakLimit = 3

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

	// LookupEndpoint overrides the read-only URL query endpoint
	// (DefaultLookupEndpoint when empty). Every vetted candidate is checked
	// against it before submission: URLhaus already listing a URL must not go
	// on the wire, because a batch containing duplicates came back in a shape
	// the submission parser refuses and failed whole (31 of 32 candidates
	// already listed, 2026-10 production run). Dry runs make no checks — they
	// promise not to contact URLhaus.
	LookupEndpoint string
	// LookupRateLimit paces those checks (0 = defaultLookupRate).
	LookupRateLimit time.Duration

	// MaxSubmissions bounds how many URLs this run may SUBMIT (0 = unbounded).
	// It counts URLs that cleared Vet and dedup — NOT candidates examined. The
	// CLI used to pass its --limit into the candidate QUERY (a SQL LIMIT ahead
	// of the gate), the same defect fixed for bazaar.MaxUploads and
	// abuseipdb.MaxReports: the query replicates dedup so the worst driver was
	// already absent here, but Vet's shortener and private-host rejects are not
	// in SQL, so a page of unvettable URLs could still occupy every slot while
	// vettable ones sat below the cut.
	MaxSubmissions int
	// OnLimitReached fires at most once, when MaxSubmissions stopped the run
	// early, with the number of candidates never examined. A bounded run must
	// never read as an exhausted one.
	OnLimitReached func(unexamined int)

	// Now overrides the clock the active-days freshness gate vets against. Zero
	// = time.Now(). Injected for tests so a fixture's FetchedAt cannot silently
	// age past the window as wall-clock time passes (that is exactly how the
	// original share_test fixtures became a time-bomb: FetchedAt was pinned to a
	// fixed date while Share vetted against the real clock). Production leaves it
	// unset. Mirrors abuseipdb.Options.Now.
	Now time.Time
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
//  1. Skip anything already in the ledger (URLhausSubmitted).
//  2. Apply the local submission-policy gate (Vet) — the single enforcement
//     point shared with any future dashboard button.
//  3. Ask URLhaus's read-only lookup whether it already lists the URL; if so,
//     record that fact in the ledger and skip it (a real run only — a dry run
//     contacts nothing).
//  4. POST the survivors in batches.
//  5. Record each submitted URL so the next run skips it.
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

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	tags := sanitiseTags(opts.ExtraTags)
	client := NewClientWithLookup(opts.Endpoint, opts.LookupEndpoint)
	lookupGap := opts.LookupRateLimit
	if lookupGap <= 0 {
		lookupGap = defaultLookupRate
	}
	var lastLookup time.Time
	lookupFails := 0

	// Vet + dedup first, so a dry run reports exactly what a real run would do.
	type pending struct {
		cand  Candidate
		entry Entry
	}
	var queue []pending
	seenURL := map[string]bool{}
	for i, cand := range candidates {
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

		// Budget check mirrors bazaar/abuseipdb: it bounds what we SUBMIT, so a
		// skip (dedup, Vet reject, already listed upstream) never costs a slot —
		// only a queued URL does. It sits after those free skips and before the
		// lookup so a full budget spends no listing checks. Everything from i
		// onward is unexamined, which is a different thing from "nothing left to
		// submit" — say so.
		if opts.MaxSubmissions > 0 && len(queue) >= opts.MaxSubmissions {
			if opts.OnLimitReached != nil {
				opts.OnLimitReached(len(candidates) - i)
			}
			break
		}

		if !opts.DryRun {
			// The duplicate pre-check. A URL URLhaus already lists is recorded
			// as such (terminal for dedup) and never submitted: a batch mixing
			// new URLs with duplicates came back unreadable and failed whole.
			if lerr := intelutil.WaitForProviderAttempt(ctx, lastLookup, lookupGap); lerr != nil {
				return submitted, skipped, lerr
			}
			listed, lerr := client.Listed(ctx, opts.APIKey, cand.URL)
			lastLookup = time.Now()
			if lerr != nil {
				// Fail closed: a URL we could not check is not submitted. An
				// auth failure will fail every check, so stop at once. A
				// streak of endpoint failures stops the CHECKS but keeps the
				// queue the successful checks verified — those URLs are known
				// not to be listed and were already vetted, so discarding them
				// would lose a run to an unrelated outage. A per-URL rejection
				// skips only its own candidate.
				if firstErr == nil {
					firstErr = lerr
				}
				skipped++
				if opts.OnProgress != nil {
					opts.OnProgress(cand, false, "listing check failed: "+lerr.Error())
				}
				if errors.Is(lerr, ErrUnauthorized) || errors.Is(lerr, ErrMissingAPIKey) {
					return submitted, skipped, firstErr
				}
				if lookupFailureIsSystemic(lerr) {
					lookupFails++
					if lookupFails >= lookupFailStreakLimit {
						break
					}
				}
				continue
			}
			lookupFails = 0
			if listed {
				if rerr := rec.RecordURLhausSubmission(cand.URL, StatusAlreadyListed, time.Now()); rerr != nil {
					observability.DurableShare(ctx, observability.URLhaus, rerr, 1)
					firstErr = errors.Join(firstErr, rerr)
					if opts.OnProgress != nil {
						opts.OnProgress(cand, false, "already listed upstream; local ledger write failed")
					}
					// Without the ledger row the next run re-checks (harmless),
					// but a failing ledger would also leave real submissions
					// unrecorded. Stop before submitting any.
					return submitted, skipped, firstErr
				}
				skipped++
				if opts.OnProgress != nil {
					opts.OnProgress(cand, false, ReasonAlreadyListed)
				}
				continue
			}
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
	var lastAttempt time.Time
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

		if err := intelutil.WaitForProviderAttempt(ctx, lastAttempt, opts.RateLimit); err != nil {
			return submitted, skipped, err
		}
		res, err := client.Submit(ctx, opts.APIKey, entries, opts.Anonymous)
		lastAttempt = time.Now()
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
		// A plaintext already_queued answer means URLhaus had the URL before
		// this run (another reporter won the race between our lookup and the
		// POST). It is not a submission of ours, so it gets the same ledger
		// status and counting as the pre-check's answer.
		alreadyQueued := strings.EqualFold(status, "already_queued")
		ledgerFailed := false
		for _, p := range batch {
			recStatus := status
			if alreadyQueued {
				recStatus = StatusAlreadyListed
			}
			if err := rec.RecordURLhausSubmission(p.cand.URL, recStatus, time.Now()); err != nil {
				observability.DurableShare(ctx, observability.URLhaus, err, 1)
				firstErr = errors.Join(firstErr, err)
				ledgerFailed = true
				if opts.OnProgress != nil {
					opts.OnProgress(p.cand, false, "accepted upstream; local ledger write failed")
				}
				continue
			}
			if alreadyQueued {
				skipped++
				if opts.OnProgress != nil {
					opts.OnProgress(p.cand, false, ReasonAlreadyListed)
				}
				continue
			}
			submitted++
			observability.DurableShare(ctx, observability.URLhaus, nil, 1)
			if opts.OnProgress != nil {
				opts.OnProgress(p.cand, true, status)
			}
		}
		if ledgerFailed {
			// The provider accepted this batch, but any missing ledger row can be
			// submitted again on the next run. Stop before creating more untracked
			// public submissions.
			return submitted, skipped, firstErr
		}
	}
	return submitted, skipped, firstErr
}
