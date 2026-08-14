package threatfox

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/intel/intelutil"
)

// SubmitRecorder is the slice of *store.Store this package depends on. Kept
// minimal so threatfox never imports store (and vice versa) — the same
// decoupling bazaar/urlhaus/abuseipdb use. Dedup is per-IOC value: one payload
// fetch yields several IOCs (url, ip:port/domain, sha256) and each is tracked
// independently, so a re-fetch that produces one new IOC still submits it.
type SubmitRecorder interface {
	ThreatFoxSubmitted(ioc string) (bool, error)
	RecordThreatFoxSubmission(ioc, iocType, malware, status string, at time.Time) error
}

// Options bundles the runtime knobs for one Share invocation.
type Options struct {
	APIKey     string
	Endpoint   string
	ExtraTags  []string
	ActiveDays int // 1..2 tightens the "still active" window; 0/invalid = 3-day default
	DryRun     bool
	RateLimit  time.Duration
	Reference  string // optional shared reference URL added to each submission

	// OnProgress reports each candidate's outcome: submitted (with the IOC
	// count) or skipped (with the Vet reason). Fires once per candidate.
	OnProgress func(c Candidate, submitted bool, iocCount int, reason string)

	// MaxSubmissions bounds how many CANDIDATES this run may submit (0 =
	// unbounded). It counts candidates that cleared Vet and had at least one
	// fresh (non-deduped) IOC — NOT candidates examined. Mirrors
	// bazaar.MaxUploads / urlhaus.MaxSubmissions: the bound lives here, after
	// the gate, never as a pre-gate query LIMIT, so the budget is spent on real
	// submissions rather than on already-shared entries at the top of the list.
	MaxSubmissions int
	// OnLimitReached fires at most once, when MaxSubmissions stopped the run
	// early, with the number of candidates never examined. A bounded run must
	// never read as an exhausted one.
	OnLimitReached func(unexamined int)

	// Now overrides the clock the active-days gate vets against. Zero =
	// time.Now(). Injected for tests so a fixture's FetchedAt cannot age past
	// the window as wall-clock time passes (the time-bomb the urlhaus tests
	// hit). Production leaves it unset.
	Now time.Time
}

const defaultConfidenceLevel = defaultConfidence

// ErrEmptyBatch is returned when Share is handed nothing to do.
var ErrEmptyBatch = errors.New("threatfox: no candidates to submit")

// Share submits IOCs derived from each vetted candidate to ThreatFox. Pipeline
// per candidate:
//
//  1. Vet — provenance, freshness, public host, and a resolvable Malpedia
//     family. Skip (no budget spent) if it fails.
//  2. For each derived IOC, skip if already submitted (dedup ledger).
//  3. Submit each fresh IOC; record it so the next run skips it.
//
// A candidate with at least one fresh IOC counts as one submission against
// MaxSubmissions. Returns (submitted, skipped, firstErr): submitted counts
// candidates that sent at least one IOC (or, in dry-run, would have); skipped
// counts candidates the gate rejected or that were fully deduped. As with the
// sibling sharers, one failing submission does not abort the run, but the first
// error is surfaced so the CLI can exit non-zero.
func Share(ctx context.Context, rec SubmitRecorder, candidates []Candidate, opts Options) (submitted, skipped int, firstErr error) {
	if strings.TrimSpace(opts.APIKey) == "" && !opts.DryRun {
		return 0, 0, ErrMissingAPIKey
	}
	if len(candidates) == 0 {
		return 0, 0, ErrEmptyBatch
	}
	if opts.RateLimit == 0 {
		opts.RateLimit = 2 * time.Second
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	tags := intelutil.SanitiseAbuseChTags(opts.ExtraTags)
	client := NewClient(opts.Endpoint)

	for i, cand := range candidates {
		if ctx.Err() != nil {
			return submitted, skipped, ctx.Err()
		}
		// Budget check mirrors the sibling sharers: it bounds candidates
		// SUBMITTED, so a skip (gate reject or full dedup) never costs a slot.
		// Everything from i onward is unexamined — a different thing from
		// "nothing left to submit".
		if opts.MaxSubmissions > 0 && submitted >= opts.MaxSubmissions {
			if opts.OnLimitReached != nil {
				opts.OnLimitReached(len(candidates) - i)
			}
			break
		}

		ok, malware, iocs, reason := Vet(cand, now, VetOptions{ActiveDays: opts.ActiveDays})
		if !ok {
			skipped++
			if opts.OnProgress != nil {
				opts.OnProgress(cand, false, 0, reason)
			}
			continue
		}

		// Dedup each derived IOC; only submit the fresh ones.
		var fresh []IOC
		dedupErr := false
		for _, ioc := range iocs {
			already, err := rec.ThreatFoxSubmitted(ioc.Value)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				dedupErr = true
				break
			}
			if !already {
				fresh = append(fresh, ioc)
			}
		}
		if dedupErr {
			// Ledger read failed; do not risk a partial/duplicate submit for
			// this candidate. Not counted as skipped (it is neither vetted-out
			// nor submitted) — same accounting gap the abuseipdb dedup-error
			// path has, and harmless to the budget.
			continue
		}
		if len(fresh) == 0 {
			// Every IOC for this candidate is already in the dataset.
			skipped++
			if opts.OnProgress != nil {
				opts.OnProgress(cand, false, 0, "all IOCs already submitted")
			}
			continue
		}

		if opts.DryRun {
			// Counts against MaxSubmissions so --dry-run --limit N previews
			// exactly the N candidates a real run would submit.
			submitted++
			if opts.OnProgress != nil {
				opts.OnProgress(cand, true, len(fresh), "dry-run")
			}
			continue
		}

		sentAny := false
		var candErr error
		for j, ioc := range fresh {
			res, err := client.Submit(ctx, opts.APIKey, Submission{
				ThreatType:      ioc.ThreatType,
				IOCType:         ioc.Type,
				Malware:         malware,
				IOC:             ioc.Value,
				ConfidenceLevel: defaultConfidenceLevel,
				Reference:       opts.Reference,
				Tags:            tags,
				Comment:         buildComment(cand),
			})
			if err != nil {
				if errors.Is(err, ErrUnauthorized) {
					// An auth failure fails identically for every remaining IOC
					// and candidate — stop the whole run rather than hammering.
					if opts.OnProgress != nil {
						opts.OnProgress(cand, false, 0, "auth key rejected")
					}
					return submitted, skipped, errors.Join(firstErr, err)
				}
				if candErr == nil {
					candErr = err
				}
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			// ThreatFox accounting: `ok` (newly added) and `duplicated` (already
			// in the dataset) are both SUCCESS — the IOC is published, so record
			// it in the dedup ledger so we never re-POST it. `ignored` (rejected
			// by validation) and any non-"ok" query_status are FAILURES: do not
			// record (a corrected future run can retry) and surface the reason.
			if res.Ignored || (res.Status != "" && res.Status != "ok") {
				reason := "threatfox rejected the IOC"
				if res.Status != "" && res.Status != "ok" {
					reason = "threatfox: " + res.Status
				}
				if candErr == nil {
					candErr = errors.New(reason)
				}
				if firstErr == nil {
					firstErr = errors.New(reason)
				}
				continue
			}
			sentAny = true
			status := "submitted"
			if res.Duplicate {
				status = "duplicate"
			}
			if rerr := rec.RecordThreatFoxSubmission(ioc.Value, ioc.Type, malware, status, time.Now().UTC()); rerr != nil && firstErr == nil {
				firstErr = rerr
			}
			// Pace between IOCs within a candidate too — each is a POST.
			if j+1 < len(fresh) {
				if !sleep(ctx, opts.RateLimit) {
					return submitted, skipped, ctx.Err()
				}
			}
		}

		if sentAny {
			submitted++
			if opts.OnProgress != nil {
				opts.OnProgress(cand, true, len(fresh), "")
			}
		} else {
			// Every IOC POST failed; report it as a non-submit with the error.
			if opts.OnProgress != nil {
				msg := "submit failed"
				if candErr != nil {
					msg = "submit failed: " + candErr.Error()
				}
				opts.OnProgress(cand, false, 0, msg)
			}
		}

		// Pace between candidates unless the budget is now spent.
		budgetSpent := opts.MaxSubmissions > 0 && submitted >= opts.MaxSubmissions
		if i+1 < len(candidates) && !budgetSpent {
			if !sleep(ctx, opts.RateLimit) {
				return submitted, skipped, ctx.Err()
			}
		}
	}
	return submitted, skipped, firstErr
}

// sleep waits d or until ctx is done; returns false if ctx was cancelled.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// buildComment assembles the public ThreatFox comment. It states the observed
// delivery (so the IOC is useful) but carries NOTHING that identifies the
// honeypot host or any internal session id — the same discipline as
// bazaar/abuseipdb comments.
func buildComment(c Candidate) string {
	parts := []string{"Malware payload fetched first-hand from this infrastructure by an SSH honeypot."}
	if c.FileKind != "" {
		parts = append(parts, "Payload: "+c.FileKind+".")
	}
	return strings.Join(parts, " ")
}
