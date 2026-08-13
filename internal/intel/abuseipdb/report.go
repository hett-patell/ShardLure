package abuseipdb

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/netmatch"
)

// ReportRecorder is the slice of *store.Store the orchestrator depends on.
// Kept minimal so this package never imports store (and vice versa), avoiding
// a circular path through any future dashboard endpoint. AbuseIPDBReported is
// TIME-WINDOWED: it returns true only if the IP was reported within the
// re-report window (AbuseIPDB permits re-reporting after 15 min; we default to
// 24h), so a persistent attacker is re-reported on later runs.
type ReportRecorder interface {
	AbuseIPDBReported(ip string, within time.Duration) (bool, error)
	RecordAbuseIPDBReport(ip, status string, score int, categories []int, at time.Time) error
}

// Options bundles the runtime knobs for one Report invocation.
type Options struct {
	APIKey     string
	Endpoint   string
	Categories []int
	Comment    string // operator suffix; the generated comment carries NO host/session identifiers
	DryRun     bool
	MinProbe   int           // ProbeScore floor (from config)
	Rewindow   time.Duration // re-report suppression window (default 24h)
	RateLimit  time.Duration // delay between POSTs (default 2s)
	Admin      *netmatch.Set // admin IPs to hard-reject; may be nil
	OnProgress func(c ReportCandidate, result *Result, err error)

	// MaxAgeDays tightens Vet's staleness gate (1..6; 0 or 7 = default 7).
	// May only make the gate stricter — see VetOptions.
	MaxAgeDays int

	// MaxReports bounds how many candidates this run may SUBMIT (0 = unbounded).
	// It counts reports actually sent (or, in dry-run, previewed) — NOT
	// candidates examined. The CLI used to truncate the slice before calling
	// Report, which is a different and much weaker guarantee: candidates arrive
	// worst-offender-first, and on any deployment with history the worst
	// offenders are exactly the ones already sitting in the re-report window, so
	// the budget was spent on dedup hits and the run reported nothing while
	// fresh brute-forcers waited below the cut. Same defect, and same fix, as
	// bazaar.Options.MaxUploads.
	MaxReports int
	// OnLimitReached fires at most once, when MaxReports stopped the run early,
	// with the number of candidates never examined. A bounded run must never
	// read as an exhausted one.
	OnLimitReached func(unexamined int)

	// Now overrides the clock for the staleness gate. Zero = time.Now().
	// Injected for tests; production leaves it unset.
	Now time.Time
}

var (
	ErrMissingAPIKey = errors.New("abuseipdb: missing API key")
	ErrEmptyBatch    = errors.New("abuseipdb: no candidates to report")
	ErrRateLimited   = errors.New("abuseipdb: rate limited (daily cap reached)")
)

// Report submits each confirmed brute-forcer to AbuseIPDB. The pipeline per
// candidate:
//
//  1. Vet (admin/private/reserved reject; confirmed-brute accept). Skip if not.
//  2. Skip if AbuseIPDBReported within the re-report window (dedup).
//  3. Dry-run short-circuit (no network).
//  4. POST /report; on 429 stop the whole batch (daily cap hit).
//  5. On success, RecordAbuseIPDBReport so the window dedup holds.
//
// Returns (reported, skipped, firstErr). firstErr is the first non-fatal error;
// a 429 or fatal status halts the batch and is returned immediately.
func Report(ctx context.Context, rec ReportRecorder, candidates []ReportCandidate, opts Options) (reported, skipped int, firstErr error) {
	if strings.TrimSpace(opts.APIKey) == "" && !opts.DryRun {
		return 0, 0, ErrMissingAPIKey
	}
	if len(candidates) == 0 {
		return 0, 0, ErrEmptyBatch
	}
	if len(opts.Categories) == 0 {
		opts.Categories = []int{18, 22} // 18=Brute-Force, 22=SSH
	}
	if opts.Rewindow == 0 {
		opts.Rewindow = 24 * time.Hour
	}
	if opts.RateLimit == 0 {
		opts.RateLimit = 2 * time.Second
	}

	// One clock for the whole batch: a long paced run must not let a candidate
	// vetted as fresh at the start be judged against a later "now".
	vetNow := opts.Now
	if vetNow.IsZero() {
		vetNow = time.Now()
	}

	c := NewClient(opts.Endpoint)
	// submitted counts candidates that cleared Vet and dedup and were therefore
	// sent (or, in dry-run, previewed). MaxReports bounds THIS, not the
	// candidates examined — a skip costs no API call, so it must not cost budget.
	submitted := 0
	for i, cand := range candidates {
		if ctx.Err() != nil {
			return reported, skipped, ctx.Err()
		}
		if opts.MaxReports > 0 && submitted >= opts.MaxReports {
			// Budget spent. Everything from i onward is unexamined, which is a
			// different thing from "no one left to report" — say so.
			if opts.OnLimitReached != nil {
				opts.OnLimitReached(len(candidates) - i)
			}
			break
		}

		// Vet first — cheap, pure, and the safety gate. A rejected candidate
		// never touches the dedup table or the network.
		if ok, reason := Vet(cand, opts.Admin, opts.MinProbe, vetNow, VetOptions{MaxAgeDays: opts.MaxAgeDays}); !ok {
			skipped++
			if opts.OnProgress != nil {
				opts.OnProgress(cand, &Result{}, errors.New("skip: "+reason))
			}
			continue
		}

		already, err := rec.AbuseIPDBReported(cand.SrcIP, opts.Rewindow)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if already {
			skipped++
			// Report the reason, like every other skip. This branch used to be
			// silent, so a run that skipped 25 candidates printed 14 reasons and
			// left the operator to guess at the other 11 — and "my worst attacker
			// isn't in the list" looks identical to a broken vet gate when the
			// actual answer is "already reported an hour ago".
			if opts.OnProgress != nil {
				opts.OnProgress(cand, &Result{}, errors.New("skip: already reported within the re-report window"))
			}
			continue
		}

		if opts.DryRun {
			// Counts against MaxReports so --dry-run --limit N previews exactly
			// the N candidates the real run would report.
			submitted++
			if opts.OnProgress != nil {
				opts.OnProgress(cand, &Result{}, nil)
			}
			continue
		}

		res, rerr := c.Submit(ctx, opts.APIKey, Submission{
			IP:         cand.SrcIP,
			Categories: opts.Categories,
			Comment:    buildComment(cand, opts.Comment),
			Timestamp:  time.Now().UTC(),
		})
		// Counted on attempt, not on acceptance: MaxReports bounds what we send
		// to AbuseIPDB, and a rejected POST was still a call we made.
		submitted++
		if rerr != nil {
			if opts.OnProgress != nil {
				opts.OnProgress(cand, nil, rerr)
			}
			if firstErr == nil {
				firstErr = rerr
			}
			continue
		}
		if res.RateLimited {
			// Daily report cap reached — stop cleanly rather than spam.
			if opts.OnProgress != nil {
				opts.OnProgress(cand, res, ErrRateLimited)
			}
			return reported, skipped, errors.Join(firstErr, ErrRateLimited)
		}
		if opts.OnProgress != nil {
			opts.OnProgress(cand, res, nil)
		}
		if rerr := rec.RecordAbuseIPDBReport(cand.SrcIP, "reported", res.Score, opts.Categories, time.Now().UTC()); rerr != nil && firstErr == nil {
			firstErr = rerr
		}
		reported++

		// Be polite to the endpoint between POSTs. Skip the wait when the budget
		// is already spent — the next iteration would only break, and pacing
		// exists to space out API calls, not to delay the summary line.
		budgetSpent := opts.MaxReports > 0 && submitted >= opts.MaxReports
		if i+1 < len(candidates) && !budgetSpent {
			t := time.NewTimer(opts.RateLimit)
			select {
			case <-ctx.Done():
				t.Stop()
				return reported, skipped, ctx.Err()
			case <-t.C:
			}
		}
	}
	return reported, skipped, firstErr
}

// buildComment assembles the public report comment. It states the observed
// behaviour (so the community feed is useful) but carries NOTHING that
// identifies the honeypot host or any internal session id — the same
// discipline as bazaar.buildComment. The attacker's own SrcIP is the API's
// `ip` field, not the comment, so the comment stays host-anonymous.
func buildComment(c ReportCandidate, extra string) string {
	parts := []string{"SSH brute-force / credential-spray attempts observed by an SSH honeypot."}
	if c.EventCount > 0 {
		parts = append(parts, "Login attempts logged during the observation window.")
	}
	if extra != "" {
		parts = append(parts, extra)
	}
	return strings.Join(parts, " ")
}
