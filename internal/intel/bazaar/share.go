package bazaar

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Candidate is one row from artifacts considered for upload. The
// orchestrator (Share) filters the artifacts table down to a slice of
// these and feeds them to the per-sample pipeline. Caller (cmd) is
// responsible for the actual artifacts query so this package stays
// store-agnostic — easier to unit-test without spinning up sqlite.
// Deliberately NO SrcIP/SessionID fields: those must never reach abuse.ch
// (they identify the honeypot host and session), and not carrying them at
// all is the strongest guarantee a future buildComment/buildReferences
// change can't leak them.
type Candidate struct {
	SHA256    string
	LocalPath string
	SizeBytes int64
	URL       string // attacker-supplied URL recovered from the cowrie session, if any
	CreatedAt time.Time
	// Origin is the artifact provenance (quarantine_fetch, cowrie_download,
	// cowrie_file_download, cowrie_tty). Vet uses it as a behavioural malware
	// signal: a script/binary FETCHED during an attacker session is malicious
	// by provenance even with no known family.
	Origin string
	// ObservedAt is when the sample was FIRST seen in the honeypot (event ts),
	// NOT when our capture runner registered the artifact row (that's
	// CreatedAt, which is "now" for re-imported archives). Vet enforces MB's
	// 10-day freshness rule against this.
	ObservedAt time.Time
}

// UploadRecorder is the slice of *store.Store we depend on. Kept
// minimal so the bazaar package never imports store directly (and
// vice versa) — avoids a circular import path through any future
// dashboard endpoint.
type UploadRecorder interface {
	BazaarUploadRecorded(sha string) (bool, error)
	RecordBazaarUpload(sha, status, mbURL string, at time.Time) error
}

// Options bundles the runtime knobs for one Share invocation. All
// fields are required; ShareWithOptions errors loudly on missing
// values rather than silently defaulting, because uploading to the
// wrong endpoint or with an empty key would be an embarrassing bug.
type Options struct {
	APIKey        string
	Endpoint      string
	ExtraTags     []string
	MaxBytes      int64
	FreshnessDays int // 0 = default (10 days); configurable via settings panel
	DryRun        bool
	Anonymous     bool
	Comment       string // operator-supplied comment appended to per-sample context
	RateLimit     time.Duration
	OnProgress    func(c Candidate, classification Classification, result *Result, err error)
}

// Errors surfaced to callers. Kept as sentinels so the CLI can map
// them to specific exit codes (e.g. missing API key is a config bug,
// upstream rejection is operational).
var (
	ErrMissingAPIKey = errors.New("bazaar: missing API key")
	ErrEmptyBatch    = errors.New("bazaar: no candidates to upload")
)

// Share submits each candidate to MalwareBazaar. The pipeline:
//
//  1. Skip if size > MaxBytes (server-side cap) or size == 0.
//  2. Skip if BazaarUploadRecorded returns true (already shipped).
//  3. Classify on disk → tag set + optional family.
//  4. POST to MalwareBazaar with combined (ExtraTags + classification).
//  5. On accepted response, RecordBazaarUpload so the next run skips it.
//
// Returns (uploaded, skipped, error). uploaded counts both inserted
// and file_already_known responses (both mean "MB has it"); skipped
// counts size/dedup skips. error is the FIRST upload-level error
// encountered — we don't fail-fast on a single bad sample, but we do
// surface the error to the caller so the CLI can exit non-zero.
func Share(ctx context.Context, rec UploadRecorder, candidates []Candidate, opts Options) (uploaded, skipped int, firstErr error) {
	if strings.TrimSpace(opts.APIKey) == "" && !opts.DryRun {
		return 0, 0, ErrMissingAPIKey
	}
	if len(candidates) == 0 {
		return 0, 0, ErrEmptyBatch
	}
	if opts.MaxBytes == 0 {
		opts.MaxBytes = 32 << 20
	}
	if opts.RateLimit == 0 {
		opts.RateLimit = 2 * time.Second
	}

	c := NewClient(opts.Endpoint)
	for i, cand := range candidates {
		if ctx.Err() != nil {
			return uploaded, skipped, ctx.Err()
		}

		// Pre-flight filters. These do NOT consult Classify because
		// the classify call costs disk IO; cheap rejects come first.
		if cand.SHA256 == "" {
			skipped++
			continue
		}
		if cand.SizeBytes <= 0 || cand.SizeBytes > opts.MaxBytes {
			skipped++
			if opts.OnProgress != nil {
				opts.OnProgress(cand, Classification{}, nil,
					fmt.Errorf("skip: size %d outside (0, %d]", cand.SizeBytes, opts.MaxBytes))
			}
			continue
		}
		alreadyUploaded, err := rec.BazaarUploadRecorded(cand.SHA256)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if alreadyUploaded {
			skipped++
			continue
		}

		// Stat to make sure the file is still on disk — purge or a
		// human cleanup could have nuked it between the artifacts
		// query and this loop iteration.
		if _, err := os.Stat(cand.LocalPath); err != nil {
			skipped++
			if opts.OnProgress != nil {
				opts.OnProgress(cand, Classification{}, nil,
					fmt.Errorf("skip: file gone: %w", err))
			}
			continue
		}

		cls, err := Classify(cand.LocalPath)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		// MalwareBazaar submission-policy gate. Runs AFTER classify (it needs
		// the file kind/family) but BEFORE any network call — so a benign,
		// junk, or stale sample is skipped locally and never touches the MB
		// API. This is the single enforcement point for both the CLI and the
		// dashboard upload button.
		if ok, reason := Vet(cand, cls, time.Now(), VetOptions{FreshnessDays: opts.FreshnessDays}); !ok {
			skipped++
			if opts.OnProgress != nil {
				opts.OnProgress(cand, cls, &Result{Status: "skipped"}, errors.New(reason))
			}
			continue
		}

		// Compose the final tag set: per-sample (cls.Tags) ∪
		// operator-supplied (opts.ExtraTags). Sanitisation happens
		// inside the client too, but doing it here gives us a clean
		// preview for --dry-run output.
		tags := append([]string{}, cls.Tags...)
		tags = append(tags, opts.ExtraTags...)
		tags = sanitiseTags(tags)

		comment := buildComment(cand, cls, opts.Comment)
		refs := buildReferences(cand)

		sub := Submission{
			Filename:       filepath.Base(cand.LocalPath),
			Anonymous:      opts.Anonymous,
			Tags:           tags,
			Comment:        comment,
			DeliveryMethod: "other",
			References:     refs,
		}

		if opts.DryRun {
			if opts.OnProgress != nil {
				opts.OnProgress(cand, cls, &Result{Status: "dry-run"}, nil)
			}
			continue
		}

		// Open just before the POST so we don't hold N file
		// descriptors during the (sequential) loop.
		f, oerr := os.Open(cand.LocalPath)
		if oerr != nil {
			if firstErr == nil {
				firstErr = oerr
			}
			continue
		}
		res, uerr := c.Upload(ctx, opts.APIKey, f, cand.SHA256, sub)
		_ = f.Close()

		if uerr != nil {
			if opts.OnProgress != nil {
				opts.OnProgress(cand, cls, nil, uerr)
			}
			if firstErr == nil {
				firstErr = uerr
			}
			// Don't sleep on errors — let the next iteration go.
			continue
		}
		if opts.OnProgress != nil {
			opts.OnProgress(cand, cls, res, nil)
		}
		if res.IsAccepted() {
			if rerr := rec.RecordBazaarUpload(cand.SHA256, res.Status, res.SampleURL, time.Now().UTC()); rerr != nil && firstErr == nil {
				firstErr = rerr
			}
			uploaded++
		} else {
			// Specific upstream rejections we want to escalate. A
			// blacklisted user or missing key is a hard stop —
			// continuing would just spam abuse.ch with rejected
			// requests.
			switch res.Status {
			case "no_api_key", "user_blacklisted":
				return uploaded, skipped, fmt.Errorf("bazaar fatal: %s", res.Status)
			}
		}

		// Be polite to the abuse.ch endpoint. Their fair-use terms
		// don't pin a number, but their own example python script
		// has no retries and the community API doc says repeat
		// violations of fair use lead to a ban. 2 s between calls
		// is conservative and still ships our 26-sample backlog in
		// under a minute.
		if i+1 < len(candidates) {
			t := time.NewTimer(opts.RateLimit)
			select {
			case <-ctx.Done():
				t.Stop() // don't leak the timer when the context wins the race
				return uploaded, skipped, ctx.Err()
			case <-t.C:
			}
		}
	}
	return uploaded, skipped, firstErr
}

// buildComment assembles the "context.comment" value sent to abuse.ch.
// We want it to be useful enough to make the upload findable later
// (operator label, sample family) but NOT to leak honeypot-internal
// identifiers (cowrie session IDs may correlate to real attacker
// activity we don't want public). Trim aggressively.
func buildComment(c Candidate, cls Classification, extra string) string {
	parts := []string{"Captured by ShardLure honeypot."}
	if cls.Family != "" {
		parts = append(parts, "Suspected family: "+cls.Family+".")
	}
	if cls.FileKind != "" {
		parts = append(parts, "File kind: "+cls.FileKind+".")
	}
	if !c.CreatedAt.IsZero() {
		parts = append(parts, "Captured: "+c.CreatedAt.UTC().Format("2006-01-02")+".")
	}
	if extra != "" {
		parts = append(parts, extra)
	}
	return strings.Join(parts, " ")
}

// buildReferences puts the attacker-supplied URL into the abuse.ch
// "links" key so URLhaus can correlate it later. We deliberately do
// NOT include the source IP — abuse.ch hashes and shares uploader
// metadata, and a stable honeypot IP could be used to derank our
// other submissions if an analyst flagged one as low-quality.
func buildReferences(c Candidate) map[string][]string {
	if strings.TrimSpace(c.URL) == "" {
		return nil
	}
	return map[string][]string{"links": {c.URL}}
}
