package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/intel/bazaar"
	"github.com/networkshard/shardlure/internal/store"
)

// cmdShare is the dispatcher for "shardlure share <destination>".
// Currently only "bazaar" is wired up; future destinations (urlhaus,
// abuseipdb, dshield) would slot in as additional cases here.
func cmdShare(st *store.Store, cfg config.Config, args []string) {
	if len(args) < 1 {
		fatal(fmt.Errorf("usage: shardlure share <bazaar> [--dry-run] [--limit N] [--sha SHA] [--since DURATION] [--anonymous] [--status]"))
	}
	switch args[0] {
	case "bazaar":
		cmdShareBazaar(st, cfg, args[1:])
	default:
		fatal(fmt.Errorf("unknown share destination: %q (supported: bazaar)", args[0]))
	}
}

func cmdShareBazaar(st *store.Store, cfg config.Config, args []string) {
	// intel.bazaar.freshness_days is the documented knob for the default
	// freshness window; --since overrides it per-run.
	freshDays := cfg.Intel.Bazaar.FreshnessDays
	if freshDays <= 0 {
		freshDays = 10
	}
	fs := flag.NewFlagSet("share bazaar", flag.ExitOnError)
	dryRun := fs.Bool("dry-run", false, "list what would upload without contacting MalwareBazaar")
	limit := fs.Int("limit", 10, "max samples to upload in this run (0 = unbounded)")
	sha := fs.String("sha", "", "upload only the sample with this sha256 (overrides limit/since)")
	since := fs.Duration("since", time.Duration(freshDays)*24*time.Hour, "only consider artifacts captured within this duration (default from intel.bazaar.freshness_days)")
	anonymous := fs.Bool("anonymous", false, "submit without attribution to your account")
	statusOnly := fs.Bool("status", false, "list past uploads from bazaar_uploads instead of uploading")
	comment := fs.String("comment", "", "extra comment appended to every sample's context.comment")
	endpoint := fs.String("endpoint", "", "override MalwareBazaar endpoint (default from config or builtin)")
	_ = fs.Parse(args)

	if *statusOnly {
		printBazaarStatus(st)
		return
	}

	apiKey := strings.TrimSpace(cfg.Intel.Bazaar.APIKey)
	if apiKey == "" && !*dryRun {
		fatal(fmt.Errorf("intel.bazaar.api_key is empty in %s — sign up at https://auth.abuse.ch/ and paste your Auth-Key into shardlure.yaml", config.DefaultConfigPath()))
	}

	cands, err := collectShareCandidates(st, *sha, *since)
	if err != nil {
		fatal(fmt.Errorf("collect candidates: %w", err))
	}
	if len(cands) == 0 {
		fmt.Println("no candidates: nothing in artifacts table within the freshness window (try --since 720h)")
		return
	}

	// Apply the limit AFTER candidate collection so the SQL stays
	// simple. With limit=0 we keep them all.
	if *limit > 0 && len(cands) > *limit {
		cands = cands[:*limit]
	}

	maxBytes := cfg.Intel.Bazaar.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 32 << 20
	}

	ep := cfg.Intel.Bazaar.Endpoint
	if *endpoint != "" {
		ep = *endpoint
	}

	fmt.Printf("candidates: %d  dry-run=%v  endpoint=%s\n", len(cands), *dryRun, ep)
	if *dryRun {
		fmt.Println("(dry-run: no upload)")
	}

	opts := bazaar.Options{
		APIKey:    apiKey,
		Endpoint:  ep,
		ExtraTags: cfg.Intel.Bazaar.Tags,
		MaxBytes:  maxBytes,
		DryRun:    *dryRun,
		Anonymous: *anonymous,
		Comment:   *comment,
		// 2 s rate limit lives inside Share's default. Hardcoded
		// here only to make it obvious in --dry-run output.
		RateLimit: 2 * time.Second,
		OnProgress: func(c bazaar.Candidate, cls bazaar.Classification, r *bazaar.Result, err error) {
			printBazaarProgress(c, cls, r, err)
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	uploaded, skipped, ferr := bazaar.Share(ctx, &bazaarRecorderAdapter{st: st}, cands, opts)
	fmt.Printf("\nresult: uploaded=%d skipped=%d\n", uploaded, skipped)
	if ferr != nil {
		fatal(ferr)
	}
}

// bazaarRecorderAdapter bridges the store.BazaarUpload struct API to
// the simpler argument list bazaar.UploadRecorder expects. Keeps the
// bazaar package free of any store import.
type bazaarRecorderAdapter struct {
	st *store.Store
}

func (a *bazaarRecorderAdapter) BazaarUploadRecorded(sha string) (bool, error) {
	return a.st.BazaarUploadRecorded(sha)
}

func (a *bazaarRecorderAdapter) RecordBazaarUpload(sha, status, mbURL string, at time.Time) error {
	return a.st.RecordBazaarUpload(store.BazaarUpload{
		SHA256:         sha,
		UploadedAt:     at,
		ResponseStatus: status,
		MBURL:          mbURL,
	})
}

// collectShareCandidates pulls every artifact eligible for upload.
// Eligibility (matched by the WHERE clause):
//
//   - status = 'fetched'    — we actually have the bytes on disk
//   - size_bytes > 1024     — skip empty + tiny redir sentinels
//   - sha256 IS NOT NULL    — needed for dedup
//   - origin LIKE '%download%'  — exclude TTY transcripts (those
//     are operator artifacts, not malware samples)
//   - created_at >= now - since  — honour abuse.ch freshness policy
//
// If singleSHA is non-empty, it overrides the WHERE clause completely
// so an operator can force-retry a specific sample regardless of
// freshness/dedup. The bazaar package still consults its own
// BazaarUploadRecorded gate.
func collectShareCandidates(st *store.Store, singleSHA string, since time.Duration) ([]bazaar.Candidate, error) {
	if singleSHA != "" {
		row, err := st.GetArtifactBySHA(singleSHA)
		if err != nil {
			return nil, fmt.Errorf("no artifact with sha256=%s: %w", singleSHA, err)
		}
		return []bazaar.Candidate{artifactToCandidate(*row)}, nil
	}
	cutoff := time.Now().Add(-since).UTC()
	rows, err := st.ArtifactsForShare(cutoff)
	if err != nil {
		return nil, err
	}
	out := make([]bazaar.Candidate, 0, len(rows))
	for _, r := range rows {
		out = append(out, artifactToCandidate(r))
	}
	return out, nil
}

func artifactToCandidate(a store.Artifact) bazaar.Candidate {
	return bazaar.Candidate{
		SHA256:    a.SHA256,
		LocalPath: a.LocalPath,
		SizeBytes: a.SizeBytes,
		URL:       a.URL,
		SrcIP:     a.SrcIP,
		SessionID: a.SessionID,
		CreatedAt: a.CreatedAt,
	}
}

// printBazaarProgress is the per-candidate OnProgress hook. It is
// deliberately verbose: this is a destructive, public action and the
// operator should be able to read the output as a contract.
func printBazaarProgress(c bazaar.Candidate, cls bazaar.Classification, r *bazaar.Result, err error) {
	prefix := shaShort(c.SHA256)
	tags := strings.Join(cls.Tags, ",")
	if tags == "" {
		tags = "-"
	}
	fam := cls.Family
	if fam == "" {
		fam = "-"
	}
	header := fmt.Sprintf("  %s %8d  %-18s %-25s", prefix, c.SizeBytes, cls.FileKind, fam)
	switch {
	case err != nil:
		fmt.Printf("%s tags=%s\n    ERROR: %v\n", header, tags, err)
	case r == nil:
		fmt.Printf("%s tags=%s\n    (no result)\n", header, tags)
	case r.Status == "dry-run":
		fmt.Printf("%s tags=%s\n", header, tags)
	default:
		extra := ""
		if r.SampleURL != "" {
			extra = " " + r.SampleURL
		}
		fmt.Printf("%s tags=%s\n    -> %s%s\n", header, tags, r.Status, extra)
	}
}

func printBazaarStatus(st *store.Store) {
	rows, err := st.ListBazaarUploads(50)
	if err != nil {
		fatal(err)
	}
	if len(rows) == 0 {
		fmt.Println("(no uploads recorded)")
		return
	}
	fmt.Printf("%-12s  %-25s  %-22s  %s\n", "sha256", "uploaded_at (UTC)", "status", "url")
	for _, u := range rows {
		ts := u.UploadedAt.UTC().Format("2006-01-02 15:04:05")
		fmt.Printf("%-12s  %-25s  %-22s  %s\n", shaShort(u.SHA256), ts, u.ResponseStatus, u.MBURL)
	}
}

func shaShort(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
