package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/intel/bazaar"
	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
)

// cmdShare is the dispatcher for "shardlure share <destination>".
// "bazaar" ships malware SAMPLES to MalwareBazaar; "urlhaus" ships the
// malware-distribution URLs those samples came from. Both gate on a single
// Vet function in their own package. Future destinations (dshield, …) slot in
// as additional cases here.
func cmdShare(st *store.Store, cfg config.Config, keys *settings.Keystore, args []string) {
	if len(args) < 1 {
		fatal(fmt.Errorf("usage: shardlure share <bazaar|urlhaus|threatfox> [flags]\n" +
			"  bazaar    [--dry-run] [--limit N] [--sha SHA] [--since DURATION] [--anonymous] [--status]\n" +
			"  urlhaus   [--dry-run] [--limit N] [--active-days N] [--anonymous] [--status]\n" +
			"  threatfox [--dry-run] [--limit N] [--active-days N] [--status]"))
	}
	switch args[0] {
	case "bazaar":
		cmdShareBazaar(st, cfg, keys, args[1:])
	case "urlhaus":
		cmdShareURLhaus(st, cfg, keys, args[1:])
	case "threatfox":
		cmdShareThreatFox(st, cfg, keys, args[1:])
	default:
		fatal(fmt.Errorf("unknown share destination: %q (supported: bazaar, urlhaus, threatfox)", args[0]))
	}
}

// abuseCHKey resolves THE abuse.ch Auth-Key for the CLI, following the
// project-wide DB > env > config precedence.
//
// The keystore comes first because that is where a key saved from the
// dashboard Settings panel lives — config is seeded INTO the keystore at
// startup, never the reverse, so a config-only lookup reported "no key" on
// precisely the deployments that had one. abuse.ch issues one key per account
// covering both MalwareBazaar and URLhaus, so this is the single resolution
// path for both subcommands (mirroring the server's abuseCHKeyLive).
func abuseCHKey(cfg config.Config, keys *settings.Keystore, extraEnv ...string) string {
	if keys != nil {
		lookups := append([]string{}, extraEnv...)
		lookups = append(lookups, settings.KeyBazaar, settings.KeyBazaarAlt)
		for _, k := range lookups {
			if v := strings.TrimSpace(keys.Get(k)); v != "" {
				return v
			}
		}
	}
	if k := strings.TrimSpace(cfg.Intel.Bazaar.APIKey); k != "" {
		return k
	}
	for _, env := range extraEnv {
		if k := strings.TrimSpace(os.Getenv(env)); k != "" {
			return k
		}
	}
	return ""
}

// validateOutboundLimit refuses a negative --limit on share/report. The
// intel packages read any non-positive budget as "no cap", so a typo'd -1
// used to turn a bounded run of irreversible submissions into an unbounded
// one — the pattern already refused for actors (final audit M4). 0 stays the
// documented "unbounded".
func validateOutboundLimit(n int) error {
	if n < 0 {
		return fmt.Errorf("--limit must be 0 (unbounded) or positive, got %d", n)
	}
	return nil
}

func cmdShareBazaar(st *store.Store, cfg config.Config, keys *settings.Keystore, args []string) {
	// intel.bazaar.freshness_days tightens both the default candidate-selection
	// window and Vet. --since may widen local selection, but never Vet policy.
	freshDays := cfg.Intel.Bazaar.FreshnessDays
	if freshDays <= 0 {
		freshDays = 10
	}
	fs := flag.NewFlagSet("share bazaar", flag.ExitOnError)
	dryRun := fs.Bool("dry-run", false, "list what would upload without contacting MalwareBazaar")
	// Bounds UPLOADS, enforced inside bazaar.Share after Vet — not a truncation
	// of the candidate list. Truncating first meant the budget was consumed by
	// already-shared hashes at the top of the newest-first list, so the default
	// shipped nothing while vettable samples sat just below the cut.
	limit := fs.Int("limit", 10, "max samples to upload in this run (0 = unbounded, negative refused); counts submissions, not candidates examined")
	sha := fs.String("sha", "", "select only the sample with this sha256 (still subject to dedup and Vet)")
	since := fs.Duration("since", time.Duration(freshDays)*24*time.Hour, "local candidate-selection window; does not change the 10-day upload ceiling")
	anonymous := fs.Bool("anonymous", false, "submit without attribution to your account")
	statusOnly := fs.Bool("status", false, "list past uploads from bazaar_uploads instead of uploading")
	comment := fs.String("comment", "", "extra comment appended to every sample's context.comment")
	endpoint := fs.String("endpoint", "", "override MalwareBazaar endpoint (default from config or builtin)")
	_ = fs.Parse(args)
	// flag stops at the first non-flag, so a stray positional would silently
	// drop every flag after it — including --dry-run, turning a preview into a
	// real, irreversible run. Refuse it, as share urlhaus/threatfox do.
	if fs.NArg() > 0 {
		fatal(fmt.Errorf("unexpected argument %q", fs.Arg(0)))
	}
	if err := validateOutboundLimit(*limit); err != nil {
		fatal(err)
	}

	if *statusOnly {
		printBazaarStatus(st)
		return
	}

	apiKey := abuseCHKey(cfg, keys)
	if apiKey == "" && !*dryRun {
		fatal(fmt.Errorf("no abuse.ch Auth-Key found — save one in the dashboard Settings panel (MalwareBazaar), set intel.bazaar.api_key in %s, or export SHARDLURE_BAZAAR_KEY; sign up at https://auth.abuse.ch/", config.DefaultConfigPath()))
	}

	cands, err := collectShareCandidates(st, *sha, *since)
	if err != nil {
		fatal(fmt.Errorf("collect candidates: %w", err))
	}
	if len(cands) == 0 {
		fmt.Println("no candidates: nothing in artifacts table within the candidate-selection window")
		return
	}

	maxBytes := cfg.Intel.Bazaar.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 32 << 20
	}

	ep := cfg.Intel.Bazaar.Endpoint
	if *endpoint != "" {
		ep = *endpoint
	}

	limitLabel := "unbounded"
	if *limit > 0 {
		limitLabel = strconv.Itoa(*limit)
	}
	fmt.Printf("candidates: %d  upload-limit=%s  dry-run=%v  endpoint=%s\n", len(cands), limitLabel, *dryRun, ep)
	if *dryRun {
		fmt.Println("(dry-run: no upload)")
	}

	opts := bazaar.Options{
		APIKey:        apiKey,
		Endpoint:      ep,
		ExtraTags:     cfg.Intel.Bazaar.Tags,
		MaxBytes:      maxBytes,
		FreshnessDays: freshDays,
		DryRun:        *dryRun,
		Anonymous:     *anonymous,
		Comment:       *comment,
		// 2 s rate limit lives inside Share's default. Hardcoded
		// here only to make it obvious in --dry-run output.
		RateLimit:  2 * time.Second,
		MaxUploads: *limit,
		OnProgress: func(c bazaar.Candidate, cls bazaar.Classification, r *bazaar.Result, err error) {
			printBazaarProgress(c, cls, r, err)
		},
		OnLimitReached: func(unexamined int) {
			// Never let a bounded run read as an exhausted one.
			fmt.Printf("\n  (upload limit %d reached — %d candidate(s) not examined; raise --limit or pass --limit=0)\n",
				*limit, unexamined)
		},
	}

	ctx, cancel := newCommandContext(context.Background())
	defer cancel()

	uploaded, skipped, ferr := bazaar.Share(ctx, &bazaarRecorderAdapter{st: st}, cands, opts)
	fmt.Printf("\nresult: uploaded=%d skipped=%d\n", uploaded, skipped)
	if ferr != nil {
		fatalRemote(ferr)
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

// collectShareCandidates pulls every artifact that could be considered for
// upload. Narrowing (see store.ArtifactsForShare):
//
//   - status = 'fetched'            — we actually have the bytes on disk
//   - size_bytes >= MinSampleBytes  — bazaar's own floor, not a second one
//   - sha256 IS NOT NULL            — needed for dedup
//   - origin IN ShareableOrigins()  — bazaar's own allowlist (excludes TTY
//     transcripts, includes quarantine_fetch, which `LIKE '%download%'` didn't)
//   - created_at >= now - since     — local candidate selection only
//
// If singleSHA is non-empty, it overrides the WHERE clause completely. Both
// paths still enter bazaar.Share, which applies dedup and the non-bypassable
// Vet freshness policy before any network call. This returns ALL candidates:
// --limit bounds submissions inside Share, so the budget is spent on samples
// that actually clear the gate.
func collectShareCandidates(st *store.Store, singleSHA string, since time.Duration) ([]bazaar.Candidate, error) {
	if singleSHA != "" {
		row, err := st.GetArtifactForShareBySHA(singleSHA, store.SharePolicy{
			MinBytes: bazaar.MinSampleBytes, Origins: bazaar.ShareableOrigins(),
		})
		if err != nil {
			return nil, fmt.Errorf("no artifact with sha256=%s: %w", singleSHA, err)
		}
		return []bazaar.Candidate{artifactToCandidate(*row)}, nil
	}
	cutoff := time.Now().Add(-since).UTC()
	// Selection narrowing comes FROM the bazaar gate, so this query can't be
	// stricter than the policy that judges the samples (it was, on both size
	// and origin, and each drift hid real payloads — see ArtifactsForShare).
	pol := store.SharePolicy{
		MinBytes: bazaar.MinSampleBytes,
		Origins:  bazaar.ShareableOrigins(),
	}
	rows, err := st.ArtifactsForShare(cutoff, pol)
	if err != nil {
		return nil, err
	}
	out := make([]bazaar.Candidate, 0, len(rows))
	for _, r := range rows {
		// The pool only decides WHICH shas to consider. The row judged for each
		// is re-picked by GetArtifactForShareBySHA — the choice --sha, the
		// dashboard upload handler and the bazaar panel make — which ranks rows
		// with a file on disk first. The pooled row is simply the newest fetch
		// and may have no local_path, so a bulk run skipped as "file gone" a
		// sample the panel showed eligible and the handler uploaded: selection
		// tighter than Vet. On a lookup failure keep the pooled row; Share then
		// reports why it skips it.
		best, err := st.GetArtifactForShareBySHA(r.SHA256, pol)
		if err != nil || best == nil {
			best = &r
		}
		out = append(out, artifactToCandidate(*best))
	}
	return out, nil
}

func artifactToCandidate(a store.Artifact) bazaar.Candidate {
	// ObservedAt drives MB's 10-day freshness check: use the event ts (when
	// the attacker actually dropped the sample), falling back to CreatedAt
	// only when ts is unknown. CreatedAt is capture-registration time, which
	// for a re-imported archive is "now" and would wrongly look fresh.
	observed := a.LastSuccessfulFetchAt
	return bazaar.Candidate{
		SHA256:     a.SHA256,
		LocalPath:  a.LocalPath,
		SizeBytes:  a.SizeBytes,
		URL:        a.URL,
		CreatedAt:  a.CreatedAt,
		Origin:     a.Origin,
		ObservedAt: observed,
	}
}

// printBazaarProgress is the per-candidate OnProgress hook. It is
// deliberately verbose: this is a destructive, public action and the
// operator should be able to read the output as a contract.
func printBazaarProgress(c bazaar.Candidate, cls bazaar.Classification, r *bazaar.Result, err error) {
	fprintBazaarProgress(os.Stdout, c, cls, r, err)
}

func fprintBazaarProgress(w io.Writer, c bazaar.Candidate, cls bazaar.Classification, r *bazaar.Result, err error) {
	// Every field below is attacker-derived (classified from their bytes) or
	// came back from MalwareBazaar, so each goes through termSafe.
	prefix := termSafe(shaShort(c.SHA256))
	tags := termSafe(strings.Join(cls.Tags, ","))
	if tags == "" {
		tags = "-"
	}
	fam := termSafe(cls.Family)
	if fam == "" {
		fam = "-"
	}
	header := fmt.Sprintf("  %s %8d  %-18s %-25s", prefix, c.SizeBytes, termSafe(cls.FileKind), fam)
	switch {
	case err != nil:
		fmt.Fprintf(w, "%s tags=%s\n    ERROR: %s\n", header, tags, termSafe(err.Error()))
	case r == nil:
		fmt.Fprintf(w, "%s tags=%s\n    (no result)\n", header, tags)
	case r.Status == "dry-run":
		fmt.Fprintf(w, "%s tags=%s\n", header, tags)
	default:
		extra := ""
		if r.SampleURL != "" {
			extra = " " + r.SampleURL
		}
		fmt.Fprintf(w, "%s tags=%s\n    -> %s%s\n", header, tags, termSafe(r.Status), termSafe(extra))
	}
}

func printBazaarStatus(st *store.Store) {
	rows, err := st.ListBazaarUploads(50)
	if err != nil {
		fatal(err)
	}
	fprintBazaarStatus(os.Stdout, rows)
}

func fprintBazaarStatus(w io.Writer, rows []store.BazaarUpload) {
	if len(rows) == 0 {
		fmt.Fprintln(w, "(no uploads recorded)")
		return
	}
	fmt.Fprintf(w, "%-12s  %-25s  %-22s  %s\n", "sha256", "uploaded_at (UTC)", "status", "url")
	for _, u := range rows {
		ts := u.UploadedAt.UTC().Format("2006-01-02 15:04:05")
		fmt.Fprintf(w, "%-12s  %-25s  %-22s  %s\n", termSafe(shaShort(u.SHA256)), ts, termSafe(u.ResponseStatus), termSafe(u.MBURL))
	}
}

func shaShort(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
