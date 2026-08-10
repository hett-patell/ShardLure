package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/intel/bazaar"
	"github.com/networkshard/shardlure/internal/intel/urlhaus"
	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
)

// urlhausAPIKey resolves the abuse.ch Auth-Key for URLhaus, following the
// project's documented DB > env > config precedence.
//
// The keystore comes FIRST because that is where a key saved from the dashboard
// Settings panel lives — config is only ever seeded into the keystore at
// startup, never the reverse, so a config-only lookup reports "no key" on
// precisely the deployments that do have one.
//
// abuse.ch issues ONE key per account covering both MalwareBazaar and URLhaus,
// so a bazaar-configured deployment is URLhaus-ready with no extra setup.
func urlhausAPIKey(cfg config.Config, keys *settings.Keystore) string {
	if keys != nil {
		for _, k := range []string{
			"SHARDLURE_URLHAUS_KEY",
			settings.KeyBazaar,
			settings.KeyBazaarAlt,
		} {
			if v := strings.TrimSpace(keys.Get(k)); v != "" {
				return v
			}
		}
	}
	if k := strings.TrimSpace(cfg.Intel.URLhaus.APIKey); k != "" {
		return k
	}
	if k := strings.TrimSpace(cfg.Intel.Bazaar.APIKey); k != "" {
		return k
	}
	// Direct env fallback for the URLhaus-specific name, which the keystore
	// registry doesn't know about.
	if k := strings.TrimSpace(os.Getenv("SHARDLURE_URLHAUS_KEY")); k != "" {
		return k
	}
	return ""
}

func cmdShareURLhaus(st *store.Store, cfg config.Config, keys *settings.Keystore, args []string) {
	activeDays := cfg.Intel.URLhaus.ActiveDays
	if activeDays <= 0 {
		activeDays = 3
	}

	fs := flag.NewFlagSet("share urlhaus", flag.ExitOnError)
	dryRun := fs.Bool("dry-run", false, "list what would be submitted without contacting URLhaus")
	limit := fs.Int("limit", 25, "max URLs to submit in this run (0 = unbounded)")
	statusOnly := fs.Bool("status", false, "list past submissions from urlhaus_submissions instead of submitting")
	anonymous := fs.Bool("anonymous", cfg.Intel.URLhaus.Anonymous, "hide your abuse.ch handle on the public record")
	activeDaysFlag := fs.Int("active-days", activeDays, "only submit URLs confirmed serving within this many days (may only tighten)")
	endpoint := fs.String("endpoint", "", "override the URLhaus endpoint (default from config or builtin)")
	// Unknown flags are fatal by convention in this CLI (flag.ExitOnError),
	// so a typo can never silently change behaviour.
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if fs.NArg() > 0 {
		fatal(fmt.Errorf("unexpected argument %q", fs.Arg(0)))
	}

	if *statusOnly {
		printURLhausStatus(st)
		return
	}

	apiKey := urlhausAPIKey(cfg, keys)
	if apiKey == "" && !*dryRun {
		fatal(fmt.Errorf("no abuse.ch Auth-Key found — save one in the dashboard Settings panel (MalwareBazaar), set intel.urlhaus.api_key / intel.bazaar.api_key in %s, or export SHARDLURE_URLHAUS_KEY; get one free at https://auth.abuse.ch/", config.DefaultConfigPath()))
	}

	rows, err := st.URLhausCandidates(*activeDaysFlag, *limit)
	if err != nil {
		fatal(fmt.Errorf("collect candidates: %w", err))
	}
	if len(rows) == 0 {
		fmt.Println("no candidates: no successfully-fetched http(s) payload URLs in the active window that haven't already been submitted")
		return
	}

	cands := make([]urlhaus.Candidate, 0, len(rows))
	for _, r := range rows {
		// Classify off disk to get the file kind. Vet needs it to confirm the
		// URL actually served a payload (and to reject SSH keys / unknown
		// blobs). Reuses the bazaar classifier rather than duplicating it.
		kind := ""
		if r.LocalPath != "" {
			if cls, cerr := bazaar.Classify(r.LocalPath); cerr == nil {
				kind = cls.FileKind
			}
		}
		cands = append(cands, urlhaus.Candidate{
			URL:       r.URL,
			SHA256:    r.SHA256,
			SizeBytes: r.SizeBytes,
			Origin:    r.Origin,
			Status:    r.Status,
			FetchedAt: r.FetchedAt,
			FileKind:  kind,
		})
	}

	ep := cfg.Intel.URLhaus.Endpoint
	if *endpoint != "" {
		ep = *endpoint
	}

	fmt.Printf("candidates: %d  dry-run=%v  active-days=%d  endpoint=%s\n",
		len(cands), *dryRun, *activeDaysFlag, ep)
	if *dryRun {
		fmt.Println("(dry-run: no submission)")
	}

	opts := urlhaus.Options{
		APIKey:     apiKey,
		Endpoint:   ep,
		ExtraTags:  cfg.Intel.URLhaus.Tags,
		ActiveDays: *activeDaysFlag,
		DryRun:     *dryRun,
		Anonymous:  *anonymous,
		RateLimit:  2 * time.Second,
		OnProgress: printURLhausProgress,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	submitted, skipped, ferr := urlhaus.Share(ctx, st, cands, opts)
	fmt.Printf("\nresult: submitted=%d skipped=%d\n", submitted, skipped)
	if ferr != nil {
		fatal(ferr)
	}
}

// printURLhausProgress is deliberately verbose: submitting to a public
// blocklist dataset is an irreversible action, so the operator should be able
// to read the output as a contract of what went out and what was held back.
func printURLhausProgress(c urlhaus.Candidate, submitted bool, reason string) {
	url := c.URL
	if len(url) > 72 {
		url = url[:69] + "..."
	}
	if submitted {
		fmt.Printf("  SUBMIT  %-72s  %s\n", url, reason)
		return
	}
	fmt.Printf("  skip    %-72s  %s\n", url, reason)
}

func printURLhausStatus(st *store.Store) {
	rows, err := st.ListURLhausSubmissions(50)
	if err != nil {
		fatal(err)
	}
	if len(rows) == 0 {
		fmt.Println("(no submissions recorded)")
		return
	}
	fmt.Printf("%-25s  %-14s  %s\n", "submitted_at (UTC)", "status", "url")
	for _, u := range rows {
		fmt.Printf("%-25s  %-14s  %s\n",
			u.SubmittedAt.UTC().Format("2006-01-02 15:04:05"), u.Status, u.URL)
	}
}
