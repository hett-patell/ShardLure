package main

import (
	"context"
	"fmt"
	"strconv"

	"flag"

	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/intel/bazaar"
	"github.com/networkshard/shardlure/internal/intel/threatfox"
	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
	"time"
)

// cmdShareThreatFox submits the malware-delivery IOCs ShardLure captured
// first-hand to abuse.ch ThreatFox — the IOC-level give-back channel alongside
// MalwareBazaar (files) and URLhaus (URLs), on the SAME abuse.ch Auth-Key.
//
// There is deliberately NO separate ThreatFox key setting: the one-key
// invariant (a single abuse.ch account covers all three) is enforced by
// resolving through the shared abuseCHKey, exactly as `share urlhaus` does.
func cmdShareThreatFox(st *store.Store, cfg config.Config, keys *settings.Keystore, args []string) {
	activeDays := cfg.Intel.URLhaus.ActiveDays // shares the URLhaus freshness default (same fetch-provenance)
	if activeDays <= 0 {
		activeDays = 3
	}

	fs := flag.NewFlagSet("share threatfox", flag.ExitOnError)
	dryRun := fs.Bool("dry-run", false, "list what would be submitted without contacting ThreatFox")
	// Bounds SUBMISSIONS, enforced inside threatfox.Share after Vet and dedup —
	// never a LIMIT on the candidate query (the D3 lesson: a pre-gate LIMIT
	// spends the budget on already-shared entries at the top of the list).
	limit := fs.Int("limit", 25, "max candidates to submit in this run (0 = unbounded); counts submissions, not candidates examined")
	statusOnly := fs.Bool("status", false, "list past submissions from threatfox_submissions instead of submitting")
	activeDaysFlag := fs.Int("active-days", activeDays, "only submit IOCs confirmed serving within this many days (may only tighten)")
	endpoint := fs.String("endpoint", "", "override the ThreatFox endpoint (default builtin)")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if fs.NArg() > 0 {
		fatal(fmt.Errorf("unexpected argument %q", fs.Arg(0)))
	}

	if *statusOnly {
		printThreatFoxStatus(st)
		return
	}

	apiKey := abuseCHKey(cfg, keys, "SHARDLURE_THREATFOX_KEY")
	if apiKey == "" && !*dryRun {
		fatal(fmt.Errorf("no abuse.ch Auth-Key found — save one in the dashboard Settings panel (MalwareBazaar), set intel.bazaar.api_key in %s, or export SHARDLURE_BAZAAR_KEY; get one free at https://auth.abuse.ch/", config.DefaultConfigPath()))
	}

	// 0 = no SQL LIMIT: the whole vettable pool is examined; the budget is
	// applied by Share after the gate.
	rows, err := st.ThreatFoxCandidates(*activeDaysFlag, 0)
	if err != nil {
		fatal(fmt.Errorf("collect candidates: %w", err))
	}
	if len(rows) == 0 {
		fmt.Println("no candidates: no successfully-fetched http(s) payload URLs in the active window that haven't already been submitted")
		return
	}

	cands := make([]threatfox.Candidate, 0, len(rows))
	for _, r := range rows {
		// Classify off disk for BOTH the file kind (real payload / reject SSH
		// keys) AND the malware family (ThreatFox's mandatory Malpedia label —
		// a candidate whose family doesn't resolve is dropped by Vet). Reuses
		// the bazaar classifier rather than duplicating it.
		kind, family := "", ""
		if r.LocalPath != "" {
			if cls, cerr := bazaar.Classify(r.LocalPath); cerr == nil {
				kind = cls.FileKind
				family = cls.Family
			}
		}
		cands = append(cands, threatfox.Candidate{
			URL:       r.URL,
			SHA256:    r.SHA256,
			SizeBytes: r.SizeBytes,
			Origin:    r.Origin,
			Status:    r.Status,
			FetchedAt: r.FetchedAt,
			FileKind:  kind,
			Family:    family,
		})
	}

	ep := *endpoint

	limitLabel := "unbounded"
	if *limit > 0 {
		limitLabel = strconv.Itoa(*limit)
	}
	fmt.Printf("candidates: %d  submit-limit=%s  dry-run=%v  active-days=%d\n",
		len(cands), limitLabel, *dryRun, *activeDaysFlag)
	if *dryRun {
		fmt.Println("(dry-run: no submission)")
	}

	opts := threatfox.Options{
		APIKey:         apiKey,
		Endpoint:       ep,
		ExtraTags:      cfg.Intel.Bazaar.Tags, // same shardlure/honeypot tags as the other channels
		ActiveDays:     *activeDaysFlag,
		DryRun:         *dryRun,
		RateLimit:      2 * time.Second,
		MaxSubmissions: *limit,
		OnProgress:     printThreatFoxProgress,
		OnLimitReached: func(unexamined int) {
			fmt.Printf("\n  (submit limit %d reached — %d candidate(s) not examined; raise --limit or pass --limit=0)\n",
				*limit, unexamined)
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	submitted, skipped, ferr := threatfox.Share(ctx, &threatFoxRecorderAdapter{st: st}, cands, opts)
	fmt.Printf("\nresult: submitted=%d skipped=%d\n", submitted, skipped)
	if ferr != nil {
		fatal(ferr)
	}
}

// threatFoxRecorderAdapter bridges store to threatfox.SubmitRecorder.
type threatFoxRecorderAdapter struct{ st *store.Store }

func (a *threatFoxRecorderAdapter) ThreatFoxSubmitted(ioc string) (bool, error) {
	return a.st.ThreatFoxSubmitted(ioc)
}

func (a *threatFoxRecorderAdapter) RecordThreatFoxSubmission(ioc, iocType, malware, status string, at time.Time) error {
	return a.st.RecordThreatFoxSubmission(ioc, iocType, malware, status, at)
}

// printThreatFoxProgress is deliberately verbose: submitting to a public IOC
// dataset is irreversible, so the operator reads the output as a contract of
// what went out and what was held back.
func printThreatFoxProgress(c threatfox.Candidate, submitted bool, iocCount int, reason string) {
	url := c.URL
	if len(url) > 64 {
		url = url[:61] + "..."
	}
	if submitted {
		fmt.Printf("  SUBMIT  %-64s  %d IOC(s)  %s\n", url, iocCount, reason)
		return
	}
	fmt.Printf("  skip    %-64s  %s\n", url, reason)
}

func printThreatFoxStatus(st *store.Store) {
	rows, err := st.ListThreatFoxSubmissions(50)
	if err != nil {
		fatal(err)
	}
	if len(rows) == 0 {
		fmt.Println("(no submissions recorded)")
		return
	}
	fmt.Printf("%-25s  %-12s  %-14s  %s\n", "submitted_at (UTC)", "type", "malware", "ioc")
	for _, r := range rows {
		fmt.Printf("%-25s  %-12s  %-14s  %s\n",
			r.SubmittedAt.UTC().Format("2006-01-02 15:04:05"), r.IOCType, r.Malware, r.IOC)
	}
}
