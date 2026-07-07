package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/intel/abuseipdb"
	"github.com/networkshard/shardlure/internal/netmatch"
	"github.com/networkshard/shardlure/internal/store"
)

// cmdReport is the dispatcher for "shardlure report <destination>". Kept
// separate from `share` (payloads → MalwareBazaar) because reporting operates
// on ACTORS, not artifacts, and has different safety semantics.
func cmdReport(st *store.Store, cfg config.Config, args []string) {
	if len(args) < 1 {
		fatal(fmt.Errorf("usage: shardlure report <abuseipdb> [--dry-run] [--limit N] [--min-probe N] [--status]"))
	}
	switch args[0] {
	case "abuseipdb":
		cmdReportAbuseIPDB(st, cfg, args[1:])
	default:
		fatal(fmt.Errorf("unknown report destination: %q (supported: abuseipdb)", args[0]))
	}
}

func cmdReportAbuseIPDB(st *store.Store, cfg config.Config, args []string) {
	minProbeDefault := cfg.Intel.AbuseIPDB.MinProbeScore
	if minProbeDefault <= 0 {
		minProbeDefault = 60
	}
	rewindowDefault := cfg.Intel.AbuseIPDB.RewindowHours
	if rewindowDefault <= 0 {
		rewindowDefault = 24
	}
	fs := flag.NewFlagSet("report abuseipdb", flag.ExitOnError)
	dryRun := fs.Bool("dry-run", false, "list what would be reported without contacting AbuseIPDB")
	limit := fs.Int("limit", 25, "max actors to report in this run (0 = unbounded)")
	minProbe := fs.Int("min-probe", minProbeDefault, "minimum actor ProbeScore to report (0-100)")
	rewindowHours := fs.Int("rewindow", rewindowDefault, "hours before a reported IP may be reported again")
	statusOnly := fs.Bool("status", false, "list past reports from abuseipdb_reports instead of reporting")
	endpoint := fs.String("endpoint", "", "override AbuseIPDB endpoint (default from config or builtin)")
	_ = fs.Parse(args)

	if *statusOnly {
		printAbuseReportStatus(st)
		return
	}

	// Reporting requires the operator to have explicitly opted in. Even a
	// --dry-run respects the gate for the live POST, but we let --dry-run run
	// without the enabled flag so an operator can preview candidates safely.
	if !cfg.Intel.AbuseIPDB.ReportEnabled && !*dryRun {
		fatal(fmt.Errorf("intel.abuseipdb.report_enabled is false in %s — set it to true to report (or use --dry-run to preview)", config.DefaultConfigPath()))
	}
	apiKey := strings.TrimSpace(os.Getenv("SHARDLURE_ABUSEIPDB_KEY"))
	if apiKey == "" && !*dryRun {
		fatal(fmt.Errorf("SHARDLURE_ABUSEIPDB_KEY is empty — export it (same key as enrichment /check) before reporting"))
	}

	cands, err := collectReportCandidates(st, *minProbe)
	if err != nil {
		fatal(fmt.Errorf("collect candidates: %w", err))
	}
	if len(cands) == 0 {
		fmt.Println("no candidates: no confirmed brute-force actors at or above the probe floor")
		return
	}
	if *limit > 0 && len(cands) > *limit {
		cands = cands[:*limit]
	}

	ep := cfg.Intel.AbuseIPDB.Endpoint
	if *endpoint != "" {
		ep = *endpoint
	}
	cats := cfg.Intel.AbuseIPDB.Categories
	if len(cats) == 0 {
		cats = []int{18, 22}
	}

	fmt.Printf("candidates: %d  dry-run=%v  min-probe=%d  endpoint=%s\n", len(cands), *dryRun, *minProbe, ep)
	if *dryRun {
		fmt.Println("(dry-run: no report sent)")
	}

	opts := abuseipdb.Options{
		APIKey:     apiKey,
		Endpoint:   ep,
		Categories: cats,
		Comment:    cfg.Intel.AbuseIPDB.Comment,
		DryRun:     *dryRun,
		MinProbe:   *minProbe,
		Rewindow:   time.Duration(*rewindowHours) * time.Hour,
		RateLimit:  2 * time.Second,
		Admin:      netmatch.New(cfg.AdminIPs),
		OnProgress: func(c abuseipdb.ReportCandidate, res *abuseipdb.Result, err error) {
			printAbuseReportProgress(c, res, err)
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reported, skipped, ferr := abuseipdb.Report(ctx, &abuseReportRecorderAdapter{st: st}, cands, opts)
	fmt.Printf("\nresult: reported=%d skipped=%d\n", reported, skipped)
	if ferr != nil {
		fatal(ferr)
	}
}

// abuseReportRecorderAdapter bridges store's AbuseReport API to the
// abuseipdb.ReportRecorder interface (keeps the abuseipdb package store-free).
type abuseReportRecorderAdapter struct {
	st *store.Store
}

func (a *abuseReportRecorderAdapter) AbuseIPDBReported(ip string, within time.Duration) (bool, error) {
	return a.st.AbuseIPDBReported(ip, within)
}

func (a *abuseReportRecorderAdapter) RecordAbuseIPDBReport(ip, status string, score int, categories []int, at time.Time) error {
	return a.st.RecordAbuseIPDBReport(ip, status, score, categories, at)
}

// collectReportCandidates pulls actors eligible for reporting. The heavy
// filtering (brute playbook, probe floor, admin/private reject) is the vet
// gate's job — this just surfaces actors above the probe floor with a primary
// IP, ordered by aggression so --limit reports the worst offenders first.
func collectReportCandidates(st *store.Store, minProbe int) ([]abuseipdb.ReportCandidate, error) {
	actors, err := st.TopActorsByRate(1000)
	if err != nil {
		return nil, err
	}
	out := make([]abuseipdb.ReportCandidate, 0, len(actors))
	for _, a := range actors {
		if a.PrimaryIP == "" || a.ProbeScore < minProbe {
			continue
		}
		out = append(out, abuseipdb.ReportCandidate{
			SrcIP:           a.PrimaryIP,
			Playbook:        a.Playbook,
			ProbeScore:      a.ProbeScore,
			EventCount:      a.EventCount,
			UniqueUsers:     a.UniqueUsers,
			AttemptsPerHour: a.AttemptsPerHour,
		})
	}
	return out, nil
}

func printAbuseReportProgress(c abuseipdb.ReportCandidate, res *abuseipdb.Result, err error) {
	header := fmt.Sprintf("  %-15s  probe=%3d  %-24s ev=%d users=%d", c.SrcIP, c.ProbeScore, c.Playbook, c.EventCount, c.UniqueUsers)
	switch {
	case err != nil:
		fmt.Printf("%s\n    %v\n", header, err)
	case res == nil:
		fmt.Printf("%s\n    (no result)\n", header)
	case res.RateLimited:
		fmt.Printf("%s\n    -> rate limited\n", header)
	default:
		fmt.Printf("%s\n    -> reported (score now %d/100)\n", header, res.Score)
	}
}

func printAbuseReportStatus(st *store.Store) {
	rows, err := st.ListAbuseReports(50)
	if err != nil {
		fatal(err)
	}
	if len(rows) == 0 {
		fmt.Println("(no reports recorded)")
		return
	}
	fmt.Printf("%-15s  %-25s  %-10s  %-10s  %s\n", "ip", "reported_at (UTC)", "status", "score", "categories")
	for _, r := range rows {
		ts := r.ReportedAt.UTC().Format("2006-01-02 15:04:05")
		cats := make([]string, 0, len(r.Categories))
		for _, c := range r.Categories {
			cats = append(cats, fmt.Sprintf("%d", c))
		}
		fmt.Printf("%-15s  %-25s  %-10s  %-10d  %s\n", r.IP, ts, r.Status, r.AbuseScore, strings.Join(cats, ","))
	}
}
