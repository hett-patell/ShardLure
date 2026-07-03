package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/networkshard/shardlure/internal/actor"
	"github.com/networkshard/shardlure/internal/capture"
	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/ingest/cowrie"
	"github.com/networkshard/shardlure/internal/ingest/journal"
	"github.com/networkshard/shardlure/internal/netmatch"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/internal/web"
	"github.com/networkshard/shardlure/tui"
)

// Build-time injected via -ldflags "-X main.version=... -X main.commit=...".
// Defaults reflect a dev build from an untagged checkout.
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	cfgPath := flag.String("config", "", "path to shardlure.yaml")
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}

	path := *cfgPath
	if path == "" {
		path = os.Getenv("SHARDLURE_CONFIG")
	}
	cfg, err := config.Load(path)
	if err != nil {
		fatal(err)
	}
	// admin_ips entries may be bare IPs or CIDR ranges. Anything that parses
	// as neither would silently match no traffic (and previously did so with
	// no signal), so warn loudly rather than treat the operator's own
	// addresses as attacker telemetry.
	if bad := netmatch.Invalid(cfg.AdminIPs); len(bad) > 0 {
		fmt.Fprintf(os.Stderr, "warning: ignoring unparseable admin_ips entries (not an IP or CIDR): %s\n", strings.Join(bad, ", "))
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		fatal(err)
	}

	st, err := store.Open(cfg.DBPath())
	if err != nil {
		fatal(err)
	}
	defer st.Close()

	switch args[0] {
	case "ingest":
		cmdIngest(st, cfg, args[1:])
	case "actors":
		cmdActors(st, args[1:])
	case "actor":
		cmdActor(st, args[1:])
	case "dashboard", "dash", "tui":
		if err := tui.Run(st, cfg.DBPath()); err != nil {
			fatal(err)
		}
	case "web":
		addr := ":8080"
		tailscaleHint := false
		for _, a := range args[1:] {
			switch a {
			case "", " ":
				continue
			case "--tailscale":
				tailscaleHint = true
			default:
				addr = a
			}
		}
		fmt.Printf("serving live dashboard on http://127.0.0.1%s\n", addr)
		if tailscaleHint {
			printTailscaleURL(addr)
		}
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		if err := web.New(st, addr, webOptions(cfg)).RunContext(ctx); err != nil {
			fatal(err)
		}
	case "live":
		cmdLive(st, cfg, args[1:])
	case "run":
		// syscall.Exec below replaces this process, so the deferred st.Close()
		// in main() would never run; close the store now (the wrapper re-opens
		// it). Harmless even though the OS would reclaim the fd on exec.
		_ = st.Close()
		cmdRun(cfg)
	case "status":
		cmdStatus(st)
	case "ioc":
		cmdIOC(st)
	case "share":
		cmdShare(st, cfg, args[1:])
	case "version":
		fmt.Printf("shardlure %s (commit %s)\n", version, commit)
	default:
		usage()
		os.Exit(1)
	}
}

func cmdIngest(st *store.Store, cfg config.Config, args []string) {
	if len(args) < 2 {
		fatal(fmt.Errorf("usage: shardlure ingest <journal|cowrie> <file.log> [--replace]"))
	}
	mode, path := args[0], args[1]
	replace := false
	for _, a := range args[2:] {
		switch a {
		case "--replace":
			replace = true
		default:
			// Fatal, not ignored: a typo like --repalce silently flipped the
			// run from replace to append, double-counting on re-ingest.
			fatal(fmt.Errorf("unknown ingest flag: %q (supported: --replace)", a))
		}
	}
	switch mode {
	case "journal":
		res, err := journal.IngestFile(st, path, cfg.AdminIPs, replace)
		if err != nil {
			fatal(err)
		}
		extras := ""
		if res.SkippedLines > 0 {
			extras += fmt.Sprintf(", skipped %d malformed sshd lines", res.SkippedLines)
		}
		if res.Duplicates > 0 {
			extras += fmt.Sprintf(", deduped %d existing events", res.Duplicates)
		}
		fmt.Printf("ingested %d events -> %d actors (skipped %d admin logins%s)\n",
			res.Events, res.Actors, res.SkippedAdmin, extras)
	case "cowrie":
		var res *cowrie.Result
		var err error
		if replace {
			res, err = cowrie.IngestFile(st, path, cfg.AdminIPs, true)
		} else {
			// Append + dedupe: safe for rotated logs (cowrie.json.YYYY-MM-DD).
			res, err = cowrie.IngestFileAppend(st, path, cfg.AdminIPs)
		}
		if err != nil {
			fatal(err)
		}
		if res.Skipped > 0 {
			fmt.Printf("ingested %d cowrie events -> %d actors (skipped %d malformed/unsupported lines)\n", res.Events, res.Actors, res.Skipped)
		} else {
			fmt.Printf("ingested %d cowrie events -> %d actors\n", res.Events, res.Actors)
		}
	default:
		fatal(fmt.Errorf("unknown ingest mode: %s (expected journal|cowrie)", mode))
	}
}

func cmdLive(st *store.Store, cfg config.Config, args []string) {
	addr := ":8080"
	if cfg.Dashboard.Port > 0 {
		addr = fmt.Sprintf(":%d", cfg.Dashboard.Port)
	}
	cowriePath := cfg.Cowrie.JSONLog
	if cowriePath == "" {
		cowriePath = "/var/log/cowrie/cowrie.json"
	}
	interval := 5 * time.Second
	journalSSH := true
	tailscaleHint := false
	for _, a := range args {
		switch {
		case a == "" || a == " ":
			continue
		case a == "--no-journal":
			journalSSH = false
		case a == "--tailscale":
			tailscaleHint = true
		case strings.HasPrefix(a, "--cowrie="):
			cowriePath = strings.TrimPrefix(a, "--cowrie=")
		case strings.HasPrefix(a, "--interval="):
			v := strings.TrimPrefix(a, "--interval=")
			if d, err := time.ParseDuration(v); err == nil && d > 0 {
				interval = d
			}
		case strings.HasPrefix(a, "--"):
			fatal(fmt.Errorf("unknown live flag: %q (supported: --no-journal --tailscale --cowrie=PATH --interval=DUR)", a))
		default:
			// Positional listen address. `web` accepts the same shape; keep
			// them consistent — previously `live 8080` was silently ignored
			// while `web 8080` worked.
			addr = a
		}
	}
	if cowriePath == "" {
		fatal(fmt.Errorf("cowrie path missing; set in config cowrie.json_log or pass --cowrie=<path>"))
	}
	dashURL := addr
	if p := addrPort(addr); p > 0 {
		dashURL = fmt.Sprintf("http://127.0.0.1:%d", p)
	}
	fmt.Printf("live wrapper: cowrie=%s journal=%v interval=%s dashboard=%s\n", cowriePath, journalSSH, interval, dashURL)
	if tailscaleHint {
		printTailscaleURL(addr)
	}

	if journalSSH {
		if _, err := journal.IngestJournalctl(st, cfg.Journal.Unit, "30 days ago", cfg.AdminIPs, false); err != nil {
			fmt.Fprintf(os.Stderr, "journal seed warning: %v\n", err)
		}
	}
	cowrie.BackfillRotatedLogs(st, cowriePath, cfg.AdminIPs)
	if _, err := cowrie.IngestFileAppend(st, cowriePath, cfg.AdminIPs); err != nil {
		fatal(fmt.Errorf("initial cowrie ingest: %w", err))
	}
	capRunner := capture.NewRunner(st, cfg)
	if n, err := capRunner.Run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "capture warning: %v\n", err)
	} else if n > 0 {
		fmt.Printf("captured %d payload artifact(s) -> %s\n", n, cfg.CaptureEvidenceDir())
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if journalSSH {
		go func() {
			// Restart the tail on failure with capped backoff. A scanner error
			// (e.g. an oversized journal line) or journalctl exiting would
			// otherwise end journal ingestion silently for the daemon's whole
			// lifetime — and since the process keeps running, Restart=always
			// never kicks in.
			backoff := time.Second
			for ctx.Err() == nil {
				err := journal.TailFollow(ctx, st, cfg.Journal.Unit, cfg.AdminIPs)
				if ctx.Err() != nil {
					return
				}
				if err != nil {
					fmt.Fprintf(os.Stderr, "journal tail stopped: %v (restarting in %s)\n", err, backoff)
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				if backoff < 30*time.Second {
					backoff *= 2
				}
			}
		}()
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := cowrie.IngestFileAppend(st, cowriePath, cfg.AdminIPs); err != nil {
					fmt.Fprintf(os.Stderr, "live ingest warning: %v\n", err)
				}
				if _, err := capRunner.Run(ctx); err != nil {
					fmt.Fprintf(os.Stderr, "capture warning: %v\n", err)
				}
			}
		}
	}()
	// Periodic data retention purge — deletes old events,
	// enrichments, artifacts, and TTY transcripts past the
	// configured retention window. Fires once at startup
	// and then every 24h.
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		runPurge := func() {
			if err := st.MaintenancePurge(cfg.RetentionDays); err != nil {
				fmt.Fprintf(os.Stderr, "maintenance purge: %v\n", err)
			}
			// Also clean Cowrie's own source dirs so they don't grow without
			// bound and so purged artifacts can't be re-archived from the
			// surviving source file on the next tick.
			capRunner.PurgeOldSourceFiles(cfg.RetentionDays)
		}
		runPurge()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				runPurge()
			}
		}
	}()

	if err := web.New(st, addr, webOptions(cfg)).RunContext(ctx); err != nil {
		fatal(err)
	}
}

func webOptions(cfg config.Config) web.Options {
	return web.Options{
		HomeLat:         cfg.Dashboard.HomeLat,
		HomeLon:         cfg.Dashboard.HomeLon,
		HomeCity:        cfg.Dashboard.HomeCity,
		HomeCountry:     cfg.Dashboard.HomeCountry,
		HomeCC:          cfg.Dashboard.HomeCC,
		GeoEnabled:      cfg.GeoIP.Enabled,
		GeoInsecureHTTP: cfg.GeoIP.InsecureHTTP,
		BazaarAPIKey:    cfg.Intel.Bazaar.APIKey,
		BazaarEndpoint:  cfg.Intel.Bazaar.Endpoint,
		BazaarTags:      cfg.Intel.Bazaar.Tags,
		BazaarMaxBytes:  cfg.Intel.Bazaar.MaxBytes,
	}
}

func cmdRun(cfg config.Config) {
	setup := findSetupScript()
	if setup == "" {
		fatal(fmt.Errorf("setup script not found; run from ShardLure checkout"))
	}
	fmt.Printf("starting ShardLure wrapper via %s\n", setup)
	if strings.HasSuffix(setup, ".py") {
		if err := syscall.Exec("/usr/bin/python3", []string{"python3", setup, "run"}, os.Environ()); err != nil {
			fatal(err)
		}
		return
	}
	if err := syscall.Exec("/bin/bash", []string{"bash", setup, "run"}, os.Environ()); err != nil {
		fatal(err)
	}
}

func findSetupScript() string {
	candidates := []string{
		"./scripts/shardlure.py",
		"../scripts/shardlure.py",
		"./scripts/shardlure",
		"../scripts/shardlure",
	}
	if exe, err := os.Executable(); err == nil {
		base := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(base, "scripts", "shardlure.py"),
			filepath.Join(base, "..", "scripts", "shardlure.py"),
			filepath.Join(base, "scripts", "shardlure"),
			filepath.Join(base, "..", "scripts", "shardlure"),
		)
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func cmdActors(st *store.Store, args []string) {
	fs := flag.NewFlagSet("actors", flag.ExitOnError)
	limit := fs.Int("limit", 25, "max actors to list")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	actors, err := st.ListActors(*limit)
	if err != nil {
		fatal(err)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ACTOR\tIP\tPLAYBOOK\tEVENTS\tUSR\tRATE/h\tLAST\tCONF")
	for _, a := range actors {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%.0f\t%s\t%d\n",
			actor.TrimActorPrefix(a.ID), a.PrimaryIP, a.Playbook, a.EventCount, a.UniqueUsers,
			a.AttemptsPerHour, a.LastSeen.Format(time.RFC3339), a.Confidence)
	}
	w.Flush()
}

func cmdActor(st *store.Store, args []string) {
	if len(args) < 2 || args[0] != "show" {
		fatal(fmt.Errorf("usage: shardlure actor show <id|ip>"))
	}
	id := args[1]
	if !strings.Contains(id, ":") {
		if a, err := st.GetActorByPrimaryIP(id); err == nil {
			id = a.ID
		} else {
			id = "journal:" + id
		}
	}
	a, err := st.GetActor(id)
	if err != nil {
		fatal(err)
	}
	users, _ := st.ActorUsers(id)
	b, _ := json.MarshalIndent(a, "", "  ")
	fmt.Println(string(b))
	fmt.Println("\nTop usernames:")
	for _, u := range users {
		fmt.Printf("  %6d  %s\n", u.Count, u.Username)
	}
}

func cmdStatus(st *store.Store) {
	ec, _ := st.EventCount()
	ac, _ := st.ActorCount()
	fmt.Printf("events: %d\nactors: %d\n", ec, ac)
}

func cmdIOC(st *store.Store) {
	actors, err := st.ListActors(50)
	if err != nil {
		fatal(err)
	}
	fmt.Println("# ShardLure IOC slice (all actors)")
	for _, a := range actors {
		fmt.Printf("%s  playbook=%s  events=%d  rate=%.0f/h  probe=%d\n",
			a.PrimaryIP, a.Playbook, a.EventCount, a.AttemptsPerHour, a.ProbeScore)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `ShardLure - attacker identity from SSH telemetry

Usage:
  shardlure ingest <journal|cowrie> <file> [--replace]
  shardlure actors [--limit=25]
  shardlure actor show <ip>
  shardlure dashboard
  shardlure web [:8080] [--tailscale]
  shardlure live [:8080] [--cowrie=/path/cowrie.json] [--interval=5s] [--no-journal] [--tailscale]
  shardlure run
  shardlure status
  shardlure ioc
  shardlure share bazaar [--dry-run] [--limit N] [--sha SHA] [--since 240h] [--anonymous] [--status]

Config: ~/.local/share/shardlure/ or -config shardlure.yaml
`)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

// printTailscaleURL prints the dashboard's Tailscale URL for --tailscale.
// Shared by the web and live subcommands (previously duplicated verbatim).
func printTailscaleURL(addr string) {
	ip := tailscaleIPv4()
	if ip == "" {
		fmt.Println("tailscale ip not found on this host (interface tailscale0 missing)")
		return
	}
	if p := addrPort(addr); p > 0 {
		fmt.Printf("tailscale url: http://%s:%d\n", ip, p)
	} else {
		fmt.Printf("tailscale url: http://%s%s (could not parse port from %q)\n", ip, addr, addr)
	}
}

func tailscaleIPv4() string {
	ifi, err := net.InterfaceByName("tailscale0")
	if err != nil {
		return ""
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil {
			continue
		}
		ip = ip.To4()
		if ip != nil {
			return ip.String()
		}
	}
	return ""
}

// addrPort extracts a TCP port from any listen address that
// net.Listen("tcp", addr) would accept: ":8080", "0.0.0.0:8080",
// "[::1]:8080", "host:8080". On malformed or zero-port input it
// returns 0 so callers can detect the failure (we don't fall back
// to a default because there's no honest default for "I don't know
// what port you bound to").
func addrPort(addr string) int {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return 0
	}
	// Bare ":N" form - net.SplitHostPort accepts this with empty host.
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// Fall back to a permissive parse: if the whole input is a
		// number, treat it as a port. Keeps `--addr=8080` working
		// even though it's not a valid listen address.
		if p, perr := strconv.Atoi(addr); perr == nil && p > 0 && p <= 65535 {
			return p
		}
		return 0
	}
	_ = host
	p, err := strconv.Atoi(port)
	if err != nil || p <= 0 || p > 65535 {
		return 0
	}
	return p
}
