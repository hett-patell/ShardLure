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
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/internal/web"
	"github.com/networkshard/shardlure/tui"
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
			if ip := tailscaleIPv4(); ip != "" {
				fmt.Printf("tailscale url: http://%s:%d\n", ip, addrPort(addr))
			} else {
				fmt.Println("tailscale ip not found on this host (interface tailscale0 missing)")
			}
		}
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		if err := web.New(st, addr, webOptions(cfg)).RunContext(ctx); err != nil {
			fatal(err)
		}
	case "live":
		cmdLive(st, cfg, args[1:])
	case "run":
		cmdRun(cfg)
	case "status":
		cmdStatus(st)
	case "ioc":
		cmdIOC(st)
	case "version":
		fmt.Println("shardlure 0.1.0")
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
		if a == "--replace" {
			replace = true
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
		case strings.HasPrefix(a, ":") || strings.Contains(a, "."):
			addr = a
		}
	}
	if cowriePath == "" {
		fatal(fmt.Errorf("cowrie path missing; set in config cowrie.json_log or pass --cowrie=<path>"))
	}
	fmt.Printf("live wrapper: cowrie=%s journal=%v interval=%s dashboard=http://127.0.0.1%s\n", cowriePath, journalSSH, interval, addr)
	if tailscaleHint {
		if ip := tailscaleIPv4(); ip != "" {
			fmt.Printf("tailscale url: http://%s:%d\n", ip, addrPort(addr))
		}
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
			if err := journal.TailFollow(ctx, st, cfg.Journal.Unit, cfg.AdminIPs); err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "journal tail stopped: %v\n", err)
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
	fmt.Println("# ShardLure IOC slice (journal actors)")
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

Config: ~/.local/share/shardlure/ or -config shardlure.yaml
`)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
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

func addrPort(addr string) int {
	if strings.HasPrefix(addr, ":") {
		p, err := strconv.Atoi(strings.TrimPrefix(addr, ":"))
		if err == nil {
			return p
		}
	}
	_, port, err := net.SplitHostPort(addr)
	if err == nil {
		p, err := strconv.Atoi(port)
		if err == nil {
			return p
		}
	}
	return 8080
}
