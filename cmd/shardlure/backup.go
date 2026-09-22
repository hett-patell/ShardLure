package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/networkshard/shardlure/internal/backup"
	"github.com/networkshard/shardlure/internal/config"
)

type backupIncludes []string

func (*backupIncludes) String() string { return "explicit administrative files" }
func (s *backupIncludes) Set(value string) error {
	if value == "" {
		return errors.New("empty file")
	}
	*s = append(*s, value)
	return nil
}

func runBackup(ctx context.Context, configPath string, args []string, out io.Writer) (result error) {
	bad := errors.New("backup: invalid arguments; use create, verify, or restore with documented flags")
	if len(args) == 0 {
		return bad
	}
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	timeout := fs.Duration("timeout", 30*time.Minute, "operation timeout")
	var input, output, to string
	var dry bool
	var includes backupIncludes
	switch args[0] {
	case "create":
		fs.StringVar(&output, "output", "", "new bundle directory")
		fs.Var(&includes, "include-file", "explicit administrative file")
	case "verify":
		fs.StringVar(&input, "input", "", "bundle directory")
	case "restore":
		fs.StringVar(&input, "input", "", "bundle directory")
		fs.StringVar(&to, "to", "", "new data directory")
		fs.BoolVar(&dry, "dry-run", false, "verify without writing")
	default:
		return bad
	}
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || *timeout <= 0 {
		return bad
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	defer func() {
		var failure *backup.Failure
		if errors.As(result, &failure) && failure.Staging != "" {
			fmt.Fprintf(out, "incomplete recovery material retained at %q\n", failure.Staging)
		}
	}()
	switch args[0] {
	case "create":
		if output == "" {
			return bad
		}
		m, err := backup.Create(ctx, backup.CreateOptions{ConfigPath: config.ResolvePath(configPath), Output: output, IncludeFiles: includes, AppVersion: version, AppCommit: commit})
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "created verified backup: files=%d schema=%d\n", len(m.Entries), m.Schema)
		return err
	case "verify":
		if input == "" {
			return bad
		}
		report, err := backup.Verify(ctx, input)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "verified backup: files=%d bytes=%d schema=%d\n", report.Files, report.Bytes, report.Schema)
		return err
	case "restore":
		if input == "" || to == "" {
			return bad
		}
		report, err := backup.Restore(ctx, backup.RestoreOptions{Input: input, To: to, DryRun: dry})
		if err != nil {
			return err
		}
		action := "restored"
		if dry {
			action = "verified restore dry-run"
		}
		_, err = fmt.Fprintf(out, "%s: files=%d schema=%d; no services started\n", action, report.Files, report.Schema)
		return err
	}
	return bad
}
