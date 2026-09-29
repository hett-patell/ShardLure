package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/backup"
	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/safefile"
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
		result = explainRefusedPath(result, input)
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

// explainRefusedPath turns a safety refusal into an actionable CLI error: the
// refused directory, the check it failed and the fix. This is the one place a
// refused path is printed (explicit operator output, like the staging path);
// backup.Failure.Error stays path-free for anything that logs it. errors.Is
// and errors.As still reach the original failure.
//
// The remedy follows the failed check and the side that was refused: advice
// about ancestor ownership is wrong for a symlink, an unsupported filesystem
// or the --input bundle, which never gets output-ownership checks.
func explainRefusedPath(err error, input string) error {
	var refusal *safefile.PathRefusal
	if !errors.As(err, &refusal) {
		return err
	}
	subject := "an output directory"
	if input != "" {
		if abs, absErr := filepath.Abs(input); absErr == nil && (refusal.Path == abs || strings.HasPrefix(refusal.Path, abs+string(filepath.Separator))) {
			subject = "a bundle path"
		}
	}
	var remedy string
	switch {
	case errors.Is(refusal.Kind, safefile.ErrUnsupported):
		remedy = "choose " + subject + " on a supported filesystem (ext4, xfs, btrfs, tmpfs or overlayfs)"
	case errors.Is(refusal.Kind, safefile.ErrUnsafePath):
		remedy = "choose " + subject + " without symlinks (pass the real directory, e.g. from realpath)"
	case errors.Is(refusal.Kind, safefile.ErrChanged):
		remedy = "choose " + subject + " that is a real directory (no symlinks) and is not renamed or replaced during the operation"
	case subject == "a bundle path":
		remedy = "choose a bundle path the running user can read without symlinks"
	default:
		remedy = "choose " + subject + " whose ancestors are all owned by root or by the running user and not writable by group or others"
	}
	return &refusedPathError{cause: err, msg: fmt.Sprintf("backup: refused %q: %s; %s", refusal.Path, refusal.Reason, remedy)}
}

type refusedPathError struct {
	cause error
	msg   string
}

func (e *refusedPathError) Error() string { return e.msg }
func (e *refusedPathError) Unwrap() error { return e.cause }
