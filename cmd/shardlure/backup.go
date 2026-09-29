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
		result = explainRefusedPath(result, refusalSides{create: args[0] == "create", config: config.ResolvePath(configPath), input: input, output: output, to: to, includes: includes})
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

// refusalSides names every path the running backup subcommand opens, so a
// refusal can be attributed to the side the operator has to fix.
type refusalSides struct {
	create                    bool
	config, input, output, to string
	includes                  []string
}

// refusedSide is who a refused path belongs to; each needs a different fix.
type refusedSide int

const (
	sideOutput  refusedSide = iota // --output / --to: choose another directory
	sideBundle                     // --input: choose another bundle path
	sideInclude                    // an --include-file source: point the flag at the real file
	sideSource                     // the config dir or a data/evidence/Cowrie root it names
)

// side attributes a refused path. A path inside --output/--to or --input is
// that side's. backup create also opens sources (the config directory, the
// data, evidence and Cowrie roots it names, each --include-file directory),
// whose refusals used to be reported as an output problem - the opposite of
// the fix (audit I1). A refused ancestor shared by several paths goes to the
// one opened first: create opens the config and --include-file directories
// before it stages the output.
func (s refusalSides) side(path string) refusedSide {
	path = filepath.Clean(path)
	within := func(p, base string) bool {
		if base == "" {
			return false
		}
		abs, err := filepath.Abs(base)
		if err != nil {
			return false
		}
		return p == abs || strings.HasPrefix(p, strings.TrimSuffix(abs, string(filepath.Separator))+string(filepath.Separator))
	}
	switch {
	case within(path, s.output), within(path, s.to):
		return sideOutput
	case within(path, s.input):
		return sideBundle
	case !s.create:
		return sideOutput
	case s.config != "" && within(filepath.Dir(mustAbs(s.config)), path):
		return sideSource
	}
	for _, inc := range s.includes {
		if within(filepath.Dir(mustAbs(inc)), path) {
			return sideInclude
		}
	}
	if within(s.output, path) {
		return sideOutput
	}
	return sideSource
}

func mustAbs(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

// explainRefusedPath turns a safety refusal into an actionable CLI error: the
// refused directory, the check it failed and the fix. This is the one place a
// refused path is printed (explicit operator output, like the staging path);
// backup.Failure.Error stays path-free for anything that logs it. errors.Is
// and errors.As still reach the original failure.
//
// The remedy follows the failed check and the side that was refused: advice
// about ancestor ownership is wrong for a symlink, an unsupported filesystem
// or the --input bundle, which never gets output-ownership checks; advice to
// choose another output is wrong for a source, which the operator fixes by
// pointing the config or the flag at the real directory.
func explainRefusedPath(err error, sides refusalSides) error {
	var refusal *safefile.PathRefusal
	if !errors.As(err, &refusal) {
		return err
	}
	side := sides.side(refusal.Path)
	if errors.Is(refusal.Kind, safefile.ErrPermission) {
		// Ownership refusals come only from Root.CheckOutput: sources are
		// read-only roots (Cowrie may own them) and never get that check, so a
		// shared ancestor refused for ownership is the output's.
		side = sideOutput
	}
	var remedy string
	switch side {
	case sideSource, sideInclude:
		what := "point the config (-config or SHARDLURE_CONFIG) and the data, evidence and Cowrie paths it names at the real directory"
		if side == sideInclude {
			what = "point --include-file at a file in the real directory"
		}
		switch {
		case errors.Is(refusal.Kind, safefile.ErrUnsupported):
			remedy = what + " on a supported filesystem (ext4, xfs, btrfs, tmpfs or overlayfs)"
		default:
			remedy = what + " (no symlinks, e.g. from realpath), and do not rename or replace it during the backup"
		}
		return &refusedPathError{cause: err, msg: fmt.Sprintf("backup: refused source %q: %s; %s", refusal.Path, refusal.Reason, remedy)}
	}
	subject := "an output directory"
	if side == sideBundle {
		subject = "a bundle path"
	}
	switch {
	case errors.Is(refusal.Kind, safefile.ErrUnsupported):
		remedy = "choose " + subject + " on a supported filesystem (ext4, xfs, btrfs, tmpfs or overlayfs)"
	case errors.Is(refusal.Kind, safefile.ErrUnsafePath):
		remedy = "choose " + subject + " without symlinks (pass the real directory, e.g. from realpath)"
	case errors.Is(refusal.Kind, safefile.ErrChanged):
		remedy = "choose " + subject + " that is a real directory (no symlinks) and is not renamed or replaced during the operation"
	case side == sideBundle:
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
