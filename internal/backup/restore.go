package backup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/safefile"
	"github.com/networkshard/shardlure/internal/store"
	"gopkg.in/yaml.v3"
)

type RestoreOptions struct {
	Input, To string
	DryRun    bool
}

func restoredEntryName(entry Entry) (string, error) {
	switch entry.Role {
	case "database":
		return "shardlure.db", nil
	case "config", "included":
		return entry.Path, nil
	case "evidence":
		return strings.TrimPrefix(entry.Path, "files/"), nil
	case "cowrie-logs":
		return "cowrie/var/log/cowrie/" + strings.TrimPrefix(entry.Path, "files/cowrie-logs/"), nil
	case "cowrie-downloads":
		return "cowrie/var/lib/cowrie/downloads/" + strings.TrimPrefix(entry.Path, "files/cowrie-downloads/"), nil
	case "cowrie-tty":
		return "cowrie/var/lib/cowrie/tty/" + strings.TrimPrefix(entry.Path, "files/cowrie-tty/"), nil
	}
	return "", ErrInvalidManifest
}

func Restore(ctx context.Context, opts RestoreOptions) (Report, error) {
	return restoreWithOperations(ctx, opts, nativeOperations())
}

func restoreWithOperations(ctx context.Context, opts RestoreOptions, ops fileOperations) (report Report, result error) {
	ctx, cancel := operationContext(ctx)
	defer cancel()
	stagePath := ""
	defer func() {
		if result != nil {
			report = Report{}
			result = failure(ErrIncomplete, result, stagePath)
		}
	}()
	if err := ctx.Err(); err != nil {
		return report, err
	}
	if opts.Input == "" || opts.To == "" {
		return report, ErrUnsafePath
	}
	input, err := filepath.Abs(opts.Input)
	if err != nil {
		return report, err
	}
	output, err := filepath.Abs(opts.To)
	if err != nil {
		return report, err
	}
	source, err := openSource(input, false)
	if err != nil {
		return report, err
	}
	defer source.root.Close()
	verified, m, err := verifyRoot(ctx, source.root, false)
	if err != nil {
		return report, err
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		return report, ErrDestinationExists
	}
	if pathsOverlap(input, output) {
		return report, ErrUnsafePath
	}
	for _, root := range m.SourceRoots {
		if pathsOverlap(root, output) {
			return report, ErrUnsafePath
		}
	}
	parent, err := safefile.OpenRoot(filepath.Dir(output))
	if err != nil {
		return report, err
	}
	defer parent.Close()
	if err := parent.CheckOutput(); err != nil {
		return report, err
	}
	free, err := ops.space(parent)
	if err != nil {
		return report, err
	}
	if uint64(verified.Bytes) > free || free-uint64(verified.Bytes) < 16<<20 {
		return report, ErrInsufficientSpace
	}
	if opts.DryRun {
		return verified, nil
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return report, err
	}
	name := ".shardlure-restore-" + hex.EncodeToString(nonce[:]) + ".incomplete"
	stage, err := parent.CreateDirectory(name)
	if err != nil {
		return report, err
	}
	defer stage.Close()
	stagePath = filepath.Join(filepath.Dir(output), name)
	stageInfo, err := stage.Info()
	if err != nil {
		return report, err
	}
	if err := writePrivate(stage, incompleteName, []byte("incomplete recovery\n"), ops); err != nil {
		return report, err
	}
	marker, err := stage.Stat(incompleteName)
	if err != nil {
		return report, err
	}
	// The source bundle is immutable input, even when an entry records the prefix
	// of an originally appendable live log. Recheck every checksum while copying.
	for _, entry := range m.Entries {
		info, err := source.root.Stat(entry.Path)
		if err != nil || info.Size() != entry.Bytes {
			return report, ErrSourceChanged
		}
		destination, err := restoredEntryName(entry)
		if err != nil {
			return report, err
		}
		saved := entry
		saved.Path = destination
		file := plannedFile{root: source, name: entry.Path, info: info, entry: saved, expectedHash: entry.SHA256, expectedSize: entry.Bytes}
		if _, err := copyPlanned(ctx, stage, file, ops); err != nil {
			return report, err
		}
	}
	stagedDB := filepath.Join(stagePath, "shardlure.db")
	dbBytes, err := stage.Stat("shardlure.db")
	if err != nil {
		return report, err
	}
	originalConfig, err := stage.OpenRegular("metadata/config.yaml")
	if err != nil {
		return report, err
	}
	raw, err := io.ReadAll(io.LimitReader(originalConfig, 4<<20+1))
	originalConfig.Close()
	if err != nil || len(raw) > 4<<20 {
		return report, ErrConfiguration
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		return report, ErrConfiguration
	}
	var literal config.Config
	if err := yaml.Unmarshal(raw, &literal); err != nil {
		return report, ErrConfiguration
	}
	targets := map[string]string{"data": output, "evidence": filepath.Join(output, "evidence"), "cowrie-logs": filepath.Join(output, "cowrie", "var", "log", "cowrie"), "cowrie-downloads": filepath.Join(output, "cowrie", "var", "lib", "cowrie", "downloads"), "cowrie-tty": filepath.Join(output, "cowrie", "var", "lib", "cowrie", "tty")}
	sourceRoots := make(map[string]string, len(m.SourceRoots)+2)
	for k, v := range m.SourceRoots {
		sourceRoots[k] = v
	}
	relativeEvidence := literal.Capture.EvidenceDir
	if relativeEvidence == "" && literal.DataDir != "" {
		relativeEvidence = filepath.Join(literal.DataDir, "evidence")
	}
	if relativeEvidence != "" && !filepath.IsAbs(relativeEvidence) {
		sourceRoots["evidence_relative"] = relativeEvidence
	}
	relativeLog := literal.Cowrie.JSONLog
	if relativeLog == "" && literal.DataDir != "" {
		relativeLog = filepath.Join(literal.DataDir, "cowrie", "var", "log", "cowrie", "cowrie.json")
	}
	if relativeLog != "" && !filepath.IsAbs(relativeLog) {
		sourceRoots["cowrie-logs_relative"] = filepath.Dir(relativeLog)
	}
	if err := store.RemapSnapshotPaths(ctx, stagedDB, sourceRoots, targets); err != nil {
		return report, err
	}
	inspected, err := store.InspectSnapshot(ctx, stagedDB)
	if err != nil || inspected.Schema != m.Schema || !reflect.DeepEqual(inspected.TableCounts, m.TableCounts) {
		return report, ErrInvalidManifest
	}
	db, err := stage.OpenRegular("shardlure.db")
	if err != nil {
		return report, err
	}
	entries := map[string]Entry{}
	for _, e := range m.Entries {
		entries[e.Path] = e
	}
	err = store.IterateSnapshotEvidence(ctx, db, func(ref store.EvidenceReference) error {
		mapped, err := mapEvidencePath(targets["evidence"], ref.Path)
		if err != nil {
			return err
		}
		expected, ok := entries[mapped]
		if !ok {
			return ErrInvalidManifest
		}
		actual, err := hashEntry(ctx, stage, strings.TrimPrefix(mapped, "files/"), "evidence")
		if err != nil {
			return err
		}
		if actual.SHA256 != expected.SHA256 || actual.Bytes != expected.Bytes {
			return ErrInvalidManifest
		}
		return nil
	})
	db.Close()
	if err != nil {
		return report, err
	}
	cfg.DataDir = output
	cfg.Capture.EvidenceDir = targets["evidence"]
	cfg.Capture.Enabled = false
	cfg.Capture.QuarantineFetch = false
	cfg.RetentionDays = 0
	cfg.Cowrie.Home = filepath.Join(output, "cowrie")
	cfg.Cowrie.JSONLog = filepath.Join(targets["cowrie-logs"], filepath.Base(cfg.Cowrie.JSONLog))
	recoveryConfig, err := yaml.Marshal(cfg)
	if err != nil {
		return report, err
	}
	if err := writePrivate(stage, "shardlure.recovery.yaml", recoveryConfig, ops); err != nil {
		return report, err
	}
	receipt, err := json.MarshalIndent(struct {
		FormatVersion int              `json:"formatVersion"`
		Schema        int              `json:"schema"`
		RecoveredAt   time.Time        `json:"recoveredAt"`
		TableCounts   map[string]int64 `json:"tableCounts"`
		Changes       []string         `json:"changes"`
	}{1, m.Schema, time.Now().UTC(), m.TableCounts, []string{"storage paths rebased", "Cowrie file cursors reset for deduplicated replay", "historical out-of-root import paths retained as inactive checkpoint metadata", "separate recovery YAML disables capture and retention; DB settings preserved"}}, "", "  ")
	if err != nil {
		return report, err
	}
	if err := writePrivate(stage, "recovery-report.json", receipt, ops); err != nil {
		return report, err
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	if current, err := os.Lstat(input); err != nil || !os.SameFile(source.info, current) {
		return report, ErrSourceChanged
	}
	publishErr := ops.publish(parent, name, filepath.Base(output))
	final, err := parent.OpenDirectory(filepath.Base(output))
	same := false
	if err == nil {
		defer final.Close()
		info, err := final.Info()
		same = err == nil && os.SameFile(stageInfo, info)
		if same {
			stagePath = output
		}
	}
	if publishErr != nil {
		return report, publishErr
	}
	if !same {
		return report, ErrSourceChanged
	}
	if err := final.RemoveCreated(incompleteName, marker); err != nil {
		return report, err
	}
	if err := ops.syncDir(final); err != nil {
		_ = writePrivate(final, incompleteName, []byte("recovery publication uncertain\n"), nativeOperations())
		return report, err
	}
	report = verified
	report.Files += 2
	finalDB, err := final.Stat("shardlure.db")
	if err != nil {
		return Report{}, err
	}
	report.Bytes += finalDB.Size() - dbBytes.Size() + int64(len(recoveryConfig)+len(receipt))
	return report, nil
}
