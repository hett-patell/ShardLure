package backup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/config"
	"github.com/networkshard/shardlure/internal/safefile"
	"github.com/networkshard/shardlure/internal/store"
)

type sourceRoot struct {
	path string
	root *safefile.Root
	info fs.FileInfo
}
type plannedFile struct {
	root         *sourceRoot
	name         string
	info         fs.FileInfo
	entry        Entry
	expectedHash string
	expectedSize int64
	appendable   bool
}
type inventory struct {
	files     []plannedFile
	names     map[string]int
	bytes     int64
	metadata  int64
	protected []fs.FileInfo
}

func (p *inventory) add(source *sourceRoot, name, relative, role string, expectedHash string, expectedSize int64) error {
	if !relativeName(name) || !relativeName(relative) {
		return ErrUnsafePath
	}
	if index, ok := p.names[relative]; ok {
		old := &p.files[index]
		if expectedHash != "" && old.expectedHash != "" && expectedHash != old.expectedHash {
			return ErrInvalidManifest
		}
		if expectedSize > 0 && old.expectedSize > 0 && expectedSize != old.expectedSize {
			return ErrInvalidManifest
		}
		if expectedHash != "" {
			old.expectedHash = expectedHash
		}
		if expectedSize > 0 {
			old.expectedSize = expectedSize
		}
		return nil
	}
	if len(p.files) >= maxManifestEntries-1 {
		return ErrManifestLimit
	}
	if source == nil || source.root == nil {
		return ErrSourceChanged
	}
	info, err := source.root.Stat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return ErrUnsafePath
	}
	for _, protected := range p.protected {
		if os.SameFile(info, protected) {
			return ErrUnsafePath
		}
	}
	if info.Size() < 0 || p.bytes > math.MaxInt64-info.Size() {
		return ErrManifestLimit
	}
	entry := Entry{Path: relative, Role: role, Bytes: info.Size()}
	if strings.HasPrefix(role, "cowrie-") {
		n := info.Size()
		entry.PrefixBytes = &n
		entry.ObservedAt = time.Now().UTC()
	}
	// Account for JSON escaping before retaining names or allocating the final
	// manifest. A 200-byte control-character filename can encode as 1,200 bytes.
	reserved := entry
	reserved.SHA256 = strings.Repeat("0", 64)
	if reserved.PrefixBytes != nil {
		reserved.ObservedAt = time.Date(2000, 1, 1, 0, 0, 0, 123456789, time.UTC)
	}
	encoded, err := json.MarshalIndent(reserved, "    ", "  ")
	if err != nil {
		return err
	}
	p.metadata += int64(len(encoded) + 6)
	if p.metadata > maxManifestBytes {
		return ErrManifestLimit
	}
	p.names[relative] = len(p.files)
	p.files = append(p.files, plannedFile{source, name, info, entry, expectedHash, expectedSize, role == "cowrie-logs"})
	p.bytes += info.Size()
	return nil
}

func openSource(path string, optional bool) (*sourceRoot, error) {
	root, err := safefile.OpenRoot(path)
	if optional && errors.Is(err, safefile.ErrNotExist) {
		return &sourceRoot{path: path}, nil
	}
	if err != nil {
		return nil, err
	}
	info, err := root.Info()
	if err != nil {
		root.Close()
		return nil, err
	}
	return &sourceRoot{path, root, info}, nil
}

func Create(ctx context.Context, opts CreateOptions) (Manifest, error) {
	return createWithOperations(ctx, opts, nativeOperations())
}

func createWithOperations(ctx context.Context, opts CreateOptions, ops fileOperations) (manifest Manifest, result error) {
	ctx, cancel := operationContext(ctx)
	defer cancel()
	stagePath := ""
	defer func() {
		if result != nil {
			manifest.Complete = false
			var f *Failure
			if !errors.As(result, &f) {
				result = failure(ErrIO, result, stagePath)
			}
		}
	}()
	if err := ctx.Err(); err != nil {
		return manifest, err
	}
	if opts.ConfigPath == "" || opts.Output == "" {
		return manifest, ErrConfiguration
	}
	if len(opts.AppVersion) > 256 || len(opts.AppCommit) > 256 {
		return manifest, ErrManifestLimit
	}
	configPath, err := filepath.Abs(opts.ConfigPath)
	if err != nil {
		return manifest, ErrConfiguration
	}
	output, err := filepath.Abs(opts.Output)
	if err != nil {
		return manifest, ErrUnsafePath
	}
	configRoot, err := openSource(filepath.Dir(configPath), false)
	if err != nil {
		return manifest, failure(ErrConfiguration, err, "")
	}
	defer configRoot.root.Close()
	cf, err := configRoot.root.OpenRegular(filepath.Base(configPath))
	if err != nil {
		return manifest, failure(ErrConfiguration, err, "")
	}
	configInfo, err := cf.Stat()
	if err != nil {
		cf.Close()
		return manifest, err
	}
	if configInfo.Size() > 4<<20 {
		cf.Close()
		return manifest, ErrManifestLimit
	}
	raw, err := io.ReadAll(io.LimitReader(cf, 4<<20+1))
	after, statErr := cf.Stat()
	closeErr := cf.Close()
	if err != nil || statErr != nil || closeErr != nil || !safefile.SameFileState(configInfo, after) {
		return manifest, ErrSourceChanged
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		return manifest, failure(ErrConfiguration, err, "")
	}
	data, err := filepath.Abs(cfg.DataDir)
	if err != nil {
		return manifest, ErrConfiguration
	}
	dbPath := filepath.Join(data, "shardlure.db")
	if err := store.CheckDatabaseOwner(dbPath); err != nil {
		return manifest, err
	}
	sourceDB, err := os.Lstat(dbPath)
	if err != nil || !sourceDB.Mode().IsRegular() {
		return manifest, ErrConfiguration
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		return manifest, ErrDestinationExists
	}
	roots := map[string]string{"data": data, "evidence": cfg.CaptureEvidenceDir(), "cowrie-logs": filepath.Dir(cfg.Cowrie.JSONLog), "cowrie-downloads": filepath.Join(cfg.Cowrie.Home, "var", "lib", "cowrie", "downloads"), "cowrie-tty": filepath.Join(cfg.Cowrie.Home, "var", "lib", "cowrie", "tty")}
	for role, value := range roots {
		absolute, err := filepath.Abs(value)
		if err != nil {
			return manifest, ErrConfiguration
		}
		roots[role] = absolute
	}
	for _, role := range []string{"evidence", "cowrie-downloads", "cowrie-tty"} {
		if pathsOverlap(output, roots[role]) {
			return manifest, ErrUnsafePath
		}
	}
	logPath, err := filepath.Abs(cfg.Cowrie.JSONLog)
	if err != nil {
		return manifest, ErrConfiguration
	}
	if within(output, logPath) {
		return manifest, ErrUnsafePath
	}
	parent, err := safefile.OpenRoot(filepath.Dir(output))
	if err != nil {
		return manifest, err
	}
	defer parent.Close()
	if err := parent.CheckOutput(); err != nil {
		return manifest, err
	}
	free, err := ops.space(parent)
	if err != nil {
		return manifest, err
	}
	protected := []fs.FileInfo{sourceDB}
	need := uint64(sourceDB.Size()) + 16<<20
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if info, err := os.Lstat(dbPath + suffix); err == nil {
			protected = append(protected, info)
			if info.Size() < 0 || uint64(info.Size()) > ^uint64(0)-need {
				return manifest, ErrInsufficientSpace
			}
			need += uint64(info.Size())
		} else if !os.IsNotExist(err) {
			return manifest, err
		}
	}
	if free < need {
		return manifest, ErrInsufficientSpace
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return manifest, err
	}
	stageName := ".shardlure-backup-" + hex.EncodeToString(nonce[:]) + ".incomplete"
	stage, err := parent.CreateDirectory(stageName)
	if err != nil {
		return manifest, err
	}
	defer stage.Close()
	stagePath = filepath.Join(filepath.Dir(output), stageName)
	stageInfo, err := stage.Info()
	if err != nil {
		return manifest, err
	}
	if err := writePrivate(stage, incompleteName, []byte("incomplete\n"), ops); err != nil {
		return manifest, err
	}
	markerInfo, err := stage.Stat(incompleteName)
	if err != nil {
		return manifest, err
	}
	for _, dir := range []string{"database", "metadata", "metadata/included", "files"} {
		root, err := ensureRelativeDirectory(stage, dir)
		if err != nil {
			return manifest, err
		}
		root.Close()
	}
	snapshotPath := filepath.Join(stagePath, "database", "shardlure.db")
	info, err := store.SnapshotDatabase(ctx, dbPath, snapshotPath)
	if err != nil {
		return manifest, err
	}
	manifest = Manifest{FormatVersion: 1, AppVersion: opts.AppVersion, AppCommit: opts.AppCommit, Schema: info.Schema, CreatedAt: time.Now().UTC(), SourceRoots: roots, TableCounts: info.TableCounts}
	header, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return manifest, err
	}
	catalog := inventory{names: map[string]int{}, protected: protected, metadata: int64(len(header) + 512)}
	configSum := sha256.Sum256(raw)
	if err := catalog.add(configRoot, filepath.Base(configPath), "metadata/config.yaml", "config", hex.EncodeToString(configSum[:]), int64(len(raw))); err != nil {
		return manifest, err
	}
	opened := map[string]*sourceRoot{}
	defer func() {
		for _, root := range opened {
			if root.root != nil {
				root.root.Close()
			}
		}
	}()
	for _, role := range []string{"evidence", "cowrie-logs", "cowrie-downloads", "cowrie-tty"} {
		source, err := openSource(roots[role], true)
		if err != nil {
			return manifest, err
		}
		opened[role] = source
	}
	snapshot, err := stage.OpenRegular("database/shardlure.db")
	if err != nil {
		return manifest, err
	}
	err = store.IterateSnapshotEvidence(ctx, snapshot, func(ref store.EvidenceReference) error {
		relative, err := mapEvidencePath(roots["evidence"], ref.Path)
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(relative, "files/evidence/")
		if err := catalog.add(opened["evidence"], name, relative, "evidence", ref.SHA256, ref.SizeBytes); err != nil {
			return err
		}
		// Available rendered transcripts are optional derivatives, never a substitute
		// for their mandatory raw evidence. Missing derivatives can be regenerated.
		if _, err := opened["evidence"].root.Stat(name + ".txt"); err == nil {
			return catalog.add(opened["evidence"], name+".txt", relative+".txt", "evidence", "", 0)
		} else if !errors.Is(err, safefile.ErrNotExist) {
			return err
		}
		return nil
	})
	snapshot.Close()
	if err != nil {
		return manifest, err
	}
	for _, role := range []string{"cowrie-logs", "cowrie-downloads", "cowrie-tty"} {
		source := opened[role]
		if source.root == nil {
			continue
		}
		if role == "cowrie-logs" {
			for {
				names, readErr := source.root.ReadNames(64)
				for _, name := range names {
					if name != filepath.Base(logPath) && !strings.HasPrefix(name, filepath.Base(logPath)+".") {
						continue
					}
					if err := catalog.add(source, name, "files/"+role+"/"+name, role, "", 0); err != nil {
						return manifest, err
					}
				}
				if readErr == io.EOF {
					break
				}
				if readErr != nil {
					return manifest, readErr
				}
				if err := ctx.Err(); err != nil {
					return manifest, err
				}
			}
		} else {
			if err := walkRoot(ctx, source.root, "", 0, func(name string, info fs.FileInfo) error {
				if info.IsDir() {
					return nil
				}
				return catalog.add(source, name, "files/"+role+"/"+name, role, "", 0)
			}); err != nil {
				return manifest, err
			}
		}
	}
	extraRoots := []*sourceRoot{}
	defer func() {
		for _, root := range extraRoots {
			root.root.Close()
		}
	}()
	// Bound explicitly requested administrative roots as well as files; normal
	// manifests can still contain the full source-entry limit via streamed roots.
	if len(opts.IncludeFiles) > 256 {
		return manifest, ErrManifestLimit
	}
	for i, value := range opts.IncludeFiles {
		absolute, err := filepath.Abs(value)
		if err != nil {
			return manifest, ErrUnsafePath
		}
		source, err := openSource(filepath.Dir(absolute), false)
		if err != nil {
			return manifest, err
		}
		extraRoots = append(extraRoots, source)
		if pathsOverlap(output, absolute) {
			return manifest, ErrUnsafePath
		}
		relative := fmt.Sprintf("metadata/included/%04d-%s", i, filepath.Base(absolute))
		if err := catalog.add(source, filepath.Base(absolute), relative, "included", "", 0); err != nil {
			return manifest, err
		}
	}
	free, err = ops.space(stage)
	if err != nil {
		return manifest, err
	}
	if uint64(catalog.bytes) > free || free-uint64(catalog.bytes) < 1<<20 {
		return manifest, ErrInsufficientSpace
	}
	sort.Slice(catalog.files, func(i, j int) bool { return catalog.files[i].entry.Path < catalog.files[j].entry.Path })
	for _, file := range catalog.files {
		entry, err := copyPlanned(ctx, stage, file, ops)
		if err != nil {
			return manifest, err
		}
		manifest.Entries = append(manifest.Entries, entry)
	}
	dbEntry, err := hashEntry(ctx, stage, "database/shardlure.db", "database")
	if err != nil {
		return manifest, err
	}
	manifest.Entries = append(manifest.Entries, dbEntry)
	sort.Slice(manifest.Entries, func(i, j int) bool { return manifest.Entries[i].Path < manifest.Entries[j].Path })
	manifest.Complete = true
	if _, _, err := validateManifest(manifest); err != nil {
		return manifest, err
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return manifest, err
	}
	if int64(len(encoded)) > maxManifestBytes {
		return manifest, ErrManifestLimit
	}
	if err := writePrivate(stage, "manifest.json", encoded, ops); err != nil {
		return manifest, err
	}
	if _, _, err := verifyRoot(ctx, stage, true); err != nil {
		return manifest, err
	}
	for _, root := range append(extraRoots, configRoot) {
		if current, err := os.Lstat(root.path); err != nil || !os.SameFile(root.info, current) {
			return manifest, ErrSourceChanged
		}
	}
	for _, root := range opened {
		if root.root != nil {
			if current, err := os.Lstat(root.path); err != nil || !os.SameFile(root.info, current) {
				return manifest, ErrSourceChanged
			}
		}
	}
	if current, err := os.Lstat(dbPath); err != nil || !os.SameFile(sourceDB, current) {
		return manifest, ErrSourceChanged
	}
	if err := ctx.Err(); err != nil {
		return manifest, err
	}
	publishErr := ops.publish(parent, stageName, filepath.Base(output))
	final, openErr := parent.OpenDirectory(filepath.Base(output))
	if openErr == nil {
		defer final.Close()
		finalInfo, err := final.Info()
		if err == nil && os.SameFile(stageInfo, finalInfo) {
			stagePath = output
		} else {
			final = nil
		}
	}
	if publishErr != nil {
		return manifest, publishErr
	}
	if final == nil || openErr != nil {
		return manifest, ErrSourceChanged
	}
	if err := final.RemoveCreated(incompleteName, markerInfo); err != nil {
		return manifest, err
	}
	if err := ops.syncDir(final); err != nil {
		_ = writePrivate(final, incompleteName, []byte("publication uncertain\n"), nativeOperations())
		return manifest, err
	}
	return manifest, nil
}

func copyPlanned(ctx context.Context, stage *safefile.Root, file plannedFile, ops fileOperations) (Entry, error) {
	entry := file.entry
	in, err := file.root.root.OpenRegular(file.name)
	if err != nil {
		return entry, err
	}
	defer in.Close()
	before, err := in.Stat()
	if err != nil {
		return entry, err
	}
	appendable := file.appendable
	if !os.SameFile(file.info, before) || before.Size() < entry.Bytes || (!appendable && !safefile.SameFileState(file.info, before)) {
		return entry, ErrSourceChanged
	}
	parent := stage
	if dir := path.Dir(entry.Path); dir != "." {
		parent, err = ensureRelativeDirectory(stage, dir)
		if err != nil {
			return entry, err
		}
		defer parent.Close()
	}
	out, err := parent.CreateExclusive(path.Base(entry.Path), 0600)
	if err != nil {
		return entry, err
	}
	defer out.Close()
	h := sha256.New()
	n, err := ops.copy(ctx, entry.Role, io.MultiWriter(out, h), in, entry.Bytes)
	if err != nil || n != entry.Bytes {
		return entry, errors.Join(err, ErrSourceChanged)
	}
	after, err := in.Stat()
	if err != nil || (!appendable && !safefile.SameFileState(before, after)) || after.Size() < entry.Bytes {
		return entry, ErrSourceChanged
	}
	current, err := file.root.root.Stat(file.name)
	if err != nil || !os.SameFile(before, current) {
		return entry, ErrSourceChanged
	}
	entry.SHA256 = hex.EncodeToString(h.Sum(nil))
	if appendable {
		second, err := hashOpenFile(ctx, in, entry.Bytes)
		if err != nil {
			return entry, errors.Join(err, ErrSourceChanged)
		}
		if second != entry.SHA256 {
			return entry, ErrSourceChanged
		}
	}
	if entry.PrefixBytes != nil {
		entry.ObservedAt = time.Now().UTC()
	}
	if (file.expectedHash != "" && file.expectedHash != entry.SHA256) || (file.expectedSize > 0 && file.expectedSize != entry.Bytes) {
		return entry, ErrSourceChanged
	}
	if err := ops.syncFile(out); err != nil {
		return entry, err
	}
	if err := out.Close(); err != nil {
		return entry, err
	}
	if err := ops.syncDir(parent); err != nil {
		return entry, err
	}
	return entry, nil
}
