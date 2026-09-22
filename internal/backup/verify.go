package backup

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"reflect"
	"strings"

	"github.com/networkshard/shardlure/internal/safefile"
	"github.com/networkshard/shardlure/internal/store"
)

func readManifest(root *safefile.Root) (Manifest, error) {
	f, err := root.OpenRegular("manifest.json")
	if err != nil {
		return Manifest{}, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return Manifest{}, err
	}
	if before.Size() > maxManifestBytes {
		return Manifest{}, ErrManifestLimit
	}
	m, err := decodeManifest(f)
	if err != nil {
		return Manifest{}, err
	}
	after, err := f.Stat()
	if err != nil || !safefile.SameFileState(before, after) {
		return Manifest{}, ErrSourceChanged
	}
	return m, nil
}

func Verify(ctx context.Context, input string) (Report, error) {
	return verifyWithOperations(ctx, input, nativeOperations())
}
func verifyWithOperations(ctx context.Context, input string, ops fileOperations) (Report, error) {
	ctx, cancel := operationContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	root, err := safefile.OpenRoot(input)
	if err != nil {
		return Report{}, failure(ErrInvalidManifest, err, "")
	}
	defer root.Close()
	report, _, err := verifyRoot(ctx, root, false, ops)
	if err != nil {
		return Report{}, failure(ErrInvalidManifest, err, "")
	}
	return report, nil
}

func verifyRoot(ctx context.Context, root *safefile.Root, allowIncomplete bool, operations ...fileOperations) (Report, Manifest, error) {
	ops := nativeOperations()
	if len(operations) > 0 {
		ops = operations[0]
	}
	var zero Report
	if _, err := root.Stat(incompleteName); err == nil && !allowIncomplete {
		return zero, Manifest{}, ErrIncomplete
	} else if err != nil && !errors.Is(err, safefile.ErrNotExist) {
		return zero, Manifest{}, err
	}
	m, err := readManifest(root)
	if err != nil {
		return zero, m, err
	}
	entries, total, err := validateManifest(m)
	if err != nil {
		return zero, m, err
	}
	directories := map[string]bool{"database": true, "metadata": true, "metadata/included": true, "files": true, "files/evidence": true, "files/cowrie-logs": true, "files/cowrie-downloads": true, "files/cowrie-tty": true}
	for name := range entries {
		for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
			directories[dir] = true
		}
	}
	seen := make(map[string]bool, len(entries))
	info, err := root.Info()
	if err != nil || info.Mode().Perm()&0077 != 0 {
		return zero, m, ErrInvalidManifest
	}
	err = walkRoot(ctx, root, "", 0, func(name string, info fs.FileInfo) error {
		if info.Mode().Perm()&0077 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
			return ErrInvalidManifest
		}
		if info.IsDir() {
			if !directories[name] {
				return ErrInvalidManifest
			}
			return nil
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0111 != 0 {
			return ErrInvalidManifest
		}
		if name == "manifest.json" || (allowIncomplete && name == incompleteName) {
			return nil
		}
		expected, ok := entries[name]
		if !ok || seen[name] {
			return ErrInvalidManifest
		}
		seen[name] = true
		got, err := hashEntryWithOperations(ctx, root, name, expected.Role, ops)
		if err != nil {
			return err
		}
		if got.Bytes != expected.Bytes || got.SHA256 != expected.SHA256 {
			return ErrInvalidManifest
		}
		return nil
	})
	if err != nil {
		return zero, m, err
	}
	if len(seen) != len(entries) {
		return zero, m, ErrInvalidManifest
	}
	db, err := ops.openFile(root, "database/shardlure.db")
	if err != nil {
		return zero, m, err
	}
	defer db.Close()
	// Bind SQLite inspection to verified bytes on THIS descriptor. A pathname
	// replacement between the inventory hash and this open must not let a
	// different, valid SQLite database inherit the old checksum's verification.
	beforeDB, err := db.Stat()
	if err != nil {
		return zero, m, err
	}
	expectedDB := entries["database/shardlure.db"]
	if beforeDB.Size() != expectedDB.Bytes {
		return zero, m, ErrInvalidManifest
	}
	dbHash, err := hashOpenFile(ctx, db, beforeDB.Size())
	if err != nil {
		return zero, m, err
	}
	if dbHash != expectedDB.SHA256 {
		return zero, m, ErrInvalidManifest
	}
	checked, err := store.InspectSnapshotFile(ctx, db)
	if err != nil {
		return zero, m, err
	}
	if checked.Schema != m.Schema || !reflect.DeepEqual(checked.TableCounts, m.TableCounts) {
		return zero, m, ErrInvalidManifest
	}
	err = store.IterateSnapshotEvidence(ctx, db, func(ref store.EvidenceReference) error {
		name, err := mapEvidencePath(m.SourceRoots["evidence"], ref.Path)
		if err != nil {
			return err
		}
		entry, ok := entries[name]
		if !ok || entry.Role != "evidence" {
			return ErrInvalidManifest
		}
		if ref.SHA256 != "" && strings.ToLower(ref.SHA256) != entry.SHA256 {
			return ErrInvalidManifest
		}
		if ref.SizeBytes > 0 && ref.SizeBytes != entry.Bytes {
			return ErrInvalidManifest
		}
		return nil
	})
	if err != nil {
		return zero, m, err
	}
	afterDB, err := db.Stat()
	if err != nil || !safefile.SameFileState(beforeDB, afterDB) {
		return zero, m, ErrSourceChanged
	}
	namedDB, err := root.Stat("database/shardlure.db")
	if err != nil || !safefile.SameFileState(afterDB, namedDB) {
		return zero, m, ErrSourceChanged
	}
	return Report{Files: len(entries), Bytes: total, Schema: m.Schema, TableCounts: m.TableCounts}, m, nil
}
