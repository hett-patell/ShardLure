//go:build linux

package backup

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

var errNotOwnStaging = errors.New("backup: staging directory is not this run's")

// removeOwnStaging deletes this run's unpublished staging directory after a
// failed create (final audit M3: a refused --include-file left a
// .shardlure-backup-<nonce>.incomplete directory, holding a snapshot of the
// database, beside the requested output). It deletes nothing else:
//
//   - the output's parent is reopened without following a final symlink and
//     must be the very directory create pinned (dev/ino of parentInfo);
//   - stageName must have create's random staging shape, and the entry under
//     it must be the directory create made (dev/ino/uid of stageInfo), so a
//     published output, a raced-in destination or another run's staging
//     directory never matches;
//   - the walk goes through directory descriptors (openat with O_NOFOLLOW),
//     unlinks symlinks rather than following them, and refuses to cross into
//     another filesystem.
//
// Any refusal or error leaves the rest in place and is returned, so the
// caller still reports the staging path as retained.
func removeOwnStaging(parentPath string, parentInfo, stageInfo fs.FileInfo, stageName string) error {
	if !strings.HasPrefix(stageName, ".shardlure-backup-") || !strings.HasSuffix(stageName, ".incomplete") || strings.ContainsRune(stageName, '/') {
		return errNotOwnStaging
	}
	wantParent, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return errNotOwnStaging
	}
	wantStage, ok := stageInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return errNotOwnStaging
	}
	pfd, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(pfd)
	var pst unix.Stat_t
	if err := unix.Fstat(pfd, &pst); err != nil {
		return err
	}
	if pst.Dev != uint64(wantParent.Dev) || pst.Ino != uint64(wantParent.Ino) {
		return errNotOwnStaging
	}
	sfd, err := unix.Openat(pfd, stageName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	var sst unix.Stat_t
	if err := unix.Fstat(sfd, &sst); err != nil {
		unix.Close(sfd)
		return err
	}
	if sst.Dev != uint64(wantStage.Dev) || sst.Ino != uint64(wantStage.Ino) || sst.Uid != uint32(os.Geteuid()) {
		unix.Close(sfd)
		return errNotOwnStaging
	}
	err = removeDirectoryContents(sfd, sst.Dev, 0)
	unix.Close(sfd)
	if err != nil {
		return err
	}
	// The name must still be the directory just emptied; rmdir itself refuses
	// a directory that is not empty.
	var again unix.Stat_t
	if err := unix.Fstatat(pfd, stageName, &again, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if again.Dev != sst.Dev || again.Ino != sst.Ino {
		return errNotOwnStaging
	}
	if err := unix.Unlinkat(pfd, stageName, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	return unix.Fsync(pfd)
}

// removeDirectoryContents empties the directory open at dirfd. The staging
// tree is at most a few levels deeper than walkRoot's source bound.
func removeDirectoryContents(dirfd int, dev uint64, depth int) error {
	if depth > 80 {
		return ErrManifestLimit
	}
	dup, err := unix.Dup(dirfd)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(dup), "staging-directory")
	defer dir.Close()
	for {
		names, readErr := dir.Readdirnames(256)
		for _, name := range names {
			var st unix.Stat_t
			if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err
			}
			if st.Dev != dev {
				return errNotOwnStaging
			}
			if st.Mode&unix.S_IFMT != unix.S_IFDIR {
				if err := unix.Unlinkat(dirfd, name, 0); err != nil {
					return err
				}
				continue
			}
			child, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			var cst unix.Stat_t
			if err := unix.Fstat(child, &cst); err != nil || cst.Dev != st.Dev || cst.Ino != st.Ino {
				unix.Close(child)
				return errors.Join(err, errNotOwnStaging)
			}
			err = removeDirectoryContents(child, dev, depth+1)
			unix.Close(child)
			if err != nil {
				return err
			}
			if err := unix.Unlinkat(dirfd, name, unix.AT_REMOVEDIR); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}
