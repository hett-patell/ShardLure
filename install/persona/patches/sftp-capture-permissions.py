#!/usr/bin/env python3
"""Give the Cowrie group read access to each finalized SFTP capture.

Cowrie's SFTP open() masks requested permissions independently of umask. The
separate shardlure user needs group read access after close(), including when
dedup keeps an existing SHA-named file. Never grant execute or other access.
"""
import sys
from pathlib import Path


OLD = """\
            if os.path.exists(shasumfile):
                os.remove(self.tempfiles[fd])
            else:
                os.rename(self.tempfiles[fd], shasumfile)
            self.update_realfile(self.getfile(self.filenames[fd]), shasumfile)
"""

NEW = """\
            if os.path.exists(shasumfile):
                os.remove(self.tempfiles[fd])
            else:
                os.rename(self.tempfiles[fd], shasumfile)
            # ShardLure reads finalized captures through the Cowrie group.
            # Normalize the retained destination even when dedup kept an old file.
            os.chmod(shasumfile, 0o640)
            self.update_realfile(self.getfile(self.filenames[fd]), shasumfile)
"""


def main() -> int:
    args = sys.argv[1:]
    if (len(args) not in (1, 2) or not args[0] or args[0] == "--check"
            or (len(args) == 2 and args[1] != "--check")):
        print(f"usage: {Path(sys.argv[0]).name} COWRIE_HOME [--check]", file=sys.stderr)
        return 2
    path = Path(args[0]) / "src/cowrie/shell/fs.py"
    content = path.read_text(encoding="utf-8")
    old_count, new_count = content.count(OLD), content.count(NEW)
    if old_count == 0 and new_count == 1:
        print(f"  [skip] {path}: already patched")
        return 0
    if old_count != 1 or new_count != 0:
        print(f"  [FAIL] {path}: target is neither pristine nor fully patched", file=sys.stderr)
        return 1
    if len(args) == 2:
        print(f"  [check] {path}: compatible")
        return 0
    path.write_text(content.replace(OLD, NEW, 1), encoding="utf-8")
    print(f"  [ok] {path}: patched")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
