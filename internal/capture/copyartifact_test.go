package capture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCopyArtifactSizeCap guards the fix for the unbounded-copy finding: a
// source larger than maxBytes must be rejected (not silently truncated, which
// would also corrupt the sha), while a within-limit file copies fine and an
// unlimited cap (<=0) always copies.
func TestCopyArtifactSizeCap(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "small")
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(small, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(big, []byte(strings.Repeat("A", 4096)), 0o600); err != nil {
		t.Fatal(err)
	}

	// Over the cap → rejected, no dest written.
	dst := filepath.Join(dir, "out-big")
	if _, _, err := copyArtifact(big, dst, 1024); err == nil {
		t.Fatal("expected oversized copy to be rejected")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatal("rejected copy must not leave a dest file")
	}

	// Within the cap → copies, correct size + nonempty sha.
	dst2 := filepath.Join(dir, "out-small")
	sum, n, err := copyArtifact(small, dst2, 1024)
	if err != nil {
		t.Fatalf("within-cap copy failed: %v", err)
	}
	if n != 5 || sum == "" {
		t.Fatalf("expected size=5 + sha, got size=%d sha=%q", n, sum)
	}

	// maxBytes <= 0 → unlimited, big file copies.
	dst3 := filepath.Join(dir, "out-unlimited")
	if _, n, err := copyArtifact(big, dst3, 0); err != nil || n != 4096 {
		t.Fatalf("unlimited copy: err=%v size=%d (want 4096)", err, n)
	}
}
