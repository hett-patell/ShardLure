package journal

import (
	"context"
	"errors"
	"github.com/networkshard/shardlure/internal/store"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStartupJournalContextCancelsActualChild(t *testing.T) {
	dir := t.TempDir()
	helper := filepath.Join(dir, "journalctl")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexec /bin/sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	st, err := store.Open(filepath.Join(t.TempDir(), "seed.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = IngestJournalctlContext(ctx, st, "inert", "inert", nil, false)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("startup child did not cancel/join: %v", err)
	}
	if n, err := st.EventCount(); err != nil || n != 0 {
		t.Fatalf("cancelled seed persisted data: %d %v", n, err)
	}
}
