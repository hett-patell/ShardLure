package cowrie

import (
	"context"
	"errors"
	"github.com/networkshard/shardlure/internal/store"
	"path/filepath"
	"testing"
)

func TestStartupCowrieContextCancelsBeforeStoreWork(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "startup.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := IngestFileAppendContext(ctx, st, "/inert/missing", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("append cancellation lost: %v", err)
	}
	if err := BackfillRotatedLogsContext(ctx, st, "/inert/missing", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("backfill cancellation lost: %v", err)
	}
}
