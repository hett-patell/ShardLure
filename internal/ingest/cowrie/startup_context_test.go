package cowrie

import (
	"context"
	"errors"
	"github.com/networkshard/shardlure/internal/store"
	"io"
	"os"
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

// The ctx-triggered close of the log file must surface as the cancellation,
// not as "seek …: file already closed", or a SIGTERM during the live seed
// exits 1. Uses a real closed-file error, the shape Seek returned in the
// shutdown reproduction.
func TestCancelledFileErrorReportsTheCancellation(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "cowrie-*.json")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	_, seekErr := f.Seek(0, io.SeekStart)
	if !errors.Is(seekErr, os.ErrClosed) {
		t.Fatalf("setup: want a closed-file error, got %v", seekErr)
	}
	live, done := context.Background(), func() context.Context {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx
	}()
	realErr := errors.New("stat: input/output error")
	for _, tc := range []struct {
		name string
		ctx  context.Context
		in   error
		want error
	}{
		{"closed by cancellation", done, seekErr, context.Canceled},
		{"closed while ctx live stays an error", live, seekErr, os.ErrClosed},
		{"other error during cancellation is kept", done, realErr, realErr},
		{"nil stays nil", done, nil, nil},
	} {
		got := cancelledFileError(tc.ctx, tc.in)
		if tc.want == nil {
			if got != nil {
				t.Errorf("%s: got %v", tc.name, got)
			}
			continue
		}
		if !errors.Is(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := cancelledFileError(done, seekErr); got != context.Canceled {
		t.Errorf("rewritten error must be the bare cancellation, got %#v", got)
	}
}
