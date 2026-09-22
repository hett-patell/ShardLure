package capture

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiagnosticPrivacyCaptureFilesystemAndCancellation(t *testing.T) {
	f := NewSafeFetcher(filepath.Join(t.TempDir(), "inert-private-key"), 1, time.Second, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.Fetch(ctx, "http://8.8.8.8/inert?token=inert-secret")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if strings.Contains(err.Error(), "inert-secret") || strings.Contains(err.Error(), "inert-private-key") {
		t.Fatal("capture error leaked private data")
	}
}
