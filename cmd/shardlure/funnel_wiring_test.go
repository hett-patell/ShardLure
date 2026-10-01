package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/networkshard/shardlure/internal/observability"
	"github.com/networkshard/shardlure/internal/store"
)

func TestFunnelWindowCopiesEveryField(t *testing.T) {
	c := store.FunnelCounts{Connected: 1, LoggedIn: 2, RanCommands: 3, DownloadAttempt: 4, Captured: 5, NewPayloads: 6, SharedBazaar: 7, SharedURLhaus: 8, SharedThreatFox: 9}
	want := observability.FunnelWindow{Connected: 1, LoggedIn: 2, RanCommands: 3, DownloadAttempt: 4, Captured: 5, NewPayloads: 6, SharedBazaar: 7, SharedURLhaus: 8, SharedThreatFox: 9}
	if got := funnelWindow(c); got != want {
		t.Fatalf("funnelWindow = %+v, want %+v", got, want)
	}
}

func TestCollectFunnelRunsBothWindows(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "funnel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := collectFunnel(st)(context.Background()); err != nil {
		t.Fatalf("collectFunnel on an empty store: %v", err)
	}
}
