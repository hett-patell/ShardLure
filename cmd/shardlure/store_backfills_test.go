package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
)

func TestRunStoreBackfillsIncludesSubmissionLedgers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backfills.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("INSERT INTO urlhaus_submissions(url,submitted_at,status) VALUES('inert','2026-09-21T10:00:00.5Z','ok')"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runStoreBackfills(ctx, st)
	if err := ctx.Err(); err != nil {
		t.Fatal(err)
	}
	var key sql.NullString
	if err := db.QueryRow("SELECT submitted_at_key FROM urlhaus_submissions WHERE url='inert'").Scan(&key); err != nil {
		t.Fatal(err)
	}
	if key.String != "2026-09-21T10:00:00.500000000Z" {
		t.Fatalf("startup left ledger unbackfilled: %+v", key)
	}
}
