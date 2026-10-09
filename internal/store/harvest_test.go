package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// insertHarvestRow writes one artifacts row the way a capture would leave it.
func insertHarvestRow(t *testing.T, st *Store, url, origin, status, sha string, size int64, depth int) int64 {
	t.Helper()
	if err := st.ensureArtifactsTable(); err != nil {
		t.Fatal(err)
	}
	res, err := st.db.Exec(`INSERT INTO artifacts(ts,src_ip,session_id,actor_id,url,local_path,sha256,size_bytes,origin,status,created_at,attempt_count,depth)
VALUES('2026-10-08T00:00:00Z','198.51.100.7','sess-1','cowrie:abc',?,?,?,?,?,?,'2026-10-08T00:00:00Z',1,?)`,
		url, "/evidence/quarantine/"+sha, sha, size, origin, status, depth)
	if err != nil {
		t.Fatal(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func harvestCursor(t *testing.T, st *Store) int64 {
	t.Helper()
	var c int64
	if err := st.db.QueryRow(`SELECT COALESCE((SELECT offset FROM ingest_state WHERE source='capture' AND path='harvest-v1'),0)`).Scan(&c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestHarvestQueuesChildrenWithParentAndProvenance(t *testing.T) {
	st := newTestStore(t, "harvest.db")
	ctx := context.Background()
	id := insertHarvestRow(t, st, "http://203.0.113.5/bins.sh", "quarantine_fetch", "fetched", "aaaa", 300, 0)
	cands, err := st.HarvestCandidates(ctx, 64)
	if err != nil || len(cands) != 1 || cands[0].ID != id || cands[0].Depth != 0 || cands[0].SrcIP != "198.51.100.7" {
		t.Fatalf("candidates=%+v err=%v", cands, err)
	}
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	n, err := st.QueueHarvestedURLs(ctx, cands[0], []string{"http://203.0.113.5/bins/x86", "http://203.0.113.5/bins/mips"}, now, 32)
	if err != nil || n != 2 {
		t.Fatalf("queued=%d err=%v", n, err)
	}
	rows, err := st.db.Query(`SELECT url, origin, status, fetch_epoch, depth, parent_sha256, src_ip, session_id, actor_id FROM artifacts WHERE depth=1 ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var u, origin, status, parent, ip, sess, actor string
		var epoch, depth int
		if err := rows.Scan(&u, &origin, &status, &epoch, &depth, &parent, &ip, &sess, &actor); err != nil {
			t.Fatal(err)
		}
		if origin != "quarantine_fetch" || status != "pending" || epoch != 0 || parent != "aaaa" || ip != "198.51.100.7" || sess != "sess-1" || actor != "cowrie:abc" {
			t.Fatalf("child row %s: origin=%s status=%s epoch=%d parent=%s ip=%s sess=%s actor=%s", u, origin, status, epoch, parent, ip, sess, actor)
		}
		got = append(got, u)
	}
	if fmt.Sprint(got) != "[http://203.0.113.5/bins/x86 http://203.0.113.5/bins/mips]" {
		t.Fatalf("children=%v", got)
	}
	if c := harvestCursor(t, st); c != id {
		t.Fatalf("cursor=%d want %d", c, id)
	}
	// Replaying the same source queues nothing new and keeps the cursor.
	n, err = st.QueueHarvestedURLs(ctx, cands[0], []string{"http://203.0.113.5/bins/x86", "http://203.0.113.5/bins/mips"}, now, 32)
	if err != nil || n != 0 {
		t.Fatalf("replay queued=%d err=%v", n, err)
	}
	var total int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM artifacts`).Scan(&total); err != nil || total != 3 {
		t.Fatalf("rows=%d err=%v", total, err)
	}
	// The pending children hold no fetched rows back, and none is a candidate.
	if cands, err := st.HarvestCandidates(ctx, 64); err != nil || len(cands) != 0 {
		t.Fatalf("after harvest candidates=%+v err=%v", cands, err)
	}
}

func TestHarvestCandidateFilter(t *testing.T) {
	st := newTestStore(t, "harvest-filter.db")
	ctx := context.Background()
	want := map[int64]bool{
		insertHarvestRow(t, st, "http://203.0.113.1/a", "quarantine_fetch", "fetched", "a1", 10, 0):        true,
		insertHarvestRow(t, st, "cowrie-download:b", "cowrie_download", "fetched", "b1", 10, 0):            true,
		insertHarvestRow(t, st, "cowrie-event:7", "cowrie_file_download", "fetched", "c1", 10, 1):          true,
		insertHarvestRow(t, st, "http://203.0.113.1/d2", "quarantine_fetch", "fetched", "d2", 10, 2):       false, // depth 2: never harvested
		insertHarvestRow(t, st, "http://203.0.113.1/big", "quarantine_fetch", "fetched", "e1", 1<<20+1, 0): false,
		insertHarvestRow(t, st, "http://203.0.113.1/empty", "quarantine_fetch", "empty", "f1", 0, 0):       false,
		insertHarvestRow(t, st, "cowrie-tty:x", "cowrie_tty", "fetched", "g1", 10, 0):                      false,
		insertHarvestRow(t, st, "http://203.0.113.1/blocked", "quarantine_fetch", "blocked", "h1", 10, 0):  false,
	}
	cands, err := st.HarvestCandidates(ctx, 64)
	if err != nil {
		t.Fatal(err)
	}
	got := map[int64]bool{}
	for _, c := range cands {
		got[c.ID] = true
	}
	for id, ok := range want {
		if got[id] != ok {
			t.Fatalf("row %d candidate=%v want %v (cands %+v)", id, got[id], ok, cands)
		}
	}
	// A depth-2 source is refused even if a caller hands it over.
	if _, err := st.QueueHarvestedURLs(ctx, HarvestSource{ID: 99, Depth: 2}, []string{"http://203.0.113.9/x"}, time.Now(), 32); err == nil {
		t.Fatal("depth-2 source queued")
	}
}

// The cursor never passes a quarantine fetch still in flight: when it
// completes, the script it fetched is harvested.
func TestHarvestCursorWaitsForInFlightCapture(t *testing.T) {
	st := newTestStore(t, "harvest-inflight.db")
	ctx := context.Background()
	pending := insertHarvestRow(t, st, "http://203.0.113.1/later.sh", "quarantine_fetch", "pending", "", 0, 0)
	done := insertHarvestRow(t, st, "cowrie-download:x", "cowrie_download", "fetched", "x1", 10, 0)
	if cands, err := st.HarvestCandidates(ctx, 64); err != nil || len(cands) != 0 {
		t.Fatalf("rows past an in-flight capture offered: %+v err=%v", cands, err)
	}
	if _, err := st.db.Exec(`UPDATE artifacts SET status='fetched', sha256='p1', size_bytes=20 WHERE id=?`, pending); err != nil {
		t.Fatal(err)
	}
	cands, err := st.HarvestCandidates(ctx, 64)
	if err != nil || len(cands) != 2 || cands[0].ID != pending || cands[1].ID != done {
		t.Fatalf("candidates=%+v err=%v", cands, err)
	}
}

func TestHarvestPerHostDailyCap(t *testing.T) {
	st := newTestStore(t, "harvest-cap.db")
	ctx := context.Background()
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	first := insertHarvestRow(t, st, "http://203.0.113.1/a.sh", "quarantine_fetch", "fetched", "s1", 10, 0)
	var urls []string
	for i := 0; i < 20; i++ {
		urls = append(urls, fmt.Sprintf("http://203.0.113.5/a/%d", i))
	}
	n, err := st.QueueHarvestedURLs(ctx, HarvestSource{ID: first, SHA256: "s1"}, urls, now, 32)
	if err != nil || n != 20 {
		t.Fatalf("first script queued=%d err=%v", n, err)
	}
	second := insertHarvestRow(t, st, "http://203.0.113.1/b.sh", "quarantine_fetch", "fetched", "s2", 10, 0)
	urls = urls[:0]
	for i := 0; i < 13; i++ {
		// One spelling differs only in case and a trailing dot: same host.
		host := "203.0.113.5"
		if i == 0 {
			host = "203.0.113.5."
		}
		urls = append(urls, fmt.Sprintf("http://%s/b/%d", host, i))
	}
	urls = append(urls, "http://198.51.100.20/other")
	n, err = st.QueueHarvestedURLs(ctx, HarvestSource{ID: second, SHA256: "s2"}, urls, now, 32)
	if err != nil || n != 13 {
		t.Fatalf("second script queued=%d err=%v (want 12 to the capped host + 1 other)", n, err)
	}
	var capped, other int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM artifacts WHERE depth=1 AND url LIKE 'http://203.0.113.5%'`).Scan(&capped); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM artifacts WHERE depth=1 AND url='http://198.51.100.20/other'`).Scan(&other); err != nil {
		t.Fatal(err)
	}
	if capped != 32 || other != 1 {
		t.Fatalf("capped host rows=%d (want 32), other host=%d", capped, other)
	}
	if c := harvestCursor(t, st); c != second {
		t.Fatalf("cursor=%d want %d", c, second)
	}
	// A day later the host has room again.
	n, err = st.QueueHarvestedURLs(ctx, HarvestSource{ID: second, SHA256: "s2"}, []string{"http://203.0.113.5/c/1"}, now.Add(25*time.Hour), 32)
	if err != nil || n != 1 {
		t.Fatalf("next day queued=%d err=%v", n, err)
	}
}

func TestHarvestCursorAdvancesWithoutURLs(t *testing.T) {
	st := newTestStore(t, "harvest-cursor.db")
	ctx := context.Background()
	a := insertHarvestRow(t, st, "cowrie-download:a", "cowrie_download", "fetched", "a1", 10, 0)
	b := insertHarvestRow(t, st, "cowrie-download:b", "cowrie_download", "fetched", "b1", 10, 0)
	if err := st.AdvanceHarvestCursor(ctx, a); err != nil {
		t.Fatal(err)
	}
	if c := harvestCursor(t, st); c != a {
		t.Fatalf("cursor=%d want %d", c, a)
	}
	if n, err := st.QueueHarvestedURLs(ctx, HarvestSource{ID: b}, nil, time.Now(), 32); err != nil || n != 0 {
		t.Fatalf("queued=%d err=%v", n, err)
	}
	if c := harvestCursor(t, st); c != b {
		t.Fatalf("cursor=%d want %d", c, b)
	}
	// Never moves backwards.
	if err := st.AdvanceHarvestCursor(ctx, a); err != nil {
		t.Fatal(err)
	}
	if c := harvestCursor(t, st); c != b {
		t.Fatalf("cursor moved back to %d", c)
	}
	if cands, err := st.HarvestCandidates(ctx, 64); err != nil || len(cands) != 0 {
		t.Fatalf("candidates=%+v err=%v", cands, err)
	}
}
