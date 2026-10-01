package web

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Final audit M2: a family's variants JSON was passed through uncapped, so a
// bot whose scripts differ only in text the normaliser keeps grew the polled
// list response and the dialog DOM with its session count. The list now sends
// the listVariantCap largest variants and the script dialog the
// scriptVariantCap largest (plus the shown fingerprint and the
// representative), each beside the true variantsTotal.
func TestScriptVariantsAreCappedWithTotal(t *testing.T) {
	_, mux, _, raw := listTotalsServer(t)
	const n = 300
	fp := func(i int) string { return fmt.Sprintf("%064x", i+1) }
	var vs []map[string]any
	for i := 0; i < n; i++ {
		vs = append(vs, map[string]any{"fingerprint": fp(i), "distance": 0.1, "sessions": i + 1, "links": false, "reason": "r"})
	}
	b, _ := json.Marshal(vs)
	family, smallest := fp(n-1), fp(0) // the representative is the largest here
	seedScriptFamily(t, raw, family, n*(n+1)/2, string(b))
	const ts = "2026-09-20T00:00:00.000000000Z"
	if _, err := raw.Exec(`INSERT INTO scripts(fingerprint,normalized,display,command_count,distinctive,family,family_distance,token_count,first_seen,last_seen)
VALUES(?,?,?,3,1,?,0.1,3,?,?)`, smallest, "n", "cd /tmp", family, ts, ts); err != nil {
		t.Fatal(err)
	}

	type variant struct {
		Fingerprint string `json:"fingerprint"`
		Sessions    int    `json:"sessions"`
	}
	var l struct {
		Families []struct {
			Variants      []variant `json:"variants"`
			VariantsTotal int       `json:"variantsTotal"`
		} `json:"families"`
	}
	getJSON(t, mux, "/api/intel/scripts", &l)
	if len(l.Families) != 1 {
		t.Fatalf("families = %d", len(l.Families))
	}
	f := l.Families[0]
	if len(f.Variants) != listVariantCap || f.VariantsTotal != n {
		t.Fatalf("list: %d variants, total %d; want %d of %d", len(f.Variants), f.VariantsTotal, listVariantCap, n)
	}
	if f.Variants[0].Sessions != n || f.Variants[listVariantCap-1].Sessions != n-listVariantCap+1 {
		t.Fatalf("list keeps the largest variants in session order: first %d last %d", f.Variants[0].Sessions, f.Variants[listVariantCap-1].Sessions)
	}

	var d struct {
		Variants      []variant `json:"variants"`
		VariantsTotal int       `json:"variantsTotal"`
		SessionsTotal int       `json:"sessionsTotal"`
	}
	getJSON(t, mux, "/api/intel/script?fp="+smallest, &d)
	if d.VariantsTotal != n || len(d.Variants) != scriptVariantCap+1 {
		t.Fatalf("script: %d variants, total %d; want %d (+ the shown one) of %d", len(d.Variants), d.VariantsTotal, scriptVariantCap, n)
	}
	var shown bool
	for _, v := range d.Variants {
		shown = shown || v.Fingerprint == smallest
	}
	// sessionsTotal is the store's count for this fingerprint (no session
	// rows here), never the materialised family's variant figure.
	if !shown || d.SessionsTotal != 0 {
		t.Fatalf("the shown variant must stay listed (found %v); sessionsTotal = %d, want the store's 0", shown, d.SessionsTotal)
	}
	// A stored value that is not an array still degrades to [] with total 0.
	seedScriptFamily(t, raw, strings.Repeat("f", 64), 0, "not json")
	getJSON(t, mux, "/api/intel/scripts", &l)
	if last := l.Families[len(l.Families)-1]; len(last.Variants) != 0 || last.VariantsTotal != 0 {
		t.Fatalf("bad variants JSON: %+v", last)
	}
}

// Final re-review, web item 3: capVariants parses every stored variant to
// rank them, so each 30 s poll cost CPU proportional to the stored arrays
// although the response was capped. The list memoises the capped result per
// family and parses again only when the stored array changed; the "N of M"
// totals stay those of the current array.
func TestScriptListParsesVariantsOnlyWhenChanged(t *testing.T) {
	s, mux, _, raw := listTotalsServer(t)
	fp := func(i int) string { return fmt.Sprintf("%064x", i+1) }
	variants := func(n int) string {
		var vs []map[string]any
		for i := 0; i < n; i++ {
			vs = append(vs, map[string]any{"fingerprint": fp(i), "distance": 0.1, "sessions": i + 1, "links": false, "reason": "r"})
		}
		b, _ := json.Marshal(vs)
		return string(b)
	}
	seedScriptFamily(t, raw, fp(1000), 10, variants(300))
	seedScriptFamily(t, raw, fp(1001), 5, variants(3))
	var l struct {
		Families []struct {
			Family        string            `json:"family"`
			Variants      []json.RawMessage `json:"variants"`
			VariantsTotal int               `json:"variantsTotal"`
		} `json:"families"`
	}
	check := func(wantParses int, wantTotals map[string]int) {
		t.Helper()
		getJSON(t, mux, "/api/intel/scripts", &l)
		s.listVariants.mu.Lock()
		parses := s.listVariants.parses
		s.listVariants.mu.Unlock()
		if parses != wantParses {
			t.Fatalf("capVariants ran %d times, want %d", parses, wantParses)
		}
		for _, f := range l.Families {
			if want := wantTotals[f.Family]; f.VariantsTotal != want || len(f.Variants) != min(want, listVariantCap) {
				t.Fatalf("family %s: %d variants of %d, want %d of %d", f.Family[:8], len(f.Variants), f.VariantsTotal, min(want, listVariantCap), want)
			}
		}
	}
	check(2, map[string]int{fp(1000): 300, fp(1001): 3})
	check(2, map[string]int{fp(1000): 300, fp(1001): 3}) // unchanged: no parse
	check(2, map[string]int{fp(1000): 300, fp(1001): 3})
	// A regroup rewrites one family's variants: only that one is parsed.
	if _, err := raw.Exec(`UPDATE script_families SET variants=? WHERE family=?`, variants(420), fp(1000)); err != nil {
		t.Fatal(err)
	}
	check(3, map[string]int{fp(1000): 420, fp(1001): 3})
}

// Premerge store-read M2 / web M2: the dialog found its family by scanning
// ListScriptFamilies(1000), so a family ranked past 1000 (the family count
// is attacker-driven) silently lost its block. It is a primary-key read now.
func TestScriptDialogFindsFamilyBeyondListRank(t *testing.T) {
	_, mux, _, raw := listTotalsServer(t)
	fp := func(i int) string { return fmt.Sprintf("%064x", i+1) }
	tx, err := raw.Begin()
	if err != nil {
		t.Fatal(err)
	}
	const ts = "2026-09-20T00:00:00.000000000Z"
	for i := 0; i < 1001; i++ { // all larger than the family under test
		if _, err := tx.Exec(`INSERT INTO script_families(family,display,variants,sessions,actors,ips,command_count,distinctive,links,reason,first_seen,last_seen)
VALUES(?,'x','[]',?,1,1,3,1,0,'r',?,?)`, fp(i), 100+i, ts, ts); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	small, member := fp(5000), fp(5001)
	b, _ := json.Marshal([]map[string]any{
		{"fingerprint": small, "distance": 0, "sessions": 1, "links": false, "reason": "r"},
		{"fingerprint": member, "distance": 0.1, "sessions": 1, "links": false, "reason": "r"},
	})
	seedScriptFamily(t, raw, small, 2, string(b))
	for _, f := range []string{small, member} {
		if _, err := raw.Exec(`INSERT INTO scripts(fingerprint,normalized,display,command_count,distinctive,family,family_distance,token_count,first_seen,last_seen)
VALUES(?,'n','cd /tmp',3,1,?,0.1,3,?,?)`, f, small, ts, ts); err != nil {
			t.Fatal(err)
		}
	}
	var d struct {
		FamilySessions *int              `json:"familySessions"`
		Variants       []json.RawMessage `json:"variants"`
	}
	getJSON(t, mux, "/api/intel/script?fp="+member, &d)
	if d.FamilySessions == nil || *d.FamilySessions != 2 || len(d.Variants) != 2 {
		t.Fatalf("family ranked 1002nd lost its dialog block: familySessions=%v variants=%d", d.FamilySessions, len(d.Variants))
	}
}
