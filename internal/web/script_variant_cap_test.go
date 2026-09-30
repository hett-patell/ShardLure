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
	if !shown || d.SessionsTotal != 1 {
		t.Fatalf("the shown variant must stay listed (found %v) and its total come from the full list (%d)", shown, d.SessionsTotal)
	}
	// A stored value that is not an array still degrades to [] with total 0.
	seedScriptFamily(t, raw, strings.Repeat("f", 64), 0, "not json")
	getJSON(t, mux, "/api/intel/scripts", &l)
	if last := l.Families[len(l.Families)-1]; len(last.Variants) != 0 || last.VariantsTotal != 0 {
		t.Fatalf("bad variants JSON: %+v", last)
	}
}
