package bazaar

import (
	"sort"
	"strings"
	"testing"
	"time"
)

// TestShareableOriginsMatchesVet pins the two exported accessors to Vet itself.
//
// They exist so candidate-selection SQL can narrow to what Vet accepts instead
// of inventing its own rule. If they drift from Vet, the pre-filter becomes a
// second, invisible policy again — which is the bug they were added for: the
// query said `origin LIKE '%download%'` (never matches "quarantine_fetch") and
// `size_bytes > 1024` (against Vet's 64 B floor), so 10 quarantine-fetched
// payloads and 13 sub-1KiB dropper scripts were rejected before Vet could
// consider them, with no reason an operator could read.
//
// Rather than assert a hardcoded list (which would just restate the constant),
// this drives every origin through Vet and requires the two answers to agree.
func TestShareableOriginsMatchesVet(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-2 * 24 * time.Hour)
	// A file with no recognised family and no malware behaviour tag: the ONLY
	// thing that can accept it is provenance, so Vet's answer isolates exactly
	// the origin question.
	novel := Classification{FileKind: "Shell script", Tags: []string{"bash", "script"}}

	shareable := map[string]bool{}
	for _, o := range ShareableOrigins() {
		shareable[o] = true
	}
	if len(shareable) == 0 {
		t.Fatal("ShareableOrigins() is empty — every candidate query would select nothing")
	}
	if len(shareable) != len(ShareableOrigins()) {
		t.Error("ShareableOrigins() contains duplicates, which would bloat the IN clause")
	}

	// Sorted, so the SQL string a caller builds is stable across runs.
	got := ShareableOrigins()
	sorted := append([]string(nil), got...)
	sort.Strings(sorted)
	for i := range got {
		if got[i] != sorted[i] {
			t.Fatalf("ShareableOrigins() = %v, want sorted order for a stable SQL string", got)
		}
	}

	// Every origin Vet knows about — the accepted set plus the ones it rejects.
	for _, o := range []string{
		"quarantine_fetch", "cowrie_download", "cowrie_file_download",
		"cowrie_tty", "manual", "", "download_something_else",
	} {
		accepts, reason := Vet(Candidate{SizeBytes: 4096, Origin: o, ObservedAt: fresh}, novel, now)
		if accepts != shareable[o] {
			t.Errorf("origin %q: Vet accepts=%v (reason=%q) but ShareableOrigins says %v — "+
				"a selection query built from this set would %s", o, accepts, reason, shareable[o],
				map[bool]string{true: "pre-reject a sample Vet wants", false: "select one Vet always skips"}[accepts])
		}
	}

	// The specific string that broke it: quarantine_fetch must be in the set, and
	// the set must not be expressible as a substring match on "download".
	if !shareable["quarantine_fetch"] {
		t.Error("quarantine_fetch missing — this is the capture runner's OWN fetch, the " +
			"novel-threat path Vet's provenance signal was written for")
	}
	for o := range shareable {
		if !strings.Contains(o, "download") && o != "quarantine_fetch" {
			t.Errorf("unexpected origin %q in the shareable set", o)
		}
	}
	if shareable["cowrie_tty"] {
		t.Error("cowrie_tty is shareable — tty transcripts are operator artifacts and Vet " +
			"hard-rejects them; selecting them would waste IO and risk a policy strike")
	}
}

// TestMinSampleBytesIsVetsFloor pins the exported constant to the gate's actual
// boundary, so a selection query using it can never be stricter than Vet.
func TestMinSampleBytesIsVetsFloor(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-time.Hour)
	cls := Classification{FileKind: "Shell script", Family: "RedTail"}

	at := Candidate{SizeBytes: MinSampleBytes, Origin: "cowrie_download", ObservedAt: fresh}
	if ok, reason := Vet(at, cls, now); !ok {
		t.Errorf("a sample of exactly MinSampleBytes (%d) was rejected (%q) — the constant "+
			"must be the inclusive floor, or an inclusive `size_bytes >= MinSampleBytes` "+
			"query selects rows Vet then drops", MinSampleBytes, reason)
	}
	below := Candidate{SizeBytes: MinSampleBytes - 1, Origin: "cowrie_download", ObservedAt: fresh}
	if ok, _ := Vet(below, cls, now); ok {
		t.Errorf("a sample of MinSampleBytes-1 (%d) was accepted — the constant is not the "+
			"boundary Vet enforces", MinSampleBytes-1)
	}
	// And the drift that actually happened: the old query's 1024 B floor sat well
	// above this, so a several-hundred-byte dropper script never reached Vet.
	dropper := Candidate{SizeBytes: 217, Origin: "cowrie_download", ObservedAt: fresh}
	if ok, reason := Vet(dropper, cls, now); !ok {
		t.Errorf("Vet rejects a 217 B dropper (%q); if that is now intended, MinSampleBytes "+
			"should say so rather than leaving the old 1024 B pre-filter's job to a query", reason)
	}
}
