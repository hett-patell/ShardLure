package store

import (
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// sharePolicyFixture mirrors the shape of the reference deployment: the three
// fetched origins the bazaar gate accepts, cowrie_tty (which it hard-rejects),
// and a payload recorded under TWO origins with the quarantine fetch NEWEST.
// That last one is the whole point — it is the shape that hid the Traffmonetizer
// and Komari droppers from the dashboard.
//
// Returns the policy the share path actually uses. Duplicating bazaar's numbers
// here rather than importing them is deliberate: store must not import
// intel/bazaar (see the UploadRecorder comment), so these tests pin the
// mechanism, and cmd/web pin that the real values are wired through.
func sharePolicyFixture(t *testing.T, st *Store, now time.Time) SharePolicy {
	t.Helper()
	rows := []Artifact{
		// Fetched by our own quarantine runner. `origin LIKE '%download%'` does
		// not match this string, which is the bug: 10 payloads / 18.6 MB were
		// invisible to the share path on the reference box.
		{URL: "http://x/quarantined", SHA256: "q1", LocalPath: "/ev/q1", SizeBytes: 4096,
			Origin: "quarantine_fetch", Status: "fetched", TS: now.Add(-1 * time.Hour)},
		{URL: "http://x/cowrie-dl", SHA256: "c1", LocalPath: "/ev/c1", SizeBytes: 4096,
			Origin: "cowrie_download", Status: "fetched", TS: now.Add(-2 * time.Hour)},
		{URL: "http://x/cowrie-file", SHA256: "c2", LocalPath: "/ev/c2", SizeBytes: 4096,
			Origin: "cowrie_file_download", Status: "fetched", TS: now.Add(-3 * time.Hour)},
		// TTY transcript: an operator artifact, never a sample.
		{URL: "http://x/tty", SHA256: "t1", LocalPath: "/ev/t1", SizeBytes: 9999,
			Origin: "cowrie_tty", Status: "fetched", TS: now.Add(-4 * time.Hour)},
		// 217 B dropper script: below the old 1024 B pre-filter, above Vet's 64.
		{URL: "http://x/small-dropper", SHA256: "s1", LocalPath: "/ev/s1", SizeBytes: 217,
			Origin: "cowrie_download", Status: "fetched", TS: now.Add(-5 * time.Hour)},
		// Genuine junk: below the floor on either side of the argument.
		{URL: "http://x/sentinel", SHA256: "j1", LocalPath: "/ev/j1", SizeBytes: 1,
			Origin: "cowrie_download", Status: "fetched", TS: now.Add(-6 * time.Hour)},
		// Never fetched: we don't have the bytes.
		{URL: "http://x/failed", SHA256: "f1", LocalPath: "", SizeBytes: 0,
			Origin: "quarantine_fetch", Status: "failed", TS: now.Add(-7 * time.Hour)},
		// The mixed-origin payload. Same sha, two URLs, two origins — and the
		// quarantine_fetch row is the newer of the pair.
		{URL: "http://x/mixed-a", SHA256: "m1", LocalPath: "/ev/m1", SizeBytes: 8192,
			Origin: "cowrie_download", Status: "fetched", TS: now.Add(-9 * time.Hour)},
		{URL: "http://x/mixed-b", SHA256: "m1", LocalPath: "/ev/m1", SizeBytes: 8192,
			Origin: "quarantine_fetch", Status: "fetched", TS: now.Add(-8 * time.Hour)},
		// A payload we DO have, whose newest row is a re-fetch that failed. The
		// reference deployment has this shape (quarantine_fetch: 12 fetched, 1
		// failed) and it is what separates a group-level MAX from an all-rows
		// MIN: exactly one row here satisfies the policy, and one qualifying row
		// is enough, because the bytes are on disk.
		{URL: "http://x/refetch-ok", SHA256: "x1", LocalPath: "/ev/x1", SizeBytes: 5120,
			Origin: "cowrie_download", Status: "fetched", TS: now.Add(-11 * time.Hour)},
		{URL: "http://x/refetch-failed", SHA256: "x1", LocalPath: "", SizeBytes: 0,
			Origin: "quarantine_fetch", Status: "failed", TS: now.Add(-10 * time.Hour)},
	}
	for _, a := range rows {
		if err := st.RecordArtifact(a); err != nil {
			t.Fatalf("RecordArtifact(%s): %v", a.URL, err)
		}
	}
	return SharePolicy{
		MinBytes: 64,
		Origins:  []string{"cowrie_download", "cowrie_file_download", "quarantine_fetch"},
	}
}

func shasOf(arts []Artifact) []string {
	out := make([]string, 0, len(arts))
	for _, a := range arts {
		out = append(out, a.SHA256)
	}
	sort.Strings(out)
	return out
}

// TestArtifactsForShareHonoursPolicyOrigins pins that candidate selection asks
// the destination's gate what to narrow to, instead of restating a guess.
//
// The guess was `origin LIKE '%download%'` AND `size_bytes > 1024`, both
// stricter than bazaar.Vet — so 10 quarantine-fetched payloads and 13 sub-1KiB
// dropper scripts were rejected by a second policy that no comment described
// and no operator could see.
func TestArtifactsForShareHonoursPolicyOrigins(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "sharepol.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	pol := sharePolicyFixture(t, st, now)

	got, err := st.ArtifactsForShare(now.Add(-24*time.Hour), pol)
	if err != nil {
		t.Fatalf("ArtifactsForShare: %v", err)
	}
	// m1 and x1 appear once each: ArtifactsForShare dedups on sha itself.
	want := []string{"c1", "c2", "m1", "q1", "s1", "x1"}
	if diff := shasOf(got); !sameStrings(diff, want) {
		t.Fatalf("selected %v, want %v", diff, want)
	}

	for _, a := range got {
		switch a.SHA256 {
		case "q1":
			if a.Origin != "quarantine_fetch" {
				t.Fatalf("q1 origin = %q", a.Origin)
			}
		case "s1":
			if a.SizeBytes != 217 {
				t.Fatalf("s1 size = %d, want the 217 B dropper", a.SizeBytes)
			}
		}
	}
}

// TestArtifactsForShareMinBytesIsInclusive pins the boundary, because an
// exclusive comparison here would silently re-introduce a one-byte-wide gap
// between selection and the gate.
func TestArtifactsForShareMinBytesIsInclusive(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "sharemin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	for _, a := range []Artifact{
		{URL: "http://x/exact", SHA256: "exact", LocalPath: "/ev/e", SizeBytes: 64,
			Origin: "cowrie_download", Status: "fetched", TS: now},
		{URL: "http://x/under", SHA256: "under", LocalPath: "/ev/u", SizeBytes: 63,
			Origin: "cowrie_download", Status: "fetched", TS: now},
	} {
		if err := st.RecordArtifact(a); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.ArtifactsForShare(now.Add(-time.Hour),
		SharePolicy{MinBytes: 64, Origins: []string{"cowrie_download"}})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"exact"}; !sameStrings(shasOf(got), want) {
		t.Fatalf("selected %v, want %v — MinBytes must be inclusive so a sample of "+
			"exactly the gate's floor is selected", shasOf(got), want)
	}
}

// TestAggregateShareableIsGroupLevel is the dashboard half of the same bug.
//
// "Can this payload be shared" is a property of the whole sha group, not of the
// newest row. The aggregate reports the newest row's origin, and 67 hashes on
// the reference deployment mix origins — the same payload recorded once by the
// cowrie download hook and again by our quarantine fetch. The dashboard derived
// its share button from that field in JavaScript, so a payload won or lost the
// button on the coin-flip of which sighting landed last, and two
// family-identified droppers lost it while the CLI was selecting them.
func TestAggregateShareableIsGroupLevel(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "shareagg.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	pol := sharePolicyFixture(t, st, now)

	aggs, err := st.ListArtifactsAggregatedSince(now.Add(-24*time.Hour), 100, pol)
	if err != nil {
		t.Fatalf("ListArtifactsAggregatedSince: %v", err)
	}
	byShare := map[string]ArtifactAggregate{}
	for _, a := range aggs {
		byShare[a.SHA256] = a
	}

	// The exact set of payloads offered a share button must equal the exact set
	// the CLI would select. If these two ever disagree, one of them is lying to
	// the operator — that was the whole finding.
	cli, err := st.ArtifactsForShare(now.Add(-24*time.Hour), pol)
	if err != nil {
		t.Fatal(err)
	}
	var uiShareable []string
	for _, a := range aggs {
		if a.Shareable {
			uiShareable = append(uiShareable, a.SHA256)
		}
	}
	sort.Strings(uiShareable)
	if !sameStrings(uiShareable, shasOf(cli)) {
		t.Fatalf("dashboard shareable = %v, CLI selects %v — the two share paths must "+
			"agree on which payloads exist", uiShareable, shasOf(cli))
	}

	// And specifically the mixed-origin one, which is the shape that broke.
	m1, ok := byShare["m1"]
	if !ok {
		t.Fatal("m1 missing from aggregate")
	}
	if m1.Origin != "quarantine_fetch" {
		t.Fatalf("fixture no longer reproduces the bug: m1's newest origin = %q, "+
			"want quarantine_fetch (the origin the old LIKE filter missed)", m1.Origin)
	}
	if !m1.Shareable {
		t.Fatal("m1 is not shareable, but one of its rows is a cowrie_download and " +
			"another a quarantine_fetch — shareability must be evaluated over ALL " +
			"rows in the group, not the newest one")
	}
	// x1: one fetched row plus a newer FAILED re-fetch. One qualifying row is
	// enough — we have the bytes. This is what distinguishes a group-level MAX
	// from an all-rows MIN; without it, a passing test tolerates "every row must
	// qualify", which drops any payload whose latest sighting was a failed fetch.
	x1, ok := byShare["x1"]
	if !ok {
		t.Fatal("x1 missing from aggregate")
	}
	if x1.Status != "failed" {
		t.Fatalf("fixture broken: x1's newest status = %q, want failed", x1.Status)
	}
	if !x1.Shareable {
		t.Fatal("x1 is not shareable, but one of its rows is a fetched cowrie_download " +
			"with bytes on disk — shareability is satisfied by ANY qualifying row, not by " +
			"all of them, and the newest row here is a failed re-fetch")
	}
	if byShare["t1"].Shareable {
		t.Fatal("cowrie_tty transcript marked shareable")
	}
	if byShare["j1"].Shareable {
		t.Fatal("1-byte sentinel marked shareable")
	}
	if byShare["f1"].Shareable {
		t.Fatal("unfetched artifact marked shareable")
	}
}

// TestAggregateZeroPolicyMarksNothingShareable pins the fail-closed default: a
// caller that forgets to pass a policy must not get a share button on every row.
func TestAggregateZeroPolicyMarksNothingShareable(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "sharezero.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	sharePolicyFixture(t, st, now)

	aggs, err := st.ListArtifactsAggregatedSince(now.Add(-24*time.Hour), 100, SharePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if len(aggs) == 0 {
		t.Fatal("fixture produced no aggregates")
	}
	for _, a := range aggs {
		if a.Shareable {
			t.Fatalf("%s shareable under the zero policy — an unset policy must fail "+
				"closed, or a forgotten argument re-creates the share-on-everything anomaly",
				a.SHA256)
		}
	}
}

// TestPayloadShareableMatchesAggregate pins that the single-sha lookup the
// payload detail modal uses gives the same answer as the list. The modal
// resolves its row via GetArtifactBySHA — the newest row — so without this it
// would show "not a download" on exactly the payloads the list offers.
func TestPayloadShareableMatchesAggregate(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "sharesingle.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	pol := sharePolicyFixture(t, st, now)

	aggs, err := st.ListArtifactsAggregatedSince(now.Add(-24*time.Hour), 100, pol)
	if err != nil {
		t.Fatal(err)
	}
	if len(aggs) == 0 {
		t.Fatal("fixture produced no aggregates")
	}
	for _, a := range aggs {
		got, err := st.PayloadShareable(a.SHA256, pol)
		if err != nil {
			t.Fatalf("PayloadShareable(%s): %v", a.SHA256, err)
		}
		if got != a.Shareable {
			t.Errorf("%s: modal says shareable=%v, list says %v — the detail view and "+
				"the library must not disagree about the same payload", a.SHA256, got, a.Shareable)
		}
	}
	// Fail closed on an unset policy and on an unknown hash, same as the list.
	if ok, err := st.PayloadShareable("m1", SharePolicy{}); err != nil || ok {
		t.Errorf("zero policy: got (%v, %v), want (false, nil)", ok, err)
	}
	if ok, err := st.PayloadShareable("", pol); err != nil || ok {
		t.Errorf("empty sha: got (%v, %v), want (false, nil)", ok, err)
	}
	if ok, err := st.PayloadShareable("nosuchhash", pol); err != nil || ok {
		t.Errorf("unknown sha: got (%v, %v), want (false, nil)", ok, err)
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
