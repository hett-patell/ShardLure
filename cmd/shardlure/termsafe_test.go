package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/networkshard/shardlure/pkg/models"
)

func TestTermSafe(t *testing.T) {
	for in, want := range map[string]string{
		"plain ascii":      "plain ascii",
		"tab\there":        `tab\x09here`,
		"del\x7f":          `del\x7f`,
		"c1\u009b31m":      `c1\u009b31m`,
		"raw c1 \x9b31m":   `raw c1 \x9b31m`, // invalid UTF-8 byte: escaped, never passed through
		"line\nbreak":      `line\x0abreak`,
		"bidi\u202eevil":   `bidi\u202eevil`,
		"unicode ok: café": "unicode ok: café",
		// A literal attacker "\x1b" must not look like a sanitised ESC.
		`lit \x1b`:      `lit \\x1b`,
		"zw\u200bsp":    `zw\u200bsp`,
		"bom\ufeff":     `bom\ufeff`,
		"shy\u00ad":     `shy\u00ad`,
		"tag\U000e0041": `tag\U000e0041`,
		"ls\u2028":      `ls\u2028`,
	} {
		if got := termSafe(in); got != want {
			t.Errorf("termSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

// actor show printed attacker usernames raw, and its JSON passed C1
// controls (U+009B is an 8-bit CSI) through as runes.
func TestWriteActorEscapesTerminalControls(t *testing.T) {
	const osc = "\x1b]0;pwned\x07"
	const csi = "\u009b31m"
	a := &models.Actor{ID: "cowrie:" + osc, PrimaryIP: "203.0.113.9" + csi, Playbook: "p" + osc,
		SSHClient: "SSH-2.0-" + csi, Notes: "run " + osc + csi, GeneratedNotes: "cmd " + osc}
	users := []models.ActorUser{{Username: "root" + osc, Count: 3}, {Username: "adm" + csi, Count: 1}}
	var b bytes.Buffer
	if err := writeActor(&b, a, users); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, r := range out {
		if r < 0x20 && r != '\n' || r == 0x7f || r >= 0x80 && r <= 0x9f {
			t.Fatalf("raw control %U reached the terminal:\n%q", r, out)
		}
	}
	if !strings.Contains(out, `root\x1b]0;pwned\x07`) || !strings.Contains(out, `adm\u009b31m`) {
		t.Errorf("usernames not escaped visibly:\n%s", out)
	}
	// The JSON half must stay valid and lossless for machine consumers.
	js, _, ok := strings.Cut(out, "\nTop usernames:")
	if !ok {
		t.Fatalf("no username section:\n%s", out)
	}
	var back models.Actor
	if err := json.Unmarshal([]byte(js), &back); err != nil {
		t.Fatalf("JSON no longer parses: %v\n%s", err, js)
	}
	if back.SSHClient != a.SSHClient || back.Notes != a.Notes || back.ID != a.ID {
		t.Errorf("JSON not lossless: %+v", back)
	}
}

func TestJSONTermSafe(t *testing.T) {
	in := "{\"a\":\"x\u009by\u007fz\u200b\U000e0041\"}"
	got := jsonTermSafe(in)
	want := `{"a":"x\u009by\u007fz\u200b\udb40\udc41"}`
	if got != want {
		t.Errorf("jsonTermSafe = %q, want %q", got, want)
	}
	var v map[string]string
	if err := json.Unmarshal([]byte(got), &v); err != nil || v["a"] != "x\u009by\u007fz\u200b\U000e0041" {
		t.Errorf("round trip: %q %v", v["a"], err)
	}
}
