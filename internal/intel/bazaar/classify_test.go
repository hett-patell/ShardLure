package bazaar

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestClassifyShellScript covers the shebang path, including family
// fingerprinting via embedded substrings. The RedTail "redtail"
// sentinel is the same one used in the real corpus we captured, so
// this test directly exercises the production code path.
func TestClassifyShellScript(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "redtail.sh")
	body := `#!/bin/bash
# stage1 dropper
ARCH=$(uname -m)
URL=http://example.com/redtail-binary
echo redtail >/tmp/.x
exit
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Classify(p)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if c.Family != "RedTail" {
		t.Errorf("family: want RedTail, got %q", c.Family)
	}
	wantTags := []string{"bash", "script", "linux", "miner", "redtail", "dropper"}
	for _, want := range wantTags {
		if !containsTag(c.Tags, want) {
			t.Errorf("missing tag %q in %v", want, c.Tags)
		}
	}
}

// TestClassifyPython hits the Python shebang + paramiko fingerprint
// path. We saw exactly this signature in three of the cowrie captures
// (SSH scanner toolkit using paramiko + tqdm).
func TestClassifyPython(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "scan.py")
	body := `#!/usr/bin/env python3
import os
import paramiko
def scan(): pass
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Classify(p)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if c.Family != "SSHScanner" {
		t.Errorf("family: want SSHScanner, got %q", c.Family)
	}
	if !containsTag(c.Tags, "python") || !containsTag(c.Tags, "script") {
		t.Errorf("python/script tags missing: %v", c.Tags)
	}
}

// TestClassifyELFx86 builds a minimal valid ELF header on disk and
// verifies that the classifier reads the e_machine field correctly.
// Going via a real binary would be more thorough but is overkill —
// debug/elf only needs the header bytes to identify the arch.
func TestClassifyELFx86(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sample")
	if err := os.WriteFile(p, minimalELF64(elf.EM_X86_64), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Classify(p)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if !containsTag(c.Tags, "elf") {
		t.Errorf("missing elf tag: %v", c.Tags)
	}
	if !containsTag(c.Tags, "x86-64") {
		t.Errorf("missing x86-64 tag: %v", c.Tags)
	}
	if !containsTag(c.Tags, "static") {
		// minimalELF64 builds a static binary (no PT_INTERP).
		t.Errorf("expected static tag, got %v", c.Tags)
	}
}

// TestClassifyELFarm verifies arch detection across machine types so
// a future EM_* added to the switch can't silently drop. Mirrors the
// multi-arch payload spread we saw in the cowrie capture (x86_64,
// i386, ARM, ARM64).
func TestClassifyELFarm(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		machine elf.Machine
		tag     string
	}{
		{elf.EM_AARCH64, "aarch64"},
		{elf.EM_ARM, "arm"},
		{elf.EM_386, "i386"},
		{elf.EM_MIPS, "mips"},
	}
	for _, tc := range cases {
		p := filepath.Join(dir, "sample-"+tc.tag)
		if err := os.WriteFile(p, minimalELF64(tc.machine), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := Classify(p)
		if err != nil {
			t.Fatalf("classify %s: %v", tc.tag, err)
		}
		if !containsTag(c.Tags, tc.tag) {
			t.Errorf("arch %s: missing %q tag, got %v", tc.tag, tc.tag, c.Tags)
		}
	}
}

// TestClassifyHeaderlessPython covers the real-world case where
// cowrie captured a Python script via `cat >file` (no shebang).
// Three of our actual cowrie samples fall in this category — without
// the fallback they all classified as "unknown" and shipped without
// the python tag, which would have been a noisy MalwareBazaar entry.
func TestClassifyHeaderlessPython(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "scan_noshebang")
	body := `import os
import paramiko
from concurrent.futures import ThreadPoolExecutor

def scan(target):
    pass

if __name__ == "__main__":
    scan("1.2.3.4")
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Classify(p)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if !containsTag(c.Tags, "python") || !containsTag(c.Tags, "script") {
		t.Errorf("missing python/script tag in %v", c.Tags)
	}
	if c.Family != "SSHScanner" {
		t.Errorf("family: want SSHScanner, got %q", c.Family)
	}
}

// TestClassifyPythonWithUTF8Comments mirrors the real-world cowrie
// capture where a Chinese-attacker's Python script had multi-byte
// UTF-8 comments that earlier pushed the printable-ratio just below
// the threshold. Regression guard so we don't tighten that ratio
// without thinking about non-ASCII source files again.
func TestClassifyPythonWithUTF8Comments(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "scan_utf8.py")
	body := `import os
import paramiko
# 中文注释 attacker comment with multi-byte UTF-8
# еще немного для разнообразия
def scan(target):
    pass

if __name__ == "__main__":
    scan("1.2.3.4")
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Classify(p)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if !containsTag(c.Tags, "python") {
		t.Errorf("UTF-8 python script mis-tagged: %v", c.Tags)
	}
}

// TestLooksLikePythonRejectsBinary asserts we don't mis-tag binary
// blobs that happen to contain ASCII like "import" inside a packed
// payload.
func TestLooksLikePythonRejectsBinary(t *testing.T) {
	junk := []byte{0xff, 0x00, 0xde, 0xad, 0xbe, 0xef}
	if looksLikePython(junk) {
		t.Errorf("binary blob mis-tagged as python")
	}
	// Even printable text without Python structure should fail.
	if looksLikePython([]byte("hello world this is just a sentence")) {
		t.Errorf("plain text mis-tagged as python")
	}
}

// TestClassifyUnknownFallsBack ensures we never panic on a file that
// is neither ELF nor PE nor a shebang script. The dashboard does not
// pre-filter; whatever cowrie captured is what we get.
func TestClassifyUnknownFallsBack(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "weird.bin")
	if err := os.WriteFile(p, []byte("just a blob of bytes, not a known format"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Classify(p)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if !containsTag(c.Tags, "unknown") {
		t.Errorf("expected unknown tag: %v", c.Tags)
	}
	if !containsTag(c.Tags, "linux") {
		t.Errorf("expected linux cross-cut tag: %v", c.Tags)
	}
}

// minimalELF64 builds the smallest ELF64 image that debug/elf.Open
// will parse successfully. Used in tests so we don't have to ship
// real malware fixtures in the repo. The header lays out a valid
// e_ident, the machine type the caller asked for, and zero program
// + section headers (which is enough for header inspection).
func minimalELF64(machine elf.Machine) []byte {
	var b bytes.Buffer
	// e_ident
	b.Write([]byte{0x7f, 'E', 'L', 'F'})
	b.WriteByte(2) // EI_CLASS = ELFCLASS64
	b.WriteByte(1) // EI_DATA = ELFDATA2LSB
	b.WriteByte(1) // EI_VERSION
	b.WriteByte(0) // EI_OSABI
	b.WriteByte(0) // EI_ABIVERSION
	b.Write(make([]byte, 7)) // padding to 16 bytes
	// e_type (2 = EXEC)
	_ = binary.Write(&b, binary.LittleEndian, uint16(2))
	// e_machine
	_ = binary.Write(&b, binary.LittleEndian, uint16(machine))
	// e_version
	_ = binary.Write(&b, binary.LittleEndian, uint32(1))
	// e_entry, e_phoff, e_shoff
	_ = binary.Write(&b, binary.LittleEndian, uint64(0))
	_ = binary.Write(&b, binary.LittleEndian, uint64(0))
	_ = binary.Write(&b, binary.LittleEndian, uint64(0))
	// e_flags
	_ = binary.Write(&b, binary.LittleEndian, uint32(0))
	// e_ehsize
	_ = binary.Write(&b, binary.LittleEndian, uint16(64))
	// e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
	_ = binary.Write(&b, binary.LittleEndian, uint16(56))
	_ = binary.Write(&b, binary.LittleEndian, uint16(0))
	_ = binary.Write(&b, binary.LittleEndian, uint16(64))
	_ = binary.Write(&b, binary.LittleEndian, uint16(0))
	_ = binary.Write(&b, binary.LittleEndian, uint16(0))
	return b.Bytes()
}

// TestFirstLineHandlesEmpty makes sure firstLine() doesn't panic on
// odd inputs (the classifier shells out to it on every script).
func TestFirstLineHandlesEmpty(t *testing.T) {
	cases := []string{"", "\n", "#!/bin/bash\n", "no newline at all"}
	for _, c := range cases {
		got := firstLine([]byte(c))
		if got == "" && strings.Contains(c, "/bash") {
			t.Errorf("firstLine dropped shebang for %q", c)
		}
	}
}
