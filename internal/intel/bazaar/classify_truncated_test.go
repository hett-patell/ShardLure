package bazaar

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// A malformed or truncated ELF still gets its family from the 256 KiB head
// scan (campaign final audit M-1). classifyELF returned as soon as
// elf.NewFile failed, before matchELFFamily ran, so a partial download of a
// generic build (Cowrie does capture them) carried no family; the campaign
// worker's generic-build exclusion depends on that family, and the payload
// linked. Only the ef-dependent tags (arch, static, structural packing) are
// gated on a parsable header.
func TestClassifyTruncatedELFStillNamesFamily(t *testing.T) {
	raw := minimalELF64(elf.EM_X86_64)
	raw = append(raw, []byte("...donate.v2.xmrig.com\x00...")...)
	whole := append([]byte(nil), raw...)
	// Point the section header table past the end of the file: NewFile
	// reads it eagerly and fails, the shape of a download cut short.
	binary.LittleEndian.PutUint64(raw[40:], 1<<20) // e_shoff
	binary.LittleEndian.PutUint16(raw[60:], 1)     // e_shnum
	if _, err := elf.NewFile(bytes.NewReader(raw)); err == nil {
		t.Fatal("precondition: the truncated ELF must not parse")
	}
	if _, err := elf.NewFile(bytes.NewReader(whole)); err != nil {
		t.Fatalf("precondition: the whole ELF must parse: %v", err)
	}
	dir := t.TempDir()
	classify := func(name string, b []byte) Classification {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := Classify(p)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if c := classify("whole", whole); c.Family != "XMRig" || !containsTag(c.Tags, "x86-64") {
		t.Fatalf("whole ELF: family %q tags %v", c.Family, c.Tags)
	}
	c := classify("truncated", raw)
	if c.Family != "XMRig" {
		t.Fatalf("truncated ELF: family %q (want XMRig from the head scan), tags %v", c.Family, c.Tags)
	}
	if !containsTag(c.Tags, "elf") || containsTag(c.Tags, "x86-64") || containsTag(c.Tags, "static") {
		t.Fatalf("truncated ELF: structural tags need a parsable header: %v", c.Tags)
	}
}
