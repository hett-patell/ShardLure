package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/intel/threatfox"
	"github.com/networkshard/shardlure/internal/store"
)

// staticELFWithXMRig is a statically linked x86-64 ELF whose single program
// header sits at 300 KiB, with an XMRig anchor near the top: the shape of a
// real 1-2 MB static miner. Cut before the program header table it is a
// partial download that debug/elf refuses to parse.
func staticELFWithXMRig() []byte {
	const phoff = 300 * 1024
	b := make([]byte, phoff+56)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	le := binary.LittleEndian
	le.PutUint16(b[16:], 2)                     // e_type EXEC
	le.PutUint16(b[18:], uint16(elf.EM_X86_64)) // e_machine
	le.PutUint32(b[20:], 1)                     // e_version
	le.PutUint64(b[32:], phoff)                 // e_phoff
	le.PutUint16(b[52:], 64)                    // e_ehsize
	le.PutUint16(b[54:], 56)                    // e_phentsize
	le.PutUint16(b[56:], 1)                     // e_phnum
	le.PutUint16(b[58:], 64)                    // e_shentsize
	copy(b[4096:], "...donate.v2.xmrig.com\x00...")
	le.PutUint32(b[phoff:], uint32(elf.PT_LOAD))
	return b
}

// The ThreatFox Malpedia gate must never pass on a head-scan family of an ELF
// that does not parse (premerge audit campaign M8): outbound labelling is
// main's, where a malformed header carried no family. The complete file of the
// same sample resolves to elf.xmrig and passes (control), so the refusal is
// down to the truncation alone.
func TestThreatFoxCandidateOfTruncatedELFHasNoFamily(t *testing.T) {
	whole := staticELFWithXMRig()
	cut := whole[:280*1024]
	if _, err := elf.NewFile(bytes.NewReader(cut)); err == nil {
		t.Fatal("precondition: the truncated ELF must not parse")
	}
	if _, err := elf.NewFile(bytes.NewReader(whole)); err != nil {
		t.Fatalf("precondition: the whole ELF must parse: %v", err)
	}
	dir := t.TempDir()
	now := time.Now()
	row := func(name string, b []byte) store.ThreatFoxCandidateRow {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return store.ThreatFoxCandidateRow{
			URL:       "http://93.184.216.34/" + name,
			SHA256:    strings.Repeat("ab", 32),
			SizeBytes: int64(len(b)),
			Origin:    "quarantine_fetch",
			Status:    "fetched",
			FetchedAt: now.Add(-time.Hour),
			LocalPath: p,
		}
	}

	c := threatfoxCandidateFromRow(row("whole", whole))
	if ok, malware, _, reason := threatfox.Vet(c, now); !ok || malware != "elf.xmrig" {
		t.Fatalf("control: the complete ELF should pass as elf.xmrig: ok=%v malware=%q reason=%q", ok, malware, reason)
	}

	c = threatfoxCandidateFromRow(row("truncated", cut))
	if c.Family != "" || c.FileKind != "ELF" {
		t.Fatalf("truncated ELF candidate: family %q kind %q, want no family", c.Family, c.FileKind)
	}
	if ok, _, _, reason := threatfox.Vet(c, now); ok || !strings.Contains(reason, "no confident Malpedia label") {
		t.Fatalf("truncated ELF passed or was refused for the wrong reason: ok=%v reason=%q", ok, reason)
	}
}
