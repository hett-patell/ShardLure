package bazaar

import (
	"bufio"
	"bytes"
	"debug/elf"
	"io"
	"os"
	"strings"
)

// Classification is the tag set we attach to one sample. Family is a
// best-guess malware family used for the upstream "signature" field
// when we have high confidence; left empty for generic captures.
type Classification struct {
	Tags     []string
	Family   string
	FileKind string // human-readable label for CLI output
}

// Classify inspects a file on disk and returns format/arch/family
// tags suitable for direct inclusion in a MalwareBazaar submission.
// All recognition is heuristic: ELF arch comes from the binary header,
// scripts are matched on shebang plus substring signatures, families
// are matched on string indicators commonly seen in our cowrie
// captures (RedTail, Mirai, c3pool, traffmonetizer, komari).
//
// Heuristics are deliberately conservative — false-positive family
// tags poison MalwareBazaar's signature index and embarrass the
// uploader. When in doubt, omit the family tag and let the abuse.ch
// pipeline (YARA, ClamAV, telfhash lookup) classify it server side.
func Classify(path string) (Classification, error) {
	f, err := os.Open(path)
	if err != nil {
		return Classification{}, err
	}
	defer f.Close()

	// 4 KiB is enough for ELF EI_NIDENT + arch fields, every shebang
	// we care about, and the early-script signature strings we look
	// for (RedTail's "redtail" sentinel sits on line ~30, etc.). For
	// longer evidence we read further below.
	head := make([]byte, 4096)
	n, _ := io.ReadFull(f, head)
	head = head[:n]

	c := Classification{}

	switch {
	case bytes.HasPrefix(head, []byte{0x7f, 'E', 'L', 'F'}):
		classifyELF(path, &c)
	case bytes.HasPrefix(head, []byte("MZ")):
		c.FileKind = "PE executable"
		c.Tags = append(c.Tags, "exe")
	case bytes.HasPrefix(head, []byte("#!")):
		classifyScript(path, head, &c)
	default:
		// No shebang and no ELF/PE magic — but cowrie often captures
		// Python tooling that's just been `cat >` into a file without
		// the shebang line. Sniff for Python-shaped content before
		// giving up and tagging "unknown".
		switch {
		case looksLikePython(head):
			c.FileKind = "Python (no shebang)"
			c.Tags = append(c.Tags, "python", "script")
			classifyScriptFamily(path, head, &c)
		case looksLikeShellWithSCPHeader(head):
			// Cowrie captured an scp transfer; the upstream "C0755
			// 4745 ..." line is scp wire framing prepended to the
			// real payload. Treat the file as the shell script it
			// almost is.
			c.FileKind = "Shell script (scp-framed)"
			c.Tags = append(c.Tags, "bash", "script")
			classifyScriptFamily(path, head, &c)
		default:
			c.FileKind = "unknown"
			c.Tags = append(c.Tags, "unknown")
		}
	}

	// Cross-cutting: every sample we ship is from a Linux SSH/SFTP
	// honeypot, so "linux" is correct whether it's ELF or script.
	if !containsTag(c.Tags, "linux") {
		c.Tags = append(c.Tags, "linux")
	}
	return c, nil
}

// classifyELF reads the ELF header to attach format and arch tags.
// We open with debug/elf rather than parsing by hand because the
// e_machine field encoding is annoyingly broad (EM_ARM, EM_AARCH64,
// EM_X86_64, EM_386, EM_MIPS, EM_MIPSEL, EM_PPC, EM_PPC64, ...).
func classifyELF(path string, c *Classification) {
	c.FileKind = "ELF"
	c.Tags = append(c.Tags, "elf")
	ef, err := elf.Open(path)
	if err != nil {
		return
	}
	defer ef.Close()
	switch ef.Machine {
	case elf.EM_X86_64:
		c.Tags = append(c.Tags, "x86-64")
	case elf.EM_386:
		c.Tags = append(c.Tags, "i386")
	case elf.EM_AARCH64:
		c.Tags = append(c.Tags, "aarch64")
	case elf.EM_ARM:
		c.Tags = append(c.Tags, "arm")
	case elf.EM_MIPS:
		c.Tags = append(c.Tags, "mips")
	case elf.EM_PPC:
		c.Tags = append(c.Tags, "ppc")
	case elf.EM_PPC64:
		c.Tags = append(c.Tags, "ppc64")
	}
	// Statically linked ELFs are the Mirai-family fingerprint —
	// they bundle libc to avoid the target's missing dynamic loader.
	if isStaticELF(ef) {
		c.Tags = append(c.Tags, "static")
	}
	// String-scan for family. We deliberately limit to a 256 KiB
	// head sweep: bigger scans cost real wall-clock time and the
	// distinctive strings live in the data section near the top of
	// the binary in practice.
	if fam, famTags := matchELFFamily(path); fam != "" {
		c.Family = fam
		c.Tags = append(c.Tags, famTags...)
	}
}

func isStaticELF(ef *elf.File) bool {
	for _, p := range ef.Progs {
		if p.Type == elf.PT_INTERP {
			return false
		}
	}
	return true
}

// matchELFFamily scans the first 256 KiB of an ELF for known family
// indicators. Returns (signature, extra-tags). The signature is the
// abuse.ch family slug; the tags are descriptive ones we want on the
// upload even if the family guess is wrong.
func matchELFFamily(path string) (string, []string) {
	f, err := os.Open(path)
	if err != nil {
		return "", nil
	}
	defer f.Close()
	buf := make([]byte, 256*1024)
	n, _ := io.ReadFull(f, buf)
	buf = buf[:n]
	low := bytes.ToLower(buf)
	switch {
	case bytes.Contains(low, []byte("redtail")):
		return "RedTail", []string{"miner", "redtail"}
	case bytes.Contains(low, []byte("xmrig")):
		return "XMRig", []string{"miner", "xmrig"}
	case bytes.Contains(low, []byte("c3pool")), bytes.Contains(low, []byte("c3pool_miner")):
		return "Coinminer", []string{"miner", "c3pool"}
	case bytes.Contains(low, []byte("traffmonetizer")):
		return "Traffmonetizer", []string{"proxyware", "traffmonetizer"}
	case bytes.Contains(low, []byte("komari")):
		return "Komari", []string{"botnet", "komari"}
	case bytes.Contains(low, []byte("mirai")):
		return "Mirai", []string{"botnet", "mirai"}
	case bytes.Contains(low, []byte("gafgyt")), bytes.Contains(low, []byte("tsunami")):
		return "Gafgyt", []string{"botnet", "gafgyt"}
	}
	// The trademark Mirai busybox-killer string (very specific —
	// the family probes for and kills /bin/busybox before infecting).
	if bytes.Contains(low, []byte("/bin/busybox")) && bytes.Contains(low, []byte("kill_proc")) {
		return "Mirai", []string{"botnet", "mirai"}
	}
	return "", nil
}

// classifyScript handles shebang-led text files: bash, sh, python,
// perl, ruby. Falls through to a substring family match because
// honeypot droppers identify themselves loudly in their first few
// hundred bytes ("# RedTail loader", URLs containing "/c3pool/", the
// telltale traffmonetizer Docker pull, ...).
func classifyScript(path string, head []byte, c *Classification) {
	shebang := firstLine(head)
	low := strings.ToLower(shebang)
	switch {
	case strings.Contains(low, "python"):
		c.FileKind = "Python script"
		c.Tags = append(c.Tags, "python", "script")
	case strings.Contains(low, "perl"):
		c.FileKind = "Perl script"
		c.Tags = append(c.Tags, "perl", "script")
	case strings.Contains(low, "ruby"):
		c.FileKind = "Ruby script"
		c.Tags = append(c.Tags, "ruby", "script")
	case strings.Contains(low, "bash"), strings.Contains(low, "/sh"):
		c.FileKind = "Shell script"
		c.Tags = append(c.Tags, "bash", "script")
	default:
		c.FileKind = "Script"
		c.Tags = append(c.Tags, "script")
	}
	classifyScriptFamily(path, head, c)
}

// classifyScriptFamily inspects the body of a script for known
// family fingerprints. Split out so both the shebang path and the
// "headerless Python" path can use it without duplication.
func classifyScriptFamily(path string, head []byte, c *Classification) {
	// Read up to 32 KiB to scan for family fingerprints — script
	// droppers vary in size but the fingerprint sits near the top
	// (config block, URLs, comments).
	if extra := readMore(path, head, 32*1024); extra != nil {
		head = extra
	}
	low2 := strings.ToLower(string(head))
	switch {
	case strings.Contains(low2, "redtail"):
		c.Family = "RedTail"
		c.Tags = append(c.Tags, "miner", "redtail", "dropper")
	case strings.Contains(low2, "xmrig"):
		c.Family = "XMRig"
		c.Tags = append(c.Tags, "miner", "xmrig", "dropper")
	case strings.Contains(low2, "c3pool"):
		c.Family = "Coinminer"
		c.Tags = append(c.Tags, "miner", "c3pool", "dropper")
	case strings.Contains(low2, "traffmonetizer"):
		c.Family = "Traffmonetizer"
		c.Tags = append(c.Tags, "proxyware", "traffmonetizer", "dropper")
	case strings.Contains(low2, "komari"):
		c.Family = "Komari"
		c.Tags = append(c.Tags, "botnet", "komari", "dropper")
	case strings.Contains(low2, "import paramiko"):
		c.Family = "SSHScanner"
		c.Tags = append(c.Tags, "scanner", "ssh-bruteforce")
	}
}

// looksLikePython reports whether the head bytes have the texture of
// a Python source file. We look for the conjunction of a few cheap
// signals — printable-ASCII dominance plus distinctive keywords —
// rather than a single substring, because attackers sometimes embed
// Python source inside other formats (heredocs, base64-decoded
// strings) and we don't want false positives on those.
func looksLikePython(head []byte) bool {
	if !mostlyPrintable(head) {
		return false
	}
	s := string(head)
	// Need at least one strong Python signal AND one supporting one.
	strong := strings.Contains(s, "\nimport ") || strings.HasPrefix(s, "import ") ||
		strings.Contains(s, "\nfrom ") || strings.HasPrefix(s, "from ") ||
		strings.Contains(s, "\ndef ") || strings.HasPrefix(s, "def ")
	weak := strings.Contains(s, ":\n") && // suite colon + newline
		(strings.Contains(s, "    ") || strings.Contains(s, "\t")) // indentation
	return strong && weak
}

// looksLikeShellWithSCPHeader detects the cowrie-captured scp wire
// framing pattern: a single line "Cnnnn nnnn name\n" followed by a
// real shebang line. The C-mode line is scp's "begin file" message
// with octal mode + size + basename, which cowrie's SFTP subsystem
// captures verbatim. Skipping the first line gives us the actual
// payload, but for tagging purposes we just need to know it IS a
// shell script underneath.
func looksLikeShellWithSCPHeader(head []byte) bool {
	if !mostlyPrintable(head) {
		return false
	}
	s := string(head)
	// First line looks like "C0644 1234 filename"?
	nl := strings.IndexByte(s, '\n')
	if nl <= 0 || nl > 100 {
		return false
	}
	first := s[:nl]
	if !strings.HasPrefix(first, "C0") {
		return false
	}
	// Second non-empty line is a shebang?
	rest := strings.TrimLeft(s[nl+1:], "\r\n")
	return strings.HasPrefix(rest, "#!")
}

// mostlyPrintable rejects binary blobs masquerading as scripts.
// 75 % printable-or-whitespace catches Python sources that contain
// UTF-8 comments (Chinese / Cyrillic / emoji — yes, attackers use
// emoji in comments) while still rejecting ELFs. Empirically the
// honeypot's Python captures sit at 85-88 %, and pure binaries
// (ELF, PE, gzip) sit at 25-40 %.
func mostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, x := range b {
		// Treat the entire upper-128 range as "probably text byte"
		// to give UTF-8 multibyte sequences a free pass.
		if (x >= 0x20 && x < 0x7f) || x >= 0x80 || x == '\n' || x == '\r' || x == '\t' {
			printable++
		}
	}
	return printable*4 >= len(b)*3
}

// firstLine returns the first \n-terminated line of b (no trailing
// newline). Used to read the shebang without parsing the whole file.
func firstLine(b []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 256), 4096)
	if sc.Scan() {
		return sc.Text()
	}
	return ""
}

// readMore returns up to max bytes of path. Falls back to head if the
// file can't be re-opened (caller already has at least head bytes).
func readMore(path string, head []byte, max int) []byte {
	f, err := os.Open(path)
	if err != nil {
		return head
	}
	defer f.Close()
	buf := make([]byte, max)
	n, _ := io.ReadFull(f, buf)
	return buf[:n]
}

func containsTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}
