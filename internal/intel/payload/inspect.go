// Package payload inspects captured artifacts on disk: magic-byte
// sniffing, printable-string extraction and a small hex preview.
// Everything is bounded so this stays safe to call on adversary-
// controlled blobs without OOM'ing the process.
package payload

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Limits keep inspection of attacker-controlled files cheap and
// predictable. The strings extractor walks only the first
// MaxScanBytes from the file; that's enough to surface the
// interesting header content of any shell script and the IAT of a
// typical PE, while bounding work on multi-MB binaries.
const (
	MaxScanBytes    = 64 * 1024
	MaxStringsLines = 80
	MaxHexBytes     = 256
	MinASCIIRun     = 6
)

// Inspection is the structured result a single artifact yields.
type Inspection struct {
	Path        string   `json:"path,omitempty"`
	Magic       string   `json:"magic,omitempty"`       // e.g. "ELF64", "PE32+", "shebang:/bin/bash", "ASCII text"
	MimeHint    string   `json:"mimeHint,omitempty"`    // best-effort; uses file extension as fallback
	SizeBytes   int64    `json:"sizeBytes"`
	Truncated   bool     `json:"truncated,omitempty"`   // strings only walked first MaxScanBytes
	Strings     []string `json:"strings,omitempty"`     // up to MaxStringsLines printable runs
	HexPreview  string   `json:"hexPreview,omitempty"`  // canonical xxd-style first MaxHexBytes
	Error       string   `json:"error,omitempty"`
}

// File runs the full inspection pipeline on a path. A missing or
// unreadable file produces a populated Error rather than a Go error
// so callers can surface a row in the UI either way.
func File(path string) Inspection {
	insp := Inspection{Path: path}
	if path == "" {
		insp.Error = "no local_path recorded; payload was never persisted"
		return insp
	}
	st, err := os.Stat(path)
	if err != nil {
		insp.Error = err.Error()
		return insp
	}
	insp.SizeBytes = st.Size()
	if st.IsDir() {
		insp.Error = "path is a directory"
		return insp
	}

	f, err := os.Open(path)
	if err != nil {
		insp.Error = err.Error()
		return insp
	}
	defer f.Close()

	// Read up to MaxScanBytes into a buffer once and reuse it for
	// magic + strings + hex.
	buf := make([]byte, MaxScanBytes)
	n, err := io.ReadFull(f, buf)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		buf = buf[:n]
	} else if err != nil {
		insp.Error = err.Error()
		return insp
	}
	insp.Truncated = int64(n) < st.Size()

	insp.Magic, insp.MimeHint = sniffMagic(buf, path)
	insp.Strings = extractStrings(buf, MinASCIIRun, MaxStringsLines)

	hexN := len(buf)
	if hexN > MaxHexBytes {
		hexN = MaxHexBytes
	}
	insp.HexPreview = canonicalHex(buf[:hexN])
	return insp
}

// sniffMagic returns a short label and mime hint for the buffer.
// Heuristics only: we'd rather be useful for shell scripts and the
// common binary formats than perfectly correct for every blob.
func sniffMagic(buf []byte, path string) (string, string) {
	if len(buf) >= 4 && string(buf[:4]) == "\x7fELF" {
		bits := "32"
		if len(buf) >= 5 && buf[4] == 2 {
			bits = "64"
		}
		return "ELF" + bits, "application/x-elf"
	}
	if len(buf) >= 2 && buf[0] == 'M' && buf[1] == 'Z' {
		return "PE/DOS executable", "application/vnd.microsoft.portable-executable"
	}
	if len(buf) >= 4 && string(buf[:4]) == "PK\x03\x04" {
		return "ZIP archive", "application/zip"
	}
	if len(buf) >= 3 && buf[0] == 0x1f && buf[1] == 0x8b && buf[2] == 0x08 {
		return "gzip", "application/gzip"
	}
	if len(buf) >= 6 && string(buf[:6]) == "ustar\x00" {
		return "tar", "application/x-tar"
	}
	if len(buf) >= 2 && buf[0] == '#' && buf[1] == '!' {
		// shebang - grab the interpreter name
		end := 2
		for end < len(buf) && end < 128 && buf[end] != '\n' && buf[end] != '\r' {
			end++
		}
		line := strings.TrimSpace(string(buf[2:end]))
		return "shebang:" + line, "text/x-shellscript"
	}

	// Look at extension as a fallback signal.
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".sh", ".bash":
		return "shell script (no shebang)", "text/x-shellscript"
	case ".py":
		return "python source", "text/x-python"
	case ".pl":
		return "perl source", "text/x-perl"
	case ".js":
		return "javascript", "application/javascript"
	}

	if isMostlyPrintable(buf) {
		return "ASCII / printable text", "text/plain"
	}
	return "binary (unknown)", "application/octet-stream"
}

// isMostlyPrintable returns true if >= 90% of the first chunk is
// printable ASCII, ignoring whitespace.
func isMostlyPrintable(buf []byte) bool {
	if len(buf) == 0 {
		return false
	}
	scan := len(buf)
	if scan > 4096 {
		scan = 4096
	}
	printable := 0
	for _, b := range buf[:scan] {
		if (b >= 0x20 && b < 0x7f) || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	return printable*10 >= scan*9
}

// extractStrings walks the buffer and emits printable ASCII runs of
// at least minRun characters, deduped in order. Stops at maxLines.
//
// We bias to longer runs (16+) by sorting them up in the result so
// the UI surfaces the most-likely-meaningful content first.
func extractStrings(buf []byte, minRun, maxLines int) []string {
	if minRun <= 0 {
		minRun = MinASCIIRun
	}
	if maxLines <= 0 {
		maxLines = MaxStringsLines
	}
	var out []string
	seen := map[string]struct{}{}

	r := bufio.NewReader(strings.NewReader(string(buf)))
	var cur strings.Builder
	flush := func() {
		if cur.Len() >= minRun {
			s := cur.String()
			if _, ok := seen[s]; !ok {
				seen[s] = struct{}{}
				out = append(out, s)
			}
		}
		cur.Reset()
	}
	for {
		b, err := r.ReadByte()
		if err != nil {
			break
		}
		// Printable + non-whitespace control set we accept as part of
		// a string run. Excludes newlines + tabs so each line of a
		// shell script becomes its own string.
		if (b >= 0x20 && b < 0x7f) {
			cur.WriteByte(b)
			continue
		}
		flush()
		if len(out) >= maxLines {
			break
		}
	}
	flush()
	if len(out) > maxLines {
		out = out[:maxLines]
	}
	return out
}

// canonicalHex returns an xxd-style hex+ASCII dump of buf, e.g.
//   00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
func canonicalHex(buf []byte) string {
	var b strings.Builder
	for off := 0; off < len(buf); off += 16 {
		end := off + 16
		if end > len(buf) {
			end = len(buf)
		}
		chunk := buf[off:end]
		fmt.Fprintf(&b, "%08x  ", off)
		hex := hex.EncodeToString(chunk)
		// space every two hex chars and an extra space at the midpoint
		for i := 0; i < 32; i++ {
			if i < len(hex) {
				b.WriteByte(hex[i])
			} else {
				b.WriteByte(' ')
			}
			if i%2 == 1 {
				b.WriteByte(' ')
			}
			if i == 15 {
				b.WriteByte(' ')
			}
		}
		b.WriteByte('|')
		for _, c := range chunk {
			if c >= 0x20 && c < 0x7f {
				b.WriteByte(c)
			} else {
				b.WriteByte('.')
			}
		}
		// pad the ASCII column to a fixed width
		for i := len(chunk); i < 16; i++ {
			b.WriteByte(' ')
		}
		b.WriteString("|\n")
	}
	return b.String()
}
