package wordlist

import (
	"strings"
	"testing"
)

func TestWriteLines(t *testing.T) {
	var b strings.Builder
	WriteLines(&b, []Entry{
		{Username: "root", Count: 5},
		{Username: "", Count: 2}, // empty value is skipped
		{Username: "admin", Count: 3},
	}, func(e Entry) string { return e.Username })
	want := "root\nadmin\n"
	if b.String() != want {
		t.Errorf("WriteLines = %q\nwant %q", b.String(), want)
	}
}

func TestWriteCombos(t *testing.T) {
	var b strings.Builder
	WriteCombos(&b, []Entry{
		{Username: "root", Password: "toor", Count: 5},
		{Username: "admin", Password: "admin", Count: 3},
	})
	want := "root:toor\nadmin:admin\n"
	if b.String() != want {
		t.Errorf("WriteCombos = %q\nwant %q", b.String(), want)
	}
}
