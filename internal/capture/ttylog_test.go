package capture

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// writeTTYFrame appends one ttylog frame to buf using the same on-disk format
// Cowrie produces. Returns the bytes written so tests can inspect the buffer.
func writeTTYFrame(buf *bytes.Buffer, op, dir int32, ts time.Time, payload []byte) {
	hdr := make([]byte, ttyHeaderSize)
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(op))
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(payload)))
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(dir))
	binary.LittleEndian.PutUint32(hdr[16:20], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(ts.Nanosecond()/1000))
	buf.Write(hdr)
	buf.Write(payload)
}

func TestDecodeTTYLog_RoundTrip(t *testing.T) {
	t.Parallel()
	var raw bytes.Buffer
	ts := time.Unix(1716383691, 514482000).UTC()

	writeTTYFrame(&raw, ttyOpOpen, 0, ts, nil)
	writeTTYFrame(&raw, ttyOpWrite, ttyDirInput, ts.Add(time.Second), []byte("uname -a\n"))
	writeTTYFrame(&raw, ttyOpWrite, ttyDirOutput, ts.Add(2*time.Second), []byte("Linux honey 5.15\n"))
	writeTTYFrame(&raw, ttyOpClose, 0, ts.Add(3*time.Second), nil)

	dir := t.TempDir()
	path := filepath.Join(dir, "session.log")
	if err := os.WriteFile(path, raw.Bytes(), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	frames, err := DecodeTTYLog(path)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got, want := len(frames), 4; got != want {
		t.Fatalf("frame count: got %d want %d", got, want)
	}
	if !frames[1].IsInput() {
		t.Fatalf("frame[1] should be INPUT")
	}
	if string(frames[1].Data) != "uname -a\n" {
		t.Fatalf("frame[1] data: %q", string(frames[1].Data))
	}
	if !frames[2].IsOutput() {
		t.Fatalf("frame[2] should be OUTPUT")
	}
}

func TestDecodeTTYLog_TruncatedTail(t *testing.T) {
	t.Parallel()
	var raw bytes.Buffer
	ts := time.Unix(1716383691, 0).UTC()
	writeTTYFrame(&raw, ttyOpWrite, ttyDirInput, ts, []byte("complete\n"))
	// Now append a header that claims 32 bytes but only deliver 4.
	hdr := make([]byte, ttyHeaderSize)
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(ttyOpWrite))
	binary.LittleEndian.PutUint32(hdr[8:12], 32)
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(ttyDirInput))
	binary.LittleEndian.PutUint32(hdr[16:20], uint32(ts.Add(time.Second).Unix()))
	raw.Write(hdr)
	raw.Write([]byte("frag"))

	dir := t.TempDir()
	path := filepath.Join(dir, "torn.log")
	_ = os.WriteFile(path, raw.Bytes(), 0o600)

	frames, err := DecodeTTYLog(path)
	if err != nil {
		t.Fatalf("decode should tolerate truncated tail: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames (1 full + 1 partial), got %d", len(frames))
	}
	if string(frames[1].Data) != "frag" {
		t.Fatalf("partial frame data: %q", string(frames[1].Data))
	}
}

func TestDecodeTTYLog_RejectsHugeFrame(t *testing.T) {
	t.Parallel()
	var raw bytes.Buffer
	hdr := make([]byte, ttyHeaderSize)
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(ttyOpWrite))
	binary.LittleEndian.PutUint32(hdr[8:12], 32*1024*1024) // 32 MiB
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(ttyDirInput))
	raw.Write(hdr)
	raw.Write([]byte("x"))

	dir := t.TempDir()
	path := filepath.Join(dir, "huge.log")
	_ = os.WriteFile(path, raw.Bytes(), 0o600)

	if _, err := DecodeTTYLog(path); err == nil {
		t.Fatalf("expected DecodeTTYLog to reject 32MiB frame")
	}
}

func TestRenderTranscript_StripsANSI(t *testing.T) {
	t.Parallel()
	frames := []TTYFrame{
		{TS: time.Unix(1, 0), Op: ttyOpWrite, Direction: ttyDirInput, Data: []byte("ls\n")},
		// CSI sequence "\x1b[31mred\x1b[0m" + plain "ok"
		{TS: time.Unix(2, 0), Op: ttyOpWrite, Direction: ttyDirOutput, Data: []byte("\x1b[31mred\x1b[0mok\n")},
	}
	got := RenderTranscript(frames, DefaultTranscriptOptions())
	if !strings.Contains(got, "ls\n") {
		t.Fatalf("transcript missing input: %q", got)
	}
	if strings.Contains(got, "\x1b") {
		t.Fatalf("transcript still has escape bytes: %q", got)
	}
	if !strings.Contains(got, "redok") {
		t.Fatalf("transcript missing stripped payload: %q", got)
	}
}

func TestRenderTranscript_PreservesUTF8SplitAcrossFrames(t *testing.T) {
	t.Parallel()
	runeBytes := []byte("界")
	frames := []TTYFrame{
		{TS: time.Unix(1, 0), Op: ttyOpWrite, Direction: ttyDirInput, Data: append([]byte("A"), runeBytes[:1]...)},
		{TS: time.Unix(2, 0), Op: ttyOpWrite, Direction: ttyDirInput, Data: append(runeBytes[1:], 'B')},
	}

	got := RenderTranscript(frames, TranscriptOptions{StripANSI: true})
	if want := "A界B"; got != want {
		t.Fatalf("transcript = %q, want %q", got, want)
	}
}

func TestRenderTranscript_StripsANSISplitAcrossFrames(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		first  string
		second string
	}{
		{name: "CSI", first: "plain\x1b[", second: "31mred\x1b[0m"},
		{name: "OSC BEL", first: "plain\x1b]0;title", second: "\x07red"},
		{name: "OSC ST", first: "plain\x1b]0;title\x1b", second: "\\red"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			frames := []TTYFrame{
				{TS: time.Unix(1, 0), Op: ttyOpWrite, Direction: ttyDirOutput, Data: []byte(tc.first)},
				{TS: time.Unix(2, 0), Op: ttyOpWrite, Direction: ttyDirOutput, Data: []byte(tc.second)},
			}
			got := RenderTranscript(frames, TranscriptOptions{IncludeOutput: true, StripANSI: true})
			if want := "plainred"; got != want {
				t.Fatalf("transcript = %q, want %q", got, want)
			}
		})
	}
}

func TestRenderTranscript_KeepsANSIStatePerDirection(t *testing.T) {
	t.Parallel()
	frames := []TTYFrame{
		{TS: time.Unix(1, 0), Op: ttyOpWrite, Direction: ttyDirInput, Data: []byte("I\x1b")},
		{TS: time.Unix(2, 0), Op: ttyOpWrite, Direction: ttyDirOutput, Data: []byte("O")},
		{TS: time.Unix(3, 0), Op: ttyOpWrite, Direction: ttyDirInput, Data: []byte("[31mred\x1b[0m")},
	}

	got := RenderTranscript(frames, TranscriptOptions{IncludeOutput: true, StripANSI: true})
	if want := "IOred"; got != want {
		t.Fatalf("transcript = %q, want %q", got, want)
	}
}

func TestRenderTranscript_KeepsUTF8StatePerDirection(t *testing.T) {
	t.Parallel()
	runeBytes := []byte("界")
	frames := []TTYFrame{
		{TS: time.Unix(1, 0), Op: ttyOpWrite, Direction: ttyDirInput, Data: append([]byte("A"), runeBytes[:1]...)},
		{TS: time.Unix(2, 0), Op: ttyOpWrite, Direction: ttyDirOutput, Data: []byte("雪")},
		{TS: time.Unix(3, 0), Op: ttyOpWrite, Direction: ttyDirInput, Data: append(runeBytes[1:], 'B')},
	}

	got := RenderTranscript(frames, TranscriptOptions{IncludeOutput: true, StripANSI: true})
	if want := "A雪界B"; got != want {
		t.Fatalf("transcript = %q, want %q", got, want)
	}
}

func TestStripANSIPreservesUTF8(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain", in: "雪だるま", want: "雪だるま"},
		{name: "CSI", in: "\x1b[31m警告\x1b[0m", want: "警告"},
		{name: "OSC BEL", in: "\x1b]0;攻撃者\x07接続", want: "接続"},
		{name: "OSC ST", in: "\x1b]8;;https://example.test\x1b\\リンク\x1b]8;;\x1b\\", want: "リンク"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Exercise the production path (transcriptStream with StripANSI),
			// not a test-only wrapper.
			stream := transcriptStream{stripANSI: true}
			stream.Write([]byte(tc.in), transcriptInput)
			if got := stream.out.String(); got != tc.want {
				t.Fatalf("transcriptStream(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestRenderTranscript_InputOnly(t *testing.T) {
	t.Parallel()
	frames := []TTYFrame{
		{TS: time.Unix(1, 0), Op: ttyOpWrite, Direction: ttyDirInput, Data: []byte("typed")},
		{TS: time.Unix(2, 0), Op: ttyOpWrite, Direction: ttyDirOutput, Data: []byte("OUTPUT")},
	}
	got := RenderTranscript(frames, TranscriptOptions{IncludeOutput: false, StripANSI: true})
	if got != "typed" {
		t.Fatalf("input-only transcript should be %q, got %q", "typed", got)
	}
}

func TestRenderTranscript_TruncatesAtMaxBytes(t *testing.T) {
	t.Parallel()
	huge := bytes.Repeat([]byte("A"), 1024)
	frames := []TTYFrame{
		{TS: time.Unix(1, 0), Op: ttyOpWrite, Direction: ttyDirInput, Data: huge},
	}
	got := RenderTranscript(frames, TranscriptOptions{IncludeOutput: false, StripANSI: false, MaxBytes: 64})
	if len(got) <= 64 {
		t.Fatalf("transcript should have truncation marker beyond the cap: len=%d", len(got))
	}
	if !strings.Contains(got, "[transcript truncated]") {
		t.Fatalf("missing truncation marker: %q", got)
	}
}

func TestRenderTranscript_TruncationPreservesUTF8(t *testing.T) {
	t.Parallel()
	frames := []TTYFrame{
		{TS: time.Unix(1, 0), Op: ttyOpWrite, Direction: ttyDirInput, Data: []byte("A界B")},
	}
	got := RenderTranscript(frames, TranscriptOptions{IncludeOutput: false, StripANSI: false, MaxBytes: 3})
	if !utf8.ValidString(got) {
		t.Fatalf("truncated transcript is not valid UTF-8: %q", got)
	}
	if want := "A\n... [transcript truncated]\n"; got != want {
		t.Fatalf("truncated transcript = %q, want %q", got, want)
	}
}

func TestRenderTranscript_MaxBytesBoundsBuffering(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 1<<20)
	payload[0], payload[1] = 'A', 'B'
	frames := []TTYFrame{
		{TS: time.Unix(1, 0), Op: ttyOpWrite, Direction: ttyDirInput, Data: payload},
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	got := RenderTranscript(frames, TranscriptOptions{StripANSI: true, MaxBytes: 1})
	runtime.ReadMemStats(&after)

	if want := "A\n... [transcript truncated]\n"; got != want {
		t.Fatalf("transcript = %q, want %q", got, want)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 128<<10 {
		t.Fatalf("RenderTranscript allocated %d bytes after a 1-byte cap; want at most %d", allocated, 128<<10)
	}
}

func TestRenderTranscript_ExactMaxWithoutMoreOutputIsNotTruncated(t *testing.T) {
	t.Parallel()
	frames := []TTYFrame{
		{TS: time.Unix(1, 0), Op: ttyOpWrite, Direction: ttyDirInput, Data: []byte("A\x1b[31m\x1b[0m")},
	}

	got := RenderTranscript(frames, TranscriptOptions{StripANSI: true, MaxBytes: 1})
	if want := "A"; got != want {
		t.Fatalf("transcript = %q, want %q", got, want)
	}
}
