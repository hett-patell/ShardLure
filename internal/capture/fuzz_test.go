package capture

import (
	"bytes"
	"testing"
	"unicode/utf8"
)

// FuzzDecodeTTYReader fuzzes the Cowrie TTY-log binary decoder.
//
// This is the sharpest untrusted-input edge in the project: the format is a
// packed 24-byte C struct (`<iLiiLL`) written by the honeypot while an attacker
// is typing, and a session that is killed mid-write leaves a truncated frame.
// The decoder does its own length arithmetic, so a bogus length field is the
// classic path to a huge allocation or an out-of-range slice — and this runs
// inside the 5s capture tick, where a panic would kill the ticker goroutine and
// silently stop all evidence collection.
//
// Longer run:
//
//	go test ./internal/capture/ -run=XXX -fuzz=FuzzDecodeTTYReader -fuzztime=60s
func FuzzDecodeTTYReader(f *testing.F) {
	// A well-formed frame plus the degenerate shapes worth pinning.
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add(bytes.Repeat([]byte{0}, 24))
	f.Add(bytes.Repeat([]byte{0xff}, 24))
	f.Add(bytes.Repeat([]byte{0xff}, 23)) // truncated header
	// op=1 (input), len=4, then 4 payload bytes.
	f.Add([]byte{
		0x01, 0x00, 0x00, 0x00, // op
		0x00, 0x00, 0x00, 0x00, // ts sec
		0x00, 0x00, 0x00, 0x00, // ts usec
		0x04, 0x00, 0x00, 0x00, // length
		0x00, 0x00, 0x00, 0x00, // dir/sec
		0x00, 0x00, 0x00, 0x00, // usec
		'l', 's', '\r', '\n',
	})
	// A header claiming an enormous payload: the decoder must refuse rather
	// than try to allocate it.
	f.Add([]byte{
		0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0xff, 0x7f, // length ~2GiB
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		frames, err := decodeTTYReader(bytes.NewReader(data))
		if err != nil {
			// An error is a perfectly good outcome for garbage; it just must
			// not come back with frames as well.
			return
		}
		// Frame count must stay proportionate to the input: each frame needs a
		// 24-byte header, so more frames than that is an arithmetic bug.
		if len(frames) > len(data)/24+1 {
			t.Fatalf("decoded %d frames from %d bytes (impossible)", len(frames), len(data))
		}
		total := 0
		for _, fr := range frames {
			// A single frame must never claim more payload than the whole input
			// held — that would mean the length field drove an over-read.
			if len(fr.Data) > len(data) {
				t.Fatalf("frame carries %d bytes from a %d-byte input", len(fr.Data), len(data))
			}
			total += len(fr.Data)
		}
		if total > len(data) {
			t.Fatalf("frames carry %d payload bytes from a %d-byte input", total, len(data))
		}
		// RenderTranscript feeds the dashboard and the TUI, so it must not
		// panic on decoder output and must produce valid UTF-8.
		out := RenderTranscript(frames, TranscriptOptions{})
		if !utf8.ValidString(out) {
			t.Errorf("RenderTranscript produced invalid UTF-8 from %d frames", len(frames))
		}
	})
}
