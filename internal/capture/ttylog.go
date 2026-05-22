package capture

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
	"unicode"
)

// Cowrie TTY log binary format
// Source: https://github.com/cowrie/cowrie/blob/master/src/cowrie/core/ttylog.py
//
//	struct TTYSTRUCT { // "<iLiiLL"  (24 bytes, little-endian)
//	    int32  op;        // 1=OPEN, 2=CLOSE, 3=WRITE, 4=EXEC
//	    uint32 _tty;
//	    int32  length;
//	    int32  direction; // 1=INPUT (from attacker), 2=OUTPUT (to attacker), 3=INTERACT
//	    uint32 sec;
//	    uint32 usec;
//	} followed by `length` bytes of payload (WRITE/EXEC only)
const (
	ttyHeaderSize = 24

	ttyOpOpen  = 1
	ttyOpClose = 2
	ttyOpWrite = 3
	ttyOpExec  = 4

	ttyDirInput    = 1
	ttyDirOutput   = 2
	ttyDirInteract = 3
)

// TTYFrame is one parsed entry from a Cowrie ttylog file.
type TTYFrame struct {
	TS        time.Time
	Op        int32
	Direction int32
	Data      []byte
}

// IsInput reports whether the frame represents bytes the attacker typed.
func (f TTYFrame) IsInput() bool {
	return f.Op == ttyOpWrite && (f.Direction == ttyDirInput || f.Direction == ttyDirInteract)
}

// IsOutput reports whether the frame represents bytes the honeypot sent back.
func (f TTYFrame) IsOutput() bool {
	return f.Op == ttyOpWrite && f.Direction == ttyDirOutput
}

// IsExec reports whether the frame is an out-of-band exec marker (non-interactive
// `ssh user@host cmd` style sessions).
func (f TTYFrame) IsExec() bool { return f.Op == ttyOpExec }

// DecodeTTYLog parses a Cowrie ttylog file end-to-end. It tolerates a truncated
// trailing frame: if the final payload is shorter than its declared length the
// partial bytes are returned and the function reports nil.
func DecodeTTYLog(path string) ([]TTYFrame, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return decodeTTYReader(f)
}

func decodeTTYReader(r io.Reader) ([]TTYFrame, error) {
	var out []TTYFrame
	hdr := make([]byte, ttyHeaderSize)
	for {
		_, err := io.ReadFull(r, hdr)
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			// Header torn across truncation -- treat as clean EOF.
			break
		}
		if err != nil {
			return out, fmt.Errorf("read ttylog header: %w", err)
		}

		op := int32(binary.LittleEndian.Uint32(hdr[0:4]))
		// hdr[4:8] is _tty (ignored)
		length := int32(binary.LittleEndian.Uint32(hdr[8:12]))
		dir := int32(binary.LittleEndian.Uint32(hdr[12:16]))
		sec := binary.LittleEndian.Uint32(hdr[16:20])
		usec := binary.LittleEndian.Uint32(hdr[20:24])
		ts := time.Unix(int64(sec), int64(usec)*1000).UTC()

		var payload []byte
		if length > 0 && (op == ttyOpWrite || op == ttyOpExec) {
			// Bound at 16 MiB per frame so a malicious / corrupt
			// header cannot make us allocate gigabytes.
			if length > 16*1024*1024 {
				return out, fmt.Errorf("ttylog frame length %d exceeds limit", length)
			}
			payload = make([]byte, length)
			n, err := io.ReadFull(r, payload)
			if errors.Is(err, io.ErrUnexpectedEOF) {
				// Trailing short read -- keep what we got.
				out = append(out, TTYFrame{TS: ts, Op: op, Direction: dir, Data: payload[:n]})
				return out, nil
			}
			if err != nil {
				return out, fmt.Errorf("read ttylog payload: %w", err)
			}
		}
		out = append(out, TTYFrame{TS: ts, Op: op, Direction: dir, Data: payload})
	}
	return out, nil
}

// TranscriptOptions controls how RenderTranscript turns frames into human-readable text.
type TranscriptOptions struct {
	// IncludeOutput keeps OUTPUT frames (what the attacker saw). False produces
	// an input-only transcript -- everything the attacker typed in order.
	IncludeOutput bool
	// StripANSI removes ANSI/VT escape sequences when true. Strongly recommended
	// for transcripts intended for the web dashboard.
	StripANSI bool
	// MaxBytes truncates the final output. 0 means no limit.
	MaxBytes int
}

// DefaultTranscriptOptions returns the rendering style used by the dashboard:
// input + output interleaved, ANSI stripped, 256 KiB cap.
func DefaultTranscriptOptions() TranscriptOptions {
	return TranscriptOptions{IncludeOutput: true, StripANSI: true, MaxBytes: 256 * 1024}
}

// RenderTranscript serialises the frame stream into a readable transcript.
// Frames are sorted by timestamp (ttylog is already monotonic in practice
// but defensive sort guards against future ingest changes).
func RenderTranscript(frames []TTYFrame, opts TranscriptOptions) string {
	sorted := make([]TTYFrame, len(frames))
	copy(sorted, frames)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].TS.Before(sorted[j].TS) })

	var buf bytes.Buffer
	for _, fr := range sorted {
		switch {
		case fr.IsInput(), fr.IsExec():
			data := fr.Data
			if opts.StripANSI {
				data = stripANSI(data)
			}
			buf.Write(data)
		case fr.IsOutput():
			if !opts.IncludeOutput {
				continue
			}
			data := fr.Data
			if opts.StripANSI {
				data = stripANSI(data)
			}
			buf.Write(data)
		}
		if opts.MaxBytes > 0 && buf.Len() >= opts.MaxBytes {
			buf.Truncate(opts.MaxBytes)
			buf.WriteString("\n... [transcript truncated]\n")
			break
		}
	}
	return buf.String()
}

// stripANSI removes the most common CSI / OSC / cursor-control escape
// sequences. This is intentionally conservative: we keep newlines, tabs, and
// printable characters; we drop escape sequences and other control bytes.
func stripANSI(in []byte) []byte {
	out := make([]byte, 0, len(in))
	i := 0
	for i < len(in) {
		b := in[i]
		if b == 0x1b && i+1 < len(in) {
			// ESC sequence: skip [ or ] introducer plus parameter bytes
			// until a final byte in 0x40-0x7e for CSI, or BEL/ST for OSC.
			next := in[i+1]
			switch next {
			case '[': // CSI
				j := i + 2
				for j < len(in) {
					c := in[j]
					if c >= 0x40 && c <= 0x7e {
						j++
						break
					}
					j++
				}
				i = j
				continue
			case ']': // OSC
				j := i + 2
				for j < len(in) {
					if in[j] == 0x07 {
						j++
						break
					}
					if in[j] == 0x1b && j+1 < len(in) && in[j+1] == '\\' {
						j += 2
						break
					}
					j++
				}
				i = j
				continue
			default:
				// two-byte sequence; skip both
				i += 2
				continue
			}
		}
		if b == '\n' || b == '\r' || b == '\t' || unicode.IsPrint(rune(b)) {
			out = append(out, b)
		}
		i++
	}
	return out
}
