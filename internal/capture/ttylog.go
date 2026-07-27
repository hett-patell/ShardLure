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
	"unicode/utf8"
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

	stream := transcriptStream{stripANSI: opts.StripANSI, maxBytes: opts.MaxBytes}
	for _, fr := range sorted {
		var data []byte
		var direction transcriptDirection
		switch {
		case fr.IsInput(), fr.IsExec():
			data = fr.Data
			direction = transcriptInput
		case fr.IsOutput():
			if !opts.IncludeOutput {
				continue
			}
			data = fr.Data
			direction = transcriptOutput
		default:
			continue
		}
		if !stream.Write(data, direction) {
			break
		}
	}
	return stream.String()
}

type ansiStreamState uint8

const (
	ansiText ansiStreamState = iota
	ansiEscape
	ansiCSI
	ansiOSC
	ansiOSCEscape
)

type transcriptDirection uint8

const (
	transcriptInput transcriptDirection = iota
	transcriptOutput
)

const transcriptTruncationMarker = "\n... [transcript truncated]\n"

// transcriptStream sanitizes selected frame bytes incrementally. Decoder and
// escape state survive frame boundaries, while the output buffer never grows
// beyond maxBytes (apart from the fixed truncation marker).
type transcriptStream struct {
	out         bytes.Buffer
	stripANSI   bool
	maxBytes    int
	ansiState   [2]ansiStreamState
	utf8Pending [2][utf8.UTFMax]byte
	utf8Len     [2]int
	truncated   bool
}

// Write consumes one selected frame. It returns false as soon as the next
// complete output rune would exceed maxBytes.
func (s *transcriptStream) Write(in []byte, direction transcriptDirection) bool {
	for _, b := range in {
		if !s.stripANSI {
			if !s.writeUTF8Byte(b, direction) {
				return false
			}
			continue
		}

		switch s.ansiState[direction] {
		case ansiText:
			if b == 0x1b {
				s.ansiState[direction] = ansiEscape
				continue
			}
			if !s.writeUTF8Byte(b, direction) {
				return false
			}
		case ansiEscape:
			switch b {
			case '[':
				s.ansiState[direction] = ansiCSI
			case ']':
				s.ansiState[direction] = ansiOSC
			default:
				s.ansiState[direction] = ansiText
			}
		case ansiCSI:
			if b >= 0x40 && b <= 0x7e {
				s.ansiState[direction] = ansiText
			}
		case ansiOSC:
			switch b {
			case 0x07:
				s.ansiState[direction] = ansiText
			case 0x1b:
				s.ansiState[direction] = ansiOSCEscape
			}
		case ansiOSCEscape:
			switch b {
			case '\\', 0x07:
				s.ansiState[direction] = ansiText
			case 0x1b:
				// This ESC can begin the ST terminator on the next byte.
			default:
				s.ansiState[direction] = ansiOSC
			}
		}
	}
	return true
}

func (s *transcriptStream) writeUTF8Byte(b byte, direction transcriptDirection) bool {
	s.utf8Pending[direction][s.utf8Len[direction]] = b
	s.utf8Len[direction]++
	for s.utf8Len[direction] > 0 && utf8.FullRune(s.utf8Pending[direction][:s.utf8Len[direction]]) {
		r, size := utf8.DecodeRune(s.utf8Pending[direction][:s.utf8Len[direction]])
		if r == utf8.RuneError && size == 1 {
			s.shiftUTF8(1, direction)
			continue
		}
		if !s.emitRune(r, s.utf8Pending[direction][:size]) {
			return false
		}
		s.shiftUTF8(size, direction)
	}
	return true
}

func (s *transcriptStream) shiftUTF8(n int, direction transcriptDirection) {
	copy(s.utf8Pending[direction][:], s.utf8Pending[direction][n:s.utf8Len[direction]])
	s.utf8Len[direction] -= n
}

func (s *transcriptStream) emitRune(r rune, encoded []byte) bool {
	if s.stripANSI && r != '\n' && r != '\r' && r != '\t' && !unicode.IsPrint(r) {
		return true
	}
	if s.maxBytes > 0 && s.out.Len()+len(encoded) > s.maxBytes {
		s.truncated = true
		return false
	}
	s.out.Write(encoded)
	return true
}

func (s *transcriptStream) String() string {
	if s.truncated {
		return s.out.String() + transcriptTruncationMarker
	}
	return s.out.String()
}

// stripANSI removes the most common CSI / OSC / cursor-control escape
// sequences. This is intentionally conservative: we keep newlines, tabs, and
// printable characters; we drop escape sequences and other control bytes.
func stripANSI(in []byte) []byte {
	stream := transcriptStream{stripANSI: true}
	stream.Write(in, transcriptInput)
	return stream.out.Bytes()
}
