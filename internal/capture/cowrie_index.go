package capture

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/networkshard/shardlure/internal/safefile"
	"github.com/networkshard/shardlure/internal/store"
)

// cowrieLogClosed is the minimal projection of a cowrie.log.closed
// event we need to record the sha->session binding. Cowrie writes one
// of these whenever a ttylog file is renamed to its sha256 sum.
type cowrieLogClosed struct {
	EventID   string `json:"eventid"`
	Session   string `json:"session"`
	SHA       string `json:"shasum"`
	Timestamp string `json:"timestamp"`
}

// indexTTYBindingsFromFile scans path for cowrie.log.closed events and
// records each sha256->session binding. Missing rotated siblings are normal;
// other I/O and persistence failures are returned so the caller can retry.
func indexTTYBindingsFromFile(st *store.Store, path string) error {
	root, err := safefile.OpenRoot(filepath.Dir(path))
	if errors.Is(err, safefile.ErrNotExist) {
		return nil
	}
	if err != nil {
		return safeCaptureError(err, "capture TTY index access failed")
	}
	defer root.Close()
	return indexTTYBindingsFromRoot(context.Background(), st, root, filepath.Base(path))
}

func indexTTYBindingsFromRoot(ctx context.Context, st *store.Store, root *safefile.Root, name string) error {
	f, err := root.OpenRegular(name)
	if errors.Is(err, safefile.ErrNotExist) {
		return nil
	}
	if err != nil {
		return safeCaptureError(err, "capture TTY index access failed")
	}
	defer f.Close()
	reader := bufio.NewReaderSize(f, 64<<10)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var line []byte
		oversized := false
		for {
			part, more, err := reader.ReadLine()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return safeCaptureError(err, "capture TTY index read failed")
			}
			if len(line)+len(part) > 2<<20 {
				oversized = true
			}
			if !oversized {
				line = append(line, part...)
			}
			if !more {
				break
			}
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if oversized {
			continue
		}
		// Cheap pre-filter: skip lines that don't even mention
		// log.closed before parsing JSON. Cowrie.json is large
		// and JSON parsing per line is expensive enough to be
		// worth this short-circuit.
		if !containsBytes(line, []byte("cowrie.log.closed")) {
			continue
		}
		var rec cowrieLogClosed
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		if rec.EventID != "cowrie.log.closed" || rec.SHA == "" || rec.Session == "" {
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(rec.Timestamp))
		if err != nil || !looksLikeSHA256(rec.SHA) {
			continue
		}
		if err := st.RecordCowrieTTYBinding(rec.SHA, rec.Session, ts); err != nil {
			return safeCaptureError(err, "capture TTY index recording failed")
		}
	}
}

// containsBytes is a tiny wrapper to keep the hot pre-filter explicit
// (avoids the strings/bytes import dance for a single call site).
func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
outer:
	for i := 0; i <= len(haystack)-len(needle); i++ {
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				continue outer
			}
		}
		return true
	}
	return false
}
