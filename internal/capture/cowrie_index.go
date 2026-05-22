package capture

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"time"

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
// records each sha256->session binding into the store. Errors opening
// or reading the file return nil (best-effort): missing rotated
// siblings are normal, and a partial scan still produces useful
// bindings.
func indexTTYBindingsFromFile(st *store.Store, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 256*1024)
	sc.Buffer(buf, 2*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
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
		ts, _ := time.Parse(time.RFC3339Nano, strings.TrimSpace(rec.Timestamp))
		_ = st.RecordCowrieTTYBinding(rec.SHA, rec.Session, ts)
	}
	return nil
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
