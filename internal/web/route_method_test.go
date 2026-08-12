package web

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestPostHandlersAreNotWrappedReadOnly derives the rule instead of restating it.
//
// guardRead rejects anything but GET/HEAD, so wrapping a POST-only handler in it
// makes that endpoint permanently unusable. That is not hypothetical: the first
// attempt at this change classified routes from a hand-written path list, the
// list did not match the real paths, and five POST endpoints - AbuseIPDB report,
// report-all, MalwareBazaar upload, URLhaus submit and the VT lookup - were
// silently wrapped GET-only. A list can be wrong; the handler's own method check
// cannot.
func TestPostHandlersAreNotWrappedReadOnly(t *testing.T) {
	server := readSource(t, "server.go")

	// Handlers that enforce POST, found by looking at what they actually do.
	postOnly := map[string]bool{}
	for _, f := range []string{"api_intel.go", "api_settings.go", "api_vt.go", "api_urlhaus.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		body := string(src)
		for _, m := range regexp.MustCompile(`func \(s \*Server\) (\w+)\(w http\.ResponseWriter`).FindAllStringSubmatch(body, -1) {
			name := m[1]
			i := strings.Index(body, m[0])
			// Look only at the head of the function, where a method guard lives.
			head := body[i:min(i+400, len(body))]
			if strings.Contains(head, "r.Method != http.MethodPost") {
				postOnly[name] = true
			}
		}
	}
	if len(postOnly) == 0 {
		t.Fatal("found no POST-only handlers; the check is not looking at anything")
	}

	for name := range postOnly {
		if strings.Contains(server, "s.guardRead(s."+name+")") {
			t.Errorf("%s enforces POST but is registered with guardRead, which allows only "+
				"GET/HEAD: the endpoint can never be called successfully", name)
		}
	}
	t.Logf("verified %d POST-only handlers are not read-only wrapped", len(postOnly))
}

// TestReadEndpointsRejectWrongMethod pins that read routes are actually wrapped,
// so the two halves of the API agree on method handling.
func TestReadEndpointsRejectWrongMethod(t *testing.T) {
	server := readSource(t, "server.go")
	if !strings.Contains(server, "func (s *Server) guardRead(") {
		t.Fatal("guardRead missing")
	}
	if n := strings.Count(server, "s.guardRead(s."); n < 20 {
		t.Errorf("only %d read routes are method-guarded, expected the bulk of /api/*", n)
	}
	// The wrapper must send Allow, or a 405 tells the caller nothing.
	i := strings.Index(server, "func (s *Server) guardRead(")
	if !strings.Contains(server[i:i+700], `w.Header().Set("Allow"`) {
		t.Error("guardRead returns 405 without an Allow header")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestReplayRejectsUnknownSession pins that the two session endpoints agree on
// existence. /api/intel/session already 404s an unknown id; replay used to
// render a script regardless, so a typo produced a 200 and a download named
// after a session that does not exist.
func TestReplayRejectsUnknownSession(t *testing.T) {
	src := readSource(t, "api_intel.go")
	i := strings.Index(src, "func (s *Server) handleIntelReplay(")
	if i < 0 {
		t.Fatal("replay handler not found")
	}
	body := src[i:min(i+1600, len(src))]
	if !strings.Contains(body, "len(events) == 0") || !strings.Contains(body, "StatusNotFound") {
		t.Error("replay does not 404 an unknown session; /api/intel/session does, and the " +
			"two must agree on whether a session exists")
	}
}
