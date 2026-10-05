package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
)

// bazaarGateFixture is the prod shape the v2.10.1 fix was written against:
// after every real sample had been uploaded, the panel still said "pending: 3"
// (two SSH-key files and one unconfirmed 257-byte blob, all of which Vet
// rejects), and the payload library offered Upload buttons on them.
type bazaarGateFixture struct {
	eligibleELF, sshKey, tty, unconfirmed, uploaded, stale string
}

// minimalFamilyELF builds a header that debug/elf parses (so Outbound() keeps
// the family) followed by an XMRig Tier-A anchor string. Inert bytes: it has no
// program headers and nothing here is ever executed.
func minimalFamilyELF() []byte {
	var b bytes.Buffer
	b.Write([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0})
	b.Write(make([]byte, 7))
	for _, v := range []any{uint16(2), uint16(62), uint32(1), uint64(0), uint64(0), uint64(0), uint32(0),
		uint16(64), uint16(56), uint16(0), uint16(64), uint16(0), uint16(0)} {
		_ = binary.Write(&b, binary.LittleEndian, v)
	}
	b.WriteString("\x00donate.v2.xmrig.com\x00")
	b.Write(bytes.Repeat([]byte("inert fixture padding "), 20))
	return b.Bytes()
}

func writeFixture(t *testing.T, dir, name string, body []byte) (path, sha string) {
	t.Helper()
	path = filepath.Join(dir, name)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, fmt.Sprintf("%x", sha256.Sum256(body))
}

func seedBazaarGateFixture(t *testing.T, st *store.Store) bazaarGateFixture {
	t.Helper()
	dir := t.TempDir()
	now := time.Now().UTC()
	var fx bazaarGateFixture
	add := func(name string, body []byte, origin string, age time.Duration) string {
		p, sha := writeFixture(t, dir, name, body)
		if err := st.RecordArtifact(store.Artifact{
			URL: "http://198.51.100.7/" + name, TS: now.Add(-age), SHA256: sha, LocalPath: p,
			SizeBytes: int64(len(body)), Origin: origin, Status: "fetched",
		}); err != nil {
			t.Fatal(err)
		}
		return sha
	}
	fx.eligibleELF = add("xmr.elf", minimalFamilyELF(), "quarantine_fetch", 1*time.Hour)
	fx.sshKey = add("authorized_keys", []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC"+strings.Repeat("Q", 300)+" fixture@host\n"),
		"cowrie_file_download", 2*time.Hour)
	fx.tty = add("session.tty", bytes.Repeat([]byte("tty transcript bytes "), 40), "cowrie_tty", 3*time.Hour)
	unconf := make([]byte, 257)
	for i := range unconf {
		unconf[i] = byte(i*37) | 0x80 // binary, not ELF/PE/script/key
	}
	fx.unconfirmed = add("blob.bin", unconf, "cowrie_download", 4*time.Hour)
	fx.uploaded = add("old.sh", []byte("#!/bin/sh\n# inert fixture, already on MalwareBazaar\n"+strings.Repeat("# pad\n", 20)),
		"cowrie_download", 5*time.Hour)
	if err := st.RecordBazaarUpload(store.BazaarUpload{SHA256: fx.uploaded, UploadedAt: now, ResponseStatus: "inserted"}); err != nil {
		t.Fatal(err)
	}
	fx.stale = add("stale.sh", []byte("#!/bin/sh\n# inert fixture, outside the freshness window\n"+strings.Repeat("# pad\n", 20)),
		"cowrie_download", 20*24*time.Hour)
	return fx
}

type bazaarCandJSON struct {
	SHA256      string   `json:"sha256"`
	SizeBytes   int64    `json:"sizeBytes"`
	FileKind    string   `json:"fileKind"`
	Family      string   `json:"family"`
	Tags        []string `json:"tags"`
	Origin      string   `json:"origin"`
	LastFetchAt string   `json:"lastFetchAt"`
	Eligible    bool     `json:"eligible"`
	Reason      string   `json:"reason"`
}

type bazaarRespJSON struct {
	Stats struct {
		TotalUploaded int `json:"totalUploaded"`
		Pending       int `json:"pending"`
	} `json:"stats"`
	Uploads         []struct{ SHA256 string } `json:"uploads"`
	Candidates      []bazaarCandJSON          `json:"candidates"`
	CandidatesTotal int                       `json:"candidatesTotal"`
	Configured      bool                      `json:"configured"`
}

func getBazaar(t *testing.T, s *Server) bazaarRespJSON {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleIntelBazaar(w, httptest.NewRequest(http.MethodGet, "/api/intel/bazaar?limit=1000", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/intel/bazaar → %d: %s", w.Code, w.Body.String())
	}
	var out bazaarRespJSON
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

// TestBazaarPanelShowsVetDecision pins requirement 2 and 3 of the v2.10.1 fix:
// the panel's candidates and pending count come from bazaar.Vet, not from the
// SharePolicy pre-filter, and the payload library's shareable flag agrees.
func TestBazaarPanelShowsVetDecision(t *testing.T) {
	s := newIntelTestServer(t, nil)
	fx := seedBazaarGateFixture(t, s.st)

	out := getBazaar(t, s)
	if out.Configured {
		t.Error("configured=true with no abuse.ch key: the panel would arm Upload buttons that fail")
	}
	got := map[string]bazaarCandJSON{}
	for _, c := range out.Candidates {
		got[c.SHA256] = c
	}
	want := map[string]struct {
		eligible bool
		reason   string
	}{
		fx.eligibleELF: {true, ""},
		fx.sshKey:      {false, "benign content (SSH key)"},
		fx.unconfirmed: {false, "unconfirmed: no family, behaviour, or provenance malware signal"},
	}
	for sha, w := range want {
		c, ok := got[sha]
		if !ok {
			t.Errorf("candidate %s missing from /api/intel/bazaar candidates", sha[:12])
			continue
		}
		if c.Eligible != w.eligible || c.Reason != w.reason {
			t.Errorf("candidate %s: eligible=%v reason=%q, want %v %q", sha[:12], c.Eligible, c.Reason, w.eligible, w.reason)
		}
	}
	for name, sha := range map[string]string{"tty transcript": fx.tty, "already uploaded": fx.uploaded, "stale": fx.stale} {
		if _, ok := got[sha]; ok {
			t.Errorf("%s sample %s must not be a candidate", name, sha[:12])
		}
	}
	if len(out.Candidates) != 3 || out.CandidatesTotal != 3 {
		t.Errorf("candidates=%d total=%d, want 3/3", len(out.Candidates), out.CandidatesTotal)
	}
	if c := got[fx.eligibleELF]; c.Family != "XMRig" || c.FileKind != "ELF" || c.Origin != "quarantine_fetch" || c.LastFetchAt == "" {
		t.Errorf("eligible candidate lacks classification/provenance: %+v", c)
	}
	// Newest first.
	if len(out.Candidates) == 3 && out.Candidates[0].SHA256 != fx.eligibleELF {
		t.Errorf("candidates not newest-first: first is %s", out.Candidates[0].SHA256[:12])
	}
	// The prod bug: pre-filter said 3 (ELF + key + blob); Vet says 1.
	if out.Stats.Pending != 1 {
		t.Errorf("stats.pending = %d, want 1 (only the Vet-eligible sample)", out.Stats.Pending)
	}
	if out.Stats.TotalUploaded != 1 || len(out.Uploads) != 1 {
		t.Errorf("uploads/totalUploaded changed: %d/%d", len(out.Uploads), out.Stats.TotalUploaded)
	}

	w := httptest.NewRecorder()
	s.handleIntelPayloads(w, httptest.NewRequest(http.MethodGet, "/api/intel/payloads?window=30d&limit=100", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/intel/payloads → %d", w.Code)
	}
	var pl struct {
		Rows []struct {
			SHA256    string `json:"sha256"`
			Shareable bool   `json:"shareable"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &pl); err != nil {
		t.Fatal(err)
	}
	if len(pl.Rows) != 6 {
		t.Fatalf("payload library rows = %d, want all 6 fixtures", len(pl.Rows))
	}
	for _, r := range pl.Rows {
		if r.Shareable != (r.SHA256 == fx.eligibleELF) {
			t.Errorf("payload %s shareable=%v; only the Vet-eligible, unshared sample may be shareable", r.SHA256[:12], r.Shareable)
		}
	}
}

// TestBazaarEligibilityAgreesWithUploadHandler pins that the panel can never
// call a sample eligible that handleBazaarUpload refuses (or the reverse): each
// candidate's advertised decision is replayed through the real upload endpoint
// against a local fake MalwareBazaar.
func TestBazaarEligibilityAgreesWithUploadHandler(t *testing.T) {
	t.Setenv("SHARDLURE_DASH_TOKEN", "")
	st, err := store.Open(filepath.Join(t.TempDir(), "agree.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	fx := seedBazaarGateFixture(t, st)
	var calls atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"query_status":"inserted"}`)
	}))
	defer endpoint.Close()
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatal(err)
	}
	s := New(st, keys, "127.0.0.1:0", Options{BazaarAPIKey: "fixture-key", BazaarEndpoint: endpoint.URL})

	first := getBazaar(t, s)
	if !first.Configured {
		t.Error("configured=false although an abuse.ch key is set")
	}
	cands := first.Candidates
	if len(cands) == 0 {
		t.Fatal("no candidates to compare")
	}
	for _, c := range cands {
		before := calls.Load()
		s.lastBazaarAt = time.Time{} // skip the 2 s inter-upload throttle in tests
		w := httptest.NewRecorder()
		s.handleBazaarUpload(w, httptest.NewRequest(http.MethodPost, "/api/intel/bazaar/upload?sha="+c.SHA256, nil))
		var resp struct{ Status, Error string }
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		submitted := calls.Load() > before
		if submitted != c.Eligible {
			t.Errorf("%s: panel eligible=%v but upload handler submitted=%v (status=%q error=%q)",
				c.SHA256[:12], c.Eligible, submitted, resp.Status, resp.Error)
		}
		if !c.Eligible && (resp.Status != "skipped" || resp.Error != c.Reason) {
			t.Errorf("%s: panel reason %q, handler said status=%q error=%q", c.SHA256[:12], c.Reason, resp.Status, resp.Error)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("fake MalwareBazaar received %d uploads, want exactly 1 (%s)", calls.Load(), fx.eligibleELF[:12])
	}
	// The upload invalidates the cache: the shipped sample leaves the pool at
	// once instead of reading "eligible" for another TTL.
	after := getBazaar(t, s)
	for _, c := range after.Candidates {
		if c.SHA256 == fx.eligibleELF {
			t.Error("uploaded sample still listed as a candidate after a successful upload")
		}
	}
	if after.Stats.Pending != 0 {
		t.Errorf("pending after upload = %d, want 0", after.Stats.Pending)
	}
}

// TestBazaarAlreadySharedReplyInvalidatesCandidates covers a ledger row written
// by another process (a CLI share run): the handler's already_shared early
// return must drop the cached evaluation too, or the panel keeps listing the
// sample as eligible for up to a TTL while the button reports it shared.
func TestBazaarAlreadySharedReplyInvalidatesCandidates(t *testing.T) {
	t.Setenv("SHARDLURE_DASH_TOKEN", "")
	st, err := store.Open(filepath.Join(t.TempDir(), "shared.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	fx := seedBazaarGateFixture(t, st)
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatal(err)
	}
	s := New(st, keys, "127.0.0.1:0", Options{BazaarAPIKey: "fixture-key", BazaarEndpoint: "http://127.0.0.1:1/unused"})
	if getBazaar(t, s).Stats.Pending != 1 {
		t.Fatal("fixture: want the ELF pending before the CLI run")
	}
	// The CLI uploads it from another process: only the ledger changes.
	if err := st.RecordBazaarUpload(store.BazaarUpload{SHA256: fx.eligibleELF, UploadedAt: time.Now(), ResponseStatus: "inserted"}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.handleBazaarUpload(w, httptest.NewRequest(http.MethodPost, "/api/intel/bazaar/upload?sha="+fx.eligibleELF, nil))
	if !strings.Contains(w.Body.String(), "already_shared") {
		t.Fatalf("want already_shared, got %s", w.Body.String())
	}
	if after := getBazaar(t, s); after.Stats.Pending != 0 {
		t.Errorf("pending = %d after an already_shared reply, want 0 (cache not invalidated)", after.Stats.Pending)
	}
}
