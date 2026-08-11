package web

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
)

const testMMDB = "testdata/GeoIP2-City-Test.mmdb"

// newGeoTestStore builds a real store so geo persistence is exercised.
func newGeoTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "geo.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func newGeoTestKeys(t *testing.T, st *store.Store, kv map[string]string) *settings.Keystore {
	t.Helper()
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatalf("settings.Load: %v", err)
	}
	for k, v := range kv {
		if err := keys.Set(k, v); err != nil {
			t.Fatalf("keys.Set(%s): %v", k, err)
		}
	}
	return keys
}

func TestOpenMMDBStates(t *testing.T) {
	// Unset: nil resolver, not ready, reports "unset".
	if m := openMMDB(""); m != nil {
		t.Errorf("blank path should give nil resolver, got %+v", m)
	}
	if got := (*mmdbResolver)(nil).status(); got != "unset" {
		t.Errorf("nil status = %q, want unset", got)
	}
	if (*mmdbResolver)(nil).ready() {
		t.Error("nil resolver must not be ready")
	}

	// Missing file: fail-open, never panics, surfaces the error.
	bad := openMMDB(filepath.Join(t.TempDir(), "nope.mmdb"))
	if bad == nil || bad.ready() {
		t.Fatalf("missing file should give a non-nil, not-ready resolver: %+v", bad)
	}
	if bad.status() == "unset" || bad.status() == "ready" {
		t.Errorf("missing file status should be an error, got %q", bad.status())
	}
	if _, ok := bad.lookup("81.2.69.142", time.Now()); ok {
		t.Error("broken resolver must not return a hit")
	}

	// Real fixture: ready.
	good := openMMDB(testMMDB)
	if good == nil || !good.ready() {
		t.Fatalf("fixture should open: %+v", good)
	}
	defer good.close()
	if good.status() != "ready" {
		t.Errorf("status = %q, want ready", good.status())
	}
}

func TestMMDBLookup(t *testing.T) {
	m := openMMDB(testMMDB)
	if m == nil || !m.ready() {
		t.Fatal("fixture failed to open")
	}
	defer m.close()
	now := time.Now()

	ent, ok := m.lookup("81.2.69.142", now)
	if !ok {
		t.Fatal("expected a hit for 81.2.69.142")
	}
	if ent.CC != "GB" || ent.City != "London" || !ent.OK {
		t.Errorf("unexpected entry: %+v", ent)
	}
	if ent.Lat == 0 || ent.Lon == 0 {
		t.Errorf("expected real coordinates, got lat=%v lon=%v", ent.Lat, ent.Lon)
	}
	if !ent.Expiry.After(now) {
		t.Errorf("expiry should be in the future, got %v", ent.Expiry)
	}

	if ent, ok := m.lookup("175.16.199.1", now); !ok || ent.CC != "CN" {
		t.Errorf("175.16.199.1 = %+v, ok=%v; want CN", ent, ok)
	}

	// Absent from the fixture → miss, so the HTTP tier can try.
	if _, ok := m.lookup("8.8.8.8", now); ok {
		t.Error("8.8.8.8 is not in the fixture; expected a miss")
	}
	// Garbage input must not panic and must miss.
	if _, ok := m.lookup("not-an-ip", now); ok {
		t.Error("unparseable IP should miss")
	}
}

// The headline behaviour: with an MMDB configured, geo works with outbound
// HTTP explicitly DISABLED — the zero-egress configuration.
func TestGeoResolverMMDBOnlyNeedsNoHTTP(t *testing.T) {
	st := newGeoTestStore(t)
	// Both geo HTTP flags off.
	keys := newGeoTestKeys(t, st, map[string]string{settings.KeyGeoHTTP: "0"})

	g := newGeoResolver(geoConfig{MMDB: testMMDB}, st, keys)
	defer g.mmdb.close()

	if !g.isEnabled() {
		t.Fatal("MMDB should enable geo even with HTTP off")
	}
	if g.httpTierEnabled() {
		t.Fatal("HTTP tier must stay disabled")
	}

	g.prefetch([]string{"81.2.69.142", "89.160.20.112"}, 2*time.Second)

	ent := g.cached("81.2.69.142")
	if !ent.OK || ent.CC != "GB" {
		t.Fatalf("expected local resolution, got %+v", ent)
	}
	if ent := g.cached("89.160.20.112"); !ent.OK || ent.CC != "SE" {
		t.Errorf("second IP = %+v, want SE", ent)
	}

	// And it was persisted for restart survival.
	if rec, found, err := st.GetEnrichment("81.2.69.142", "geo"); err != nil || !found {
		t.Errorf("geo not persisted: found=%v err=%v", found, err)
	} else if rec.Payload == "" {
		t.Error("persisted payload is empty")
	}
}

// The coverage fix: the 48-IP cap bounds outbound HTTP only. A local database
// must resolve an arbitrarily large batch in one prefetch.
func TestGeoPrefetchMMDBIgnores48Cap(t *testing.T) {
	st := newGeoTestStore(t)
	keys := newGeoTestKeys(t, st, map[string]string{settings.KeyGeoHTTP: "0"})
	g := newGeoResolver(geoConfig{MMDB: testMMDB}, st, keys)
	defer g.mmdb.close()

	// 120 distinct IPs inside the fixture's 81.2.69.128/25 range, well over
	// the 48-per-call HTTP cap.
	var ips []string
	for i := 130; i < 250; i++ {
		ips = append(ips, "81.2.69."+strconv.Itoa(i))
	}
	g.prefetch(ips, 3*time.Second)

	resolved := 0
	for _, ip := range ips {
		if g.cached(ip).OK {
			resolved++
		}
	}
	if resolved <= 48 {
		t.Fatalf("only %d/%d resolved — the HTTP 48-cap is wrongly bounding local lookups", resolved, len(ips))
	}
}

// An MMDB miss must fall through to the HTTP tier when that tier is enabled.
func TestGeoMMDBMissFallsThroughToHTTP(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","country":"Testland","city":"Testville","countryCode":"TL","lat":1.5,"lon":2.5}`))
	}))
	defer srv.Close()

	st := newGeoTestStore(t)
	keys := newGeoTestKeys(t, st, map[string]string{
		settings.KeyGeoHTTP:     "1",
		settings.KeyGeoInsecure: "1",
	})
	g := newGeoResolver(geoConfig{MMDB: testMMDB, Enabled: true, InsecureHTTP: true}, st, keys)
	defer g.mmdb.close()
	// Point the HTTP tier at the stub.
	g.lookupURLOverride = func(ip string) string { return srv.URL + "/" + ip }

	// In the fixture → local, no HTTP.
	g.prefetch([]string{"81.2.69.142"}, 2*time.Second)
	if hits != 0 {
		t.Errorf("local hit should not touch HTTP, got %d requests", hits)
	}
	if g.cached("81.2.69.142").CC != "GB" {
		t.Error("expected GB from the local tier")
	}

	// Not in the fixture → HTTP fallback.
	g.prefetch([]string{"8.8.8.8"}, 2*time.Second)
	if hits != 1 {
		t.Errorf("expected exactly 1 HTTP fallback request, got %d", hits)
	}
	if ent := g.cached("8.8.8.8"); ent.CC != "TL" {
		t.Errorf("expected the HTTP tier's answer, got %+v", ent)
	}
}
