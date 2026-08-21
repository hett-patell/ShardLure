package web

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// mmdbResolver wraps a MaxMind GeoLite2/GeoIP2 City database as the local,
// zero-egress tier of geolocation.
//
// Why this exists (it is not just a speed optimisation):
//
//  1. COVERAGE. The ip-api.com tier is structurally partial. prefetch() caps
//     each call at 48 IPs plus a wall-clock budget and only ever resolves IPs
//     currently rendered in the UI, so IPs that never hit a dashboard
//     viewport were never resolved at all. An MMDB lookup is a memory-mapped
//     read with no quota, so every attacker IP can be resolved.
//
//  2. PRIVACY. Every ip-api lookup ships an attacker IP to a third party, and
//     on the free tier it goes over PLAIN HTTP (see geoLookupURL). That
//     contradicts the discipline the rest of the codebase follows, where the
//     bazaar/abuseipdb candidate structs deliberately omit identifiers so
//     nothing leaks. MMDB lookups leave the host entirely.
//
//  3. AIR-GAP. With the globe engine vendored locally, MMDB is the last piece
//     needed for the dashboard to render a fully populated globe on an
//     egress-filtered network.
//
// The reader is opened once at startup and is safe for concurrent use
// (maxminddb decodes from an immutable mmap). A missing or corrupt file is NOT
// fatal: open() reports the error, geo silently falls back to the HTTP tier,
// and the Settings panel surfaces the reason. That fail-open posture matches
// the keyless enrichment providers.
type mmdbResolver struct {
	db   *geoip2.Reader
	path string
	err  string // human-readable open error, surfaced in the settings badge

	// warnOnce keeps a per-process lid on lookup-error logging: a subtly
	// broken database would otherwise emit one line per IP per poll.
	warnOnce sync.Once
}

// openMMDB opens the database at path. A blank path is the normal
// "not configured" case and yields a nil resolver with no error.
func openMMDB(path string) *mmdbResolver {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	db, err := geoip2.Open(path)
	if err != nil {
		// Report, don't fail: the operator gets a badge in Settings and geo
		// degrades to the HTTP tier rather than the dashboard losing its globe.
		return &mmdbResolver{path: path, err: err.Error()}
	}
	return &mmdbResolver{db: db, path: path}
}

// ready reports whether lookups can be served locally.
func (m *mmdbResolver) ready() bool {
	return m != nil && m.db != nil
}

func (m *mmdbResolver) close() {
	if m != nil && m.db != nil {
		_ = m.db.Close()
	}
}

// lookup resolves one IP locally. The bool is false when the database isn't
// usable, the IP is unparseable, or the database has no city/location record
// for it — all of which mean "let the HTTP tier try".
//
// A record with no coordinates is treated as a miss: the globe plots arcs, so
// a country name with a 0,0 location would draw an arc into the Gulf of
// Guinea. Better to fall through than to render a confident wrong point.
func (m *mmdbResolver) lookup(ip string, now time.Time) (geoEntry, bool) {
	if !m.ready() {
		return geoEntry{}, false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return geoEntry{}, false
	}
	rec, err := m.db.City(parsed)
	if err != nil {
		m.warnOnce.Do(func() {
			fmt.Printf("geo: mmdb lookup failed (%s); falling back to HTTP tier: %v\n", m.path, err)
		})
		return geoEntry{}, false
	}
	if rec == nil {
		return geoEntry{}, false
	}
	lat, lon := rec.Location.Latitude, rec.Location.Longitude
	cc := rec.Country.IsoCode
	if lat == 0 && lon == 0 && cc == "" {
		return geoEntry{}, false
	}

	ent := geoEntry{
		OK:      true,
		Lat:     lat,
		Lon:     lon,
		Country: rec.Country.Names["en"],
		City:    rec.City.Names["en"],
		CC:      cc,
		// A local database has no quota and changes only when the operator
		// swaps the file, so a short TTL would just churn the LRU. The 24h
		// expiry keeps parity with the HTTP tier and bounds staleness after
		// a monthly GeoLite2 refresh.
		Expiry: now.Add(24 * time.Hour),
	}
	return ent, true
}
