package web

import (
	"testing"
	"time"

	"github.com/networkshard/shardlure/internal/settings"
	"github.com/networkshard/shardlure/internal/store"
	"github.com/networkshard/shardlure/pkg/models"
)

func addSummaryEvent(t *testing.T, s *Server, ip string) {
	t.Helper()
	if err := s.st.InsertEvent(&models.Event{
		TS:      time.Now().UTC(),
		Source:  models.SourceCowrie,
		Kind:    models.KindFailedPass,
		SrcIP:   ip,
		ActorID: "cowrie:" + ip,
	}); err != nil {
		t.Fatalf("InsertEvent: %v", err)
	}
}

// The 10-second dashboard cache must not drag slow, all-history aggregates
// along with it. Production takes about three seconds on each statsTTL expiry;
// lifetime values change slowly and have their own longer cache lifetime.
func TestSummaryStatsLifetimeValuesOutliveStatsTTL(t *testing.T) {
	s, _ := hasshTestServer(t)
	addSummaryEvent(t, s, "192.0.2.1")

	first, err := s.summaryStatsCached()
	if err != nil {
		t.Fatalf("first summaryStatsCached: %v", err)
	}
	if first.Events != 1 || first.UniqueIPs != 1 {
		t.Fatalf("first stats = events %d, unique IPs %d; want 1, 1", first.Events, first.UniqueIPs)
	}

	addSummaryEvent(t, s, "192.0.2.2")
	s.statsMu.Lock()
	s.statsAt = time.Now().Add(-statsTTL - time.Second)
	s.statsMu.Unlock()

	second, err := s.summaryStatsCached()
	if err != nil {
		t.Fatalf("second summaryStatsCached: %v", err)
	}
	if second.Events != 2 {
		t.Fatalf("events after short-cache expiry = %d, want 2", second.Events)
	}
	if second.UniqueIPs != 1 {
		t.Fatalf("unique IPs after only short-cache expiry = %d, want cached value 1", second.UniqueIPs)
	}
}

func TestSummaryStatsLifetimeValuesRefreshAfterTheirTTL(t *testing.T) {
	s, _ := hasshTestServer(t)
	addSummaryEvent(t, s, "192.0.2.1")
	if _, err := s.summaryStatsCached(); err != nil {
		t.Fatalf("first summaryStatsCached: %v", err)
	}
	addSummaryEvent(t, s, "192.0.2.2")

	s.lifetimeMu.Lock()
	s.lifetimeAt = time.Now().Add(-lifetimeStatsTTL - time.Second)
	s.lifetimeMu.Unlock()

	got, err := s.summaryStatsCached()
	if err != nil {
		t.Fatalf("refreshed summaryStatsCached: %v", err)
	}
	if got.UniqueIPs != 2 {
		t.Fatalf("unique IPs after lifetime-cache expiry = %d, want 2", got.UniqueIPs)
	}
}

func TestSummaryStatsDistributionsRefreshIndependently(t *testing.T) {
	s, _ := hasshTestServer(t)
	addSummaryEvent(t, s, "192.0.2.1")
	first, err := s.summaryStatsCached()
	if err != nil {
		t.Fatalf("first summaryStatsCached: %v", err)
	}
	if got := labelCount(first.SourceCounts, string(models.SourceCowrie)); got != 1 {
		t.Fatalf("first cowrie source count = %d, want 1", got)
	}

	addSummaryEvent(t, s, "192.0.2.2")
	s.distributionMu.Lock()
	s.distributionAt = time.Now().Add(-distributionStatsTTL - time.Second)
	s.distributionMu.Unlock()

	second, err := s.summaryStatsCached()
	if err != nil {
		t.Fatalf("second summaryStatsCached: %v", err)
	}
	if got := labelCount(second.SourceCounts, string(models.SourceCowrie)); got != 2 {
		t.Fatalf("cowrie source count after distribution expiry = %d, want 2", got)
	}
	if second.UniqueIPs != 1 {
		t.Fatalf("lifetime unique IPs changed with only distribution expiry: got %d, want 1", second.UniqueIPs)
	}
}

func labelCount(rows []store.LabelCount, label string) int {
	for _, row := range rows {
		if row.Label == label {
			return row.Hits
		}
	}
	return 0
}

func TestSummaryCacheTTLsAreTiered(t *testing.T) {
	if distributionStatsTTL <= statsTTL {
		t.Fatalf("distributionStatsTTL (%s) must exceed statsTTL (%s)", distributionStatsTTL, statsTTL)
	}
	if lifetimeStatsTTL <= distributionStatsTTL {
		t.Fatalf("lifetimeStatsTTL (%s) must exceed distributionStatsTTL (%s)", lifetimeStatsTTL, distributionStatsTTL)
	}
	if countriesTTL != lifetimeStatsTTL {
		t.Fatalf("countriesTTL = %s, want lifetimeStatsTTL %s", countriesTTL, lifetimeStatsTTL)
	}
}

// A tier's refresh can fail transiently (TopCommands is a whole-table GROUP BY,
// the likeliest to trip on a WAL checkpoint). The combiner must serve the
// tier's last-good value instead of turning that into a 500 on /api/intel.
func TestSummaryStatsServesLastGoodWhenATierFails(t *testing.T) {
	s, st := hasshTestServer(t)
	addSummaryEvent(t, s, "192.0.2.1")
	first, err := s.summaryStatsCached()
	if err != nil {
		t.Fatalf("first summaryStatsCached: %v", err)
	}
	s.lifetimeMu.Lock()
	s.lifetimeAt = time.Now().Add(-lifetimeStatsTTL - time.Second)
	s.lifetimeMu.Unlock()
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	got, err := s.summaryStatsCached()
	if err != nil {
		t.Fatalf("a failed lifetime refresh surfaced as an error: %v", err)
	}
	if got.UniqueIPs != first.UniqueIPs || got.Events != first.Events {
		t.Fatalf("stale values not served: got ips %d events %d, want %d/%d", got.UniqueIPs, got.Events, first.UniqueIPs, first.Events)
	}
}

// On a fresh database the geo table is filled asynchronously by the handler
// that reads these values, so an empty first read must expire on the SHORT
// TTL — caching it for five minutes froze Attack Geography at "resolving…".
func TestEmptyGeoResultsExpireOnTheShortTTL(t *testing.T) {
	s, st := hasshTestServer(t)
	// A configured MMDB makes geo enabled on its own (no outbound HTTP), which
	// is the production shape; without it the tier would rightly treat a zero
	// as final and this test would prove nothing.
	keys, err := settings.Load(st)
	if err != nil {
		t.Fatalf("settings.Load: %v", err)
	}
	s.geo = newGeoResolver(geoConfig{MMDB: testMMDB}, st, keys)
	if !s.geo.isEnabled() {
		t.Fatal("test MMDB did not enable geo")
	}
	addSummaryEvent(t, s, "192.0.2.1")
	if rows := s.topCountriesCached(); len(rows) != 0 {
		t.Fatalf("expected no countries before any geo lookup, got %d", len(rows))
	}
	if age := time.Since(s.countriesAt); age < countriesTTL-statsTTL-time.Second {
		t.Fatalf("empty country list stamped for the long TTL (age %s)", age)
	}
	if _, err := s.lifetimeSummaryStatsCached(); err != nil {
		t.Fatalf("lifetime tier: %v", err)
	}
	if age := time.Since(s.lifetimeAt); age < lifetimeStatsTTL-statsTTL-time.Second {
		t.Fatalf("zero-country lifetime value stamped for the long TTL (age %s)", age)
	}
}
