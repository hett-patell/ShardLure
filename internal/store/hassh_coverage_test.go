package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// TestHASSHCoverage verifies the identity-over-IP coverage metric is
// EVENT-weighted over cowrie telemetry, not actor-row weighted.
//
// Row-counting was wrong and actively misleading: a hassh-keyed actor is a
// CONSOLIDATED identity (one observed on the live box spanned 784 IPs) while an
// IP-keyed actor is a single IP, so the better clustering worked the worse the
// ratio looked — the live dashboard reported 3% while 93.5% of cowrie events
// actually carried a fingerprint. Journal events are excluded from the
// denominator because sshd logs cannot carry a HASSH at all.
func TestHASSHCoverage(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "cov.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	ev := []*models.Event{
		// 3 cowrie events WITH a fingerprint, all one actor (mimics clustering).
		{TS: now, Source: models.SourceCowrie, Kind: models.KindCommand, SrcIP: "1.1.1.1", SessionID: "s1", HASSH: "aa:bb", ActorID: "cowrie:aa:bb"},
		{TS: now, Source: models.SourceCowrie, Kind: models.KindCommand, SrcIP: "2.2.2.2", SessionID: "s2", HASSH: "aa:bb", ActorID: "cowrie:aa:bb"},
		{TS: now, Source: models.SourceCowrie, Kind: models.KindCommand, SrcIP: "3.3.3.3", SessionID: "s3", HASSH: "aa:bb", ActorID: "cowrie:aa:bb"},
		// 1 cowrie event WITHOUT a fingerprint (never completed kex).
		{TS: now, Source: models.SourceCowrie, Kind: models.KindConnect, SrcIP: "4.4.4.4", SessionID: "s4", ActorID: "cowrie:4.4.4.4"},
		// 5 journal events — MUST NOT appear in the denominator (sshd has no hassh).
		{TS: now, Source: models.SourceJournal, Kind: models.KindFailedPass, SrcIP: "9.9.9.9", Username: "root", ActorID: "journal:9.9.9.9"},
		{TS: now, Source: models.SourceJournal, Kind: models.KindFailedPass, SrcIP: "9.9.9.9", Username: "admin", ActorID: "journal:9.9.9.9"},
		{TS: now, Source: models.SourceJournal, Kind: models.KindFailedPass, SrcIP: "9.9.9.9", Username: "test", ActorID: "journal:9.9.9.9"},
		{TS: now, Source: models.SourceJournal, Kind: models.KindFailedPass, SrcIP: "9.9.9.9", Username: "oracle", ActorID: "journal:9.9.9.9"},
		{TS: now, Source: models.SourceJournal, Kind: models.KindFailedPass, SrcIP: "9.9.9.9", Username: "deploy", ActorID: "journal:9.9.9.9"},
	}
	if err := st.AppendEventsAndUpsertActorsAgg(ev, nil); err != nil {
		t.Fatal(err)
	}

	fp, total, err := st.HASSHCoverage()
	if err != nil {
		t.Fatal(err)
	}
	// 4 cowrie events total, 3 fingerprinted. Journal's 5 are excluded.
	if total != 4 {
		t.Fatalf("total = %d, want 4 (cowrie events only; journal must be excluded)", total)
	}
	if fp != 3 {
		t.Fatalf("fingerprinted = %d, want 3 (cowrie events carrying a hassh)", fp)
	}
}
