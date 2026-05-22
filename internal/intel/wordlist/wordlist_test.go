package wordlist

import (
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func TestCollectUsernames(t *testing.T) {
	t0 := time.Now()
	ev := func(u, p string, k models.EventKind) *models.Event {
		return &models.Event{TS: t0, Source: models.SourceCowrie, Kind: k, Username: u, Password: p}
	}
	events := []*models.Event{
		ev("root", "toor", models.KindFailedPass),
		ev("root", "123456", models.KindFailedPass),
		ev("root", "", models.KindFailedKey),
		ev("admin", "admin", models.KindFailedPass),
		ev("admin", "password", models.KindFailedPass),
		ev("postgres", "postgres", models.KindInvalidUser),
		// command event - should NOT contribute usernames
		ev("root", "", models.KindCommand),
	}

	u := CollectUsernames(events)
	if len(u) != 3 {
		t.Fatalf("got %d users want 3: %+v", len(u), u)
	}
	if u[0].Username != "root" || u[0].Count != 3 {
		t.Errorf("top user = %+v, want root/3", u[0])
	}
	if u[1].Username != "admin" || u[1].Count != 2 {
		t.Errorf("second user = %+v, want admin/2", u[1])
	}
}

func TestCollectPasswords(t *testing.T) {
	t0 := time.Now()
	ev := func(u, p string, k models.EventKind) *models.Event {
		return &models.Event{TS: t0, Kind: k, Username: u, Password: p}
	}
	events := []*models.Event{
		ev("a", "123456", models.KindFailedPass),
		ev("b", "123456", models.KindFailedPass),
		ev("c", "toor", models.KindFailedPass),
		// empty password - skipped
		ev("d", "", models.KindFailedPass),
	}
	p := CollectPasswords(events)
	if len(p) != 2 || p[0].Password != "123456" || p[0].Count != 2 {
		t.Errorf("top password = %+v", p)
	}
}

func TestCollectCombos(t *testing.T) {
	t0 := time.Now()
	ev := func(u, p string) *models.Event {
		return &models.Event{TS: t0, Kind: models.KindFailedPass, Username: u, Password: p}
	}
	events := []*models.Event{
		ev("root", "toor"), ev("root", "toor"), ev("root", "toor"),
		ev("admin", "admin"),
		ev("root", "123456"),
	}
	c := CollectCombos(events)
	if len(c) != 3 {
		t.Fatalf("got %d combos want 3: %+v", len(c), c)
	}
	if c[0].Username != "root" || c[0].Password != "toor" || c[0].Count != 3 {
		t.Errorf("top combo = %+v", c[0])
	}
}

func TestWriteCombos(t *testing.T) {
	var b strings.Builder
	WriteCombos(&b, []Entry{
		{Username: "root", Password: "toor", Count: 5},
		{Username: "admin", Password: "admin", Count: 3},
	})
	want := "root:toor\nadmin:admin\n"
	if b.String() != want {
		t.Errorf("WriteCombos = %q\nwant %q", b.String(), want)
	}
}
