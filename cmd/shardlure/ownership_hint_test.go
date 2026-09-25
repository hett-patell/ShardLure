package main

import "testing"

// A refused open used to end at "run as the owning service account", which
// named neither the account nor the command. The hint names both.
func TestOwnershipHintNamesOwnerAndCommand(t *testing.T) {
	names := map[uint32]string{0: "root", 999: "shardlure"}
	lookup := func(uid uint32) (string, bool) { n, ok := names[uid]; return n, ok }
	for _, tc := range []struct {
		name       string
		owner, uid uint32
		args       []string
		want       string
	}{
		{"root-owned, normal user", 0, 1001, []string{"shardlure", "dashboard"}, "the database is owned by root; run: sudo shardlure dashboard"},
		{"service-owned, root", 999, 0, []string{"shardlure", "-config", "/var/lib/shardlure/shardlure.yaml", "status"}, "the database is owned by shardlure; run: sudo -u shardlure shardlure -config /var/lib/shardlure/shardlure.yaml status"},
		{"service-owned, other user", 999, 1001, []string{"./shardlure", "actors"}, "the database is owned by shardlure; run: sudo -u shardlure ./shardlure actors"},
		{"unknown owner", 4242, 1001, []string{"shardlure", "status"}, "the database is owned by uid 4242; run: sudo -u '#4242' shardlure status"},
		{"argument with spaces", 0, 1001, []string{"shardlure", "-config", "/srv/my cfg.yaml", "status"}, "the database is owned by root; run: sudo shardlure -config '/srv/my cfg.yaml' status"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ownershipHint(tc.owner, tc.uid, lookup, tc.args); got != tc.want {
				t.Fatalf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}
