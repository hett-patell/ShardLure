package web

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// GetScript lists the newest 500 sessions and the actors among them; the
// detail JSON carries the store's true sessionsTotal and actorsTotal so the
// dialog never reads the capped lists as the whole (store-reads audit M2).
func TestScriptDetailCarriesTrueTotals(t *testing.T) {
	_, mux, _, raw := listTotalsServer(t)
	fp := strings.Repeat("a", 64)
	const ts = "2026-09-20T00:00:00.000000000Z"
	if _, err := raw.Exec(`INSERT INTO scripts(fingerprint,normalized,display,command_count,distinctive,family,family_distance,token_count,first_seen,last_seen)
VALUES(?,?,?,3,1,?,0,3,?,?)`, fp, "n", "cd /tmp", fp, ts, ts); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 503; i++ {
		// The two oldest sessions belong to actors seen nowhere else, so
		// they fall outside the 500-session list.
		actor := "cowrie:bulk"
		if i < 2 {
			actor = fmt.Sprintf("cowrie:old%d", i)
		}
		at := base.Add(time.Duration(i) * time.Minute).Format("2006-01-02T15:04:05.000000000Z")
		if _, err := raw.Exec(`INSERT INTO session_scripts(session_id,actor_id,src_ip,first_seen,last_seen,updated_at,settled_at,fingerprint)
VALUES(?,?,?,?,?,?,?,?)`, fmt.Sprintf("s%03d", i), actor, "198.51.100.1", at, at, at, at, fp); err != nil {
			t.Fatal(err)
		}
	}
	var d struct {
		Sessions      []any    `json:"sessions"`
		Actors        []string `json:"actors"`
		SessionsTotal int      `json:"sessionsTotal"`
		ActorsTotal   int      `json:"actorsTotal"`
	}
	getJSON(t, mux, "/api/intel/script?fp="+fp, &d)
	if len(d.Sessions) != 500 || d.SessionsTotal != 503 || len(d.Actors) != 1 || d.ActorsTotal != 3 {
		t.Fatalf("sessions %d of %d, actors %d of %d; want 500 of 503, 1 of 3", len(d.Sessions), d.SessionsTotal, len(d.Actors), d.ActorsTotal)
	}
}

// The dialog's subtitle uses actorsTotal, and the capped session list says
// "showing N of M".
func TestScriptDialogUsesTrueActorTotal(t *testing.T) {
	out := runCampaignJS(t, `
  replyGet = () => jsonReply({ fingerprint: 'a'.repeat(64), family: 'a'.repeat(64), display: 'cd /tmp',
    sessions: [{ sessionId: 's1', actorId: 'cowrie:bulk', srcIp: '198.51.100.1' }], actors: ['cowrie:bulk'], sessionsTotal: 503, actorsTotal: 3 });
  await openScript('a'.repeat(64));
  console.log(JSON.stringify({ sub: document.getElementById('cm-sub').textContent, body: document.getElementById('cm-body').innerHTML }));
`)
	var got struct{ Sub, Body string }
	decodeJS(t, out, &got)
	if got.Sub != "503 sessions · 3 actors" {
		t.Errorf("sub = %q, want the true totals", got.Sub)
	}
	if !strings.Contains(got.Body, `sessions <span class="cm-more">(showing 1 of 503)</span>`) {
		t.Errorf("capped session list not disclosed: %s", got.Body)
	}
}
