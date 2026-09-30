package web

import (
	"strings"
	"testing"
)

// Final audit M2, frontend half: the Scripts row counts variantsTotal (not
// the capped list), and the script dialog names the family's true variant
// count and says "showing N of M" above the capped variant list.
func TestScriptDialogDisclosesVariantCap(t *testing.T) {
	out := runCampaignJS(t, `
  const fp = n => String(n).repeat(64);
  replyGet = url => url.startsWith('/api/intel/scripts')
    ? jsonReply({ families: [{ family: fp(1), display: 'cd /tmp', variants: [{ fingerprint: fp(1), sessions: 9 }], variantsTotal: 300, sessions: 900 }], total: 1 })
    : jsonReply({ fingerprint: fp(2), family: fp(1), display: 'cd /tmp', sessions: [], sessionsTotal: 4, actors: [],
        familySessions: 900, familyActors: 7, variants: [{ fingerprint: fp(1), sessions: 9 }, { fingerprint: fp(2), sessions: 4 }], variantsTotal: 300 });
  await refreshScripts();
  const row = document.querySelector('#scripts-table tbody').innerHTML;
  await openScript(fp(2));
  console.log(JSON.stringify({ row, sub: document.getElementById('cm-sub').textContent, body: document.getElementById('cm-body').innerHTML }));
`)
	var got struct{ Row, Sub, Body string }
	decodeJS(t, out, &got)
	if !strings.Contains(got.Row, `<td class="num">300</td>`) {
		t.Errorf("Scripts row must count variantsTotal: %s", got.Row)
	}
	if !strings.Contains(got.Sub, "family: 300 variants") {
		t.Errorf("dialog subtitle = %q, want the family's true variant count", got.Sub)
	}
	if !strings.Contains(got.Body, "variants in this family <span class=\"cm-more\">(showing 2 of 300)</span>") {
		t.Errorf("variant list must disclose its cap: %s", got.Body)
	}
}
