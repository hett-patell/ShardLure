package web

import "testing"

// Final audit M1, frontend half: a capped list's meta line says "showing N of
// M" from the API's total, and an uncapped (or total-less) list shows its
// plain count. Runs the page's refreshCampaigns/refreshScripts under node.
func TestCampaignListsDiscloseCapInMeta(t *testing.T) {
	out := runCampaignJS(t, `
  const res = {};
  for (const total of [1234, 2, undefined]) {
    replyGet = url => url.startsWith('/api/intel/campaigns')
      ? jsonReply({ campaigns: [{ id: 'c-000000000001' }, { id: 'c-000000000002' }], total })
      : jsonReply({ families: [{ family: 'a', display: 'x' }, { family: 'b', display: 'y' }], total });
    await refreshCampaigns();
    await refreshScripts();
    res[String(total)] = [document.getElementById('campaigns-meta').textContent, document.getElementById('scripts-meta').textContent];
  }
  console.log(JSON.stringify(res));
`)
	var got map[string][2]string
	decodeJS(t, out, &got)
	want := map[string][2]string{
		"1234":      {"showing 2 of 1,234 campaigns", "showing 2 of 1,234 script families"},
		"2":         {"2 campaigns", "2 script families"},
		"undefined": {"2 campaigns", "2 script families"},
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("total %s: meta = %q, want %q", k, got[k], w)
		}
	}
}
