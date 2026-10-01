package campaign

import (
	"strings"
	"testing"
	"time"
)

// The API contract lists reasons[].label; Task 11 reads it, so an empty label
// is still emitted.
func TestReasonsJSONAlwaysCarriesLabel(t *testing.T) {
	got := reasonsJSON([]Reason{{Kind: "ssh_key", Value: "k", FirstSeen: time.Unix(0, 0)}})
	if !strings.Contains(got, `"label":""`) {
		t.Fatalf("reasons = %s", got)
	}
}
