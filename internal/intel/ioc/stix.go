package ioc

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"time"
)

// STIX 2.1 bundle exporter.
//
// We emit a single bundle containing one identity SDO ("ShardLure")
// and one indicator SDO per IOC value, with a STIX pattern matching
// the IOC kind. Deterministic IDs are derived from a sha1 over
// kind|value so re-exports of the same window produce stable IDs.
//
// References: https://docs.oasis-open.org/cti/stix/v2.1/

const (
	stixSpecVersion = "2.1"
	stixIdentity    = "identity--6e1b3f7b-8c19-4d6e-9c1c-7a3d2b7a51a0" // stable, hard-coded
	stixIdentityName = "ShardLure"
)

type stixBundle struct {
	Type        string      `json:"type"`
	ID          string      `json:"id"`
	SpecVersion string      `json:"spec_version"`
	Objects     []stixObject `json:"objects"`
}

type stixObject struct {
	Type           string    `json:"type"`
	SpecVersion    string    `json:"spec_version,omitempty"`
	ID             string    `json:"id"`
	Created        string    `json:"created,omitempty"`
	Modified       string    `json:"modified,omitempty"`
	Name           string    `json:"name,omitempty"`
	Description    string    `json:"description,omitempty"`
	IdentityClass  string    `json:"identity_class,omitempty"`
	Pattern        string    `json:"pattern,omitempty"`
	PatternType    string    `json:"pattern_type,omitempty"`
	ValidFrom      string    `json:"valid_from,omitempty"`
	Labels         []string  `json:"labels,omitempty"`
	IndicatorTypes []string  `json:"indicator_types,omitempty"`
	CreatedByRef   string    `json:"created_by_ref,omitempty"`
	KillChainPhases []killChainPhase `json:"kill_chain_phases,omitempty"`
	ExternalReferences []externalRef `json:"external_references,omitempty"`
}

type killChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

type externalRef struct {
	SourceName string `json:"source_name"`
	URL        string `json:"url,omitempty"`
	ExternalID string `json:"external_id,omitempty"`
}

// WriteSTIX serialises a STIX 2.1 bundle to w.
func WriteSTIX(w io.Writer, indicators []Indicator) error {
	now := time.Now().UTC().Format(time.RFC3339)

	objects := []stixObject{
		{
			Type:          "identity",
			SpecVersion:   stixSpecVersion,
			ID:            stixIdentity,
			Created:       now,
			Modified:      now,
			Name:          stixIdentityName,
			Description:   "ShardLure honeypot intelligence platform",
			IdentityClass: "organization",
		},
	}

	for _, ind := range indicators {
		obj, ok := indicatorToSTIX(ind, now)
		if !ok {
			continue
		}
		objects = append(objects, obj)
	}

	bundleID := "bundle--" + uuidFromSeed("shardlure-bundle-"+now)
	bundle := stixBundle{
		Type:        "bundle",
		ID:          bundleID,
		SpecVersion: stixSpecVersion,
		Objects:     objects,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(&bundle)
}

func indicatorToSTIX(ind Indicator, created string) (stixObject, bool) {
	var (
		pattern string
		labels  = []string{"malicious-activity"}
	)
	switch ind.Kind {
	case KindIP:
		pattern = "[ipv4-addr:value = '" + stixEsc(ind.Value) + "']"
	case KindHash:
		pattern = "[file:hashes.'SHA-256' = '" + stixEsc(strings.ToLower(ind.Value)) + "']"
	case KindURL:
		pattern = "[url:value = '" + stixEsc(ind.Value) + "']"
	case KindUser:
		// STIX 2.1 has user-account; we pattern on account_login since
		// the username is the only field we have.
		pattern = "[user-account:account_login = '" + stixEsc(ind.Value) + "']"
		labels = []string{"credential-attempt"}
	default:
		return stixObject{}, false
	}

	id := "indicator--" + uuidFromSeed(string(ind.Kind)+"|"+ind.Value)
	desc := "Observed " + string(ind.Kind) + " '" + ind.Value + "' across " +
		joinOrNone(ind.Sources, ",") + " sources from " +
		ind.FirstSeen.UTC().Format(time.RFC3339) + " to " +
		ind.LastSeen.UTC().Format(time.RFC3339) + ". " +
		"Count: " + itoa(ind.Count) + "."
	if ind.SampleCommand != "" {
		desc += " Sample: " + truncate(ind.SampleCommand, 256)
	}

	return stixObject{
		Type:           "indicator",
		SpecVersion:    stixSpecVersion,
		ID:             id,
		Created:        created,
		Modified:       created,
		Name:           string(ind.Kind) + ":" + ind.Value,
		Description:    desc,
		Pattern:        pattern,
		PatternType:    "stix",
		ValidFrom:      ind.FirstSeen.UTC().Format(time.RFC3339),
		Labels:         labels,
		IndicatorTypes: []string{"malicious-activity"},
		CreatedByRef:   stixIdentity,
	}, true
}

func stixEsc(s string) string {
	// STIX 2.1 string literals are single-quoted with backslash
	// escaping for single quotes and backslashes themselves.
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return s
}

func joinOrNone(parts []string, sep string) string {
	if len(parts) == 0 {
		return "no"
	}
	return strings.Join(parts, sep)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func itoa(i int) string {
	// avoid pulling strconv for one call site; ints in IOC counts are tiny
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// uuidFromSeed produces a deterministic UUIDv5-shaped string from a
// stable seed. STIX 2.1 wants `type--<uuid>`; we hash the seed with
// sha1, take 16 bytes, and format as 8-4-4-4-12. The variant + version
// nibbles are forced to v5 / RFC 4122 for spec compliance.
func uuidFromSeed(seed string) string {
	sum := sha1.Sum([]byte(seed))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50 // version 5
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
