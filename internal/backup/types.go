// Package backup creates and verifies owner-only, non-executable recovery data.
// It never starts services, migrates an application store, or calls providers.
package backup

import "time"

type CreateOptions struct {
	ConfigPath, Output, AppVersion, AppCommit string
	IncludeFiles                              []string
}
type Entry struct {
	Path        string    `json:"path"`
	Role        string    `json:"role"`
	SHA256      string    `json:"sha256"`
	Bytes       int64     `json:"bytes"`
	PrefixBytes *int64    `json:"prefixBytes,omitempty"`
	ObservedAt  time.Time `json:"observedAt,omitzero"`
}
type Manifest struct {
	FormatVersion int               `json:"formatVersion"`
	Complete      bool              `json:"complete"`
	AppVersion    string            `json:"appVersion"`
	AppCommit     string            `json:"appCommit"`
	Schema        int               `json:"schema"`
	CreatedAt     time.Time         `json:"createdAt"`
	SourceRoots   map[string]string `json:"sourceRoots"`
	TableCounts   map[string]int64  `json:"tableCounts"`
	Entries       []Entry           `json:"entries"`
}
type Report struct {
	Files       int              `json:"files"`
	Bytes       int64            `json:"bytes"`
	Schema      int              `json:"schema"`
	TableCounts map[string]int64 `json:"tableCounts"`
}

const maxManifestBytes int64 = 64 << 20
const maxManifestEntries = 1_000_000
const incompleteName = ".incomplete"

var rootRoles = map[string]bool{"data": true, "evidence": true, "cowrie-logs": true, "cowrie-downloads": true, "cowrie-tty": true}
