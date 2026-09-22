package backup

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

func relativeName(name string) bool {
	return name != "" && name != "." && len(name) <= 4096 && !strings.HasPrefix(name, "/") && path.Clean(name) == name && name != ".." && !strings.HasPrefix(name, "../") && !strings.ContainsRune(name, 0) && utf8.ValidString(name)
}
func validHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && s == strings.ToLower(s)
}
func entryAllowed(e Entry) bool {
	if !relativeName(e.Path) || e.Bytes < 0 || !validHash(e.SHA256) {
		return false
	}
	switch e.Role {
	case "database":
		if e.Path != "database/shardlure.db" {
			return false
		}
	case "config":
		if e.Path != "metadata/config.yaml" {
			return false
		}
	case "included":
		if !strings.HasPrefix(e.Path, "metadata/included/") {
			return false
		}
	case "evidence", "cowrie-logs", "cowrie-downloads", "cowrie-tty":
		if !strings.HasPrefix(e.Path, "files/"+e.Role+"/") {
			return false
		}
	default:
		return false
	}
	source := strings.HasPrefix(e.Role, "cowrie-")
	if source {
		_, zone := e.ObservedAt.Zone()
		return e.PrefixBytes != nil && *e.PrefixBytes == e.Bytes && !e.ObservedAt.IsZero() && zone == 0
	}
	return e.PrefixBytes == nil && e.ObservedAt.IsZero()
}

func validateManifest(m Manifest) (map[string]Entry, int64, error) {
	if m.FormatVersion != 1 || !m.Complete || m.Schema < 1 || m.Schema > 24 || m.CreatedAt.IsZero() {
		return nil, 0, ErrInvalidManifest
	}
	if _, zone := m.CreatedAt.Zone(); zone != 0 {
		return nil, 0, ErrInvalidManifest
	}
	if len(m.Entries) > maxManifestEntries || len(m.AppVersion) > 256 || len(m.AppCommit) > 256 {
		return nil, 0, ErrManifestLimit
	}
	if len(m.SourceRoots) != len(rootRoles) || len(m.TableCounts) > 64 {
		return nil, 0, ErrInvalidManifest
	}
	for role := range rootRoles {
		value := m.SourceRoots[role]
		if len(value) > 4096 || !filepath.IsAbs(value) || filepath.Clean(value) != value || strings.ContainsRune(value, 0) || !utf8.ValidString(value) {
			return nil, 0, ErrInvalidManifest
		}
	}
	for k, n := range m.TableCounts {
		if k == "" || len(k) > 64 || n < 0 {
			return nil, 0, ErrInvalidManifest
		}
	}
	entries := make(map[string]Entry, len(m.Entries))
	var total int64
	for _, e := range m.Entries {
		if !entryAllowed(e) {
			return nil, 0, ErrInvalidManifest
		}
		if _, ok := entries[e.Path]; ok {
			return nil, 0, ErrInvalidManifest
		}
		if total > math.MaxInt64-e.Bytes {
			return nil, 0, ErrInvalidManifest
		}
		total += e.Bytes
		entries[e.Path] = e
	}
	if entries["database/shardlure.db"].Role != "database" || entries["metadata/config.yaml"].Role != "config" {
		return nil, 0, ErrInvalidManifest
	}
	return entries, total, nil
}

// Decode entries individually: a short JSON array of millions of empty objects
// must hit the entry limit before allocating an unbounded []Entry. The byte
// limit also bounds a single enormous JSON string before its field validation.
func decodeManifest(r io.Reader) (m Manifest, result error) {
	limit := &io.LimitedReader{R: r, N: maxManifestBytes + 1}
	defer func() {
		if limit.N <= 0 {
			result = ErrManifestLimit
		}
	}()
	d := json.NewDecoder(limit)
	d.DisallowUnknownFields()
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return m, ErrInvalidManifest
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return m, ErrInvalidManifest
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return m, ErrInvalidManifest
		}
		seen[key] = true
		switch key {
		case "formatVersion":
			err = d.Decode(&m.FormatVersion)
		case "complete":
			err = d.Decode(&m.Complete)
		case "appVersion":
			err = d.Decode(&m.AppVersion)
		case "appCommit":
			err = d.Decode(&m.AppCommit)
		case "schema":
			err = d.Decode(&m.Schema)
		case "createdAt":
			err = d.Decode(&m.CreatedAt)
		case "sourceRoots":
			m.SourceRoots, err = decodeRoots(d)
		case "tableCounts":
			m.TableCounts, err = decodeCounts(d)
		case "entries":
			token, err = d.Token()
			if err != nil || token != json.Delim('[') {
				return m, ErrInvalidManifest
			}
			for d.More() {
				if len(m.Entries) >= maxManifestEntries {
					return m, ErrManifestLimit
				}
				e, err := decodeEntry(d)
				if err != nil {
					return m, ErrInvalidManifest
				}
				if !entryAllowed(e) {
					return m, ErrInvalidManifest
				}
				m.Entries = append(m.Entries, e)
			}
			token, err = d.Token()
			if err == nil && token != json.Delim(']') {
				err = ErrInvalidManifest
			}
		default:
			return m, ErrInvalidManifest
		}
		if err != nil {
			return m, err
		}
		if limit.N <= 0 {
			return m, ErrManifestLimit
		}
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return m, ErrInvalidManifest
	}
	if _, err = d.Token(); err != io.EOF {
		return m, ErrInvalidManifest
	}
	if limit.N <= 0 {
		return m, ErrManifestLimit
	}
	return m, nil
}

func decodeEntry(d *json.Decoder) (Entry, error) {
	var e Entry
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return e, ErrInvalidManifest
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return e, ErrInvalidManifest
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return e, ErrInvalidManifest
		}
		seen[key] = true
		switch key {
		case "path":
			err = d.Decode(&e.Path)
		case "role":
			err = d.Decode(&e.Role)
		case "sha256":
			err = d.Decode(&e.SHA256)
		case "bytes":
			err = d.Decode(&e.Bytes)
		case "prefixBytes":
			err = d.Decode(&e.PrefixBytes)
		case "observedAt":
			err = d.Decode(&e.ObservedAt)
		default:
			return e, ErrInvalidManifest
		}
		if err != nil {
			return e, ErrInvalidManifest
		}
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') {
		return e, ErrInvalidManifest
	}
	for _, key := range []string{"path", "role", "sha256", "bytes"} {
		if !seen[key] {
			return e, ErrInvalidManifest
		}
	}
	return e, nil
}

func decodeRoots(d *json.Decoder) (map[string]string, error) {
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrInvalidManifest
	}
	out := make(map[string]string, len(rootRoles))
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, ErrInvalidManifest
		}
		key, ok := token.(string)
		if !ok || !rootRoles[key] {
			return nil, ErrInvalidManifest
		}
		if _, ok := out[key]; ok {
			return nil, ErrInvalidManifest
		}
		var value string
		if err := d.Decode(&value); err != nil || len(value) > 4096 {
			return nil, ErrInvalidManifest
		}
		out[key] = value
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') {
		return nil, ErrInvalidManifest
	}
	return out, nil
}
func decodeCounts(d *json.Decoder) (map[string]int64, error) {
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrInvalidManifest
	}
	out := map[string]int64{}
	for d.More() {
		if len(out) >= 64 {
			return nil, ErrManifestLimit
		}
		token, err := d.Token()
		if err != nil {
			return nil, ErrInvalidManifest
		}
		key, ok := token.(string)
		if !ok || len(key) > 64 {
			return nil, ErrInvalidManifest
		}
		if _, ok := out[key]; ok {
			return nil, ErrInvalidManifest
		}
		var value int64
		if err := d.Decode(&value); err != nil || value < 0 {
			return nil, ErrInvalidManifest
		}
		out[key] = value
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') {
		return nil, ErrInvalidManifest
	}
	return out, nil
}
