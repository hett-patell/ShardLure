package ioc

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"
	"time"
)

// WriteCSV writes indicators to w with a stable schema.
//
// Schema:
//
//	kind,value,first_seen,last_seen,count,sources,actors,sample_command
//
// Time fields are RFC3339 UTC. List fields use a `|` separator so the
// CSV survives downstream tools that re-quote per-field commas.
func WriteCSV(w io.Writer, indicators []Indicator) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write([]string{
		"kind", "value", "first_seen", "last_seen", "count",
		"sources", "actors", "sample_command",
	}); err != nil {
		return err
	}
	for _, ind := range indicators {
		row := []string{
			string(ind.Kind),
			csvSafe(ind.Value),
			ind.FirstSeen.UTC().Format(time.RFC3339),
			ind.LastSeen.UTC().Format(time.RFC3339),
			strconv.Itoa(ind.Count),
			csvSafe(strings.Join(ind.Sources, "|")),
			csvSafe(strings.Join(ind.Actors, "|")),
			csvSafe(ind.SampleCommand),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	return cw.Error()
}

// csvSafe neutralizes spreadsheet formula injection (CSV injection, CWE-1236).
// encoding/csv only does RFC4180 quoting; it does NOT stop a cell beginning
// with = + - @ (or a leading tab/CR) from being evaluated as a formula when
// the export is opened in Excel/LibreOffice/Sheets. Several IOC fields are
// fully attacker-controlled (a captured username or shell command), so prefix
// any such field with an apostrophe to force literal text.
func csvSafe(v string) string {
	if v == "" {
		return v
	}
	switch v[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + v
	}
	return v
}
