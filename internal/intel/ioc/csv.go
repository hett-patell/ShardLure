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
	return WriteCSVWithCoverage(w, indicators, Coverage{})
}

// WriteCSVWithCoverage is WriteCSV plus an in-band sampling disclosure.
//
// When cov reports a sampled window, a single `#`-prefixed comment line is
// emitted BEFORE the header row, because a downloaded file cannot carry the
// advisory HTTP header the API sets (see Coverage). A leading `#` comment is
// the least invasive place to put it: the column schema is documented as
// stable, and adding a column would break every consumer parsing by index,
// whereas RFC4180 readers configured for comments skip the line and strict
// ones surface it as an obvious single-field row rather than corrupt data.
//
// An unsampled (zero) Coverage writes nothing extra, so a complete export
// stays byte-identical to what WriteCSV always produced.
func WriteCSVWithCoverage(w io.Writer, indicators []Indicator, cov Coverage) error {
	if note := cov.Note(); note != "" {
		// Written directly, not through the csv.Writer: encoding/csv would
		// quote it into a data row, which is exactly what it must not become.
		if _, err := io.WriteString(w, "# "+note+"\n"); err != nil {
			return err
		}
	}

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
