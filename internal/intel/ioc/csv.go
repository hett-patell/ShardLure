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
			ind.Value,
			ind.FirstSeen.UTC().Format(time.RFC3339),
			ind.LastSeen.UTC().Format(time.RFC3339),
			strconv.Itoa(ind.Count),
			strings.Join(ind.Sources, "|"),
			strings.Join(ind.Actors, "|"),
			ind.SampleCommand,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	return cw.Error()
}
