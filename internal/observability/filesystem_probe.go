package observability

import (
	"context"
	"github.com/networkshard/shardlure/internal/safefile"
	"time"
)

// NewFilesystemProbe checks only the two configured directory descriptors and
// the supplied cheap DB probe. It never walks evidence or opens payload bytes.
func NewFilesystemProbe(database func(context.Context) error, data, evidence string, capture bool) Probe {
	return func(ctx context.Context) (Sample, error) {
		sample := Sample{At: time.Now().UTC(), CaptureRequired: capture}
		if err := ctx.Err(); err != nil {
			return sample, err
		}
		sample.DatabaseUp = database != nil && database(ctx) == nil
		if err := ctx.Err(); err != nil {
			return sample, err
		}
		sample.DataAccessible, sample.DataFreeBytes = probeVolume(data)
		if err := ctx.Err(); err != nil {
			return sample, err
		}
		if capture {
			sample.EvidenceAccessible, sample.EvidenceFreeBytes = probeVolume(evidence)
		}
		return sample, ctx.Err()
	}
}
func probeVolume(path string) (bool, uint64) {
	root, err := safefile.OpenRoot(path)
	if err != nil {
		return false, 0
	}
	defer root.Close()
	if err := root.CheckWritable(); err != nil {
		return false, 0
	}
	free, err := root.AvailableBytes()
	if err != nil {
		return false, 0
	}
	return true, free
}
