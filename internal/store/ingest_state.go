package store

import (
	"database/sql"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// IngestState tracks an append-mode reader's position in a log file so that
// re-reads only scan new bytes. Inode is captured so a log-rotated file with
// the same path but different inode resets the offset.
type IngestState struct {
	Source models.Source
	Path   string
	Inode  uint64
	Offset int64
}

func (s *Store) GetIngestState(source models.Source, path string) (IngestState, bool, error) {
	row := s.db.QueryRow(`SELECT inode, offset FROM ingest_state WHERE source=? AND path=?`, source, path)
	var st IngestState
	st.Source = source
	st.Path = path
	var inode int64
	if err := row.Scan(&inode, &st.Offset); err != nil {
		if err == sql.ErrNoRows {
			return st, false, nil
		}
		return st, false, err
	}
	st.Inode = uint64(inode)
	return st, true, nil
}

func (s *Store) SetIngestState(st IngestState) error {
	_, err := s.execWrite(`
INSERT INTO ingest_state (source, path, inode, offset, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(source, path) DO UPDATE SET inode=excluded.inode, offset=excluded.offset, updated_at=excluded.updated_at`,
		st.Source, st.Path, int64(st.Inode), st.Offset, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
