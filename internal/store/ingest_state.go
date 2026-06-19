package store

import (
	"database/sql"
	"time"

	"github.com/networkshard/shardlure/pkg/models"
)

// IngestState tracks an append-mode reader's position in a log file so that
// re-reads only scan new bytes. Inode is captured so a log-rotated file with
// the same path but different inode resets the offset. HeadSig is a fingerprint
// of the file's first bytes: copytruncate-style rotation (truncate-in-place,
// same inode, then regrow) keeps the inode but changes the head, so a HeadSig
// mismatch signals the file was replaced and the offset must reset to 0.
type IngestState struct {
	Source  models.Source
	Path    string
	Inode   uint64
	Offset  int64
	HeadSig string
}

func (s *Store) GetIngestState(source models.Source, path string) (IngestState, bool, error) {
	row := s.db.QueryRow(`SELECT inode, offset, COALESCE(head_sig, '') FROM ingest_state WHERE source=? AND path=?`, source, path)
	var st IngestState
	st.Source = source
	st.Path = path
	var inode int64
	if err := row.Scan(&inode, &st.Offset, &st.HeadSig); err != nil {
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
INSERT INTO ingest_state (source, path, inode, offset, head_sig, updated_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(source, path) DO UPDATE SET inode=excluded.inode, offset=excluded.offset, head_sig=excluded.head_sig, updated_at=excluded.updated_at`,
		st.Source, st.Path, int64(st.Inode), st.Offset, st.HeadSig, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
