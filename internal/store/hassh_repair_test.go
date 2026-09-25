package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestRepairCanonicalHASSHBoundedResumable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repair.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	err = s.WithTx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO cowrie_session_hassh(session_id,hassh) VALUES('s','known')`); err != nil {
			return err
		}
		for _, row := range [][3]string{{"cowrie", "cowrie:known", ""}, {"cowrie", "cowrie:known", ""}, {"cowrie", "cowrie:known", ""}, {"cowrie", "cowrie:1.2.3.4", ""}, {"journal", "cowrie:known", ""}, {"cowrie", "cowrie:known", "explicit"}} {
			if _, err := tx.Exec(`INSERT INTO events(ts,source,kind,session_id,actor_id,hassh) VALUES('2026-01-01T00:00:00Z',?,'connect','s',?,?)`, row[0], row[1], row[2]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.RepairCanonicalHASSHBatch(2)
	if err != nil || n != 2 {
		t.Fatalf("first batch=%d %v", n, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	n, err = s.RepairCanonicalHASSHBatch(2)
	if err != nil || n != 1 {
		t.Fatalf("resumed batch=%d %v", n, err)
	}
	for i := 0; i < 2; i++ {
		n, err = s.RepairCanonicalHASSHBatch(2)
		if err != nil || n != 0 {
			t.Fatalf("repeat=%d %v", n, err)
		}
	}
	rows, err := s.db.Query(`SELECT hassh FROM events ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	want := []string{"known", "known", "known", "", "", "explicit"}
	i := 0
	for rows.Next() {
		var got string
		if err := rows.Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want[i] {
			t.Errorf("row %d=%q want %q", i, got, want[i])
		}
		i++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}
