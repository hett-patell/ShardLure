package store

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

func remapStoredPath(value, role string, source, target map[string]string) (string, error) {
	from, to := source[role], target[role]
	if !filepath.IsAbs(to) || filepath.Clean(to) != to || strings.ContainsRune(to, 0) || !utf8.ValidString(to) {
		return "", ErrSnapshotInvalid
	}
	if !filepath.IsAbs(value) {
		from = source[role+"_relative"]
		if from == "" || filepath.IsAbs(from) {
			return "", ErrSnapshotInvalid
		}
	}
	if from == "" {
		return "", ErrSnapshotInvalid
	}
	rel, err := filepath.Rel(from, filepath.Clean(value))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || strings.ContainsRune(value, 0) {
		return "", ErrSnapshotInvalid
	}
	mapped := filepath.Join(to, rel)
	if len(mapped) > 4096 {
		return "", ErrSnapshotInvalid
	}
	return mapped, nil
}

// Explicit one-off imports leave Cowrie checkpoints outside the live log root.
// They are metadata, not files a restore may open or automatically replay. Keep
// their identity (including distinct imports with the same basename), but let
// the normal cursor update below clear the old inode/offset/head signature.
// Only canonical absolute paths qualify; evidence and malformed paths retain
// the strict remapping refusal. Validate both roots before allowing this case
// so a bad destination cannot be mistaken for an unrelated historical import.
func detachedCowrieCursor(value string, source, target map[string]string) bool {
	from, to := source["cowrie-logs"], target["cowrie-logs"]
	for _, p := range []string{value, from, to} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || len(p) > 4096 || strings.ContainsRune(p, 0) || !utf8.ValidString(p) {
			return false
		}
	}
	rel, err := filepath.Rel(from, value)
	return err == nil && (rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// RemapSnapshotPaths changes only portable storage/cursor pointers in a private,
// standalone snapshot. It never opens a migrating Store or activates services.
// Partial failure leaves the caller's unpublished recovery staging incomplete.
func RemapSnapshotPaths(ctx context.Context, dbPath string, sourceRoots, targetRoots map[string]string) (result error) {
	ctx, cancel := snapshotContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := CheckDatabaseOwner(dbPath); err != nil {
		return err
	}
	before, err := InspectSnapshot(ctx, dbPath)
	if err != nil {
		return err
	}
	uri, err := sqliteFileURI(dbPath, url.Values{"mode": {"rw"}, "_pragma": {"journal_mode(DELETE)", "trusted_schema(OFF)", "foreign_keys(OFF)", "busy_timeout(25)"}})
	if err != nil {
		return err
	}
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return safeSnapshotError(err)
	}
	db.SetMaxOpenConns(1)
	defer func() { result = safeSnapshotError(errors.Join(result, db.Close())) }()
	for _, target := range []struct {
		table, column, role, predicate string
		since                          int
	}{
		{"artifacts", "local_path", "evidence", "1", 1},
		{"capture_file_jobs", "result_path", "evidence", "1", 24},
		{"ingest_state", "path", "cowrie-logs", "source='cowrie'", 1},
	} {
		if before.Schema < target.since {
			continue
		}
		present, err := snapshotTablePresent(ctx, db, target.table)
		if err != nil {
			return err
		}
		if !present {
			continue
		}
		columns := map[string]bool{}
		rows, err := db.QueryContext(ctx, "PRAGMA table_info("+target.table+")")
		if err != nil {
			return err
		}
		for rows.Next() {
			var id, notnull, pk int
			var name, kind string
			var def any
			if err := rows.Scan(&id, &name, &kind, &notnull, &def, &pk); err != nil {
				rows.Close()
				return err
			}
			columns[name] = true
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if !columns[target.column] {
			continue
		}
		// No shipped trigger belongs to a remapped table. Executing an untrusted
		// bundle's trigger could rewrite evidence/settings while appearing to remap.
		var triggers int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_schema WHERE type='trigger' AND tbl_name=?", target.table).Scan(&triggers); err != nil {
			return err
		}
		if triggers != 0 {
			return ErrSnapshotInvalid
		}
		var cursor int64
		for {
			rows, err := db.QueryContext(ctx, "SELECT rowid,CASE WHEN length(CAST("+target.column+" AS BLOB))<=4096 THEN "+target.column+" END FROM "+target.table+" WHERE rowid>? AND COALESCE("+target.column+",'')<>'' AND "+target.predicate+" ORDER BY rowid LIMIT 256", cursor)
			if err != nil {
				return err
			}
			type change struct {
				id   int64
				path string
			}
			var changes []change
			for rows.Next() {
				var id int64
				var raw sql.NullString
				if err := rows.Scan(&id, &raw); err != nil {
					rows.Close()
					return err
				}
				if !raw.Valid {
					rows.Close()
					return ErrSnapshotInvalid
				}
				newPath, err := remapStoredPath(raw.String, target.role, sourceRoots, targetRoots)
				if err != nil && target.table == "ingest_state" && detachedCowrieCursor(raw.String, sourceRoots, targetRoots) {
					newPath, err = raw.String, nil
				}
				if err != nil {
					rows.Close()
					return err
				}
				changes = append(changes, change{id, newPath})
				cursor = id
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			if len(changes) == 0 {
				break
			}
			updates := target.column + "=?"
			if target.table == "ingest_state" {
				for _, column := range []string{"inode", "offset"} {
					if columns[column] {
						updates += "," + column + "=0"
					}
				}
				if columns["head_sig"] {
					updates += ",head_sig=''"
				}
			}
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			for _, change := range changes {
				if _, err = tx.ExecContext(ctx, "UPDATE "+target.table+" SET "+updates+" WHERE rowid=?", change.path, change.id); err != nil {
					break
				}
			}
			if err != nil {
				tx.Rollback()
				return err
			}
			if err := tx.Commit(); err != nil {
				return err
			}
			if len(changes) < 256 {
				break
			}
		}
	}
	return ctx.Err()
}
