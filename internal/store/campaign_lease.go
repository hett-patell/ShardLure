package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// The campaign worker lease is one ingest_state row beside the recorder
// cursor it protects: head_sig holds the owner identity, offset the expiry as
// unix nanoseconds (seconds would round a short TTL to "already expired").
// `shardlure live` and a separately started `shardlure web` on one database
// both run the campaign worker, and the pipeline assumes a
// single sequential caller (AssignScriptFamilies and PruneOrphanScripts share
// representatives; the version reset and the hold release are process-wide
// state machines). The lease lets exactly one process run it: the other skips
// its ticks until the lease expires or is released, so a crashed owner is
// replaced after campaignLeaseTTL and a stopped one at once.
const (
	campaignLeaseSource = evidenceCursorSource
	campaignLeasePath   = "worker-lease"
)

// ErrCampaignLeaseInvalid rejects an empty owner, a zero time or a TTL outside
// (0, 1h]: a lease with no owner could be renewed by anyone, and a TTL longer
// than an hour would leave the pipeline idle that long after a crash.
var ErrCampaignLeaseInvalid = errors.New("campaign lease: invalid owner, time or ttl")

// AcquireCampaignLease takes or renews the campaign worker lease for owner and
// reports whether owner holds it afterwards. One statement decides: the row
// is written when it is absent, already owned by owner (renewal), or expired
// at now (takeover); otherwise it is left to its current holder. The decision
// and the read-back run in one write transaction, so two processes racing
// for an expired lease see one winner. A held lease is not an error: the
// caller skips its work quietly.
//
// The row is read on a plain connection first, and the write runs only when
// that read says the lease is absent, owner's or expired. The conditional
// upsert alone answered "held elsewhere" with a WHERE that was false, but
// the statement still took SQLite's write lock to find that out: behind a
// long writer in the other process (a CLI --replace is one multi-minute
// transaction on prod) a non-holder's every tick waited busy_timeout and
// failed with SQLITE_BUSY, which the worker counted as a failure (backoff,
// worker_error=1, a logged error) on a process that had nothing to do
// (pipeline audit M2). The read is only an admission check, never the
// decision: a stale read that admits a contender still meets the conditional
// write, so two takers of an expired lease still see one winner.
func (s *Store) AcquireCampaignLease(ctx context.Context, owner string, now time.Time, ttl time.Duration) (bool, error) {
	if owner == "" || now.IsZero() || ttl <= 0 || ttl > time.Hour {
		return false, ErrCampaignLeaseInvalid
	}
	if holder, until, err := s.CampaignLeaseHolder(ctx); err != nil {
		return false, err
	} else if holder != "" && holder != owner && until.After(now) {
		return false, nil
	}
	held := false
	err := s.WithTxContext(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ingest_state(source,path,inode,offset,head_sig,updated_at) VALUES(?,?,0,?,?,?)
ON CONFLICT(source,path) DO UPDATE SET offset=excluded.offset, head_sig=excluded.head_sig, updated_at=excluded.updated_at
WHERE ingest_state.head_sig=excluded.head_sig OR ingest_state.offset<=?`,
			campaignLeaseSource, campaignLeasePath, now.Add(ttl).UnixNano(), owner, formatFixedUTC(now), now.UnixNano()); err != nil {
			return err
		}
		var holder sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT head_sig FROM ingest_state WHERE source=? AND path=?`, campaignLeaseSource, campaignLeasePath).Scan(&holder); err != nil {
			return err
		}
		held = holder.Valid && holder.String == owner
		return nil
	})
	return held, err
}

// ReleaseCampaignLease deletes the lease if owner still holds it, so the next
// process to try acquires at once instead of waiting out the TTL. Releasing
// a lease owned by someone else is a no-op: an owner that lost its lease to
// a takeover must not evict the new holder.
func (s *Store) ReleaseCampaignLease(ctx context.Context, owner string) error {
	if owner == "" {
		return ErrCampaignLeaseInvalid
	}
	return s.WithTxContext(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM ingest_state WHERE source=? AND path=? AND head_sig=?`, campaignLeaseSource, campaignLeasePath, owner)
		return err
	})
}

// CampaignLeaseHolder reports the current lease owner and expiry ("" and zero
// when no row exists). Read-only, for tests and diagnostics; it does not say
// whether the lease has expired, AcquireCampaignLease decides that.
func (s *Store) CampaignLeaseHolder(ctx context.Context) (string, time.Time, error) {
	var holder sql.NullString
	var until int64
	err := s.db.QueryRowContext(ctx, `SELECT head_sig, offset FROM ingest_state WHERE source=? AND path=?`, campaignLeaseSource, campaignLeasePath).Scan(&holder, &until)
	if err == sql.ErrNoRows {
		return "", time.Time{}, nil
	}
	if err != nil {
		return "", time.Time{}, err
	}
	return holder.String, time.Unix(0, until), nil
}

// ErrCampaignLeaseLost means the lease row no longer names the caller as an
// unexpired holder, so a write that assumes single ownership was refused.
var ErrCampaignLeaseLost = errors.New("campaign lease: not held by this owner")

// RenewCampaignLease extends owner's lease by ttl from now and reports
// whether it did. Unlike AcquireCampaignLease it never inserts a missing row
// and never takes over an expired one: a holder whose lease lapsed during a
// phase (a stall past the TTL, a wall-clock step) must not get it back here
// and carry on, because another process may have held it, run the pipeline
// and released it in between; only the start of a tick takes over.
func (s *Store) RenewCampaignLease(ctx context.Context, owner string, now time.Time, ttl time.Duration) (bool, error) {
	if owner == "" || now.IsZero() || ttl <= 0 || ttl > time.Hour {
		return false, ErrCampaignLeaseInvalid
	}
	held := false
	err := s.WithTxContext(ctx, func(tx *sql.Tx) error {
		r, err := tx.ExecContext(ctx, `UPDATE ingest_state SET offset=?, updated_at=? WHERE source=? AND path=? AND head_sig=? AND offset>?`,
			now.Add(ttl).UnixNano(), formatFixedUTC(now), campaignLeaseSource, campaignLeasePath, owner, now.UnixNano())
		if err != nil {
			return err
		}
		n, err := r.RowsAffected()
		held = n == 1
		return err
	})
	return held, err
}

// campaignLeaseHeldTx reports, inside a write transaction, whether owner
// holds the lease unexpired at now: the predicate SaveGroupingAsLeaseHolder
// puts in front of its replace, in the same transaction, so no takeover can
// slip between the check and the write.
func campaignLeaseHeldTx(tx *sql.Tx, owner string, now time.Time) (bool, error) {
	var holder sql.NullString
	var until int64
	err := tx.QueryRow(`SELECT head_sig, offset FROM ingest_state WHERE source=? AND path=?`, campaignLeaseSource, campaignLeasePath).Scan(&holder, &until)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return holder.Valid && holder.String == owner && until > now.UnixNano(), nil
}
