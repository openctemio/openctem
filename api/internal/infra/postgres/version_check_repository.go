package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/openctemio/openctem/api/internal/app/versioncheck"
	"github.com/openctemio/openctem/api/pkg/releasefeed"
)

// VersionCheckRepository stores the version check's one row in
// version_check_state (instance-level, no tenant data).
type VersionCheckRepository struct {
	db *DB
}

// NewVersionCheckRepository creates the repository.
func NewVersionCheckRepository(db *DB) *VersionCheckRepository {
	return &VersionCheckRepository{db: db}
}

var _ versioncheck.Repository = (*VersionCheckRepository)(nil)

// Get reads the state; a zero State when the row does not exist yet.
func (r *VersionCheckRepository) Get(ctx context.Context) (versioncheck.State, error) {
	var (
		st                     versioncheck.State
		feed                   []byte
		origin, lastError      sql.NullString
		applied, attempt, next sql.NullTime
		seq, ksv               int64
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT feed, origin, applied_sequence, keyset_version, applied_at, last_attempt_at,
		       last_error, consecutive_failures, next_check_at
		FROM version_check_state WHERE id = 1`).
		Scan(&feed, &origin, &seq, &ksv, &applied, &attempt, &lastError, &st.ConsecutiveFailures, &next)
	if errors.Is(err, sql.ErrNoRows) {
		return versioncheck.State{}, nil
	}
	if err != nil {
		return versioncheck.State{}, fmt.Errorf("get version check state: %w", err)
	}
	if len(feed) > 0 {
		var f releasefeed.Feed
		if err := json.Unmarshal(feed, &f); err != nil {
			return versioncheck.State{}, fmt.Errorf("decode stored release feed: %w", err)
		}
		st.Feed = &f
	}
	st.Origin, st.LastError = origin.String, lastError.String
	st.AppliedSequence, st.KeySetVersion = uint64(max(seq, 0)), uint64(max(ksv, 0)) //nolint:gosec // non-negative
	st.AppliedAt, st.LastAttemptAt, st.NextCheckAt = scannedTime(applied), scannedTime(attempt), scannedTime(next)
	return st, nil
}

func scannedTime(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}

// ClaimDue creates the row when absent (first check at first), then moves a
// due check to next. Exactly one caller wins a due check.
func (r *VersionCheckRepository) ClaimDue(ctx context.Context, now, first, next time.Time) (bool, error) {
	if _, err := r.db.ExecContext(ctx,
		`INSERT INTO version_check_state (id, next_check_at) VALUES (1, $1) ON CONFLICT (id) DO NOTHING`, first); err != nil {
		return false, fmt.Errorf("create version check state: %w", err)
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE version_check_state SET next_check_at = $2, last_attempt_at = $1
		WHERE id = 1 AND next_check_at <= $1`, now, next)
	if err != nil {
		return false, fmt.Errorf("claim version check: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func toInt64(v uint64) (int64, error) {
	if v > math.MaxInt64 {
		return 0, errors.New("value out of range")
	}
	return int64(v), nil
}

// Apply stores a verified feed unless a newer sequence or key set is stored.
func (r *VersionCheckRepository) Apply(ctx context.Context, v *releasefeed.Verified, origin string, now time.Time) (bool, error) {
	feed, err := json.Marshal(v.Feed)
	if err != nil {
		return false, err
	}
	seq, err := toInt64(v.Feed.Sequence)
	if err != nil {
		return false, err
	}
	ksv, err := toInt64(v.KeySetVersion)
	if err != nil {
		return false, err
	}
	var id int
	err = r.db.QueryRowContext(ctx, `
		INSERT INTO version_check_state (id, feed, origin, applied_sequence, keyset_version, applied_at,
		                                 last_error, consecutive_failures)
		VALUES (1, $1, $2, $3, $4, $5, NULL, 0)
		ON CONFLICT (id) DO UPDATE SET
		    feed = EXCLUDED.feed, origin = EXCLUDED.origin,
		    applied_sequence = EXCLUDED.applied_sequence, keyset_version = EXCLUDED.keyset_version,
		    applied_at = EXCLUDED.applied_at, last_error = NULL, consecutive_failures = 0
		WHERE version_check_state.applied_sequence <= EXCLUDED.applied_sequence
		  AND version_check_state.keyset_version <= EXCLUDED.keyset_version
		RETURNING id`, feed, origin, seq, ksv, now).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil // a newer feed is stored
	}
	if err != nil {
		return false, fmt.Errorf("store release feed: %w", err)
	}
	return true, nil
}

// RecordFailure counts a failed online check and sets the next one.
func (r *VersionCheckRepository) RecordFailure(ctx context.Context, code string, now time.Time, next func(failures int) time.Time) (int, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var failures int
	if err := tx.QueryRowContext(ctx, `
		UPDATE version_check_state
		SET consecutive_failures = consecutive_failures + 1, last_error = $1, last_attempt_at = $2
		WHERE id = 1 RETURNING consecutive_failures`, code, now).Scan(&failures); err != nil {
		return 0, fmt.Errorf("record version check failure: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE version_check_state SET next_check_at = $1 WHERE id = 1`, next(failures)); err != nil {
		return 0, fmt.Errorf("schedule version check: %w", err)
	}
	return failures, tx.Commit()
}
