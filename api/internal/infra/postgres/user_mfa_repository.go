package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/mfa"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// UserMFARepository persists user two-factor state (user_mfa,
// user_mfa_recovery_codes, user_mfa_challenges). Every query is keyed by the
// authenticated user's id; this is per-user, not per-tenant, data.
type UserMFARepository struct {
	db *DB
}

// NewUserMFARepository creates a new UserMFARepository.
func NewUserMFARepository(db *DB) *UserMFARepository {
	return &UserMFARepository{db: db}
}

var _ mfa.Repository = (*UserMFARepository)(nil)

// GetFactor returns the user's factor.
func (r *UserMFARepository) GetFactor(ctx context.Context, userID shared.ID) (*mfa.Factor, error) {
	const q = `
		SELECT COALESCE(secret_encrypted, ''), COALESCE(pending_secret_encrypted, ''),
		       pending_created_at, enabled, enabled_at, last_used_step
		FROM user_mfa WHERE user_id = $1`
	f := mfa.Factor{UserID: userID}
	var pendingAt, enabledAt sql.NullTime
	err := r.db.QueryRowContext(ctx, q, userID.String()).Scan(
		&f.SecretEncrypted, &f.PendingSecretEncrypted, &pendingAt, &f.Enabled, &enabledAt, &f.LastUsedStep,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, mfa.ErrFactorNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user mfa: %w", err)
	}
	if pendingAt.Valid {
		t := pendingAt.Time
		f.PendingCreatedAt = &t
	}
	if enabledAt.Valid {
		t := enabledAt.Time
		f.EnabledAt = &t
	}
	return &f, nil
}

// SavePendingSecret stores a not-yet-confirmed secret.
func (r *UserMFARepository) SavePendingSecret(ctx context.Context, userID shared.ID, secretEncrypted string) error {
	const q = `
		INSERT INTO user_mfa (user_id, pending_secret_encrypted, pending_created_at, updated_at)
		VALUES ($1, $2, NOW(), NOW())
		ON CONFLICT (user_id) DO UPDATE SET
		    pending_secret_encrypted = EXCLUDED.pending_secret_encrypted,
		    pending_created_at = NOW(),
		    updated_at = NOW()`
	if _, err := r.db.ExecContext(ctx, q, userID.String(), secretEncrypted); err != nil {
		return fmt.Errorf("save pending mfa secret: %w", err)
	}
	return nil
}

// Activate promotes the pending secret and replaces the recovery codes.
func (r *UserMFARepository) Activate(ctx context.Context, userID shared.ID, step int64, codeHashes []string) (bool, error) {
	activated := false
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE user_mfa SET
			    secret_encrypted = pending_secret_encrypted,
			    pending_secret_encrypted = NULL,
			    pending_created_at = NULL,
			    enabled = TRUE,
			    enabled_at = NOW(),
			    last_used_step = $2,
			    updated_at = NOW()
			WHERE user_id = $1 AND pending_secret_encrypted IS NOT NULL`,
			userID.String(), step)
		if err != nil {
			return fmt.Errorf("activate mfa: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("activate mfa: %w", err)
		}
		if n == 0 {
			return nil
		}
		if err := replaceRecoveryCodesTx(ctx, tx, userID, codeHashes); err != nil {
			return err
		}
		activated = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return activated, nil
}

// Disable removes the factor and every recovery code.
func (r *UserMFARepository) Disable(ctx context.Context, userID shared.ID) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM user_mfa_recovery_codes WHERE user_id = $1`, userID.String()); err != nil {
			return fmt.Errorf("delete recovery codes: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM user_mfa WHERE user_id = $1`, userID.String()); err != nil {
			return fmt.Errorf("delete mfa factor: %w", err)
		}
		return nil
	})
}

// AdvanceStep records step as used only when it is newer than the last one.
// The compare-and-set in one statement is what makes two concurrent requests
// carrying the same code unable to both succeed.
func (r *UserMFARepository) AdvanceStep(ctx context.Context, userID shared.ID, step int64) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE user_mfa SET last_used_step = $2, updated_at = NOW()
		WHERE user_id = $1 AND enabled AND last_used_step < $2`,
		userID.String(), step)
	if err != nil {
		return false, fmt.Errorf("advance mfa step: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("advance mfa step: %w", err)
	}
	return n == 1, nil
}

// ListUnusedRecoveryCodes returns the codes not used yet.
func (r *UserMFARepository) ListUnusedRecoveryCodes(ctx context.Context, userID shared.ID) ([]mfa.RecoveryCode, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, code_hash FROM user_mfa_recovery_codes
		WHERE user_id = $1 AND used_at IS NULL
		ORDER BY created_at ASC
		LIMIT 50`, userID.String())
	if err != nil {
		return nil, fmt.Errorf("list recovery codes: %w", err)
	}
	defer rows.Close()
	codes := make([]mfa.RecoveryCode, 0, mfa.RecoveryCodeCount)
	for rows.Next() {
		var idStr, hash string
		if err := rows.Scan(&idStr, &hash); err != nil {
			return nil, fmt.Errorf("scan recovery code: %w", err)
		}
		id, err := shared.IDFromString(idStr)
		if err != nil {
			return nil, fmt.Errorf("scan recovery code: %w", err)
		}
		codes = append(codes, mfa.RecoveryCode{ID: id, UserID: userID, CodeHash: hash})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list recovery codes: %w", err)
	}
	return codes, nil
}

// ConsumeRecoveryCode marks a code used if it was unused.
func (r *UserMFARepository) ConsumeRecoveryCode(ctx context.Context, userID, codeID shared.ID) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE user_mfa_recovery_codes SET used_at = NOW()
		WHERE id = $1 AND user_id = $2 AND used_at IS NULL`,
		codeID.String(), userID.String())
	if err != nil {
		return false, fmt.Errorf("consume recovery code: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("consume recovery code: %w", err)
	}
	return n == 1, nil
}

// ReplaceRecoveryCodes deletes every code and stores codeHashes instead.
func (r *UserMFARepository) ReplaceRecoveryCodes(ctx context.Context, userID shared.ID, codeHashes []string) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		return replaceRecoveryCodesTx(ctx, tx, userID, codeHashes)
	})
}

func replaceRecoveryCodesTx(ctx context.Context, tx *sql.Tx, userID shared.ID, codeHashes []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_mfa_recovery_codes WHERE user_id = $1`, userID.String()); err != nil {
		return fmt.Errorf("delete recovery codes: %w", err)
	}
	for _, h := range codeHashes {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO user_mfa_recovery_codes (user_id, code_hash) VALUES ($1, $2)`,
			userID.String(), h); err != nil {
			return fmt.Errorf("insert recovery code: %w", err)
		}
	}
	return nil
}

// CreateChallenge stores a new challenge.
func (r *UserMFARepository) CreateChallenge(ctx context.Context, c *mfa.Challenge) error {
	if !c.Purpose.IsValid() {
		return mfa.ErrInvalidPurpose
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO user_mfa_challenges
		    (id, user_id, token_hash, purpose, attempts, ip_address, user_agent, expires_at, created_at)
		VALUES ($1, $2, $3, $4, 0, NULLIF($5, ''), NULLIF($6, ''), $7, $8)`,
		c.ID.String(), c.UserID.String(), c.TokenHash, string(c.Purpose),
		truncateMFAField(c.IPAddress, 45), c.UserAgent, c.ExpiresAt, c.CreatedAt)
	if err != nil {
		return fmt.Errorf("create mfa challenge: %w", err)
	}
	return nil
}

// GetChallengeByTokenHash returns the challenge for a token hash.
func (r *UserMFARepository) GetChallengeByTokenHash(ctx context.Context, tokenHash string) (*mfa.Challenge, error) {
	const q = `
		SELECT id, user_id, token_hash, purpose, attempts, COALESCE(ip_address, ''),
		       COALESCE(user_agent, ''), expires_at, consumed_at, created_at
		FROM user_mfa_challenges WHERE token_hash = $1`
	var (
		c                mfa.Challenge
		idStr, userIDStr string
		purpose          string
		consumedAt       sql.NullTime
		expires, created time.Time
	)
	err := r.db.QueryRowContext(ctx, q, tokenHash).Scan(
		&idStr, &userIDStr, &c.TokenHash, &purpose, &c.Attempts, &c.IPAddress,
		&c.UserAgent, &expires, &consumedAt, &created,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, mfa.ErrChallengeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get mfa challenge: %w", err)
	}
	if c.ID, err = shared.IDFromString(idStr); err != nil {
		return nil, fmt.Errorf("get mfa challenge: %w", err)
	}
	if c.UserID, err = shared.IDFromString(userIDStr); err != nil {
		return nil, fmt.Errorf("get mfa challenge: %w", err)
	}
	c.Purpose = mfa.Purpose(purpose)
	c.ExpiresAt = expires
	c.CreatedAt = created
	if consumedAt.Valid {
		t := consumedAt.Time
		c.ConsumedAt = &t
	}
	return &c, nil
}

// RecordChallengeAttempt increments and returns the attempt counter.
func (r *UserMFARepository) RecordChallengeAttempt(ctx context.Context, id shared.ID) (int, error) {
	var attempts int
	err := r.db.QueryRowContext(ctx,
		`UPDATE user_mfa_challenges SET attempts = attempts + 1 WHERE id = $1 RETURNING attempts`,
		id.String()).Scan(&attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, mfa.ErrChallengeNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("record mfa challenge attempt: %w", err)
	}
	return attempts, nil
}

// ConsumeChallenge marks the challenge used if it is still usable.
func (r *UserMFARepository) ConsumeChallenge(ctx context.Context, id shared.ID) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE user_mfa_challenges SET consumed_at = NOW()
		WHERE id = $1 AND consumed_at IS NULL AND expires_at > NOW()`, id.String())
	if err != nil {
		return false, fmt.Errorf("consume mfa challenge: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("consume mfa challenge: %w", err)
	}
	return n == 1, nil
}

// DeleteExpiredChallenges removes challenges past their expiry.
func (r *UserMFARepository) DeleteExpiredChallenges(ctx context.Context) (int64, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM user_mfa_challenges WHERE expires_at < NOW() - INTERVAL '1 hour'`)
	if err != nil {
		return 0, fmt.Errorf("delete expired mfa challenges: %w", err)
	}
	return res.RowsAffected()
}

func truncateMFAField(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
