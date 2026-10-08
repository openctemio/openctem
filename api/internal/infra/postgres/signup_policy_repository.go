package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/signup"
)

// SignupPolicyRepository stores the sign-up policy in platform_settings
// (migration 001304). Platform data: no tenant column.
type SignupPolicyRepository struct {
	db *DB
}

// NewSignupPolicyRepository creates the repository.
func NewSignupPolicyRepository(db *DB) *SignupPolicyRepository {
	return &SignupPolicyRepository{db: db}
}

var _ signup.Repository = (*SignupPolicyRepository)(nil)

// Get returns the stored policy, or signup.ErrNotFound.
func (r *SignupPolicyRepository) Get(ctx context.Context) (signup.State, error) {
	var (
		raw       []byte
		version   int
		source    string
		updatedBy sql.NullString
		updatedAt time.Time
	)
	err := r.db.QueryRowContext(ctx,
		`SELECT value, version, source, updated_by, updated_at FROM platform_settings WHERE key = $1`,
		signup.SettingKey,
	).Scan(&raw, &version, &source, &updatedBy, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return signup.State{}, signup.ErrNotFound
		}
		return signup.State{}, fmt.Errorf("get sign-up policy: %w", err)
	}
	p, err := signup.Decode(raw)
	if err != nil {
		return signup.State{}, err
	}
	st := signup.State{Policy: p, Version: version, Source: signup.Source(source), UpdatedAt: updatedAt}
	if updatedBy.Valid {
		if id, perr := shared.IDFromString(updatedBy.String); perr == nil {
			st.UpdatedBy = &id
		}
	}
	return st, nil
}

// CreateIfAbsent stores the first policy; false when one is stored already.
func (r *SignupPolicyRepository) CreateIfAbsent(ctx context.Context, s signup.State) (bool, error) {
	raw, err := s.Policy.Encode()
	if err != nil {
		return false, err
	}
	var by any
	if s.UpdatedBy != nil {
		by = s.UpdatedBy.String()
	}
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO platform_settings (key, value, version, source, updated_by, updated_at)
		VALUES ($1, $2, 1, $3, $4, $5)
		ON CONFLICT (key) DO NOTHING`,
		signup.SettingKey, raw, string(s.Source), by, s.UpdatedAt,
	)
	if err != nil {
		return false, fmt.Errorf("seed sign-up policy: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	return n == 1, nil
}

// Update stores p when the stored version still equals expectedVersion.
func (r *SignupPolicyRepository) Update(ctx context.Context, p signup.Policy, expectedVersion int, by shared.ID, at time.Time) (signup.State, error) {
	raw, err := p.Encode()
	if err != nil {
		return signup.State{}, err
	}
	var version int
	err = r.db.QueryRowContext(ctx, `
		UPDATE platform_settings
		   SET value = $2, version = version + 1, source = 'console', updated_by = $3, updated_at = $4
		 WHERE key = $1 AND version = $5
		RETURNING version`,
		signup.SettingKey, raw, by.String(), at, expectedVersion,
	).Scan(&version)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return signup.State{}, signup.ErrVersionConflict
		}
		return signup.State{}, fmt.Errorf("update sign-up policy: %w", err)
	}
	return signup.State{Policy: p, Version: version, Source: signup.SourceConsole, UpdatedBy: &by, UpdatedAt: at}, nil
}
