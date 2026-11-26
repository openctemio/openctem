package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/user"
)

// RecordOrganizationSignIn records that tenantID's single sign-on signed the
// account in (research 539): the first time and organization are kept, never
// overwritten. In the same statement an account without a password loses any
// outstanding set-password or reset link, so a link issued before cannot be
// used once the organization's IdP is the account's way in.
func (r *UserRepository) RecordOrganizationSignIn(ctx context.Context, userID, tenantID shared.ID) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE users
		SET sso_signed_in_at = COALESCE(sso_signed_in_at, NOW()),
		    sso_tenant_id = COALESCE(sso_tenant_id, $2),
		    password_reset_token = CASE WHEN password_hash IS NULL THEN NULL ELSE password_reset_token END,
		    password_reset_expires_at = CASE WHEN password_hash IS NULL THEN NULL ELSE password_reset_expires_at END
		WHERE id = $1
	`, userID.String(), tenantID.String())
	if err != nil {
		return fmt.Errorf("record organization sign-in: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return user.NotFoundError(userID)
	}
	return nil
}

// OrganizationSignIn returns when an organization's single sign-on first
// signed the account in (nil: never) and which organization (nil: unknown).
func (r *UserRepository) OrganizationSignIn(ctx context.Context, userID shared.ID) (*time.Time, *shared.ID, error) {
	var (
		at     sql.NullTime
		tenant sql.NullString
	)
	err := r.db.QueryRowContext(ctx,
		`SELECT sso_signed_in_at, sso_tenant_id FROM users WHERE id = $1`, userID.String()).Scan(&at, &tenant)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, user.NotFoundError(userID)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read organization sign-in: %w", err)
	}
	var atPtr *time.Time
	if at.Valid {
		t := at.Time
		atPtr = &t
	}
	var tenantPtr *shared.ID
	if tenant.Valid {
		id, perr := shared.IDFromString(tenant.String)
		if perr != nil {
			return nil, nil, fmt.Errorf("parse sso tenant: %w", perr)
		}
		tenantPtr = &id
	}
	return atPtr, tenantPtr, nil
}
