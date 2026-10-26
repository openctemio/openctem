package postgres

// Storage behind the "Require SSO" guard: the proof that an administrator
// signed in through the organization's IdP, whether an owner can use
// break-glass (password and second factor), and the credentials that were
// created before enforcement began.
//
// Every statement is bound to one tenant id.

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SSOEnforcementRepository implements tenant.SSOEnforcementStore.
type SSOEnforcementRepository struct {
	db *DB
}

// NewSSOEnforcementRepository creates the repository.
func NewSSOEnforcementRepository(db *DB) *SSOEnforcementRepository {
	return &SSOEnforcementRepository{db: db}
}

// RecordSSOSignIn stamps an owner's or admin's sign-in through the
// organization's own identity provider. Other roles are not stamped.
func (r *SSOEnforcementRepository) RecordSSOSignIn(ctx context.Context, tenantID, userID shared.ID) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE tenant_members SET last_sso_signin_at = NOW()
		WHERE tenant_id = $1 AND user_id = $2 AND status = 'active' AND role IN ('owner', 'admin')`,
		tenantID.String(), userID.String())
	if err != nil {
		return fmt.Errorf("record sso sign-in: %w", err)
	}
	return nil
}

// HasAdminSSOSignIn reports whether an active owner or admin has signed in
// through the organization's identity provider at least once.
func (r *SSOEnforcementRepository) HasAdminSSOSignIn(ctx context.Context, tenantID shared.ID) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM tenant_members
			WHERE tenant_id = $1 AND status = 'active' AND role IN ('owner', 'admin')
			  AND last_sso_signin_at IS NOT NULL)`, tenantID.String()).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check admin sso sign-in: %w", err)
	}
	return ok, nil
}

// HasOwnerWithSecondFactor reports whether an active owner has two-factor
// authentication on, which is what owner break-glass needs.
func (r *SSOEnforcementRepository) HasOwnerWithSecondFactor(ctx context.Context, tenantID shared.ID) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM tenant_members m
			JOIN user_mfa f ON f.user_id = m.user_id AND f.enabled
			WHERE m.tenant_id = $1 AND m.status = 'active' AND m.role = 'owner')`, tenantID.String()).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check owner second factor: %w", err)
	}
	return ok, nil
}

// CountCredentials counts the live user API keys and connector (MCP) grants
// of the organization.
func (r *SSOEnforcementRepository) CountCredentials(ctx context.Context, tenantID shared.ID) (keys, grants int, err error) {
	err = r.db.QueryRowContext(ctx, `
		SELECT
		  (SELECT COUNT(*) FROM api_keys WHERE tenant_id = $1 AND user_id IS NOT NULL AND status IN ('active', 'suspended')),
		  (SELECT COUNT(*) FROM mcp_oauth_grants WHERE tenant_id = $1 AND revoked_at IS NULL AND expires_at > NOW())`,
		tenantID.String()).Scan(&keys, &grants)
	if err != nil {
		return 0, 0, fmt.Errorf("count credentials: %w", err)
	}
	return keys, grants, nil
}

// RevokeCredentials revokes the live user API keys and connector grants of
// the organization in one transaction.
func (r *SSOEnforcementRepository) RevokeCredentials(ctx context.Context, tenantID, actorID shared.ID) (keys, grants int, err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("begin revoke credentials: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var actor any
	if !actorID.IsZero() {
		actor = actorID.String()
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE api_keys SET status = 'revoked', revoked_at = NOW(), revoked_by = $2, updated_at = NOW()
		WHERE tenant_id = $1 AND user_id IS NOT NULL AND status IN ('active', 'suspended')`,
		tenantID.String(), actor)
	if err != nil {
		return 0, 0, fmt.Errorf("revoke api keys: %w", err)
	}
	n, _ := res.RowsAffected()
	keys = int(n)

	// Tokens first: they are found through the grants that are still live.
	if _, err = tx.ExecContext(ctx, `
		DELETE FROM mcp_oauth_tokens t USING mcp_oauth_grants g
		WHERE t.grant_id = g.id AND g.tenant_id = $1 AND g.revoked_at IS NULL`, tenantID.String()); err != nil {
		return 0, 0, fmt.Errorf("delete connector tokens: %w", err)
	}
	res, err = tx.ExecContext(ctx, `
		UPDATE mcp_oauth_grants SET revoked_at = NOW(), revoked_reason = 'sso_enforced'
		WHERE tenant_id = $1 AND revoked_at IS NULL`, tenantID.String())
	if err != nil {
		return 0, 0, fmt.Errorf("revoke connector grants: %w", err)
	}
	n, _ = res.RowsAffected()
	grants = int(n)

	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("commit revoke credentials: %w", err)
	}
	return keys, grants, nil
}
