package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// The platform administrator may create only the first owner of an
// organization that has none (owner decision 2026-10-02, RFC-022). These two
// methods back that rule; the check and the insert share one transaction and a
// per-organization advisory lock, so two concurrent requests cannot both see
// "no owner" and create two owners.

// activeOwnerExistsQuery is true when the organization has an active member
// who is its owner by membership label or by holding the system owner role.
const activeOwnerExistsQuery = `
	SELECT EXISTS (
		SELECT 1 FROM tenant_members m
		 WHERE m.tenant_id = $1
		   AND COALESCE(m.status, 'active') = 'active'
		   AND (m.role = 'owner' OR EXISTS (
		        SELECT 1 FROM user_roles ur
		         WHERE ur.tenant_id = m.tenant_id AND ur.user_id = m.user_id
		           AND ur.role_id = '00000000-0000-0000-0000-000000000001'))
	)`

// HasActiveOwner reports whether the organization has an active owner.
func (r *TenantRepository) HasActiveOwner(ctx context.Context, tenantID shared.ID) (bool, error) {
	var exists bool
	if err := r.db.QueryRowContext(ctx, activeOwnerExistsQuery, tenantID.String()).Scan(&exists); err != nil {
		return false, fmt.Errorf("check organization owner: %w", err)
	}
	return exists, nil
}

// CreateFirstOwnerMembership inserts m, which must be an owner membership, and
// the matching system owner role, only when the organization has no active
// owner. It returns tenant.ErrOrganizationHasOwner otherwise.
func (r *TenantRepository) CreateFirstOwnerMembership(ctx context.Context, m *tenant.Membership) (err error) {
	if !m.IsOwner() {
		return fmt.Errorf("%w: first-owner membership must have the owner role", shared.ErrValidation)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	tenantID := m.TenantID().String()
	if _, err = tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock(hashtext('tenant_first_owner'), hashtext($1))`, tenantID); err != nil {
		return fmt.Errorf("lock organization: %w", err)
	}
	var exists bool
	if err = tx.QueryRowContext(ctx, activeOwnerExistsQuery, tenantID).Scan(&exists); err != nil {
		return fmt.Errorf("check organization owner: %w", err)
	}
	if exists {
		err = tenant.ErrOrganizationHasOwner
		return err
	}

	var invitedBy sql.NullString
	if m.InvitedBy() != nil {
		invitedBy = sql.NullString{String: m.InvitedBy().String(), Valid: true}
	}
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO tenant_members (id, user_id, tenant_id, role, invited_by, joined_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		m.ID().String(), m.UserID().String(), tenantID, m.Role().String(), invitedBy, m.JoinedAt(),
	); err != nil {
		if isCheckViolation(err) {
			err = tenant.ErrPlatformAdminMembership
			return err
		}
		return fmt.Errorf("failed to create membership: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO user_roles (user_id, tenant_id, role_id, assigned_at, assigned_by)
		SELECT $1, $2, r.id, $3, $4
		FROM roles r
		WHERE r.slug = $5 AND r.is_system = TRUE AND r.tenant_id IS NULL
		ON CONFLICT (user_id, tenant_id, role_id) DO NOTHING`,
		m.UserID().String(), tenantID, m.JoinedAt(), invitedBy, m.Role().String(),
	); err != nil {
		return fmt.Errorf("failed to create user role: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit first owner: %w", err)
	}
	return nil
}
