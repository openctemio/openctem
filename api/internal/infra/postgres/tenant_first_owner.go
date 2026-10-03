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
//
// Any owner membership counts, active or suspended: an organization whose
// owner is suspended has an owner, and its data is theirs. Only the explicit
// owner recovery (super admin, recovery=true) may add an owner then, and only
// while none of its owners is active.

// ownerPresenceQuery reports whether the organization has any member who is
// its owner (by membership label or by holding the system owner role), and
// whether any of them is active.
const ownerPresenceQuery = `
	SELECT COUNT(*) > 0,
	       COALESCE(BOOL_OR(COALESCE(m.status, 'active') = 'active'), FALSE)
	  FROM tenant_members m
	 WHERE m.tenant_id = $1
	   AND (m.role = 'owner' OR EXISTS (
	        SELECT 1 FROM user_roles ur
	         WHERE ur.tenant_id = m.tenant_id AND ur.user_id = m.user_id
	           AND ur.role_id = '00000000-0000-0000-0000-000000000001'))`

type ownerQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func queryOwnerPresence(ctx context.Context, q ownerQuerier, tenantID string) (tenant.OwnerPresence, error) {
	var p tenant.OwnerPresence
	if err := q.QueryRowContext(ctx, ownerPresenceQuery, tenantID).Scan(&p.Any, &p.Active); err != nil {
		return p, fmt.Errorf("check organization owner: %w", err)
	}
	return p, nil
}

// OwnerPresence reports whether the organization has an owner, and whether
// any of its owners is active.
func (r *TenantRepository) OwnerPresence(ctx context.Context, tenantID shared.ID) (tenant.OwnerPresence, error) {
	return queryOwnerPresence(ctx, r.db, tenantID.String())
}

// CreateFirstOwnerMembership inserts m, which must be an owner membership, and
// the matching system owner role, only when the organization has no owner at
// all, or, with recovery, no active owner. It returns
// tenant.ErrOrganizationHasOwner otherwise.
func (r *TenantRepository) CreateFirstOwnerMembership(ctx context.Context, m *tenant.Membership, recovery bool) (err error) {
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
	presence, err := queryOwnerPresence(ctx, tx, tenantID)
	if err != nil {
		return err
	}
	if presence.BlocksBootstrap(recovery) {
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
