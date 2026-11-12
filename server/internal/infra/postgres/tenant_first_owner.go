package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ssochange"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// The platform administrator may create only the first owner of an
// organization that has none (owner decision 2026-10-02, RFC-022). These two
// methods back that rule; the check and the insert share one transaction and a
// per-organization advisory lock, so two concurrent requests cannot both see
// "no owner" and create two owners.
//
// Any owner membership counts, active or suspended: an organization whose
// owner is suspended (or whose owner's account is blocked or erased) has an
// owner, and its data is theirs. Only the explicit owner recovery (super
// admin, recovery=true) may add an owner then, and only while none of its
// owners is usable (UsableOwnerExists).

// ownerPresenceQuery reports whether the organization has any member who is
// its owner (by membership label or by holding the system owner role), and
// whether any of them is usable (UsableOwnerExists: active membership and an
// account that is active and not erased).
var ownerPresenceQuery = `
	SELECT EXISTS (
	        SELECT 1 FROM tenant_members m
	         WHERE m.tenant_id = $1
	           AND EXISTS (
	                SELECT 1 FROM v_user_effective_role ver
	                 WHERE ver.tenant_id = m.tenant_id AND ver.user_id = m.user_id
	                   AND ver.role = 'owner')),
	       ` + UsableOwnerExists("$1")

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

	err = insertOwnerMembershipTx(ctx, tx, m)
	if err != nil {
		return err
	}
	// A new first owner ends any ownership invitation still waiting
	// (docs/architecture/organization-ownership-invitations.md).
	if _, err = tx.ExecContext(ctx, `
		UPDATE organization_owner_invitations
		   SET status = 'canceled', responded_at = $2, updated_at = $2
		 WHERE tenant_id = $1 AND status = 'pending'`, tenantID, m.JoinedAt()); err != nil {
		return fmt.Errorf("cancel ownership invitation: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit first owner: %w", err)
	}
	return nil
}

// activeOwnersQuery lists the organization's active owners (same definition as
// activeOwnerExistsQuery) whose user account is active.
const activeOwnersQuery = `
	SELECT u.id, u.email, u.name
	  FROM tenant_members m
	  JOIN users u ON u.id = m.user_id
	 WHERE m.tenant_id = $1
	   AND COALESCE(m.status, 'active') = 'active'
	   AND u.status = 'active'
	   AND EXISTS (
	        SELECT 1 FROM v_user_effective_role ver
	         WHERE ver.tenant_id = m.tenant_id AND ver.user_id = m.user_id
	           AND ver.role = 'owner')`

// ListActiveOwners returns the organization's active owners, for notifying
// them of an SSO change that waits for their approval.
func (r *TenantRepository) ListActiveOwners(ctx context.Context, tenantID shared.ID) ([]ssochange.OwnerContact, error) {
	rows, err := r.db.QueryContext(ctx, activeOwnersQuery+` ORDER BY u.email`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list organization owners: %w", err)
	}
	defer rows.Close()
	var out []ssochange.OwnerContact
	for rows.Next() {
		var idStr string
		var c ssochange.OwnerContact
		if err := rows.Scan(&idStr, &c.Email, &c.Name); err != nil {
			return nil, fmt.Errorf("scan organization owner: %w", err)
		}
		id, err := shared.IDFromString(idStr)
		if err != nil {
			return nil, fmt.Errorf("parse owner id: %w", err)
		}
		c.UserID = id
		out = append(out, c)
	}
	return out, rows.Err()
}

// IsActiveOwner reports whether userID is an active owner of the organization,
// read from the database rather than from the caller's token.
func (r *TenantRepository) IsActiveOwner(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
	var exists bool
	q := `SELECT EXISTS (` + activeOwnersQuery + ` AND m.user_id = $2)`
	if err := r.db.QueryRowContext(ctx, q, tenantID.String(), userID.String()).Scan(&exists); err != nil {
		return false, fmt.Errorf("check organization owner: %w", err)
	}
	return exists, nil
}
