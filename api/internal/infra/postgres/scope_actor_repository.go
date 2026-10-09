package postgres

// Names of the people on scope entries and exclusions (research/53 §4.6).
// Only users with a current (active or suspended) membership of the tenant
// are named; anyone else, including a user of another organization and an
// offboarded member, is absent and shows as a former member. No e-mail is
// returned; ScopeApprovers reads it to send approval requests only.

import (
	"context"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// scopeApprovePermission is the permission that makes a member a scope
// approver.
var scopeApprovePermission = permission.ScopeApprove.String()

// ScopeActorRepository names tenant members.
type ScopeActorRepository struct {
	db *DB
}

// NewScopeActorRepository creates the repository.
func NewScopeActorRepository(db *DB) *ScopeActorRepository {
	return &ScopeActorRepository{db: db}
}

// maxActorNames bounds one lookup.
const maxActorNames = 500

// MemberNames maps the given user ids that are current members of the
// tenant to their display names (an empty name falls back to "Member").
func (r *ScopeActorRepository) MemberNames(ctx context.Context, tenantID shared.ID, userIDs []string) (map[string]string, error) {
	out := map[string]string{}
	ids := make([]string, 0, len(userIDs))
	for _, id := range userIDs {
		if _, err := shared.IDFromString(id); err == nil && len(ids) < maxActorNames {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT u.id::text, u.name
		FROM tenant_members tm
		JOIN users u ON u.id = tm.user_id
		WHERE tm.tenant_id = $1 AND tm.user_id = ANY($2::uuid[]) AND tm.status <> 'offboarded'`,
		tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("name scope actors: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		if name = strings.TrimSpace(name); name == "" {
			name = "Member"
		}
		out[id] = name
	}
	return out, rows.Err()
}

// maxScopeApprovers bounds the approver list of one organization.
const maxScopeApprovers = 200

// ScopeApprovers lists the members who may approve scope entries (RFC-054
// §7): active members with an active account and an unexpired membership
// whose effective role is owner or admin, or who hold
// attack_surface:scope:approve through a role. Owners first, then by name.
// Tenant-scoped: only this organization's memberships and role rows.
func (r *ScopeActorRepository) ScopeApprovers(ctx context.Context, tenantID shared.ID) ([]scope.Approver, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT u.id::text, u.name, u.email, COALESCE(ver.role = 'owner', false) AS owner
		FROM tenant_members m
		JOIN users u ON u.id = m.user_id AND u.status = 'active'
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.tenant_id = $1 AND m.status = 'active'
		  AND (m.expires_at IS NULL OR m.expires_at > now())
		  AND (ver.role IN ('owner', 'admin') OR EXISTS (
		        SELECT 1 FROM user_roles ur
		        JOIN role_permissions rp ON rp.role_id = ur.role_id
		        JOIN permissions p ON p.id = rp.permission_id AND p.is_active = TRUE
		        WHERE ur.tenant_id = m.tenant_id AND ur.user_id = m.user_id
		          AND rp.permission_id = $2))
		ORDER BY COALESCE(ver.role = 'owner', false) DESC, u.name, u.id
		LIMIT $3`,
		tenantID.String(), scopeApprovePermission, maxScopeApprovers)
	if err != nil {
		return nil, fmt.Errorf("list scope approvers: %w", err)
	}
	defer rows.Close()
	var out []scope.Approver
	for rows.Next() {
		var a scope.Approver
		if err := rows.Scan(&a.UserID, &a.Name, &a.Email, &a.Owner); err != nil {
			return nil, fmt.Errorf("scan scope approver: %w", err)
		}
		if a.Name = strings.TrimSpace(a.Name); a.Name == "" {
			a.Name = "Member"
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
