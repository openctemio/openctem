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
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/finding"
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
	return r.approversWith(ctx, tenantID, scopeApprovePermission)
}

// FindingApprovers lists the members who may approve finding false-positive
// and accepted-risk requests: the same rule as ScopeApprovers with
// findings:approve. The data scope of each is checked by the caller.
func (r *ScopeActorRepository) FindingApprovers(ctx context.Context, tenantID shared.ID) ([]finding.FindingApprover, error) {
	all, err := r.approversWith(ctx, tenantID, permission.FindingsApprove.String())
	if err != nil {
		return nil, err
	}
	persons, err := r.personIDs(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]finding.FindingApprover, 0, len(all))
	for _, a := range all {
		// A service account never signs in: it is never told, and four-eyes
		// is a second person.
		if !persons[a.UserID] {
			continue
		}
		out = append(out, finding.FindingApprover{UserID: a.UserID, Name: a.Name, Email: a.Email, Owner: a.Owner})
	}
	return out, nil
}

// approversWith lists active members with an active account and an
// unexpired membership whose effective role is owner or admin, or who hold
// perm through a role. Owners first, then by name.
func (r *ScopeActorRepository) approversWith(ctx context.Context, tenantID shared.ID, perm string) ([]scope.Approver, error) {
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
		tenantID.String(), perm, maxScopeApprovers)
	if err != nil {
		return nil, fmt.Errorf("list approvers: %w", err)
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

// personIDs are the tenant's members that are people (users.kind =
// 'person'), not service accounts.
func (r *ScopeActorRepository) personIDs(ctx context.Context, tenantID shared.ID) (map[string]bool, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT u.id::text FROM tenant_members m JOIN users u ON u.id = m.user_id
		WHERE m.tenant_id = $1 AND u.kind = 'person'`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list member persons: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// IsSoleActiveOwner reports whether userID is the only active person in the
// tenant and an owner of it: exactly one active membership of a person (an
// active, unexpired membership of an active account; service accounts do
// not count) and that membership is userID's with the owner role. Read at
// decision time, never cached.
func (r *ScopeActorRepository) IsSoleActiveOwner(ctx context.Context, tenantID shared.ID, userID string) (bool, error) {
	var members int
	var soleIsOwner bool
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*),
		       COALESCE(BOOL_AND(m.user_id = $2::uuid AND ver.role = 'owner'), false)
		FROM tenant_members m
		JOIN users u ON u.id = m.user_id AND u.status = 'active' AND u.kind = 'person'
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.tenant_id = $1 AND m.status = 'active'
		  AND (m.expires_at IS NULL OR m.expires_at > now())`,
		tenantID.String(), userID).Scan(&members, &soleIsOwner)
	if err != nil {
		return false, fmt.Errorf("count active members: %w", err)
	}
	return members == 1 && soleIsOwner, nil
}

// RecentMemberRemoval answers when, within window, the tenant last lost a
// possible second approver: a member suspended, offboarded, removed,
// expired, demoted, or a role change that can strip the approve permission
// (recentApproverChange; nil: none). A sole-member self-approval is refused
// while one is recent, so removing or demoting the other approver cannot be
// used to open the path.
func (r *ScopeActorRepository) RecentMemberRemoval(ctx context.Context, tenantID shared.ID, window time.Duration) (*time.Time, error) {
	return recentApproverChange(ctx, r.db, tenantID, time.Now().Add(-window))
}
