package postgres

// Recent changes that took away a second approver, shared by every owner
// self-approval path (exposure dispositions, suppression rules, a sole
// member's finding request): while one is recent, an owner may not approve
// their own request alone. A stolen owner session could otherwise remove or
// demote the other approver and approve at once.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// approverChangeAuditActions are the audit actions that can take the right
// to approve away from a member: removing, suspending or offboarding them
// (from the organization or from a team: member.removed), changing their
// membership or team role (owner/admin to member or viewer), changing their
// custom roles or a team's role bindings (role.unassigned), changing or
// deleting a role (which can strip the approve permission from everyone
// holding it), deleting or changing a team (its members lose the roles bound
// to it), changing a permission set, or changing the SCIM group-to-role
// mappings.
var approverChangeAuditActions = []string{ //nolint:gochecknoglobals // static list
	"member.removed", "member.suspended", "member.offboarded",
	"member.role_changed",
	"role.unassigned", "user.roles_updated",
	"role.updated", "role.deleted",
	"group.updated", "group.deleted",
	"permission_set.updated", "permission_set.deleted", "permission_set.unassigned",
	"scim.group_mappings_updated",
}

// recentApproverChange answers the latest time after since at which the
// tenant lost a possible second approver (nil: none): a membership suspended,
// offboarded or expired, or an audited removal, demotion or role change. A
// removed member's row is gone and a role change leaves no timestamp on the
// membership, so the audit log counts too. Only this tenant's rows are read.
func recentApproverChange(ctx context.Context, db *DB, tenantID shared.ID, since time.Time) (*time.Time, error) {
	var at sql.NullTime
	err := db.QueryRowContext(ctx, `
		SELECT max(t) FROM (
			SELECT suspended_at AS t FROM tenant_members WHERE tenant_id = $1 AND suspended_at > $2
			UNION ALL SELECT offboarded_at FROM tenant_members WHERE tenant_id = $1 AND offboarded_at > $2
			UNION ALL SELECT expires_at FROM tenant_members WHERE tenant_id = $1 AND expires_at > $2 AND expires_at <= now()
			UNION ALL SELECT logged_at FROM audit_logs WHERE tenant_id = $1 AND logged_at > $2
				AND action = ANY($3)
		) recent`, tenantID.String(), since, pq.Array(approverChangeAuditActions)).Scan(&at)
	if err != nil {
		return nil, fmt.Errorf("recent approver change: %w", err)
	}
	if !at.Valid {
		return nil, nil
	}
	t := at.Time
	return &t, nil
}
