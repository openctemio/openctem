package accesscontrol

import (
	"context"
	"fmt"

	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	roledom "github.com/openctemio/openctem/server/pkg/domain/role"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// PrivilegeNotifier tells an organization's administrators that a member
// gained privileges (TenantService.NotifyPrivilegeIncreaseMsg, RFC-058).
type PrivilegeNotifier interface {
	NotifyPrivilegeIncreaseMsg(ctx context.Context, tenantID, userID shared.ID, what string, whatMsg *notificationdom.Message)
}

// SetPrivilegeNotifier wires the privilege-increase notice.
func (s *RoleService) SetPrivilegeNotifier(n PrivilegeNotifier) { s.privilege = n }

// elevated reports whether granting r is a privilege increase worth telling
// the administrators: the owner or administrator role, or any role with full
// data access (it lifts the data scope).
func elevated(r *roledom.Role) bool {
	if r == nil {
		return false
	}
	return r.ID() == roledom.OwnerRoleID || r.ID() == roledom.AdminRoleID || r.HasFullDataAccess()
}

func (s *RoleService) notifyElevated(ctx context.Context, tid roledom.ID, users []roledom.ID, r *roledom.Role) {
	if s.privilege == nil || !elevated(r) {
		return
	}
	tenantID, err := shared.IDFromString(tid.String())
	if err != nil {
		return
	}
	for _, u := range users {
		uid, err := shared.IDFromString(u.String())
		if err != nil {
			continue
		}
		s.privilege.NotifyPrivilegeIncreaseMsg(ctx, tenantID, uid, fmt.Sprintf("role %q granted", r.Name()),
			notificationdom.Msg("member.privilege.role_granted", "role_name", r.Name()))
	}
}
