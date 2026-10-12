package tenant

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Privilege increases are told to the organization's owners and
// administrators (RFC-058): a role raised, an administrator or
// full-data-access role granted, a newcomer approved.

// NotifyPrivilegeIncrease tells the administrators that userID gained
// privileges in tenantID; what says how ("membership role raised from viewer
// to member", "role 'Admin' granted"). Best effort.
func (s *TenantService) NotifyPrivilegeIncrease(ctx context.Context, tenantID, userID shared.ID, what string) {
	s.notifyPrivilegeIncrease(ctx, tenantID, userID, what)
}

func (s *TenantService) notifyPrivilegeIncrease(ctx context.Context, tenantID, userID shared.ID, what string) {
	who := userID.String()
	if s.userInfoProvider != nil {
		if name, err := s.userInfoProvider.GetUserNameByID(ctx, userID); err == nil && name != "" {
			who = name
		}
	}
	s.notifyAdmins(ctx, tenantID, "A member gained privileges",
		fmt.Sprintf("%s: %s.", who, what), "medium")
}
