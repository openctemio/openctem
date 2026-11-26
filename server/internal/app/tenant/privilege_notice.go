package tenant

import (
	"context"
	"fmt"
	"strings"

	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
)

// Privilege increases are told to the organization's owners and
// administrators (RFC-058): a role raised, an administrator or
// full-data-access role granted, a newcomer approved.

// NotifyPrivilegeIncrease tells the administrators that userID gained
// privileges in tenantID; what says how ("membership role raised from viewer
// to member", "role 'Admin' granted"). Best effort.
func (s *TenantService) NotifyPrivilegeIncrease(ctx context.Context, tenantID, userID shared.ID, what string) {
	s.notifyPrivilegeIncrease(ctx, tenantID, userID, what, nil)
}

// NotifyPrivilegeIncreaseMsg is NotifyPrivilegeIncrease with the
// language-neutral form of what (nil leaves the English text only).
func (s *TenantService) NotifyPrivilegeIncreaseMsg(ctx context.Context, tenantID, userID shared.ID, what string, whatMsg *notificationdom.Message) {
	s.notifyPrivilegeIncrease(ctx, tenantID, userID, what, whatMsg)
}

// notifyPrivilegeIncrease is NotifyPrivilegeIncrease with the language-neutral
// form of what (nil leaves the English text only).
func (s *TenantService) notifyPrivilegeIncrease(ctx context.Context, tenantID, userID shared.ID, what string, whatMsg *notificationdom.Message) {
	who := userID.String()
	if s.userInfoProvider != nil {
		if name, err := s.userInfoProvider.GetUserNameByID(ctx, userID); err == nil && name != "" {
			who = name
		}
	}
	var msg *notificationdom.Message
	if whatMsg != nil {
		msg = notificationdom.Msg("member.privileges_gained", "member", who, "what", whatMsg)
	}
	s.notifyAdminsMsg(ctx, tenantID, msg, "A member gained privileges",
		fmt.Sprintf("%s: %s.", who, what), "medium")
}

// pausedMessage is the language-neutral list of what a disabled member's
// pause stopped: member.paused.<scans|reports|workflows combination> with the
// three counts.
func pausedMessage(r *tenantdom.DisableResult) *notificationdom.Message {
	var parts []string
	if len(r.PausedScans) > 0 {
		parts = append(parts, "scans")
	}
	if len(r.PausedReports) > 0 {
		parts = append(parts, "reports")
	}
	if len(r.PausedWorkflow) > 0 {
		parts = append(parts, "workflows")
	}
	code := "member.paused.none"
	if len(parts) > 0 {
		code = "member.paused." + strings.Join(parts, "_")
	}
	return notificationdom.Msg(code, "scans", len(r.PausedScans), "reports", len(r.PausedReports), "workflows", len(r.PausedWorkflow))
}

// actorParam is the name a notice gives for the person who acted: their name,
// or the message for "an administrator" when it is unknown.
func actorParam(name string) any {
	if name == "" {
		return notificationdom.Msg("settings.someone.administrator")
	}
	return name
}

// roleMessage is the nested message for an organization role (member.role.<role>);
// a role the web does not know is member.role.other.
func roleMessage(role string) *notificationdom.Message {
	switch role {
	case "owner", "admin", "member", "viewer":
		return notificationdom.Msg("member.role." + role)
	}
	return notificationdom.Msg("member.role.other")
}
