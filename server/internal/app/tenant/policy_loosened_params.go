package tenant

import (
	"context"
	"fmt"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/scangov"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
)

// someAdministrator names an actor whose name is unknown in the English text.
const someAdministrator = "An administrator"

// resourceTenantSettings is the resource type of a settings notice.
const resourceTenantSettings = "tenant_settings"

// notifyPolicyLoosenedWith is notifyPolicyLoosenedCode for a notice that also
// carries values of its own (kv: alternating name, value after "who").
func (s *TenantService) notifyPolicyLoosenedWith(ctx context.Context, tenantID string, actx auditapp.AuditContext, code, title, what, url string, kv ...any) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return
	}
	who, named := someAdministrator, ""
	if actx.ActorID != "" && s.userInfoProvider != nil {
		if uid, err := shared.IDFromString(actx.ActorID); err == nil {
			if name, err := s.userInfoProvider.GetUserNameByID(ctx, uid); err == nil && name != "" {
				who, named = name, name
			}
		}
	}
	s.notifyAdminsAboutMsg(ctx, tid, adminNotice{
		Type: notificationdom.TypeSystemAlert, ResourceType: resourceTenantSettings, URL: url,
	}, notificationdom.Msg(code, append([]any{"who", actorParam(named)}, kv...)...),
		title, fmt.Sprintf("%s changed %s.", who, what), notificationdom.SeverityHigh)
}

// NotifyPolicyLoosenedWith is notifyPolicyLoosenedWith for the services that
// keep an organization policy outside this package (AI settings).
func (s *TenantService) NotifyPolicyLoosenedWith(ctx context.Context, tenantID string, actx auditapp.AuditContext, code, title, what, url string, kv ...any) {
	s.notifyPolicyLoosenedWith(ctx, tenantID, actx, code, title, what, url, kv...)
}

// closureLoosenedParams are the values of the closing-mode notice: the mode
// and the critical-findings choice as nested messages, and when it takes
// effect (RFC3339).
func closureLoosenedParams(next tenantdom.ClosureSettings, effectiveAt string) []any {
	mode := "review"
	switch next.EffectiveMode() {
	case tenantdom.ClosingModeAuto:
		mode = "auto"
	case tenantdom.ClosingModeOff:
		mode = "off"
	}
	critical := "no"
	if next.CriticalAutoClose {
		critical = "yes"
	}
	return []any{
		"mode", notificationdom.Msg("settings.closing_mode." + mode),
		"critical", notificationdom.Msg("settings.closing_critical." + critical),
		"takes_effect_at", effectiveAt,
	}
}

// scanModeParam is a scan approval mode as a nested message
// (settings.scan_approval_mode.<off|on|strict>).
func scanModeParam(m scangov.Mode) *notificationdom.Message {
	switch m {
	case scangov.ModeOn:
		return notificationdom.Msg("settings.scan_approval_mode.on")
	case scangov.ModeStrict:
		return notificationdom.Msg("settings.scan_approval_mode.strict")
	}
	return notificationdom.Msg("settings.scan_approval_mode.off")
}
