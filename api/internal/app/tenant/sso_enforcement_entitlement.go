package tenant

// SSO enforcement after the organization lost it (research/232 D16): enforcement is
// switched off once the read-only grace ended, so members fall back to
// password and two-factor sign-in instead of being locked out.

import (
	"context"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
)

// SweepDeniedSSOEnforcement turns SSO enforcement off for every organization
// that may no longer use sso.enforcement and whose grace ended, and
// tells its owners and administrators. During the grace enforcement stays.
// An entitlement read error keeps enforcement (it is only ever lifted on a
// clear answer). Returns how many organizations were changed.
func (s *TenantService) SweepDeniedSSOEnforcement(ctx context.Context) (int, error) {
	if s.features == nil || s.enforced == nil {
		return 0, nil
	}
	ids, err := s.enforced.ListSSOEnforcedTenantIDs(ctx, 1000)
	if err != nil {
		return 0, err
	}
	off := false
	changed := 0
	for _, id := range ids {
		usable, uerr := s.features.Usable(ctx, id, limits.FeatureSSOEnforcement)
		if uerr != nil {
			s.logger.Warn("read sso.enforcement entitlement", "tenant_id", id.String(), "error", uerr)
			continue
		}
		if usable {
			continue
		}
		actx := auditapp.AuditContext{TenantID: id.String(), ActorEmail: "system:entitlement"}
		if _, err := s.UpdateSecuritySettings(ctx, id.String(), UpdateSecuritySettingsInput{SSOEnforced: &off}, actx); err != nil {
			s.logger.Error("turn off sso enforcement after a limits change", "tenant_id", id.String(), "error", err)
			continue
		}
		changed++
		s.logger.Warn("SSO enforcement turned off: no longer available for this organization", "tenant_id", id.String())
		s.notifyAdminsAbout(ctx, id, adminNotice{
			Type: notificationdom.TypeSystemAlert, ResourceType: "tenant_settings", URL: "/settings/authentication",
		}, "Single sign-on is no longer required",
			fmt.Sprintf("Requiring single sign-on is no longer available for this organization, and its %d-day grace period ended. "+
				"Members can sign in with a password again (with two-factor where it is required). Sign-in through your identity provider keeps working.",
				int(limits.GracePeriod.Hours()/24)), notificationdom.SeverityHigh)
	}
	return changed, nil
}
