package tenant

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// securityChangeSeverity grades a security-settings change for the audit log.
// A change that weakens the organization's protection is High or Critical so
// it stands out in the log and in alerting; a change that tightens it, or is
// neutral, is Medium.
//
//   - Critical: 2FA requirement turned off, SSO enforcement turned off, the IP
//     allowlist emptied (any network may connect again).
//   - High: IP allowlist widened (entries added), allowed email domains
//     widened or removed, email verification set to "never", the private
//     target local-policy requirement turned off, the administrators'
//     two-factor requirement turned off (while 2FA is not required of
//     everyone), the personal-account policy made less strict, JIT approval
//     turned off, a sign-in exception added.
func securityChangeSeverity(before, after tenantdom.SecuritySettings) audit.Severity {
	switch {
	case before.MFARequired && !after.MFARequired,
		before.SSOEnforced && !after.SSOEnforced,
		len(before.IPWhitelist) > 0 && len(after.IPWhitelist) == 0,
		!before.AllowSensorInteractsh && after.AllowSensorInteractsh,
		!before.AllowSensorCustomTemplates && after.AllowSensorCustomTemplates:
		return audit.SeverityCritical
	case widensNetworks(before.IPWhitelist, after.IPWhitelist) && len(before.IPWhitelist) > 0,
		len(before.AllowedDomains) > 0 && (len(after.AllowedDomains) == 0 || addsEntries(before.AllowedDomains, after.AllowedDomains)),
		before.EmailVerificationMode != tenantdom.EmailVerificationNever && after.EmailVerificationMode == tenantdom.EmailVerificationNever,
		before.RequireSensorLocalPolicyForPrivateTargets && !after.RequireSensorLocalPolicyForPrivateTargets,
		before.ForbidToolInsecureTLS && !after.ForbidToolInsecureTLS,
		// Opening who may be invited, or dropping the required end of access.
		before.EffectiveInvitees() != tenantdom.InviteesAny && after.EffectiveInvitees() == tenantdom.InviteesAny,
		before.ExternalAccessEndRequired && !after.ExternalAccessEndRequired,
		before.MFARequiredForAdmins && !after.MFARequiredForAdmins && !after.MFARequired,
		personalPolicyRank(after.PersonalAccounts) < personalPolicyRank(before.PersonalAccounts),
		before.JITRequiresApproval && !after.JITRequiresApproval,
		addsSSOExceptions(before.SSOExceptions, after.SSOExceptions):
		return audit.SeverityHigh
	default:
		return audit.SeverityMedium
	}
}

// personalPolicyRank orders the personal-account policies from the least
// (0) to the most strict.
func personalPolicyRank(p tenantdom.PersonalAccountsPolicy) int {
	switch p.Effective() {
	case tenantdom.PersonalAccountsBlocked:
		return 2
	case tenantdom.PersonalAccountsAllowedWithMFA:
		return 1
	default:
		return 0
	}
}

// addsSSOExceptions reports whether after names a member that before did not.
func addsSSOExceptions(before, after []tenantdom.SSOException) bool {
	for _, a := range after {
		found := false
		for _, b := range before {
			if a.UserID == b.UserID {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return false
}

// loosenedSummary lists, in words, what a security change loosened, for the
// notice sent to the administrators.
func loosenedSummary(before, after tenantdom.SecuritySettings) string {
	var parts []string
	add := func(cond bool, text string) {
		if cond {
			parts = append(parts, text)
		}
	}
	add(before.MFARequired && !after.MFARequired, "two-factor no longer required")
	add(before.MFARequiredForAdmins && !after.MFARequiredForAdmins && !after.MFARequired, "two-factor no longer required for administrators")
	add(before.SSOEnforced && !after.SSOEnforced, "single sign-on no longer enforced")
	add(len(before.IPWhitelist) > 0 && len(after.IPWhitelist) == 0, "IP allowlist emptied")
	add(len(before.IPWhitelist) > 0 && len(after.IPWhitelist) > 0 && widensNetworks(before.IPWhitelist, after.IPWhitelist), "IP allowlist widened")
	add(len(before.AllowedDomains) > 0 && (len(after.AllowedDomains) == 0 || addsEntries(before.AllowedDomains, after.AllowedDomains)), "allowed email domains widened")
	add(before.EmailVerificationMode != tenantdom.EmailVerificationNever && after.EmailVerificationMode == tenantdom.EmailVerificationNever, "email verification turned off")
	add(personalPolicyRank(after.PersonalAccounts) < personalPolicyRank(before.PersonalAccounts), "personal accounts policy relaxed")
	add(before.JITRequiresApproval && !after.JITRequiresApproval, "approval of new single sign-on members turned off")
	add(addsSSOExceptions(before.SSOExceptions, after.SSOExceptions), "single sign-on exception added")
	add(!before.AllowSensorInteractsh && after.AllowSensorInteractsh, "sensor out-of-band interaction allowed")
	add(!before.AllowSensorCustomTemplates && after.AllowSensorCustomTemplates, "sensor custom templates allowed")
	add(before.RequireSensorLocalPolicyForPrivateTargets && !after.RequireSensorLocalPolicyForPrivateTargets, "sensor local policy no longer required for private targets")
	add(before.ForbidToolInsecureTLS && !after.ForbidToolInsecureTLS, "insecure TLS allowed for tools")
	add(before.EffectiveInvitees() != tenantdom.InviteesAny && after.EffectiveInvitees() == tenantdom.InviteesAny, "anyone may be invited")
	add(before.ExternalAccessEndRequired && !after.ExternalAccessEndRequired, "end date no longer required for external access")
	return strings.Join(parts, "; ")
}

// addsEntries reports whether after contains a value that before does not.
func addsEntries(before, after []string) bool {
	for _, v := range after {
		if !slices.Contains(before, v) {
			return true
		}
	}
	return false
}

// widensNetworks reports whether after allows an address that before did not:
// some entry of after (an IP or CIDR) is not inside any entry of before.
// Entries that do not parse are compared as text.
func widensNetworks(before, after []string) bool {
	for _, a := range after {
		an := parseNetwork(a)
		covered := false
		for _, b := range before {
			if a == b {
				covered = true
				break
			}
			if bn := parseNetwork(b); an != nil && bn != nil && networkContains(bn, an) {
				covered = true
				break
			}
		}
		if !covered {
			return true
		}
	}
	return false
}

func parseNetwork(v string) *net.IPNet {
	if _, n, err := net.ParseCIDR(v); err == nil {
		return n
	}
	ip := net.ParseIP(v)
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

func networkContains(outer, inner *net.IPNet) bool {
	ob, obits := outer.Mask.Size()
	ib, ibits := inner.Mask.Size()
	return obits == ibits && ob <= ib && outer.Contains(inner.IP)
}

// profileAuditView is the organization profile as recorded in audit diffs.
type profileAuditView struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description"`
	LogoURL     string `json:"logo_url"`
}

func profileOf(t *tenantdom.Tenant) profileAuditView {
	return profileAuditView{Name: t.Name(), Slug: t.Slug(), Description: t.Description(), LogoURL: t.LogoURL()}
}

// notifySecurityLoosened tells the organization's owners and administrators,
// in-app, when a security-settings change was graded High or Critical, so a
// loosened sign-in policy is never silent. Best effort: the change is saved
// and audited.
func (s *TenantService) notifySecurityLoosened(ctx context.Context, tenantID string, actx auditapp.AuditContext, before, after tenantdom.SecuritySettings) {
	sev := securityChangeSeverity(before, after)
	if sev != audit.SeverityHigh && sev != audit.SeverityCritical {
		return
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return
	}
	who := "An administrator"
	if actx.ActorID != "" && s.userInfoProvider != nil {
		if uid, err := shared.IDFromString(actx.ActorID); err == nil {
			if name, err := s.userInfoProvider.GetUserNameByID(ctx, uid); err == nil && name != "" {
				who = name
			}
		}
	}
	body := who + " changed the sign-in security settings."
	if what := loosenedSummary(before, after); what != "" {
		body = fmt.Sprintf("%s changed the sign-in security settings: %s.", who, what)
	}
	s.notifyAdminsAbout(ctx, tid, adminNotice{
		Type: notificationdom.TypeSystemAlert, ResourceType: "tenant_settings", URL: "/settings/authentication",
	}, "Sign-in security was loosened", body, notificationdom.SeverityHigh)
}
