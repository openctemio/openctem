package tenant

import (
	"net"
	"slices"

	"github.com/openctemio/openctem/api/pkg/domain/audit"
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
//     target local-policy requirement turned off, the session timeout made
//     longer.
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
		after.SessionTimeoutMin > before.SessionTimeoutMin && before.SessionTimeoutMin > 0:
		return audit.SeverityHigh
	default:
		return audit.SeverityMedium
	}
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
