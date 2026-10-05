package tenant

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/audit"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

func TestSecurityChangeSeverity(t *testing.T) {
	base := tenantdom.SecuritySettings{
		MFARequired:           true,
		SSOEnforced:           true,
		IPWhitelist:           []string{"10.0.0.0/8"},
		AllowedDomains:        []string{"corp.example"},
		EmailVerificationMode: tenantdom.EmailVerificationAuto,
		SessionTimeoutMin:     30,
		RequireSensorLocalPolicyForPrivateTargets: true,
	}
	with := func(f func(s *tenantdom.SecuritySettings)) tenantdom.SecuritySettings {
		s := base
		s.IPWhitelist = append([]string(nil), base.IPWhitelist...)
		s.AllowedDomains = append([]string(nil), base.AllowedDomains...)
		f(&s)
		return s
	}
	cases := []struct {
		name  string
		after tenantdom.SecuritySettings
		want  audit.Severity
	}{
		{"mfa off", with(func(s *tenantdom.SecuritySettings) { s.MFARequired = false }), audit.SeverityCritical},
		{"sso off", with(func(s *tenantdom.SecuritySettings) { s.SSOEnforced = false }), audit.SeverityCritical},
		{"allowlist emptied", with(func(s *tenantdom.SecuritySettings) { s.IPWhitelist = nil }), audit.SeverityCritical},
		{"allowlist widened", with(func(s *tenantdom.SecuritySettings) { s.IPWhitelist = append(s.IPWhitelist, "0.0.0.0/0") }), audit.SeverityHigh},
		{"domains removed", with(func(s *tenantdom.SecuritySettings) { s.AllowedDomains = nil }), audit.SeverityHigh},
		{"domains widened", with(func(s *tenantdom.SecuritySettings) { s.AllowedDomains = append(s.AllowedDomains, "gmail.com") }), audit.SeverityHigh},
		{"verification never", with(func(s *tenantdom.SecuritySettings) { s.EmailVerificationMode = tenantdom.EmailVerificationNever }), audit.SeverityHigh},
		{"local policy off", with(func(s *tenantdom.SecuritySettings) { s.RequireSensorLocalPolicyForPrivateTargets = false }), audit.SeverityHigh},
		{"session longer", with(func(s *tenantdom.SecuritySettings) { s.SessionTimeoutMin = 240 }), audit.SeverityHigh},
		{"allowlist narrowed", with(func(s *tenantdom.SecuritySettings) { s.IPWhitelist = []string{"10.1.0.0/16", "10.2.3.4"} }), audit.SeverityMedium},
		{"tightened", with(func(s *tenantdom.SecuritySettings) { s.SessionTimeoutMin = 15 }), audit.SeverityMedium},
		{"no change", base, audit.SeverityMedium},
	}
	for _, tc := range cases {
		if got := securityChangeSeverity(base, tc.after); got != tc.want {
			t.Errorf("%s: severity = %s, want %s", tc.name, got, tc.want)
		}
	}
	// Turning protection on is never a downgrade.
	off := tenantdom.SecuritySettings{}
	if got := securityChangeSeverity(off, base); got != audit.SeverityMedium {
		t.Errorf("enabling protection: severity = %s, want medium", got)
	}
}
