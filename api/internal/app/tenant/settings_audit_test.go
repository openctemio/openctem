package tenant

import (
	"context"
	"strings"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestSecurityChangeSeverity(t *testing.T) {
	base := tenantdom.SecuritySettings{
		MFARequired:           true,
		SSOEnforced:           true,
		IPWhitelist:           []string{"10.0.0.0/8"},
		AllowedDomains:        []string{"corp.example"},
		EmailVerificationMode: tenantdom.EmailVerificationAuto,
		RequireSensorLocalPolicyForPrivateTargets: true,
		ForbidToolInsecureTLS:                     true,
		PersonalAccounts:                          tenantdom.PersonalAccountsAllowedWithMFA,
		JITRequiresApproval:                       true,
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
		{"tool insecure tls allowed again", with(func(s *tenantdom.SecuritySettings) { s.ForbidToolInsecureTLS = false }), audit.SeverityHigh},
		{"personal accounts relaxed", with(func(s *tenantdom.SecuritySettings) { s.PersonalAccounts = tenantdom.PersonalAccountsAllowed }), audit.SeverityHigh},
		{"jit approval off", with(func(s *tenantdom.SecuritySettings) { s.JITRequiresApproval = false }), audit.SeverityHigh},
		{"sso exception added", with(func(s *tenantdom.SecuritySettings) {
			s.SSOExceptions = []tenantdom.SSOException{{UserID: "u1"}}
		}), audit.SeverityHigh},
		{"personal accounts tightened", with(func(s *tenantdom.SecuritySettings) { s.PersonalAccounts = tenantdom.PersonalAccountsBlocked }), audit.SeverityMedium},
		{"allowlist narrowed", with(func(s *tenantdom.SecuritySettings) { s.IPWhitelist = []string{"10.1.0.0/16", "10.2.3.4"} }), audit.SeverityMedium},
		{"tightened", with(func(s *tenantdom.SecuritySettings) { s.MFARequiredForAdmins = true }), audit.SeverityMedium},
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

func TestSecurityChangeSeverity_AdminsTwoFactor(t *testing.T) {
	adminsOnly := tenantdom.SecuritySettings{MFARequiredForAdmins: true}
	if got := securityChangeSeverity(adminsOnly, tenantdom.SecuritySettings{}); got != audit.SeverityHigh {
		t.Errorf("admins 2FA off: severity = %s, want high", got)
	}
	// Everyone still needs 2FA, so administrators do too.
	everyone := tenantdom.SecuritySettings{MFARequired: true, MFARequiredForAdmins: true}
	if got := securityChangeSeverity(everyone, tenantdom.SecuritySettings{MFARequired: true}); got != audit.SeverityMedium {
		t.Errorf("admins flag off while 2FA required of all: severity = %s, want medium", got)
	}
}

type recordedNotice struct {
	params notificationdom.NotificationParams
}

type recordingNotifier struct{ got []recordedNotice }

func (r *recordingNotifier) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	r.got = append(r.got, recordedNotice{p})
	return nil
}

type fixedAdmins struct {
	tenantdom.LifecycleRepository
	ids []shared.ID
}

func (f fixedAdmins) ActiveAdminIDs(context.Context, shared.ID) ([]shared.ID, error) {
	return f.ids, nil
}

type fixedName struct{}

func (fixedName) GetUserNameByID(context.Context, shared.ID) (string, error) { return "Alice", nil }

// A High or Critical change reaches every owner and administrator in-app,
// naming the actor and what loosened; a Medium one stays in the audit log.
func TestNotifySecurityLoosened(t *testing.T) {
	a1, a2 := shared.NewID(), shared.NewID()
	rec := &recordingNotifier{}
	svc := &TenantService{
		lifecycle:         fixedAdmins{ids: []shared.ID{a1, a2}},
		lifecycleNotifier: rec,
		userInfoProvider:  fixedName{},
		logger:            logger.NewNop(),
	}
	tid := shared.NewID().String()
	actx := auditapp.AuditContext{ActorID: shared.NewID().String()}
	ctx := context.Background()

	svc.notifySecurityLoosened(ctx, tid, actx,
		tenantdom.SecuritySettings{MFARequired: true, IPWhitelist: []string{"10.0.0.0/8"}},
		tenantdom.SecuritySettings{})
	if len(rec.got) != 2 {
		t.Fatalf("critical change: %d notices, want 2 (one per administrator)", len(rec.got))
	}
	p := rec.got[0].params
	if p.URL != "/settings/authentication" || p.NotificationType != notificationdom.TypeSystemAlert ||
		p.Title != "Sign-in security was loosened" || p.Severity != notificationdom.SeverityHigh {
		t.Errorf("unexpected notice: %+v", p)
	}
	for _, want := range []string{"Alice", "two-factor no longer required", "IP allowlist emptied"} {
		if !strings.Contains(p.Body, want) {
			t.Errorf("body %q lacks %q", p.Body, want)
		}
	}

	rec.got = nil
	svc.notifySecurityLoosened(ctx, tid, actx,
		tenantdom.SecuritySettings{}, tenantdom.SecuritySettings{MFARequired: true})
	if len(rec.got) != 0 {
		t.Errorf("tightening notified %d times, want 0", len(rec.got))
	}
	svc.notifySecurityLoosened(ctx, tid, actx,
		tenantdom.SecuritySettings{PersonalAccounts: tenantdom.PersonalAccountsAllowedWithMFA},
		tenantdom.SecuritySettings{PersonalAccounts: tenantdom.PersonalAccountsAllowed})
	if len(rec.got) != 2 {
		t.Errorf("high change: %d notices, want 2", len(rec.got))
	}
}
