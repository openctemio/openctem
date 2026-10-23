package unit

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/audit"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// fixedSSODomain answers HasVerifiedSSODomain for one tenant (or every tenant
// when only is zero).
type fixedSSODomain struct {
	ok   bool
	err  error
	only shared.ID
}

func (f fixedSSODomain) HasVerifiedSSODomain(_ context.Context, tenantID shared.ID) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	if !f.only.IsZero() && tenantID != f.only {
		return false, nil
	}
	return f.ok, nil
}

// Turning SSO enforcement on needs a domain verified for SSO (research/232
// D11, T24); it fails closed.
func TestEnforceNeedsVerifiedDomain(t *testing.T) {
	enable := tenantapp.UpdateSecuritySettingsInput{SSOEnforced: boolPtr(true)}

	t.Run("refused without a verified SSO domain", func(t *testing.T) {
		svc, repo := newTestTenantService()
		svc.SetSSOPathChecker(&mockSSOPathChecker{usable: true})
		svc.SetSSODomainChecker(fixedSSODomain{ok: false})
		tn := seedTenant(repo, "Team", "no-domain")
		_, err := svc.UpdateSecuritySettings(context.Background(), tn.ID().String(), enable, audit.AuditContext{})
		if !errors.Is(err, tenantapp.ErrSSOEnforceNeedsVerifiedDomain) || !shared.IsValidation(err) {
			t.Fatalf("got %v, want a validation refusal naming the verified domain", err)
		}
		if stored, _ := repo.GetByID(context.Background(), tn.ID()); stored.TypedSettings().Security.SSOEnforced {
			t.Fatal("enforcement was stored despite the refusal")
		}
	})

	t.Run("another tenant's verified domain does not count", func(t *testing.T) {
		svc, repo := newTestTenantService()
		svc.SetSSOPathChecker(&mockSSOPathChecker{usable: true})
		svc.SetSSODomainChecker(fixedSSODomain{ok: true, only: shared.NewID()})
		tn := seedTenant(repo, "Team", "cross")
		if _, err := svc.UpdateSecuritySettings(context.Background(), tn.ID().String(), enable, audit.AuditContext{}); !errors.Is(err, tenantapp.ErrSSOEnforceNeedsVerifiedDomain) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("refused when the check is not wired or fails", func(t *testing.T) {
		svc, repo := newTestTenantService()
		svc.SetSSOPathChecker(&mockSSOPathChecker{usable: true})
		tn := seedTenant(repo, "Team", "unwired")
		if _, err := svc.UpdateSecuritySettings(context.Background(), tn.ID().String(), enable, audit.AuditContext{}); !errors.Is(err, tenantapp.ErrSSOEnforceNeedsVerifiedDomain) {
			t.Fatalf("unwired: got %v", err)
		}
		svc.SetSSODomainChecker(fixedSSODomain{err: errors.New("db down")})
		if _, err := svc.UpdateSecuritySettings(context.Background(), tn.ID().String(), enable, audit.AuditContext{}); err == nil {
			t.Fatal("a failing check must refuse")
		}
	})

	t.Run("allowed with a verified SSO domain", func(t *testing.T) {
		svc, repo := newTestTenantService()
		svc.SetSSOPathChecker(&mockSSOPathChecker{usable: true})
		tn := seedTenant(repo, "Team", "verified")
		svc.SetSSODomainChecker(fixedSSODomain{ok: true, only: tn.ID()})
		got, err := svc.UpdateSecuritySettings(context.Background(), tn.ID().String(), enable, audit.AuditContext{})
		if err != nil || !got.Security.SSOEnforced {
			t.Fatalf("got %v, enforced=%v", err, got != nil && got.Security.SSOEnforced)
		}
	})

	t.Run("already enforced: other saves and disabling never need the domain", func(t *testing.T) {
		svc, repo := newTestTenantService()
		svc.SetSSOPathChecker(&mockSSOPathChecker{usable: true})
		tn := seedTenant(repo, "Team", "lapsed")
		st := tn.TypedSettings()
		st.Security.SSOEnforced = true
		_ = tn.UpdateSettings(st)
		svc.SetSSODomainChecker(fixedSSODomain{ok: false}) // the domain lapsed since
		if _, err := svc.UpdateSecuritySettings(context.Background(), tn.ID().String(), enable, audit.AuditContext{}); err != nil {
			t.Fatalf("re-asserting enforcement after a lapse must not fail: %v", err)
		}
		if _, err := svc.UpdateSecuritySettings(context.Background(), tn.ID().String(),
			tenantapp.UpdateSecuritySettingsInput{MFARequired: boolPtr(true)}, audit.AuditContext{}); err != nil {
			t.Fatalf("an unrelated save must not fail: %v", err)
		}
		if _, err := svc.UpdateSecuritySettings(context.Background(), tn.ID().String(),
			tenantapp.UpdateSecuritySettingsInput{SSOEnforced: boolPtr(false)}, audit.AuditContext{}); err != nil {
			t.Fatalf("disabling must never be blocked: %v", err)
		}
	})
}

type lossAdmins struct {
	tenant.LifecycleRepository
	ids []shared.ID
}

func (l lossAdmins) ActiveAdminIDs(context.Context, shared.ID) ([]shared.ID, error) {
	return l.ids, nil
}

type lossNotices struct {
	got []notificationdom.NotificationParams
}

func (l *lossNotices) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	l.got = append(l.got, p)
	return nil
}

// T24: a lapsed SSO domain alerts the owners and administrators but never
// lifts SSO enforcement.
func TestReverifyFailureKeepsEnforcement(t *testing.T) {
	svc, repo := newTestTenantService()
	admin := shared.NewID()
	notices := &lossNotices{}
	svc.SetLifecycleRepository(lossAdmins{ids: []shared.ID{admin}})
	svc.SetLifecycleNotifier(notices)
	tn := seedTenant(repo, "Team", "dns-lost")
	st := tn.TypedSettings()
	st.Security.SSOEnforced = true
	_ = tn.UpdateSettings(st)

	svc.SSODomainVerificationLost(context.Background(), tn.ID(), "corp.example.com")

	stored, _ := repo.GetByID(context.Background(), tn.ID())
	if !stored.TypedSettings().Security.SSOEnforced {
		t.Fatal("a failed DNS re-verification must not lift SSO enforcement")
	}
	if len(notices.got) != 1 || *notices.got[0].AudienceID != admin || notices.got[0].TenantID != tn.ID() {
		t.Fatalf("expected one alert to the organization's administrator, got %+v", notices.got)
	}
	n := notices.got[0]
	if n.Severity != notificationdom.SeverityHigh || !strings.Contains(n.Body, "corp.example.com") ||
		!strings.Contains(n.Body, "stays required") {
		t.Fatalf("alert must name the domain and say enforcement stays: %+v", n)
	}
}
