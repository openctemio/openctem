package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/audit"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// entGate answers the plan check per tenant: allowed (configure) and usable
// (keep running, i.e. allowed or inside the grace).
type entGate struct {
	allowed map[shared.ID]bool
	usable  map[shared.ID]bool
	err     error
}

func (g entGate) Allowed(_ context.Context, id shared.ID, f string) (bool, error) {
	if f != limits.FeatureSSOEnforcement {
		return false, errors.New("unexpected feature " + f)
	}
	return g.allowed[id], g.err
}

func (g entGate) Usable(_ context.Context, id shared.ID, f string) (bool, error) {
	if f != limits.FeatureSSOEnforcement {
		return false, errors.New("unexpected feature " + f)
	}
	return g.usable[id], g.err
}

type entEnforced []shared.ID

func (e entEnforced) ListSSOEnforcedTenantIDs(context.Context, int) ([]shared.ID, error) {
	return e, nil
}

type entAdmins struct {
	tenant.LifecycleRepository
	ids []shared.ID
}

func (a entAdmins) ActiveAdminIDs(context.Context, shared.ID) ([]shared.ID, error) { return a.ids, nil }

type entNotices struct {
	got []notificationdom.NotificationParams
}

func (n *entNotices) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	n.got = append(n.got, p)
	return nil
}

func enforcedTenant(t *testing.T, repo *mockTenantRepo, slug string) *tenant.Tenant {
	t.Helper()
	tn := seedTenant(repo, "Team", slug)
	st := tn.TypedSettings()
	st.Security.SSOEnforced = true
	_ = tn.UpdateSettings(st)
	return tn
}

// research/232 D16: requiring SSO needs sso.enforcement in the plan.
func TestSSOEnforcementFeatureDeniedRefusesEnable(t *testing.T) {
	svc, repo := newTestTenantService()
	svc.SetSSOPathChecker(&mockSSOPathChecker{usable: true})
	tn := seedTenant(repo, "Team", "free-plan")
	svc.SetSSOFeatureGate(entGate{}, nil)
	_, err := svc.UpdateSecuritySettings(context.Background(), tn.ID().String(),
		tenantapp.UpdateSecuritySettingsInput{SSOEnforced: boolPtr(true)}, audit.AuditContext{})
	var fd *limits.ErrFeatureDenied
	if !errors.As(err, &fd) || fd.Feature != limits.FeatureSSOEnforcement {
		t.Fatalf("got %v, want the sso.enforcement refusal", err)
	}
	svc.SetSSOFeatureGate(entGate{err: errors.New("db down")}, nil)
	if _, err := svc.UpdateSecuritySettings(context.Background(), tn.ID().String(),
		tenantapp.UpdateSecuritySettingsInput{SSOEnforced: boolPtr(true)}, audit.AuditContext{}); err == nil {
		t.Fatal("an unreadable plan must refuse (fail-closed)")
	}
	svc.SetSSOFeatureGate(entGate{allowed: map[shared.ID]bool{tn.ID(): true}}, nil)
	if _, err := svc.UpdateSecuritySettings(context.Background(), tn.ID().String(),
		tenantapp.UpdateSecuritySettingsInput{SSOEnforced: boolPtr(true)}, audit.AuditContext{}); err != nil {
		t.Fatalf("a plan with sso.enforcement must enable: %v", err)
	}
}

// After a downgrade, enforcement stays during the grace and is switched off
// once it ends, so members fall back to password and two-factor sign-in
// instead of being locked out; the configured connections are untouched.
// An entitlement read error never lifts enforcement.
func TestDowngradeDisablesEnforcementNotLogin(t *testing.T) {
	svc, repo := newTestTenantService()
	admin := shared.NewID()
	notices := &entNotices{}
	svc.SetLifecycleRepository(entAdmins{ids: []shared.ID{admin}})
	svc.SetLifecycleNotifier(notices)
	inGrace := enforcedTenant(t, repo, "in-grace")
	expired := enforcedTenant(t, repo, "grace-over")
	paid := enforcedTenant(t, repo, "paid")
	svc.SetSSOFeatureGate(entGate{usable: map[shared.ID]bool{inGrace.ID(): true, paid.ID(): true}},
		entEnforced{inGrace.ID(), expired.ID(), paid.ID()})

	n, err := svc.SweepDeniedSSOEnforcement(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("sweep: n=%d err=%v, want one organization changed", n, err)
	}
	enforced := func(id shared.ID) bool {
		got, _ := repo.GetByID(context.Background(), id)
		return got.TypedSettings().Security.SSOEnforced
	}
	if enforced(expired.ID()) {
		t.Fatal("enforcement must be off once the grace ended")
	}
	if !enforced(inGrace.ID()) || !enforced(paid.ID()) {
		t.Fatal("enforcement must stay during the grace and on a plan that includes it")
	}
	if len(notices.got) == 0 || notices.got[len(notices.got)-1].TenantID != expired.ID() {
		t.Fatalf("the downgraded organization's administrators must be told: %+v", notices.got)
	}

	// A read error never lifts enforcement.
	keep := enforcedTenant(t, repo, "read-error")
	svc.SetSSOFeatureGate(entGate{err: errors.New("db down")}, entEnforced{keep.ID()})
	if n, _ := svc.SweepDeniedSSOEnforcement(context.Background()); n != 0 || !enforced(keep.ID()) {
		t.Fatal("an unreadable plan must keep enforcement")
	}
}
