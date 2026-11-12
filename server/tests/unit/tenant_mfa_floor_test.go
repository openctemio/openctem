package unit

import (
	"context"
	"errors"
	"testing"

	audit "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/platformmfa"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// An organization may tighten the platform two-factor floor, never loosen
// below it: a save that leaves the result under the floor is refused (and
// nothing is stored); a stored value from before the floor was raised is
// left alone and clamped on read.
func TestTenantSvc_UpdateSecuritySettings_MFAFloor(t *testing.T) {
	off, on := false, true
	ctx := context.Background()

	t.Run("under an admins floor, switching admin 2FA off is refused", func(t *testing.T) {
		svc, repo := newTestTenantService()
		svc.SetMFAFloorSource(&floorStub{p: platformmfa.Policy{Floor: tenant.MFAFloorAdmins}})
		tn := seedTenant(repo, "Team", "floor-admins")
		st := tn.TypedSettings()
		st.Security.MFARequiredForAdmins = true
		_ = tn.UpdateSettings(st)

		_, err := svc.UpdateSecuritySettings(ctx, tn.ID().String(), tenantapp.UpdateSecuritySettingsInput{MFARequiredForAdmins: &off}, audit.AuditContext{})
		if !errors.Is(err, tenantapp.ErrMFABelowPlatformFloor) || !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("err = %v, want ErrMFABelowPlatformFloor", err)
		}
		if !repo.tenants[tn.ID().String()].TypedSettings().Security.MFARequiredForAdmins {
			t.Fatal("the refused save changed the stored settings")
		}
	})

	t.Run("under an admins floor, requiring everyone is allowed", func(t *testing.T) {
		svc, repo := newTestTenantService()
		svc.SetMFAFloorSource(&floorStub{p: platformmfa.Policy{Floor: tenant.MFAFloorAdmins}})
		tn := seedTenant(repo, "Team", "floor-tighten")
		if _, err := svc.UpdateSecuritySettings(ctx, tn.ID().String(), tenantapp.UpdateSecuritySettingsInput{MFARequired: &on}, audit.AuditContext{}); err != nil {
			t.Fatalf("tightening above the floor: %v", err)
		}
	})

	t.Run("under an everyone floor, only requiring everyone is accepted", func(t *testing.T) {
		svc, repo := newTestTenantService()
		svc.SetMFAFloorSource(&floorStub{p: platformmfa.Policy{Floor: tenant.MFAFloorEveryone}})
		tn := seedTenant(repo, "Team", "floor-everyone")
		_, err := svc.UpdateSecuritySettings(ctx, tn.ID().String(), tenantapp.UpdateSecuritySettingsInput{MFARequiredForAdmins: &on}, audit.AuditContext{})
		if !errors.Is(err, tenantapp.ErrMFABelowPlatformFloor) {
			t.Fatalf("admins-only under an everyone floor: %v", err)
		}
	})

	t.Run("a raise of the floor clamps on read without rewriting the stored row, and unrelated saves still work", func(t *testing.T) {
		svc, repo := newTestTenantService()
		tn := seedTenant(repo, "Team", "floor-clamp")
		st := tn.TypedSettings()
		st.Security.MFARequired, st.Security.MFARequiredForAdmins = false, false
		_ = tn.UpdateSettings(st)
		svc.SetMFAFloorSource(&floorStub{p: platformmfa.Policy{Floor: tenant.MFAFloorEveryone}})

		got, err := svc.GetTenantSettings(ctx, tn.ID().String())
		if err != nil {
			t.Fatal(err)
		}
		clamped, floor := svc.ApplyMFAFloor(ctx, got)
		if floor != tenant.MFAFloorEveryone || !clamped.Security.MFARequired {
			t.Fatalf("floor %q required %v: want the read clamped up", floor, clamped.Security.MFARequired)
		}
		if got.Security.MFARequired || repo.tenants[tn.ID().String()].TypedSettings().Security.MFARequired {
			t.Fatal("the stored settings must not be rewritten")
		}
		ua := "scanner"
		if _, err := svc.UpdateSecuritySettings(ctx, tn.ID().String(), tenantapp.UpdateSecuritySettingsInput{ToolHTTPUserAgent: &ua}, audit.AuditContext{}); err != nil {
			t.Fatalf("an unrelated save must not trip the floor: %v", err)
		}
	})

	t.Run("an unreadable floor refuses the save", func(t *testing.T) {
		svc, repo := newTestTenantService()
		svc.SetMFAFloorSource(&floorStub{err: errors.New("store down")})
		tn := seedTenant(repo, "Team", "floor-unreadable")
		if _, err := svc.UpdateSecuritySettings(ctx, tn.ID().String(), tenantapp.UpdateSecuritySettingsInput{MFARequired: &on}, audit.AuditContext{}); err == nil {
			t.Fatal("a 2FA save went through on an unreadable floor")
		}
	})
}
