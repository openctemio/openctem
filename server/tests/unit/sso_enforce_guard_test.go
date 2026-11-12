package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/audit"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Require SSO can only be turned on once an administrator has signed in
// through the IdP and an owner can use break-glass (research/287 D6, F-20).
func TestEnforceSSO_Preconditions(t *testing.T) {
	enable := func(extra *bool) tenantapp.UpdateSecuritySettingsInput {
		return tenantapp.UpdateSecuritySettingsInput{SSOEnforced: boolPtr(true), RevokeCredentialsOnSSOEnforce: extra}
	}
	setup := func(store *fakeSSOStore) (*tenantapp.TenantService, shared.ID, func() bool) {
		svc, repo := newTestTenantService()
		svc.SetSSOPathChecker(&mockSSOPathChecker{usable: true})
		tn := seedTenant(repo, "Team", "guard")
		svc.SetSSODomainChecker(fixedSSODomain{ok: true, only: tn.ID()})
		if store != nil {
			svc.SetSSOEnforcementStore(store)
		}
		return svc, tn.ID(), func() bool {
			stored, _ := repo.GetByID(context.Background(), tn.ID())
			return stored.TypedSettings().Security.SSOEnforced
		}
	}

	t.Run("refused without an administrator SSO sign-in", func(t *testing.T) {
		store := readySSOStore()
		store.signedIn = false
		svc, id, enforced := setup(store)
		_, err := svc.UpdateSecuritySettings(context.Background(), id.String(), enable(nil), audit.AuditContext{})
		if !errors.Is(err, tenantapp.ErrSSOEnforceNeedsAdminSignIn) || !shared.IsValidation(err) {
			t.Fatalf("got %v", err)
		}
		if enforced() || store.revoked {
			t.Fatal("a refused enable stored the setting or revoked credentials")
		}
	})

	t.Run("refused when no owner has a second factor (break-glass would not work)", func(t *testing.T) {
		store := readySSOStore()
		store.ownerFactor = false
		svc, id, enforced := setup(store)
		_, err := svc.UpdateSecuritySettings(context.Background(), id.String(), enable(nil), audit.AuditContext{})
		if !errors.Is(err, tenantapp.ErrSSOEnforceNeedsOwnerSecondFactor) {
			t.Fatalf("got %v", err)
		}
		if enforced() {
			t.Fatal("enforcement stored despite the refusal")
		}
	})

	t.Run("refused when the store is missing or fails (fail closed)", func(t *testing.T) {
		svc, id, _ := setup(nil)
		if _, err := svc.UpdateSecuritySettings(context.Background(), id.String(), enable(nil), audit.AuditContext{}); err == nil {
			t.Fatal("unwired store must refuse")
		}
		store := readySSOStore()
		store.err = errors.New("db down")
		svc, id, _ = setup(store)
		if _, err := svc.UpdateSecuritySettings(context.Background(), id.String(), enable(nil), audit.AuditContext{}); err == nil {
			t.Fatal("a failing store must refuse")
		}
	})

	t.Run("allowed when both hold, and credentials are revoked by default", func(t *testing.T) {
		store := readySSOStore()
		svc, id, enforced := setup(store)
		if _, err := svc.UpdateSecuritySettings(context.Background(), id.String(), enable(nil), audit.AuditContext{}); err != nil {
			t.Fatal(err)
		}
		if !enforced() || !store.revoked {
			t.Fatalf("enforced=%v revoked=%v, want both true", enforced(), store.revoked)
		}
	})

	t.Run("opting out keeps the credentials", func(t *testing.T) {
		store := readySSOStore()
		svc, id, enforced := setup(store)
		if _, err := svc.UpdateSecuritySettings(context.Background(), id.String(), enable(boolPtr(false)), audit.AuditContext{}); err != nil {
			t.Fatal(err)
		}
		if !enforced() || store.revoked {
			t.Fatalf("enforced=%v revoked=%v, want enforced and not revoked", enforced(), store.revoked)
		}
	})

	t.Run("readiness reports the counts", func(t *testing.T) {
		svc, id, _ := setup(readySSOStore())
		r, err := svc.SSOEnforcementReadiness(context.Background(), id)
		if err != nil || !r.AdminSSOSignIn || !r.OwnerSecondFactor || r.APIKeys != 2 || r.ConnectorGrants != 1 {
			t.Fatalf("got %+v %v", r, err)
		}
	})
}
