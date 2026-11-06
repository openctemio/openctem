package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	audit "github.com/openctemio/openctem/api/internal/app/audit"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type guardSessions map[string]*session.Session

func (g guardSessions) GetByID(_ context.Context, id shared.ID) (*session.Session, error) {
	if s, ok := g[id.String()]; ok {
		return s, nil
	}
	return nil, shared.ErrNotFound
}

// "SSO must prove two-factor" must not lock out the owner who turns it on
// from a session issued by the organization's own IdP without MFA proof:
// the owner could not get a token again to turn it off.
func TestTenantSvc_UpdateSecuritySettings_SSOMFAProofLockoutGuard(t *testing.T) {
	on := true
	newSess := func(t *testing.T, idpTenant shared.ID, method session.AuthMethod, proof bool) *session.Session {
		t.Helper()
		s, err := session.New(shared.NewID(), "tok", "127.0.0.1", "ua", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		s.SetAuthMethod(method)
		if !idpTenant.IsZero() {
			s.SetIDPTenant(idpTenant)
		}
		s.SetMFAEvidence(proof)
		return s
	}

	t.Run("own-IdP session without proof is refused and nothing is saved", func(t *testing.T) {
		svc, repo := newTestTenantService()
		tn := seedTenant(repo, "Team", "proof-guard")
		st := tn.TypedSettings()
		st.Security.MFARequiredForAdmins = true
		_ = tn.UpdateSettings(st)
		sess := newSess(t, tn.ID(), session.AuthMethodSAML, false)
		svc.SetSessionReader(guardSessions{sess.ID().String(): sess})

		_, err := svc.UpdateSecuritySettings(context.Background(), tn.ID().String(), tenantapp.UpdateSecuritySettingsInput{
			SSORequireMFAEvidence: &on, RequesterSessionID: sess.ID().String(),
		}, audit.AuditContext{})
		if !errors.Is(err, tenantapp.ErrSSOMFAProofLocksOutRequester) || !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("turning the switch on from an unproven own-IdP session must be refused, got %v", err)
		}
		if repo.tenants[tn.ID().String()].TypedSettings().Security.SSORequireMFAEvidence {
			t.Fatal("the switch must not be saved")
		}
	})

	t.Run("turning the 2FA rule on while the switch is on is refused too", func(t *testing.T) {
		svc, repo := newTestTenantService()
		tn := seedTenant(repo, "Team", "proof-guard-2")
		st := tn.TypedSettings()
		st.Security.MFARequiredForAdmins = false
		st.Security.MFARequired = false
		st.Security.SSORequireMFAEvidence = true
		_ = tn.UpdateSettings(st)
		sess := newSess(t, tn.ID(), session.AuthMethodSSO, false)
		svc.SetSessionReader(guardSessions{sess.ID().String(): sess})

		_, err := svc.UpdateSecuritySettings(context.Background(), tn.ID().String(), tenantapp.UpdateSecuritySettingsInput{
			MFARequired: &on, RequesterSessionID: sess.ID().String(),
		}, audit.AuditContext{})
		if !errors.Is(err, tenantapp.ErrSSOMFAProofLocksOutRequester) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("a proven own-IdP session or a password session may turn it on", func(t *testing.T) {
		for name, sessFor := range map[string]func(shared.ID) *session.Session{
			"proven sso": func(id shared.ID) *session.Session { return newSess(t, id, session.AuthMethodSSO, true) },
			"password":   func(shared.ID) *session.Session { return newSess(t, shared.ID{}, session.AuthMethodPassword, false) },
		} {
			svc, repo := newTestTenantService()
			tn := seedTenant(repo, "Team", "proof-ok-"+name)
			st := tn.TypedSettings()
			st.Security.MFARequiredForAdmins = true
			_ = tn.UpdateSettings(st)
			sess := sessFor(tn.ID())
			svc.SetSessionReader(guardSessions{sess.ID().String(): sess})
			if _, err := svc.UpdateSecuritySettings(context.Background(), tn.ID().String(), tenantapp.UpdateSecuritySettingsInput{
				SSORequireMFAEvidence: &on, RequesterSessionID: sess.ID().String(),
			}, audit.AuditContext{}); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
	})

	t.Run("an unreadable session fails closed", func(t *testing.T) {
		svc, repo := newTestTenantService()
		tn := seedTenant(repo, "Team", "proof-guard-3")
		st := tn.TypedSettings()
		st.Security.MFARequiredForAdmins = true
		_ = tn.UpdateSettings(st)
		svc.SetSessionReader(guardSessions{})
		if _, err := svc.UpdateSecuritySettings(context.Background(), tn.ID().String(), tenantapp.UpdateSecuritySettingsInput{
			SSORequireMFAEvidence: &on, RequesterSessionID: shared.NewID().String(),
		}, audit.AuditContext{}); err == nil {
			t.Fatal("a session that cannot be read must not pass the guard")
		}
	})
}
