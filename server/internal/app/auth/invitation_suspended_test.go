package auth

import (
	"context"
	"errors"
	"testing"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
)

type suspendedGate struct{ calls int }

func (g *suspendedGate) CheckAccess(context.Context, shared.ID) error {
	g.calls++
	return tenantdom.ErrOrganizationSuspended
}

type fixedAcceptor struct {
	m   *tenantdom.Membership
	err error
}

func (a fixedAcceptor) AcceptInvitation(context.Context, string, shared.ID, string, auditapp.AuditContext) (*tenantdom.Membership, error) {
	return a.m, a.err
}

// Accepting an invitation of a suspended organization is refused with
// ORGANIZATION_SUSPENDED and the session is kept: the refresh token the
// browser holds is neither spent nor replaced, so its next use is not a
// reuse that ends the session. Two ways in: the organization's acceptance
// refuses it (TenantService checks the gate), or the organization was
// suspended between the acceptance and the token.
func TestAcceptInvitationWithRefreshToken_SuspendedKeepsSession(t *testing.T) {
	for _, tc := range []struct {
		name     string
		acceptor func(m *tenantdom.Membership) InvitationAcceptor
	}{
		{"acceptance refused", func(*tenantdom.Membership) InvitationAcceptor {
			return fixedAcceptor{err: tenantdom.ErrOrganizationSuspended}
		}},
		{"suspended after acceptance", func(m *tenantdom.Membership) InvitationAcceptor { return fixedAcceptor{m: m} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, rt := challengeFixture(t, false, nil)
			tn, err := tenantdom.NewTenant("Acme", "acme", "creator")
			if err != nil {
				t.Fatal(err)
			}
			if err := tn.UpdateSecuritySettings(tenantdom.SecuritySettings{}); err != nil {
				t.Fatal(err)
			}
			uid := s.userRepo.(*mfaInvUserRepo).u.ID()
			m, err := tenantdom.NewMembership(uid, tn.ID(), tenantdom.RoleMember, nil)
			if err != nil {
				t.Fatal(err)
			}
			s.tenantRepo = &mfaInvTenantRepo{tenant: tn, role: tenantdom.RoleMember, membership: m}
			spend := &mfaInvSpendRepo{mfaInvRefreshRepo: *s.refreshTokenRepo.(*mfaInvRefreshRepo)}
			s.refreshTokenRepo = spend
			s.SetOrganizationGate(&suspendedGate{})
			s.SetInvitationAcceptor(tc.acceptor(m))

			_, err = s.AcceptInvitationWithRefreshToken(context.Background(), AcceptInvitationWithRefreshTokenInput{
				RefreshToken: rt, InvitationToken: "inv",
			})
			if !errors.Is(err, tenantdom.ErrOrganizationSuspended) {
				t.Fatalf("err = %v, want ErrOrganizationSuspended", err)
			}
			if spend.spent != 0 || spend.created != 0 {
				t.Fatalf("spent=%d created=%d: a refused acceptance must keep the refresh token", spend.spent, spend.created)
			}
		})
	}
}
