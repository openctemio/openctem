package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// toggleGate suspends the organizations in its set.
type toggleGate struct{ suspended map[string]bool }

func (g *toggleGate) CheckAccess(_ context.Context, id shared.ID) error {
	if g.suspended[id.String()] {
		return tenant.ErrOrganizationSuspended
	}
	return nil
}

// No tenant token is minted or refreshed for a suspended organization, and
// the refusal does not spend the refresh token: the member can still open
// another organization, or this one once the suspension is lifted
// (docs/architecture/organization-suspension.md).
func TestTokenForSuspendedOrganizationRefused(t *testing.T) {
	ctx := context.Background()
	h := newMFAHarness(t)
	acme := newPolicyTenant(t, h.tenants, "susp-acme", false)
	beta := newPolicyTenant(t, h.tenants, "susp-beta", false)
	h.tenants.userMemberships = []tenant.UserMembership{
		{TenantID: acme.ID().String(), TenantSlug: acme.Slug(), TenantName: "Acme", Role: "member"},
		{TenantID: beta.ID().String(), TenantSlug: beta.Slug(), TenantName: "Beta", Role: "member"},
	}
	uid := h.seedUser(t, "member@acme.test")
	for _, tn := range []*tenant.Tenant{acme, beta} {
		ms, _ := tenant.NewMembership(uid, tn.ID(), tenant.RoleMember, nil)
		h.tenants.memberships = append(h.tenants.memberships, ms)
	}
	gate := &toggleGate{suspended: map[string]bool{acme.ID().String(): true}}
	h.svc.SetOrganizationGate(gate)

	res := h.login(t, "member@acme.test")
	_, err := h.svc.ExchangeToken(ctx, auth.ExchangeTokenInput{RefreshToken: res.RefreshToken, TenantID: acme.ID().String()})
	if !errors.Is(err, tenant.ErrOrganizationSuspended) {
		t.Fatalf("exchange for the suspended organization: %v", err)
	}
	// The same refresh token still opens the other organization.
	ex, err := h.svc.ExchangeToken(ctx, auth.ExchangeTokenInput{RefreshToken: res.RefreshToken, TenantID: beta.ID().String()})
	if err != nil {
		t.Fatalf("exchange for the other organization after a refusal: %v", err)
	}
	// Refresh into the suspended organization: refused, token not spent.
	if _, err := h.svc.RefreshToken(ctx, auth.RefreshTokenInput{RefreshToken: ex.RefreshToken, TenantID: acme.ID().String()}); !errors.Is(err, tenant.ErrOrganizationSuspended) {
		t.Fatalf("refresh for the suspended organization: %v", err)
	}
	delete(gate.suspended, acme.ID().String())
	if _, err := h.svc.RefreshToken(ctx, auth.RefreshTokenInput{RefreshToken: ex.RefreshToken, TenantID: acme.ID().String()}); err != nil {
		t.Fatalf("refresh after the suspension was lifted: %v", err)
	}
}
