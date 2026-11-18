package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/auth"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
)

// The memberships listing says, per organization, what the token request of
// this session would answer: open for one without a rule, the 2FA refusal for
// one that requires it, and nothing at all for a session that is not the
// caller's (no organization of another person is evaluated).
func TestMembershipAdmission(t *testing.T) {
	ctx := context.Background()
	h := newMFAHarness(t)
	open := newPolicyTenant(t, h.tenants, "adm-open", false)
	strict := newPolicyTenant(t, h.tenants, "adm-2fa", false)
	h.tenants.userMemberships = []tenant.UserMembership{
		{TenantID: open.ID().String(), TenantSlug: open.Slug(), TenantName: "Open", Role: "member"},
		{TenantID: strict.ID().String(), TenantSlug: strict.Slug(), TenantName: "Strict", Role: "member"},
	}
	uid := h.seedUser(t, "adm@example.com")
	for _, tn := range []*tenant.Tenant{open, strict} {
		ms, _ := tenant.NewMembership(uid, tn.ID(), tenant.RoleMember, nil)
		h.tenants.memberships = append(h.tenants.memberships, ms)
	}
	res := h.login(t, "adm@example.com")
	st := strict.TypedSettings()
	st.Security.MFARequired = true
	_ = strict.UpdateSettings(st)

	got, err := h.svc.MembershipAdmission(ctx, uid.String(), res.SessionID)
	if err != nil {
		t.Fatalf("admission: %v", err)
	}
	if got[open.ID().String()] != nil {
		t.Fatalf("open organization: %v, want admitted", got[open.ID().String()])
	}
	if !errors.Is(got[strict.ID().String()], auth.ErrMFAEnrollmentRequired) {
		t.Fatalf("2FA organization: %v, want ErrMFAEnrollmentRequired", got[strict.ID().String()])
	}
	if len(got) != 2 {
		t.Fatalf("answered for %d organizations, want only the caller's 2", len(got))
	}

	// Another person's id with this session: refused, nothing evaluated.
	if _, err := h.svc.MembershipAdmission(ctx, shared.NewID().String(), res.SessionID); !errors.Is(err, auth.ErrAdmissionSessionUnknown) {
		t.Fatalf("someone else's session: %v, want ErrAdmissionSessionUnknown", err)
	}
	if _, err := h.svc.MembershipAdmission(ctx, uid.String(), shared.NewID().String()); !errors.Is(err, auth.ErrAdmissionSessionUnknown) {
		t.Fatalf("unknown session: %v, want ErrAdmissionSessionUnknown", err)
	}
}
