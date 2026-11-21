package unit

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/auth"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
)

// The memberships listing and the entry check only ask whether the session
// would be admitted. They must not record an owner break-glass sign-in or
// notify administrators; the token exchange, which mints, still does, once
// per exchange.
func TestAdmissionChecksDoNotRecordBreakGlass(t *testing.T) {
	ctx := context.Background()
	h := newBreakGlassHarness(t)
	tn := mustNewEnforcedTenant(t, h.deps.tenantRepo, "adm-bg", true)
	h.deps.tenantRepo.userMemberships = []tenant.UserMembership{{TenantID: tn.ID().String(), TenantSlug: tn.Slug(), TenantName: "Acme", Role: "owner"}}
	rt, sessID := loginPassword(t, h.svc, h.deps, "owner-adm@acme.com")
	uid := h.deps.sessionRepo.sessions[sessID].UserID()
	h.ownerOf(t, uid, tn.ID())
	h.enableFactor(t, uid)

	for i := 0; i < 3; i++ {
		got, err := h.svc.MembershipAdmission(ctx, uid.String(), sessID)
		if err != nil {
			t.Fatalf("admission: %v", err)
		}
		if e, ok := got[tn.ID().String()]; !ok || e != nil {
			t.Fatalf("the owner with a factor must be reported admitted, got %v", got)
		}
	}
	for i := 0; i < 3; i++ {
		if err := h.svc.CheckEntry(ctx, sessID, uid.String(), tn.ID().String()); err != nil {
			t.Fatalf("entry check: %v", err)
		}
	}
	if n := len(breakGlassLogs(h.audits)); n != 0 || len(h.notice.calls) != 0 {
		t.Fatalf("checks recorded break-glass: audits=%d notices=%d", n, len(h.notice.calls))
	}

	if _, err := h.svc.ExchangeToken(ctx, auth.ExchangeTokenInput{RefreshToken: rt, TenantID: tn.ID().String()}); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if n := len(breakGlassLogs(h.audits)); n != 1 || len(h.notice.calls) != 1 {
		t.Fatalf("the exchange must record exactly one sign-in: audits=%d notices=%d", n, len(h.notice.calls))
	}
}
