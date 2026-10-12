package integration

// Least-privilege defaults (RFC-058) on a real database:
//   - a just-in-time membership held for approval is stored suspended, with
//     the reason, and approving it re-enables it;
//   - the admin console lowers a domain's just-in-time provisioning at once,
//     while raising it waits for an owner of the organization.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/auth/domainverify"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ssochange"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestLeastPrivilege_HeldMembershipAndDomainJITApproval(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	pg := &postgres.DB{DB: db}
	tenantRepo := postgres.NewTenantRepository(pg)

	tn := createTestTenant(t, db, "lp-org")
	stamp := shared.NewID().String()[28:]
	owner := createTestUser(t, db, "owner-"+stamp+"@lp.example", "Owner")
	newcomer := createTestUser(t, db, "new-"+stamp+"@lp.example", "New")
	t.Cleanup(func() {
		c := context.Background()
		_, _ = db.ExecContext(c, `DELETE FROM sso_pending_changes WHERE tenant_id = $1`, tn.String())
		_, _ = db.ExecContext(c, `DELETE FROM verified_domains WHERE tenant_id = $1`, tn.String())
		_, _ = db.ExecContext(c, `DELETE FROM user_roles WHERE tenant_id = $1`, tn.String())
		_, _ = db.ExecContext(c, `DELETE FROM tenant_members WHERE tenant_id = $1`, tn.String())
		cleanupTestData(db, tn)
	})
	createTestMembership(t, db, tn, owner, "owner")

	// Held membership.
	m, err := tenant.NewMembership(newcomer, tn, tenant.RoleViewer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.HoldForApproval(); err != nil {
		t.Fatal(err)
	}
	if err := tenantRepo.CreateMembership(ctx, m); err != nil {
		t.Fatal(err)
	}
	got, err := tenantRepo.GetMembership(ctx, newcomer, tn)
	if err != nil {
		t.Fatal(err)
	}
	if !got.AwaitsApproval() || got.IsActive() {
		t.Fatalf("stored membership: status=%s reason=%q, want suspended awaiting_approval", got.Status(), got.SuspendedReason())
	}
	if err := got.Reactivate(); err != nil {
		t.Fatal(err)
	}
	if err := tenantRepo.UpdateMembershipStatus(ctx, got); err != nil {
		t.Fatal(err)
	}
	if again, _ := tenantRepo.GetMembership(ctx, newcomer, tn); again == nil || !again.IsActive() || again.SuspendedReason() != "" {
		t.Fatalf("approved membership must be active with no reason: %+v", again)
	}

	// Domain JIT through the SSO change service.
	vdRepo := postgres.NewVerifiedDomainRepository(pg)
	domains := domainverify.NewService(vdRepo, nil, logger.NewNop())
	vd, _ := verifieddomain.New(shared.NewID(), tn, "lp-"+stamp+".example", "tok")
	vd.WithPurpose(verifieddomain.PurposeSSO)
	if err := vdRepo.Create(ctx, vd); err != nil {
		t.Fatal(err)
	}
	vd.MarkVerified(time.Now())
	if err := vdRepo.Update(ctx, vd); err != nil {
		t.Fatal(err)
	}
	changes := auth.NewSSOChangeService(postgres.NewSSOChangeRepository(pg), nil, nil, tenantRepo, tenantRepo, logger.NewNop())
	changes.SetDomainJITStore(domains)
	by := auth.SSOChangeRequester{Email: "platform@ops.example"}

	// Lowering (default -> viewer) applies at once.
	res, applied, err := changes.SubmitDomainJIT(ctx, tn, vd.ID(), true, "viewer", by)
	if err != nil || !res.Applied || applied == nil {
		t.Fatalf("lowering must apply: res=%+v err=%v", res, err)
	}
	// Raising (viewer -> member) waits for the owner.
	res, applied, err = changes.SubmitDomainJIT(ctx, tn, vd.ID(), true, "member", by)
	if err != nil || res.Applied || applied != nil || res.Change == nil || res.Change.Kind != ssochange.KindDomainJIT {
		t.Fatalf("raising must wait: res=%+v err=%v", res, err)
	}
	if on, role, _ := domains.DomainJITPolicy(ctx, tn.String(), vd.Domain()); !on || role != "viewer" {
		t.Fatalf("before approval: %v %q, want viewer", on, role)
	}
	// Only an owner approves.
	if _, err := changes.Approve(ctx, tn, res.Change.ID, newcomer); err == nil {
		t.Fatal("a non-owner must not approve")
	}
	if _, err := changes.Approve(ctx, tn, res.Change.ID, owner); err != nil {
		t.Fatalf("owner approves: %v", err)
	}
	if on, role, _ := domains.DomainJITPolicy(ctx, tn.String(), vd.Domain()); !on || role != "member" {
		t.Fatalf("after approval: %v %q, want member", on, role)
	}
}
