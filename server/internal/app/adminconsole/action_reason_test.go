package adminconsole

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/admin"
)

// auditReason is the "reason" of an audit row's body, and whether it has one.
func auditReason(t *testing.T, e *admin.AuditLog) (string, bool) {
	t.Helper()
	if e == nil {
		t.Fatal("no audit row")
	}
	v, ok := e.RequestBody["reason"]
	if !ok {
		return "", false
	}
	s, _ := v.(string)
	return s, true
}

// Each roster action keeps the administrator's reason, trimmed, in its own
// audit row; without a reason the row has none (the reason is optional).
func TestRosterActionsKeepTheReason(t *testing.T) {
	ctx := context.Background()
	b := newBGHarness(t)
	b.svc.SetInvitationMailer(&fakeInvites{can: true})

	// New administrator.
	if _, err := b.svc.Provision(ctx, b.admin, ProvisionInput{
		Email: "reason@acme.io", Name: "New", Role: admin.AdminRoleReadonly, Reason: "  auditor for the Q4 review ",
	}, client); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if got, ok := auditReason(t, b.entries.find(ActionAdminProvisioned)); !ok || got != "auditor for the Q4 review" {
		t.Fatalf("provision reason = %q (%v)", got, ok)
	}

	// Two-step reset.
	other, _ := b.addAdmin(t, "other@acme.io", admin.AdminRoleOpsAdmin, false)
	if err := b.svc.ResetCredentials(ctx, b.admin, other.ID(), "lost phone, ticket 42", client); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if got, ok := auditReason(t, b.entries.find(ActionCredentialsReset)); !ok || got != "lost phone, ticket 42" {
		t.Fatalf("reset reason = %q (%v)", got, ok)
	}

	// Identity-provider unbind.
	if err := b.svc.UnbindIdP(ctx, b.admin, other.ID(), "IdP account recreated", client); err != nil {
		t.Fatalf("unbind: %v", err)
	}
	if got, ok := auditReason(t, b.entries.find(ActionIdPUnbound)); !ok || got != "IdP account recreated" {
		t.Fatalf("unbind reason = %q (%v)", got, ok)
	}

	// Break-glass test (the account needs a sign-in to confirm).
	bg, _ := b.addAdmin(t, "bg-reason@acme.io", admin.AdminRoleSuperAdmin, true)
	used := b.clock.Add(-time.Minute)
	bg = admin.Reconstitute(bg.ID(), bg.Email(), bg.Name(), bg.Role(), true, bg.UserID(), &used, "", 0, nil, nil, "", bg.CreatedAt(), nil, bg.UpdatedAt()).
		WithSignInState(bg.SignInState())
	_ = b.admins.Update(ctx, bg)
	if _, err := b.svc.ConfirmBreakGlassTest(ctx, b.admin, bg.ID(), "quarterly drill", client); err != nil {
		t.Fatalf("break-glass test: %v", err)
	}
	e := b.entries.find(ActionBreakGlassTested)
	if got, ok := auditReason(t, e); !ok || got != "quarterly drill" {
		t.Fatalf("break-glass test reason = %q (%v)", got, ok)
	}
	if e.RequestBody["sign_in_at"] == nil {
		t.Fatal("the break-glass row keeps the sign-in time beside the reason")
	}
}

func TestRosterActionsWithoutReason(t *testing.T) {
	ctx := context.Background()
	b := newBGHarness(t)
	b.svc.SetInvitationMailer(&fakeInvites{can: true})
	if _, err := b.svc.Provision(ctx, b.admin, ProvisionInput{
		Email: "noreason@acme.io", Name: "New", Role: admin.AdminRoleReadonly,
	}, client); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if _, ok := auditReason(t, b.entries.find(ActionAdminProvisioned)); ok {
		t.Fatal("no reason given: the row has none")
	}
	other, _ := b.addAdmin(t, "other@acme.io", admin.AdminRoleOpsAdmin, false)
	if err := b.svc.ResetCredentials(ctx, b.admin, other.ID(), "   ", client); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if _, ok := auditReason(t, b.entries.find(ActionCredentialsReset)); ok {
		t.Fatal("a blank reason is no reason")
	}
	if err := b.svc.UnbindIdP(ctx, b.admin, other.ID(), "", client); err != nil {
		t.Fatalf("unbind: %v", err)
	}
	if _, ok := auditReason(t, b.entries.find(ActionIdPUnbound)); ok {
		t.Fatal("no reason given: the row has none")
	}
}
