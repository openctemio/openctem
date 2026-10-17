package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/internal/app/audit"
	app "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// Step-up re-authentication for actions that need it only in some cases
// (docs/architecture/step-up-reauth.md): making someone an administrator or
// an owner, and renaming the organization's slug. The services ask their
// gate; the HTTP gate answers from the caller's session.

// recordingGate refuses (or admits, when err is nil) and records each actor.
type recordingGate struct {
	err    error
	actors []string
}

func (g *recordingGate) RequireRecentAuth(_ context.Context, actorID string) error {
	g.actors = append(g.actors, actorID)
	return g.err
}

func refusingGate() *recordingGate {
	return &recordingGate{err: middleware.ErrStepUpRequired}
}

func wantStepUp(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, middleware.ErrStepUpRequired) {
		t.Fatalf("%s: want a step-up refusal, got %v", what, err)
	}
}

// The admin role reaches a person only through the membership or an
// invitation / created account (GrantExactRoles); the Roles API takes custom
// roles only. Making someone an administrator needs a recent authentication,
// and the owner role is never granted that way.
func TestStepUp_GrantingAdminNeedsRecentAuth(t *testing.T) {
	ctx := context.Background()
	f := newCeilingFixture(t)
	gate := refusingGate()
	f.svc.SetStepUpGate(gate)
	grant := func() error {
		return f.svc.GrantExactRoles(ctx, f.tenant.String(), f.member.String(), []string{role.AdminRoleID.String()},
			f.owner.String(), audit.AuditContext{})
	}
	wantStepUp(t, "GrantExactRoles admin", grant())
	if f.repo.has(f.member, role.AdminRoleID) {
		t.Fatal("the role was granted without a recent authentication")
	}
	if len(gate.actors) != 1 || gate.actors[0] != f.owner.String() {
		t.Fatalf("the gate must be asked about the acting owner, got %v", gate.actors)
	}
	// Inside the window the same grant goes through.
	gate.err = nil
	if err := grant(); err != nil {
		t.Fatalf("inside the window: %v", err)
	}
	if !f.repo.has(f.member, role.AdminRoleID) {
		t.Fatal("role not granted inside the window")
	}
	// The owner role is refused outright, window or not.
	err := f.svc.GrantExactRoles(ctx, f.tenant.String(), f.member.String(), []string{role.OwnerRoleID.String()},
		f.owner.String(), audit.AuditContext{})
	if !errors.Is(err, accesscontrol.ErrSystemRoleViaRoles) {
		t.Fatalf("GrantExactRoles owner: %v", err)
	}
}

func TestStepUp_OrdinaryGrantsDoNotAsk(t *testing.T) {
	ctx := context.Background()
	f := newCeilingFixture(t)
	gate := refusingGate()
	f.svc.SetStepUpGate(gate)
	tid := f.tenant.String()

	if err := f.svc.AssignRole(ctx, accesscontrol.AssignRoleInput{TenantID: tid, UserID: f.member.String(), RoleID: f.analyst.ID().String()},
		f.owner.String(), audit.AuditContext{}); err != nil {
		t.Fatalf("a non-administrator role needs no step-up: %v", err)
	}
	// The admin keeps the admin role while gaining another: no promotion.
	if err := f.svc.SetUserRoles(ctx, accesscontrol.SetUserRolesInput{TenantID: tid, UserID: f.admin.String(),
		RoleIDs: []string{f.analyst.ID().String()}}, f.owner.String(), audit.AuditContext{}); err != nil {
		t.Fatalf("an existing administrator is not a promotion: %v", err)
	}
	if len(gate.actors) != 0 {
		t.Fatalf("the gate was asked for %v", gate.actors)
	}
	// The owner role is refused for anyone, before any step-up is asked.
	err := f.svc.AssignRole(ctx, accesscontrol.AssignRoleInput{TenantID: tid, UserID: f.member.String(), RoleID: role.OwnerRoleID.String()},
		f.admin.String(), audit.AuditContext{})
	if !errors.Is(err, accesscontrol.ErrSystemRoleViaRoles) || errors.Is(err, middleware.ErrStepUpRequired) {
		t.Fatalf("granting owner must be refused outright, got %v", err)
	}
}

// tenantWithOwner seeds an organization and an active owner membership for
// the acting user.
func tenantWithOwner(t *testing.T) (*app.TenantService, *mockTenantRepo, *tenant.Tenant, shared.ID, *recordingGate) {
	t.Helper()
	svc, repo := newTestTenantService()
	tn := seedTenant(repo, "Acme", "acme")
	owner := shared.NewID()
	seedMembershipInRepo(repo, owner, tn.ID(), tenant.RoleOwner)
	gate := refusingGate()
	svc.SetStepUpGate(gate)
	return svc, repo, tn, owner, gate
}

func TestStepUp_TenantAdminPromotionNeedsRecentAuth(t *testing.T) {
	ctx := context.Background()

	t.Run("add a member as administrator", func(t *testing.T) {
		svc, _, tn, owner, gate := tenantWithOwner(t)
		_, err := svc.AddMember(ctx, tn.ID().String(), app.AddMemberInput{UserID: shared.NewID(), Role: "admin"}, owner,
			audit.AuditContext{ActorID: owner.String(), TenantID: tn.ID().String()})
		wantStepUp(t, "AddMember admin", err)
		gate.err = nil
		if _, err := svc.AddMember(ctx, tn.ID().String(), app.AddMemberInput{UserID: shared.NewID(), Role: "admin"}, owner,
			audit.AuditContext{ActorID: owner.String(), TenantID: tn.ID().String()}); err != nil {
			t.Fatalf("inside the window: %v", err)
		}
	})

	t.Run("change a member's role to administrator", func(t *testing.T) {
		svc, repo, tn, owner, _ := tenantWithOwner(t)
		ms := seedMembershipInRepo(repo, shared.NewID(), tn.ID(), tenant.RoleMember)
		_, err := svc.UpdateMemberRole(ctx, ms.ID().String(), app.UpdateMemberRoleInput{Role: "admin"},
			audit.AuditContext{ActorID: owner.String(), TenantID: tn.ID().String()})
		wantStepUp(t, "UpdateMemberRole admin", err)
		if ms.Role() != tenant.RoleMember {
			t.Fatal("the member was promoted without a recent authentication")
		}
	})

	t.Run("a member role needs no step-up", func(t *testing.T) {
		svc, repo, tn, owner, gate := tenantWithOwner(t)
		ms := seedMembershipInRepo(repo, shared.NewID(), tn.ID(), tenant.RoleViewer)
		if _, err := svc.UpdateMemberRole(ctx, ms.ID().String(), app.UpdateMemberRoleInput{Role: "member"},
			audit.AuditContext{ActorID: owner.String(), TenantID: tn.ID().String()}); err != nil {
			t.Fatal(err)
		}
		if len(gate.actors) != 0 {
			t.Fatalf("asked for %v", gate.actors)
		}
	})

	t.Run("invite someone as administrator", func(t *testing.T) {
		svc, _, tn, owner, _ := tenantWithOwner(t)
		_, err := svc.CreateInvitation(ctx, tn.ID().String(), app.CreateInvitationInput{Email: "new@acme.test",
			RoleIDs: []string{role.AdminRoleID.String()}}, owner, audit.AuditContext{ActorID: owner.String(), TenantID: tn.ID().String()})
		wantStepUp(t, "CreateInvitation admin", err)
	})
}

func TestStepUp_SlugRenameNeedsRecentAuth(t *testing.T) {
	ctx := context.Background()
	svc, repo, tn, owner, gate := tenantWithOwner(t)
	actx := audit.AuditContext{ActorID: owner.String(), TenantID: tn.ID().String()}

	slug := "acme-renamed"
	_, err := svc.UpdateTenant(ctx, tn.ID().String(), app.UpdateTenantInput{Slug: &slug, CallerIsOwner: true}, actx)
	wantStepUp(t, "slug rename", err)
	if repo.tenants[tn.ID().String()].Slug() != "acme" || repo.updateCalls != 0 {
		t.Fatal("the slug changed without a recent authentication")
	}

	name, same := "Acme Corp", "acme"
	if _, err := svc.UpdateTenant(ctx, tn.ID().String(), app.UpdateTenantInput{Name: &name, Slug: &same, CallerIsOwner: true}, actx); err != nil {
		t.Fatalf("renaming the organization without touching the slug needs no step-up: %v", err)
	}
	if len(gate.actors) != 1 {
		t.Fatalf("the gate must be asked only for the slug change, got %v", gate.actors)
	}

	gate.err = nil
	if _, err := svc.UpdateTenant(ctx, tn.ID().String(), app.UpdateTenantInput{Slug: &slug, CallerIsOwner: true}, actx); err != nil {
		t.Fatalf("inside the window: %v", err)
	}
}
