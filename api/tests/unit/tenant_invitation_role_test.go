package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// An invitation may only carry system roles or roles of the inviting tenant.
// A role id from another tenant used to be stored as-is: the admin path skips
// canGrantRoles, and nothing else looked at the role's tenant until accept.

func newInvitationRoleFixture(t *testing.T) (*tenant.TenantService, *mockTenantRepo, *mockRoleRepo, string) {
	t.Helper()
	svc, repo := newTestTenantService()
	tn := seedTenant(repo, "Team", "team-slug")
	roleRepo := newMockRoleRepo()
	svc.SetRoleService(app.NewRoleService(roleRepo, newMockPermissionRepo(), logger.NewNop()))
	return svc, repo, roleRepo, tn.ID().String()
}

func TestCreateInvitation_RejectsRoleOfAnotherTenant(t *testing.T) {
	svc, repo, roleRepo, tenantID := newInvitationRoleFixture(t)
	foreign := seedCustomRole(roleRepo, role.NewID(), "foreign", "Foreign", []string{"assets:read"})

	_, err := svc.CreateInvitation(context.Background(), tenantID, tenant.CreateInvitationInput{
		Email:   "new@example.com",
		RoleIDs: []string{foreign.ID().String()},
	}, shared.NewID(), app.AuditContext{})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want a validation error for another tenant's role, got %v", err)
	}
	if len(repo.invitations) != 0 {
		t.Fatalf("invitation stored despite the foreign role: %d rows", len(repo.invitations))
	}
}

func TestCreateInvitation_RejectsUnknownRole(t *testing.T) {
	svc, _, _, tenantID := newInvitationRoleFixture(t)
	_, err := svc.CreateInvitation(context.Background(), tenantID, tenant.CreateInvitationInput{
		Email:   "new@example.com",
		RoleIDs: []string{role.NewID().String()},
	}, shared.NewID(), app.AuditContext{})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want a validation error for an unknown role, got %v", err)
	}
}

func TestCreateInvitation_AcceptsSystemAndOwnTenantRoles(t *testing.T) {
	svc, repo, roleRepo, tenantID := newInvitationRoleFixture(t)
	viewer := seedSystemRole(roleRepo, role.ViewerRoleID, "viewer", "Viewer")
	tid, _ := role.ParseID(tenantID)
	own := seedCustomRole(roleRepo, tid, "analyst", "Analyst", []string{"assets:read"})

	inv, err := svc.CreateInvitation(context.Background(), tenantID, tenant.CreateInvitationInput{
		Email:   "new@example.com",
		RoleIDs: []string{viewer.ID().String(), own.ID().String()},
	}, shared.NewID(), app.AuditContext{})
	if err != nil {
		t.Fatalf("system + own-tenant roles must be accepted: %v", err)
	}
	if inv == nil || len(repo.invitations) != 1 {
		t.Fatalf("want one stored invitation, got %d", len(repo.invitations))
	}
}

func TestRoleService_ValidateRolesForTenant(t *testing.T) {
	svc, roleRepo, _ := newTestRoleService()
	tenantID := role.NewID()
	own := seedCustomRole(roleRepo, tenantID, "own", "Own", nil)
	foreign := seedCustomRole(roleRepo, role.NewID(), "foreign", "Foreign", nil)
	sys := seedSystemRole(roleRepo, role.MemberRoleID, "member", "Member")

	ctx := context.Background()
	if err := svc.ValidateRolesForTenant(ctx, tenantID.String(), []string{own.ID().String(), sys.ID().String()}); err != nil {
		t.Fatalf("own + system roles: %v", err)
	}
	for name, ids := range map[string][]string{
		"foreign": {own.ID().String(), foreign.ID().String()},
		"unknown": {role.NewID().String()},
		"garbage": {"not-a-uuid"},
	} {
		if err := svc.ValidateRolesForTenant(ctx, tenantID.String(), ids); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: want validation error, got %v", name, err)
		}
	}
}
