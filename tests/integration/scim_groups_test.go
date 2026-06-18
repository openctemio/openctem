package integration

import (
	"context"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/app/scim"
	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/domain/scimgroup"
	"github.com/openctemio/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/logger"
)

// UpdateMemberRole extends scimMemberMgr (scim_provisioning_test.go) to satisfy
// scim.RoleManager for the SCIM group → role mapping.
func (a scimMemberMgr) UpdateMemberRole(ctx context.Context, tenantID, membershipID shared.ID, role string) error {
	_, err := a.svc.UpdateMemberRole(ctx, membershipID.String(),
		app.UpdateMemberRoleInput{Role: role},
		app.AuditContext{TenantID: tenantID.String(), ActorEmail: "scim-provisioning"})
	return err
}

// TestSCIMGroups_RoleMapping_RealDB verifies, against real Postgres, that SCIM
// group membership drives a user's tenant role: adding a member to an "admin"
// group promotes them, removing reverts to member, and the highest-privilege
// role-group wins.
func TestSCIMGroups_RoleMapping_RealDB(t *testing.T) {
	sqlDB := setupTestDB(t)
	db := &postgres.DB{DB: sqlDB}
	log := logger.NewNop()
	ctx := context.Background()

	tenantID := createTestTenant(t, sqlDB, "scimgrp")
	email := "grpuser@example.com"
	t.Cleanup(func() {
		cleanupTestData(sqlDB, tenantID)
		_, _ = sqlDB.Exec("DELETE FROM users WHERE email = $1", email)
	})

	userRepo := postgres.NewUserRepository(db)
	tenantRepo := postgres.NewTenantRepository(db)
	tenantSvc := app.NewTenantService(tenantRepo, log)
	mgr := scimMemberMgr{svc: tenantSvc}
	prov := scim.NewProvisioningService(userRepo, tenantRepo, mgr, log)
	groupSvc := scim.NewGroupService(postgres.NewScimGroupRepository(db), tenantRepo, mgr, log)

	// Provision the user as a plain member.
	res, _, err := prov.CreateOrActivate(ctx, tenantID, scim.ProvisionInput{UserName: email, Active: true})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	userID, _ := shared.IDFromString(res.ID)

	roleOf := func() tenantdom.Role {
		m, gerr := tenantRepo.GetMembership(ctx, userID, tenantID)
		if gerr != nil {
			t.Fatalf("get membership: %v", gerr)
		}
		return m.Role()
	}
	if roleOf() != tenantdom.RoleMember {
		t.Fatalf("initial role = %s, want member", roleOf())
	}

	// Create an "admin" group with the user → role becomes admin.
	adminGrp, err := groupSvc.Create(ctx, tenantID, scim.GroupInput{
		DisplayName: "admin", MemberIDs: []shared.ID{userID},
	})
	if err != nil {
		t.Fatalf("create admin group: %v", err)
	}
	if roleOf() != tenantdom.RoleAdmin {
		t.Errorf("after admin group: role = %s, want admin", roleOf())
	}

	// Add the user to a "viewer" group too → admin still wins (highest privilege).
	if _, err := groupSvc.Create(ctx, tenantID, scim.GroupInput{
		DisplayName: "viewer", MemberIDs: []shared.ID{userID},
	}); err != nil {
		t.Fatalf("create viewer group: %v", err)
	}
	if roleOf() != tenantdom.RoleAdmin {
		t.Errorf("admin should win over viewer: role = %s", roleOf())
	}

	// Remove the user from the admin group → now only viewer → role viewer.
	if _, err := groupSvc.PatchMembers(ctx, tenantID, adminGrp.ID(), nil, []shared.ID{userID}); err != nil {
		t.Fatalf("patch remove from admin: %v", err)
	}
	if roleOf() != tenantdom.RoleViewer {
		t.Errorf("after removing from admin (still in viewer): role = %s, want viewer", roleOf())
	}

	// Delete the viewer group → no role-group left → revert to member default.
	viewerGroups, _ := groupSvc.List(ctx, tenantID)
	for _, g := range viewerGroups {
		if g.DisplayName() == "viewer" {
			if err := groupSvc.Delete(ctx, tenantID, g.ID()); err != nil {
				t.Fatalf("delete viewer group: %v", err)
			}
		}
	}
	if roleOf() != tenantdom.RoleMember {
		t.Errorf("after all role-groups gone: role = %s, want member", roleOf())
	}
}

// TestSCIMGroups_Repository_RoundTrip checks the group repository CRUD + member
// ops against real SQL.
func TestSCIMGroups_Repository_RoundTrip(t *testing.T) {
	sqlDB := setupTestDB(t)
	db := &postgres.DB{DB: sqlDB}
	ctx := context.Background()

	tenantID := createTestTenant(t, sqlDB, "scimgrp-repo")
	u1 := createTestUser(t, sqlDB, "g1@example.com", "G One")
	u2 := createTestUser(t, sqlDB, "g2@example.com", "G Two")
	t.Cleanup(func() {
		cleanupTestData(sqlDB, tenantID)
		_, _ = sqlDB.Exec("DELETE FROM users WHERE email IN ('g1@example.com','g2@example.com')")
	})

	repo := postgres.NewScimGroupRepository(db)
	g := scimgroup.New(shared.NewID(), tenantID, "Engineering", "", []shared.ID{u1})
	if err := repo.Create(ctx, g); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := repo.GetByID(ctx, tenantID, g.ID())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.DisplayName() != "Engineering" || len(got.Members()) != 1 || got.Members()[0] != u1 {
		t.Fatalf("round-trip mismatch: name=%s members=%v", got.DisplayName(), got.Members())
	}

	if err := repo.AddMembers(ctx, g.ID(), []shared.ID{u2}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := repo.RemoveMembers(ctx, g.ID(), []shared.ID{u1}); err != nil {
		t.Fatalf("remove: %v", err)
	}
	names, err := repo.RoleGroupNamesForUser(ctx, tenantID, u2)
	if err != nil {
		t.Fatalf("names for user: %v", err)
	}
	if len(names) != 1 || names[0] != "Engineering" {
		t.Errorf("group names for u2 = %v, want [Engineering]", names)
	}
	// u1 removed → no groups.
	if n, _ := repo.RoleGroupNamesForUser(ctx, tenantID, u1); len(n) != 0 {
		t.Errorf("u1 should have no groups after removal, got %v", n)
	}

	if err := repo.Delete(ctx, tenantID, g.ID()); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := repo.GetByID(ctx, tenantID, g.ID()); err == nil {
		t.Error("group should be gone after delete")
	}
}
