package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/scim"
	"github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/scimgroup"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// UpdateMemberRole extends scimMemberMgr (scim_provisioning_test.go) to satisfy
// scim.RoleManager for the SCIM group → role mapping, exactly as the server's
// scimMembershipAdapter does: as the actor when there is one, else as SCIM
// provisioning.
func (a scimMemberMgr) UpdateMemberRole(ctx context.Context, tenantID, membershipID shared.ID, role string, actorID *shared.ID) error {
	actx := auditapp.AuditContext{TenantID: tenantID.String(), ActorEmail: "scim-provisioning"}
	if actorID != nil {
		actx = auditapp.AuditContext{TenantID: tenantID.String(), ActorID: actorID.String()}
	}
	_, err := a.svc.UpdateMemberRole(ctx, membershipID.String(), tenant.UpdateMemberRoleInput{Role: role}, actx)
	return err
}

// scimTestOwner adds an owner membership to tenantID and returns the user id.
func scimTestOwner(t *testing.T, sqlDB *sql.DB, tenantID shared.ID, role string) shared.ID {
	t.Helper()
	id := shared.NewID()
	email := role + "-" + id.String() + "@scim-owner.test"
	if _, err := sqlDB.Exec(`INSERT INTO users (id, email, name, status, auth_provider, email_verified)
		VALUES ($1, $2, $2, 'active', 'local', true)`, id.String(), email); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() { _, _ = sqlDB.Exec(`DELETE FROM users WHERE id = $1`, id.String()) })
	if _, err := sqlDB.Exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, $3)`,
		id.String(), tenantID.String(), role); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	return id
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
	tenantSvc := tenant.NewTenantService(tenantRepo, log)
	mgr := scimMemberMgr{svc: tenantSvc}
	prov := scim.NewProvisioningService(userRepo, tenantRepo, mgr, log)
	groupSvc := scim.NewGroupService(postgres.NewScimGroupRepository(db), tenantRepo, mgr, log)

	// Only the owner's mapping makes the "admin" group grant admin (23b S-H1).
	owner := scimTestOwner(t, sqlDB, tenantID, "owner")
	if err := groupSvc.SetRoleMappings(ctx, tenantID, map[string]string{"admin": "admin"}, auditapp.AuditContext{ActorID: owner.String()}); err != nil {
		t.Fatalf("owner maps admin: %v", err)
	}

	// Provision the user: a viewer until a group maps them higher (RFC-058).
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
	if roleOf() != tenantdom.RoleViewer {
		t.Fatalf("initial role = %s, want viewer", roleOf())
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

	// Delete the viewer group → no role-group left → the role is kept (a
	// group change never raises anyone by default).
	viewerGroups, _ := groupSvc.List(ctx, tenantID)
	for _, g := range viewerGroups {
		if g.DisplayName() == "viewer" {
			if err := groupSvc.Delete(ctx, tenantID, g.ID()); err != nil {
				t.Fatalf("delete viewer group: %v", err)
			}
		}
	}
	if roleOf() != tenantdom.RoleViewer {
		t.Errorf("after all role-groups gone: role = %s, want viewer", roleOf())
	}
}

// TestSCIMGroups_ConfigurableMapping_RealDB verifies that a per-tenant group →
// role override (for arbitrary IdP group names) drives the role against real SQL.
func TestSCIMGroups_ConfigurableMapping_RealDB(t *testing.T) {
	sqlDB := setupTestDB(t)
	db := &postgres.DB{DB: sqlDB}
	log := logger.NewNop()
	ctx := context.Background()

	tenantID := createTestTenant(t, sqlDB, "scimmap")
	email := "mapuser@example.com"
	t.Cleanup(func() {
		cleanupTestData(sqlDB, tenantID)
		_, _ = sqlDB.Exec("DELETE FROM users WHERE email = $1", email)
	})

	userRepo := postgres.NewUserRepository(db)
	tenantRepo := postgres.NewTenantRepository(db)
	tenantSvc := tenant.NewTenantService(tenantRepo, log)
	mgr := scimMemberMgr{svc: tenantSvc}
	prov := scim.NewProvisioningService(userRepo, tenantRepo, mgr, log)
	groupSvc := scim.NewGroupService(postgres.NewScimGroupRepository(db), tenantRepo, mgr, log)

	res, _, err := prov.CreateOrActivate(ctx, tenantID, scim.ProvisionInput{UserName: email, Active: true})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	userID, _ := shared.IDFromString(res.ID)

	roleOf := func() tenantdom.Role {
		m, _ := tenantRepo.GetMembership(ctx, userID, tenantID)
		return m.Role()
	}

	// The owner maps an arbitrary IdP group name to admin.
	owner := scimTestOwner(t, sqlDB, tenantID, "owner")
	ownerCtx := auditapp.AuditContext{ActorID: owner.String()}
	if err := groupSvc.SetRoleMappings(ctx, tenantID, map[string]string{"Acme-OpenCTEM-Admins": "admin"}, ownerCtx); err != nil {
		t.Fatalf("set mappings: %v", err)
	}

	// A group with that name (not "admin") now promotes via the mapping.
	if _, err := groupSvc.Create(ctx, tenantID, scim.GroupInput{
		DisplayName: "Acme-OpenCTEM-Admins", MemberIDs: []shared.ID{userID},
	}); err != nil {
		t.Fatalf("create mapped group: %v", err)
	}
	if roleOf() != tenantdom.RoleAdmin {
		t.Errorf("mapped group should promote to admin, got %s", roleOf())
	}

	// Round-trip the mapping read.
	got, err := groupSvc.GetRoleMappings(ctx, tenantID)
	if err != nil {
		t.Fatalf("get mappings: %v", err)
	}
	if got["acme-openctem-admins"] != "admin" {
		t.Errorf("mapping read mismatch: %v", got)
	}

	// An invalid role is rejected.
	if err := groupSvc.SetRoleMappings(ctx, tenantID, map[string]string{"x": "owner"}, ownerCtx); err == nil {
		t.Error("mapping to owner must be rejected")
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

	if err := repo.AddMembers(ctx, tenantID, g.ID(), []shared.ID{u2}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := repo.RemoveMembers(ctx, tenantID, g.ID(), []shared.ID{u1}); err != nil {
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

// TestSCIMGroups_AdminMappingOwnerOnly_RealDB: against real Postgres and the
// real tenant + audit services, an administrator cannot demote a peer
// administrator through the SCIM group mappings (23b S-H1); the owner can
// configure an admin mapping; the mapping change and every SCIM-driven role
// change are audited at High, a push naming the SCIM token that made it.
func TestSCIMGroups_AdminMappingOwnerOnly_RealDB(t *testing.T) {
	sqlDB := setupTestDB(t)
	db := &postgres.DB{DB: sqlDB}
	log := logger.NewNop()
	ctx := context.Background()

	tenantID := createTestTenant(t, sqlDB, "scimowner")
	t.Cleanup(func() {
		_, _ = sqlDB.Exec(`DELETE FROM audit_log_chain WHERE tenant_id = $1`, tenantID.String())
		_, _ = sqlDB.Exec(`DELETE FROM audit_logs WHERE tenant_id = $1`, tenantID.String())
		cleanupTestData(sqlDB, tenantID)
	})

	tenantRepo := postgres.NewTenantRepository(db)
	auditSvc := auditapp.NewAuditService(postgres.NewAuditRepository(db), log)
	tenantSvc := tenant.NewTenantService(tenantRepo, log, tenant.WithTenantAuditService(auditSvc))
	groupSvc := scim.NewGroupService(postgres.NewScimGroupRepository(db), tenantRepo, scimMemberMgr{svc: tenantSvc}, log)
	groupSvc.SetAuditService(auditSvc)

	owner := scimTestOwner(t, sqlDB, tenantID, "owner")
	admin := scimTestOwner(t, sqlDB, tenantID, "admin")
	peer := scimTestOwner(t, sqlDB, tenantID, "admin")
	newbie := scimTestOwner(t, sqlDB, tenantID, "member")
	roleOf := func(uid shared.ID) tenantdom.Role {
		t.Helper()
		m, err := tenantRepo.GetMembership(ctx, uid, tenantID)
		if err != nil {
			t.Fatalf("membership: %v", err)
		}
		return m.Role()
	}

	// The owner maps the IT admins group to admin; the peer is in it.
	if err := groupSvc.SetRoleMappings(ctx, tenantID, map[string]string{"IT-Admins": "admin"}, auditapp.AuditContext{ActorID: owner.String()}); err != nil {
		t.Fatalf("owner sets admin mapping: %v", err)
	}
	var byOwner bool
	var by sql.NullString
	if err := sqlDB.QueryRow(`SELECT configured_by, configured_by_owner FROM scim_group_role_mappings
		WHERE tenant_id = $1 AND group_name = 'it-admins'`, tenantID.String()).Scan(&by, &byOwner); err != nil {
		t.Fatal(err)
	}
	if !byOwner || by.String != owner.String() {
		t.Fatalf("mapping provenance = %v/%v, want configured by the owner", by.String, byOwner)
	}

	// The IdP pushes the group with the peer and a newcomer (SCIM token request).
	scimCtx := auditapp.WithSCIMTokenActor(ctx, shared.NewID().String(), "scim_tst")
	if _, err := groupSvc.Create(scimCtx, tenantID, scim.GroupInput{DisplayName: "IT-Admins", MemberIDs: []shared.ID{peer, newbie}}); err != nil {
		t.Fatalf("push group: %v", err)
	}
	if roleOf(newbie) != tenantdom.RoleAdmin {
		t.Fatalf("newcomer in the owner-mapped group: %s, want admin", roleOf(newbie))
	}

	// The admin tries to demote the peer by remapping the group: refused, nothing changes.
	err := groupSvc.SetRoleMappings(ctx, tenantID, map[string]string{"IT-Admins": "viewer"}, auditapp.AuditContext{ActorID: admin.String()})
	if !errors.Is(err, scim.ErrOwnerRequiredForAdminMapping) {
		t.Fatalf("admin remaps the admin group: err = %v, want owner required", err)
	}
	if roleOf(peer) != tenantdom.RoleAdmin || roleOf(newbie) != tenantdom.RoleAdmin {
		t.Errorf("a refused remap demoted someone: peer %s newcomer %s", roleOf(peer), roleOf(newbie))
	}
	var role string
	if err := sqlDB.QueryRow(`SELECT role FROM scim_group_role_mappings WHERE tenant_id = $1 AND group_name = 'it-admins'`,
		tenantID.String()).Scan(&role); err != nil || role != "admin" {
		t.Errorf("mapping after refused remap = %q (%v), want admin", role, err)
	}

	// Audit: the owner's mapping change, High, with the group's before/after.
	var actor, severity string
	var changes []byte
	if err := sqlDB.QueryRow(`SELECT actor_id::text, severity, changes FROM audit_logs
		WHERE tenant_id = $1 AND action = 'scim.group_mappings_updated'`, tenantID.String()).Scan(&actor, &severity, &changes); err != nil {
		t.Fatalf("mapping audit row: %v", err)
	}
	if actor != owner.String() || severity != "high" {
		t.Errorf("mapping audit actor %s severity %s, want the owner at high", actor, severity)
	}
	var ch struct {
		After map[string]any `json:"after"`
	}
	if err := json.Unmarshal(changes, &ch); err != nil || ch.After["mapping:it-admins"] != "admin" {
		t.Errorf("mapping audit changes = %s (%v)", changes, err)
	}

	// Audit: the push's role change, High, naming the SCIM token.
	var meta []byte
	if err := sqlDB.QueryRow(`SELECT severity, metadata FROM audit_logs
		WHERE tenant_id = $1 AND action = 'member.role_changed' ORDER BY logged_at DESC LIMIT 1`,
		tenantID.String()).Scan(&severity, &meta); err != nil {
		t.Fatalf("role change audit row: %v", err)
	}
	var m map[string]any
	_ = json.Unmarshal(meta, &m)
	if severity != "high" || m["auth_method"] != "scim_token" || m["scim_token_prefix"] != "scim_tst" {
		t.Errorf("role change audit = %s %s, want high with the SCIM token", severity, meta)
	}
}
