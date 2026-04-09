package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/role"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// =============================================================================
// Mock Role Repository
// =============================================================================

type mockRoleRepo struct {
	// Storage
	roles map[string]*role.Role

	// User role assignments: key = "tenantID:userID"
	userRoles map[string][]role.ID

	// Error overrides for specific methods
	createErr         error
	getByIDErr        error
	getBySlugErr      error
	updateErr         error
	deleteErr         error
	assignRoleErr     error
	removeRoleErr     error
	listForTenantErr  error
	listSystemErr     error
	getUserRolesErr   error
	getUserPermsErr   error
	setUserRolesErr   error
	bulkAssignErr     error
	listMembersErr    error
	countUsersErr     error
	hasFullAccessErr  error

	// Call tracking
	createCalls       int
	getByIDCalls      int
	getBySlugCalls    int
	updateCalls       int
	deleteCalls       int
	assignRoleCalls   int
	removeRoleCalls   int
	listMembersCalls  int
	countUsersCalls   int

	// Additional behavior
	hasFullAccessResult bool
	countUsersResult    int
	userPermissions     []string
	roleMembers         []*role.UserRole
}

func newMockRoleRepo() *mockRoleRepo {
	return &mockRoleRepo{
		roles:     make(map[string]*role.Role),
		userRoles: make(map[string][]role.ID),
	}
}

func (m *mockRoleRepo) Create(_ context.Context, r *role.Role) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.roles[r.ID().String()] = r
	return nil
}

func (m *mockRoleRepo) GetByID(_ context.Context, id role.ID) (*role.Role, error) {
	m.getByIDCalls++
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	r, ok := m.roles[id.String()]
	if !ok {
		return nil, role.ErrRoleNotFound
	}
	return r, nil
}

func (m *mockRoleRepo) GetBySlug(_ context.Context, _ *role.ID, slug string) (*role.Role, error) {
	m.getBySlugCalls++
	if m.getBySlugErr != nil {
		return nil, m.getBySlugErr
	}
	for _, r := range m.roles {
		if r.Slug() == slug {
			return r, nil
		}
	}
	return nil, role.ErrRoleNotFound
}

func (m *mockRoleRepo) ListForTenant(_ context.Context, _ role.ID) ([]*role.Role, error) {
	if m.listForTenantErr != nil {
		return nil, m.listForTenantErr
	}
	result := make([]*role.Role, 0, len(m.roles))
	for _, r := range m.roles {
		result = append(result, r)
	}
	return result, nil
}

func (m *mockRoleRepo) ListSystemRoles(_ context.Context) ([]*role.Role, error) {
	if m.listSystemErr != nil {
		return nil, m.listSystemErr
	}
	result := make([]*role.Role, 0)
	for _, r := range m.roles {
		if r.IsSystem() {
			result = append(result, r)
		}
	}
	return result, nil
}

func (m *mockRoleRepo) Update(_ context.Context, r *role.Role) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	m.roles[r.ID().String()] = r
	return nil
}

func (m *mockRoleRepo) Delete(_ context.Context, id role.ID) error {
	m.deleteCalls++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if _, ok := m.roles[id.String()]; !ok {
		return role.ErrRoleNotFound
	}
	delete(m.roles, id.String())
	return nil
}

func (m *mockRoleRepo) GetUserRoles(_ context.Context, _ role.ID, _ role.ID) ([]*role.Role, error) {
	if m.getUserRolesErr != nil {
		return nil, m.getUserRolesErr
	}
	return []*role.Role{}, nil
}

func (m *mockRoleRepo) GetUsersRoles(_ context.Context, _ role.ID, _ []role.ID) (map[string][]*role.Role, error) {
	if m.getUserRolesErr != nil {
		return nil, m.getUserRolesErr
	}
	return map[string][]*role.Role{}, nil
}

func (m *mockRoleRepo) GetUserPermissions(_ context.Context, _ role.ID, _ role.ID) ([]string, error) {
	if m.getUserPermsErr != nil {
		return nil, m.getUserPermsErr
	}
	return m.userPermissions, nil
}

func (m *mockRoleRepo) HasFullDataAccess(_ context.Context, _ role.ID, _ role.ID) (bool, error) {
	if m.hasFullAccessErr != nil {
		return false, m.hasFullAccessErr
	}
	return m.hasFullAccessResult, nil
}

func (m *mockRoleRepo) AssignRole(_ context.Context, tenantID, userID, roleID role.ID, _ *role.ID) error {
	m.assignRoleCalls++
	if m.assignRoleErr != nil {
		return m.assignRoleErr
	}
	key := tenantID.String() + ":" + userID.String()
	m.userRoles[key] = append(m.userRoles[key], roleID)
	return nil
}

func (m *mockRoleRepo) RemoveRole(_ context.Context, _ role.ID, _ role.ID, _ role.ID) error {
	m.removeRoleCalls++
	if m.removeRoleErr != nil {
		return m.removeRoleErr
	}
	return nil
}

func (m *mockRoleRepo) SetUserRoles(_ context.Context, _ role.ID, _ role.ID, _ []role.ID, _ *role.ID) error {
	if m.setUserRolesErr != nil {
		return m.setUserRolesErr
	}
	return nil
}

func (m *mockRoleRepo) BulkAssignRoleToUsers(_ context.Context, _ role.ID, _ role.ID, _ []role.ID, _ *role.ID) error {
	if m.bulkAssignErr != nil {
		return m.bulkAssignErr
	}
	return nil
}

func (m *mockRoleRepo) ListRoleMembers(_ context.Context, _ role.ID, _ role.ID) ([]*role.UserRole, error) {
	m.listMembersCalls++
	if m.listMembersErr != nil {
		return nil, m.listMembersErr
	}
	return m.roleMembers, nil
}

func (m *mockRoleRepo) CountUsersWithRole(_ context.Context, _ role.ID) (int, error) {
	m.countUsersCalls++
	if m.countUsersErr != nil {
		return 0, m.countUsersErr
	}
	return m.countUsersResult, nil
}

// =============================================================================
// Mock Permission Repository
// =============================================================================

type mockPermissionRepo struct {
	permissions    []*role.Permission
	modules        []*role.Module
	validResult    bool
	invalidIDs     []string
	validateErr    error
	listPermsErr   error
	listModulesErr error
}

func newMockPermissionRepo() *mockPermissionRepo {
	return &mockPermissionRepo{
		validResult: true,
	}
}

func (m *mockPermissionRepo) ListModulesWithPermissions(_ context.Context) ([]*role.Module, error) {
	if m.listModulesErr != nil {
		return nil, m.listModulesErr
	}
	return m.modules, nil
}

func (m *mockPermissionRepo) ListPermissions(_ context.Context) ([]*role.Permission, error) {
	if m.listPermsErr != nil {
		return nil, m.listPermsErr
	}
	return m.permissions, nil
}

func (m *mockPermissionRepo) GetByID(_ context.Context, id string) (*role.Permission, error) {
	for _, p := range m.permissions {
		if p.ID == id {
			return p, nil
		}
	}
	return nil, errors.New("permission not found")
}

func (m *mockPermissionRepo) Exists(_ context.Context, id string) (bool, error) {
	for _, p := range m.permissions {
		if p.ID == id {
			return true, nil
		}
	}
	return false, nil
}

func (m *mockPermissionRepo) ValidatePermissions(_ context.Context, _ []string) (bool, []string, error) {
	if m.validateErr != nil {
		return false, nil, m.validateErr
	}
	return m.validResult, m.invalidIDs, nil
}

// =============================================================================
// Helper: create a RoleService for testing
// =============================================================================

func newTestRoleService() (*app.RoleService, *mockRoleRepo, *mockPermissionRepo) {
	roleRepo := newMockRoleRepo()
	permRepo := newMockPermissionRepo()
	log := logger.NewNop()
	svc := app.NewRoleService(roleRepo, permRepo, log)
	return svc, roleRepo, permRepo
}

// Helper: create a custom role entity and store it in the mock repo.
func seedCustomRole(repo *mockRoleRepo, tenantID role.ID, slug, name string, permissions []string) *role.Role {
	createdBy := role.NewID()
	r := role.New(tenantID, slug, name, "description", 10, false, permissions, createdBy)
	repo.roles[r.ID().String()] = r
	return r
}

// Helper: create a system role entity and store it in the mock repo.
func seedSystemRole(repo *mockRoleRepo, id role.ID, slug, name string) *role.Role {
	now := time.Now()
	r := role.Reconstruct(id, nil, slug, name, "system role", true, 0, true, nil, now, now, nil)
	repo.roles[r.ID().String()] = r
	return r
}

// =============================================================================
// CreateRole Tests
// =============================================================================

func TestCreateRole_Success(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	tenantID := role.NewID()

	input := app.CreateRoleInput{
		TenantID:       tenantID.String(),
		Slug:           "security-analyst",
		Name:           "Security Analyst",
		Description:    "Reviews findings",
		HierarchyLevel: 10,
		Permissions:    []string{"findings:read", "assets:read"},
	}

	r, err := svc.CreateRole(context.Background(), input, role.NewID().String(), app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if r == nil {
		t.Fatal("expected role, got nil")
	}
	if r.Name() != "Security Analyst" {
		t.Errorf("expected name 'Security Analyst', got %q", r.Name())
	}
	if r.Slug() != "security-analyst" {
		t.Errorf("expected slug 'security-analyst', got %q", r.Slug())
	}
	if r.IsSystem() {
		t.Error("custom role should not be system")
	}
	if repo.createCalls != 1 {
		t.Errorf("expected 1 create call, got %d", repo.createCalls)
	}
}

func TestCreateRole_DuplicateSlug(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	tenantID := role.NewID()

	// Seed existing role with same slug
	seedCustomRole(repo, tenantID, "analyst", "Analyst", nil)

	input := app.CreateRoleInput{
		TenantID: tenantID.String(),
		Slug:     "analyst",
		Name:     "Another Analyst",
	}

	_, err := svc.CreateRole(context.Background(), input, role.NewID().String(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for duplicate slug")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestCreateRole_InvalidPermissions(t *testing.T) {
	svc, _, permRepo := newTestRoleService()
	tenantID := role.NewID()

	// Configure permission repo to reject permissions
	permRepo.validResult = false
	permRepo.invalidIDs = []string{"bogus:perm"}

	input := app.CreateRoleInput{
		TenantID:    tenantID.String(),
		Slug:        "bad-perms",
		Name:        "Bad Perms Role",
		Permissions: []string{"bogus:perm"},
	}

	_, err := svc.CreateRole(context.Background(), input, role.NewID().String(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for invalid permissions")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestCreateRole_InvalidTenantID(t *testing.T) {
	svc, _, _ := newTestRoleService()

	input := app.CreateRoleInput{
		TenantID: "not-a-uuid",
		Slug:     "test",
		Name:     "Test",
	}

	_, err := svc.CreateRole(context.Background(), input, role.NewID().String(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestCreateRole_RepoError(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	tenantID := role.NewID()
	repo.createErr = errors.New("db connection error")

	input := app.CreateRoleInput{
		TenantID: tenantID.String(),
		Slug:     "new-role",
		Name:     "New Role",
	}

	_, err := svc.CreateRole(context.Background(), input, role.NewID().String(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

func TestCreateRole_RepoSlugExists(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	tenantID := role.NewID()
	repo.createErr = role.ErrRoleSlugExists

	input := app.CreateRoleInput{
		TenantID: tenantID.String(),
		Slug:     "dup-slug",
		Name:     "Dup Slug",
	}

	_, err := svc.CreateRole(context.Background(), input, role.NewID().String(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for slug exists")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// =============================================================================
// GetRole Tests
// =============================================================================

func TestGetRole_Success(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	tenantID := role.NewID()
	r := seedCustomRole(repo, tenantID, "viewer", "Viewer", nil)

	found, err := svc.GetRole(context.Background(), r.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if found.ID() != r.ID() {
		t.Errorf("expected role ID %s, got %s", r.ID(), found.ID())
	}
	if repo.getByIDCalls != 1 {
		t.Errorf("expected 1 GetByID call, got %d", repo.getByIDCalls)
	}
}

func TestGetRole_NotFound(t *testing.T) {
	svc, _, _ := newTestRoleService()

	_, err := svc.GetRole(context.Background(), role.NewID().String())
	if err == nil {
		t.Fatal("expected error for role not found")
	}
	if !errors.Is(err, role.ErrRoleNotFound) {
		t.Errorf("expected ErrRoleNotFound, got %v", err)
	}
}

func TestGetRole_InvalidID(t *testing.T) {
	svc, _, _ := newTestRoleService()

	_, err := svc.GetRole(context.Background(), "invalid-id")
	if err == nil {
		t.Fatal("expected error for invalid role ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// =============================================================================
// UpdateRole Tests
// =============================================================================

func TestUpdateRole_Success(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	tenantID := role.NewID()
	r := seedCustomRole(repo, tenantID, "editor", "Editor", []string{"assets:read"})

	newName := "Senior Editor"
	input := app.UpdateRoleInput{
		Name: &newName,
	}

	updated, err := svc.UpdateRole(context.Background(), r.ID().String(), input, app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.Name() != "Senior Editor" {
		t.Errorf("expected name 'Senior Editor', got %q", updated.Name())
	}
	if repo.updateCalls != 1 {
		t.Errorf("expected 1 update call, got %d", repo.updateCalls)
	}
}

func TestUpdateRole_NotFound(t *testing.T) {
	svc, _, _ := newTestRoleService()

	newName := "Ghost"
	input := app.UpdateRoleInput{
		Name: &newName,
	}

	_, err := svc.UpdateRole(context.Background(), role.NewID().String(), input, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for role not found")
	}
	if !errors.Is(err, role.ErrRoleNotFound) {
		t.Errorf("expected ErrRoleNotFound, got %v", err)
	}
}

func TestUpdateRole_SystemRoleCannotBeModified(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	sysRole := seedSystemRole(repo, role.OwnerRoleID, "owner", "Owner")

	newName := "Super Owner"
	input := app.UpdateRoleInput{
		Name: &newName,
	}

	_, err := svc.UpdateRole(context.Background(), sysRole.ID().String(), input, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for system role modification")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestUpdateRole_UpdatePermissions(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	tenantID := role.NewID()
	r := seedCustomRole(repo, tenantID, "analyst", "Analyst", []string{"findings:read"})

	newPerms := []string{"findings:read", "findings:write", "assets:read"}
	input := app.UpdateRoleInput{
		Permissions: newPerms,
	}

	updated, err := svc.UpdateRole(context.Background(), r.ID().String(), input, app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(updated.Permissions()) != 3 {
		t.Errorf("expected 3 permissions, got %d", len(updated.Permissions()))
	}
}

func TestUpdateRole_InvalidPermissions(t *testing.T) {
	svc, repo, permRepo := newTestRoleService()
	tenantID := role.NewID()
	r := seedCustomRole(repo, tenantID, "analyst", "Analyst", nil)

	permRepo.validResult = false
	permRepo.invalidIDs = []string{"invalid:perm"}

	input := app.UpdateRoleInput{
		Permissions: []string{"invalid:perm"},
	}

	_, err := svc.UpdateRole(context.Background(), r.ID().String(), input, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for invalid permissions")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestUpdateRole_RepoError(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	tenantID := role.NewID()
	r := seedCustomRole(repo, tenantID, "editor", "Editor", nil)
	repo.updateErr = errors.New("db error")

	newName := "Updated"
	input := app.UpdateRoleInput{
		Name: &newName,
	}

	_, err := svc.UpdateRole(context.Background(), r.ID().String(), input, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

// =============================================================================
// DeleteRole Tests
// =============================================================================

func TestDeleteRole_Success(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	tenantID := role.NewID()
	r := seedCustomRole(repo, tenantID, "temp-role", "Temp Role", nil)

	err := svc.DeleteRole(context.Background(), r.ID().String(), app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if repo.deleteCalls != 1 {
		t.Errorf("expected 1 delete call, got %d", repo.deleteCalls)
	}
	// Verify role removed from store
	if _, ok := repo.roles[r.ID().String()]; ok {
		t.Error("expected role to be removed from store")
	}
}

func TestDeleteRole_RoleInUse(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	tenantID := role.NewID()
	r := seedCustomRole(repo, tenantID, "in-use", "In Use Role", nil)
	repo.deleteErr = role.ErrRoleInUse

	err := svc.DeleteRole(context.Background(), r.ID().String(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for role in use")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestDeleteRole_NotFound(t *testing.T) {
	svc, _, _ := newTestRoleService()

	err := svc.DeleteRole(context.Background(), role.NewID().String(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for role not found")
	}
	if !errors.Is(err, role.ErrRoleNotFound) {
		t.Errorf("expected ErrRoleNotFound, got %v", err)
	}
}

func TestDeleteRole_SystemRoleCannotBeDeleted(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	sysRole := seedSystemRole(repo, role.AdminRoleID, "admin", "Admin")

	err := svc.DeleteRole(context.Background(), sysRole.ID().String(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for system role deletion")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestDeleteRole_InvalidID(t *testing.T) {
	svc, _, _ := newTestRoleService()

	err := svc.DeleteRole(context.Background(), "bad-uuid", app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// =============================================================================
// ListRoles Tests
// =============================================================================

func TestListRolesForTenant_Success(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	tenantID := role.NewID()

	seedCustomRole(repo, tenantID, "role-a", "Role A", nil)
	seedCustomRole(repo, tenantID, "role-b", "Role B", nil)
	seedCustomRole(repo, tenantID, "role-c", "Role C", nil)

	roles, err := svc.ListRolesForTenant(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(roles) != 3 {
		t.Errorf("expected 3 roles, got %d", len(roles))
	}
}

func TestListRolesForTenant_InvalidTenantID(t *testing.T) {
	svc, _, _ := newTestRoleService()

	_, err := svc.ListRolesForTenant(context.Background(), "not-uuid")
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestListRolesForTenant_RepoError(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	repo.listForTenantErr = errors.New("db error")

	_, err := svc.ListRolesForTenant(context.Background(), role.NewID().String())
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

func TestListSystemRoles_Success(t *testing.T) {
	svc, repo, _ := newTestRoleService()

	seedSystemRole(repo, role.OwnerRoleID, "owner", "Owner")
	seedSystemRole(repo, role.AdminRoleID, "admin", "Admin")
	seedCustomRole(repo, role.NewID(), "custom", "Custom", nil)

	roles, err := svc.ListSystemRoles(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(roles) != 2 {
		t.Errorf("expected 2 system roles, got %d", len(roles))
	}
}

// =============================================================================
// AssignRole Tests
// =============================================================================

func TestAssignRole_Success(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	tenantID := role.NewID()
	r := seedCustomRole(repo, tenantID, "analyst", "Analyst", nil)
	userID := role.NewID()
	assignedBy := role.NewID()

	input := app.AssignRoleInput{
		TenantID: tenantID.String(),
		UserID:   userID.String(),
		RoleID:   r.ID().String(),
	}

	err := svc.AssignRole(context.Background(), input, assignedBy.String(), app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if repo.assignRoleCalls != 1 {
		t.Errorf("expected 1 assign call, got %d", repo.assignRoleCalls)
	}
}

func TestAssignRole_RoleNotFound(t *testing.T) {
	svc, _, _ := newTestRoleService()
	tenantID := role.NewID()

	input := app.AssignRoleInput{
		TenantID: tenantID.String(),
		UserID:   role.NewID().String(),
		RoleID:   role.NewID().String(),
	}

	err := svc.AssignRole(context.Background(), input, role.NewID().String(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for role not found")
	}
	if !errors.Is(err, role.ErrRoleNotFound) {
		t.Errorf("expected ErrRoleNotFound, got %v", err)
	}
}

func TestAssignRole_UserAlreadyHasRole(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	tenantID := role.NewID()
	r := seedCustomRole(repo, tenantID, "analyst", "Analyst", nil)
	repo.assignRoleErr = role.ErrUserRoleExists

	input := app.AssignRoleInput{
		TenantID: tenantID.String(),
		UserID:   role.NewID().String(),
		RoleID:   r.ID().String(),
	}

	err := svc.AssignRole(context.Background(), input, role.NewID().String(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for duplicate assignment")
	}
}

func TestAssignRole_InvalidTenantID(t *testing.T) {
	svc, _, _ := newTestRoleService()

	input := app.AssignRoleInput{
		TenantID: "bad",
		UserID:   role.NewID().String(),
		RoleID:   role.NewID().String(),
	}

	err := svc.AssignRole(context.Background(), input, role.NewID().String(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAssignRole_InvalidUserID(t *testing.T) {
	svc, _, _ := newTestRoleService()

	input := app.AssignRoleInput{
		TenantID: role.NewID().String(),
		UserID:   "bad",
		RoleID:   role.NewID().String(),
	}

	err := svc.AssignRole(context.Background(), input, role.NewID().String(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for invalid user ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAssignRole_RoleBelongsToDifferentTenant(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	otherTenantID := role.NewID()
	r := seedCustomRole(repo, otherTenantID, "other-role", "Other Role", nil)

	thisTenantID := role.NewID()
	input := app.AssignRoleInput{
		TenantID: thisTenantID.String(),
		UserID:   role.NewID().String(),
		RoleID:   r.ID().String(),
	}

	err := svc.AssignRole(context.Background(), input, role.NewID().String(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for cross-tenant role assignment")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAssignRole_SystemRoleCanBeAssigned(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	tenantID := role.NewID()
	sysRole := seedSystemRole(repo, role.MemberRoleID, "member", "Member")

	input := app.AssignRoleInput{
		TenantID: tenantID.String(),
		UserID:   role.NewID().String(),
		RoleID:   sysRole.ID().String(),
	}

	err := svc.AssignRole(context.Background(), input, role.NewID().String(), app.AuditContext{})
	if err != nil {
		t.Fatalf("system roles should be assignable, got error: %v", err)
	}
}

// =============================================================================
// RemoveRole Tests
// =============================================================================

func TestRemoveRole_Success(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	tenantID := role.NewID()
	r := seedCustomRole(repo, tenantID, "analyst", "Analyst", nil)
	userID := role.NewID()

	err := svc.RemoveRole(context.Background(), tenantID.String(), userID.String(), r.ID().String(), app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if repo.removeRoleCalls != 1 {
		t.Errorf("expected 1 remove call, got %d", repo.removeRoleCalls)
	}
}

func TestRemoveRole_NotFound(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	tenantID := role.NewID()
	r := seedCustomRole(repo, tenantID, "analyst", "Analyst", nil)
	repo.removeRoleErr = role.ErrUserRoleNotFound

	err := svc.RemoveRole(context.Background(), tenantID.String(), role.NewID().String(), r.ID().String(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for user role not found")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestRemoveRole_InvalidTenantID(t *testing.T) {
	svc, _, _ := newTestRoleService()

	err := svc.RemoveRole(context.Background(), "bad", role.NewID().String(), role.NewID().String(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestRemoveRole_InvalidUserID(t *testing.T) {
	svc, _, _ := newTestRoleService()

	err := svc.RemoveRole(context.Background(), role.NewID().String(), "bad", role.NewID().String(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for invalid user ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestRemoveRole_InvalidRoleID(t *testing.T) {
	svc, _, _ := newTestRoleService()

	err := svc.RemoveRole(context.Background(), role.NewID().String(), role.NewID().String(), "bad", app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for invalid role ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestRemoveRole_RepoError(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	tenantID := role.NewID()
	r := seedCustomRole(repo, tenantID, "analyst", "Analyst", nil)
	repo.removeRoleErr = errors.New("db error")

	err := svc.RemoveRole(context.Background(), tenantID.String(), role.NewID().String(), r.ID().String(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

// =============================================================================
// HasPermission / GetUserPermissions Tests
// =============================================================================

func TestHasPermission_True(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	tenantID := role.NewID()
	userID := role.NewID()
	repo.userPermissions = []string{"findings:read", "assets:read", "dashboard:read"}

	has, err := svc.HasPermission(context.Background(), tenantID.String(), userID.String(), "findings:read")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !has {
		t.Error("expected user to have 'findings:read' permission")
	}
}

func TestHasPermission_False(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	tenantID := role.NewID()
	userID := role.NewID()
	repo.userPermissions = []string{"findings:read"}

	has, err := svc.HasPermission(context.Background(), tenantID.String(), userID.String(), "team:delete")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if has {
		t.Error("expected user NOT to have 'team:delete' permission")
	}
}

func TestGetUserPermissions_Success(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	tenantID := role.NewID()
	userID := role.NewID()
	repo.userPermissions = []string{"findings:read", "assets:read"}

	perms, err := svc.GetUserPermissions(context.Background(), tenantID.String(), userID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(perms) != 2 {
		t.Errorf("expected 2 permissions, got %d", len(perms))
	}
}

// =============================================================================
// HasFullDataAccess Tests
// =============================================================================

func TestHasFullDataAccess_True(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	repo.hasFullAccessResult = true

	has, err := svc.HasFullDataAccess(context.Background(), role.NewID().String(), role.NewID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !has {
		t.Error("expected full data access to be true")
	}
}

func TestHasFullDataAccess_False(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	repo.hasFullAccessResult = false

	has, err := svc.HasFullDataAccess(context.Background(), role.NewID().String(), role.NewID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if has {
		t.Error("expected full data access to be false")
	}
}

// =============================================================================
// ListRoleMembers / CountUsersWithRole Tests
// =============================================================================

func TestListRoleMembers_Success(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	tenantID := role.NewID()
	roleID := role.NewID()

	repo.roleMembers = []*role.UserRole{
		role.NewUserRole(role.NewID(), tenantID, roleID, nil),
		role.NewUserRole(role.NewID(), tenantID, roleID, nil),
	}

	members, err := svc.ListRoleMembers(context.Background(), tenantID.String(), roleID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(members) != 2 {
		t.Errorf("expected 2 members, got %d", len(members))
	}
}

func TestCountUsersWithRole_Success(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	repo.countUsersResult = 5

	count, err := svc.CountUsersWithRole(context.Background(), role.NewID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 5 {
		t.Errorf("expected 5, got %d", count)
	}
}

// =============================================================================
// ListPermissions / ListModulesWithPermissions Tests
// =============================================================================

func TestListPermissions_Success(t *testing.T) {
	svc, _, permRepo := newTestRoleService()
	permRepo.permissions = []*role.Permission{
		{ID: "findings:read", Name: "Read Findings"},
		{ID: "assets:read", Name: "Read Assets"},
	}

	perms, err := svc.ListPermissions(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(perms) != 2 {
		t.Errorf("expected 2 permissions, got %d", len(perms))
	}
}

func TestListModulesWithPermissions_Success(t *testing.T) {
	svc, _, permRepo := newTestRoleService()
	permRepo.modules = []*role.Module{
		{ID: "findings", Name: "Findings"},
		{ID: "assets", Name: "Assets"},
	}

	modules, err := svc.ListModulesWithPermissions(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(modules) != 2 {
		t.Errorf("expected 2 modules, got %d", len(modules))
	}
}
