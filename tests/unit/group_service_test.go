package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/group"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// =============================================================================
// Mock Group Repository
// =============================================================================

// mockGroupRepo implements group.Repository for testing.
type mockGroupRepo struct {
	groups        map[shared.ID]*group.Group
	members       map[shared.ID]map[shared.ID]*group.Member // groupID -> userID -> member
	slugExists    map[string]bool                           // slug -> exists
	createErr     error
	getByIDErr    error
	updateErr     error
	deleteErr     error
	addMemberErr  error
	listMembersOv []*group.Member // override for ListMembers
}

func newMockGroupRepo() *mockGroupRepo {
	return &mockGroupRepo{
		groups:     make(map[shared.ID]*group.Group),
		members:    make(map[shared.ID]map[shared.ID]*group.Member),
		slugExists: make(map[string]bool),
	}
}

func (m *mockGroupRepo) Create(_ context.Context, g *group.Group) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.groups[g.ID()] = g
	m.slugExists[g.Slug()] = true
	return nil
}

func (m *mockGroupRepo) GetByID(_ context.Context, id shared.ID) (*group.Group, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	g, ok := m.groups[id]
	if !ok {
		return nil, group.ErrGroupNotFound
	}
	return g, nil
}

func (m *mockGroupRepo) GetBySlug(_ context.Context, tenantID shared.ID, slug string) (*group.Group, error) {
	for _, g := range m.groups {
		if g.TenantID() == tenantID && g.Slug() == slug {
			return g, nil
		}
	}
	return nil, group.ErrGroupNotFound
}

func (m *mockGroupRepo) Update(_ context.Context, g *group.Group) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.groups[g.ID()] = g
	return nil
}

func (m *mockGroupRepo) Delete(_ context.Context, id shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.groups, id)
	return nil
}

func (m *mockGroupRepo) List(_ context.Context, tenantID shared.ID, filter group.ListFilter) ([]*group.Group, error) {
	var result []*group.Group
	for _, g := range m.groups {
		if g.TenantID() == tenantID {
			result = append(result, g)
		}
	}
	return result, nil
}

func (m *mockGroupRepo) Count(_ context.Context, tenantID shared.ID, filter group.ListFilter) (int64, error) {
	var count int64
	for _, g := range m.groups {
		if g.TenantID() == tenantID {
			count++
		}
	}
	return count, nil
}

func (m *mockGroupRepo) ExistsBySlug(_ context.Context, tenantID shared.ID, slug string) (bool, error) {
	for _, g := range m.groups {
		if g.TenantID() == tenantID && g.Slug() == slug {
			return true, nil
		}
	}
	return false, nil
}

func (m *mockGroupRepo) ListByIDs(_ context.Context, _ []shared.ID) ([]*group.Group, error) {
	return nil, nil
}

func (m *mockGroupRepo) GetByExternalID(_ context.Context, _ shared.ID, _ group.ExternalSource, _ string) (*group.Group, error) {
	return nil, nil
}

func (m *mockGroupRepo) AddMember(_ context.Context, member *group.Member) error {
	if m.addMemberErr != nil {
		return m.addMemberErr
	}
	gid := member.GroupID()
	if m.members[gid] == nil {
		m.members[gid] = make(map[shared.ID]*group.Member)
	}
	m.members[gid][member.UserID()] = member
	return nil
}

func (m *mockGroupRepo) GetMember(_ context.Context, groupID, userID shared.ID) (*group.Member, error) {
	if members, ok := m.members[groupID]; ok {
		if member, ok := members[userID]; ok {
			return member, nil
		}
	}
	return nil, group.ErrMemberNotFound
}

func (m *mockGroupRepo) UpdateMember(_ context.Context, member *group.Member) error {
	gid := member.GroupID()
	if m.members[gid] == nil {
		return group.ErrMemberNotFound
	}
	m.members[gid][member.UserID()] = member
	return nil
}

func (m *mockGroupRepo) RemoveMember(_ context.Context, groupID, userID shared.ID) error {
	if members, ok := m.members[groupID]; ok {
		delete(members, userID)
	}
	return nil
}

func (m *mockGroupRepo) ListMembers(_ context.Context, groupID shared.ID) ([]*group.Member, error) {
	if m.listMembersOv != nil {
		return m.listMembersOv, nil
	}
	var result []*group.Member
	if members, ok := m.members[groupID]; ok {
		for _, member := range members {
			result = append(result, member)
		}
	}
	return result, nil
}

func (m *mockGroupRepo) ListMembersWithUserInfo(_ context.Context, _ shared.ID, _, _ int) ([]*group.MemberWithUser, int64, error) {
	return nil, 0, nil
}

func (m *mockGroupRepo) CountMembers(_ context.Context, groupID shared.ID) (int64, error) {
	if members, ok := m.members[groupID]; ok {
		return int64(len(members)), nil
	}
	return 0, nil
}

func (m *mockGroupRepo) CountMembersByGroups(_ context.Context, _ []shared.ID) (map[shared.ID]int, error) {
	return nil, nil
}
func (m *mockGroupRepo) CountUniqueMembers(_ context.Context, _ []shared.ID) (int, error) {
	return 0, nil
}

func (m *mockGroupRepo) GetMemberStats(_ context.Context, _ shared.ID) (*group.MemberStats, error) {
	return nil, nil
}

func (m *mockGroupRepo) IsMember(_ context.Context, groupID, userID shared.ID) (bool, error) {
	if members, ok := m.members[groupID]; ok {
		_, exists := members[userID]
		return exists, nil
	}
	return false, nil
}

func (m *mockGroupRepo) ListGroupsByUser(_ context.Context, _, _ shared.ID) ([]*group.GroupWithRole, error) {
	return nil, nil
}

func (m *mockGroupRepo) ListGroupIDsByUser(_ context.Context, _, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}

func (m *mockGroupRepo) AssignPermissionSet(_ context.Context, _, _ shared.ID, _ *shared.ID) error {
	return nil
}

func (m *mockGroupRepo) RemovePermissionSet(_ context.Context, _, _ shared.ID) error {
	return nil
}

func (m *mockGroupRepo) ListPermissionSetIDs(_ context.Context, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}

func (m *mockGroupRepo) ListGroupsWithPermissionSet(_ context.Context, _ shared.ID) ([]*group.Group, error) {
	return nil, nil
}

// =============================================================================
// Test Helpers
// =============================================================================

func newTestGroupService(repo *mockGroupRepo) *app.GroupService {
	log := logger.NewNop()
	return app.NewGroupService(repo, log)
}

func createTestGroup(t *testing.T, svc *app.GroupService, tenantID shared.ID, name, slug string) *group.Group {
	t.Helper()
	input := app.CreateGroupInput{
		TenantID:  tenantID.String(),
		Name:      name,
		Slug:      slug,
		GroupType: "team",
	}
	g, err := svc.CreateGroup(context.Background(), input, shared.NewID(), app.AuditContext{})
	if err != nil {
		t.Fatalf("failed to create test group: %v", err)
	}
	return g
}

// =============================================================================
// Tests for CreateGroup
// =============================================================================

func TestCreateGroup_Success(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)
	tenantID := shared.NewID()
	creatorID := shared.NewID()

	input := app.CreateGroupInput{
		TenantID:    tenantID.String(),
		Name:        "Security Team Alpha",
		Slug:        "security-team-alpha",
		Description: "Main security team",
		GroupType:   "security_team",
	}

	g, err := svc.CreateGroup(context.Background(), input, creatorID, app.AuditContext{})
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}

	if g == nil {
		t.Fatal("Expected non-nil group")
	}
	if g.Name() != "Security Team Alpha" {
		t.Errorf("Expected name 'Security Team Alpha', got '%s'", g.Name())
	}
	if g.Slug() != "security-team-alpha" {
		t.Errorf("Expected slug 'security-team-alpha', got '%s'", g.Slug())
	}
	if g.GroupType() != group.GroupTypeSecurityTeam {
		t.Errorf("Expected type security_team, got '%s'", g.GroupType())
	}
	if !g.IsActive() {
		t.Error("Expected group to be active by default")
	}

	// Creator should be added as owner
	if len(repo.members[g.ID()]) != 1 {
		t.Errorf("Expected 1 member (creator), got %d", len(repo.members[g.ID()]))
	}
}

func TestCreateGroup_ValidationError_EmptyName(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)
	tenantID := shared.NewID()

	input := app.CreateGroupInput{
		TenantID:  tenantID.String(),
		Name:      "",
		Slug:      "test-slug",
		GroupType: "team",
	}

	_, err := svc.CreateGroup(context.Background(), input, shared.NewID(), app.AuditContext{})
	if err == nil {
		t.Fatal("Expected error for empty name")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestCreateGroup_ValidationError_InvalidGroupType(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)
	tenantID := shared.NewID()

	input := app.CreateGroupInput{
		TenantID:  tenantID.String(),
		Name:      "Test Group",
		Slug:      "test-group",
		GroupType: "invalid_type",
	}

	_, err := svc.CreateGroup(context.Background(), input, shared.NewID(), app.AuditContext{})
	if err == nil {
		t.Fatal("Expected error for invalid group type")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestCreateGroup_ValidationError_InvalidSlug(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)
	tenantID := shared.NewID()

	input := app.CreateGroupInput{
		TenantID:  tenantID.String(),
		Name:      "Test Group",
		Slug:      "INVALID SLUG!",
		GroupType: "team",
	}

	_, err := svc.CreateGroup(context.Background(), input, shared.NewID(), app.AuditContext{})
	if err == nil {
		t.Fatal("Expected error for invalid slug")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestCreateGroup_DuplicateSlug(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)
	tenantID := shared.NewID()

	// Create first group
	createTestGroup(t, svc, tenantID, "First Group", "my-slug")

	// Try to create second group with same slug
	input := app.CreateGroupInput{
		TenantID:  tenantID.String(),
		Name:      "Second Group",
		Slug:      "my-slug", // duplicate
		GroupType: "team",
	}

	_, err := svc.CreateGroup(context.Background(), input, shared.NewID(), app.AuditContext{})
	if err == nil {
		t.Fatal("Expected error for duplicate slug")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestCreateGroup_InvalidTenantID(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)

	input := app.CreateGroupInput{
		TenantID:  "not-a-uuid",
		Name:      "Test Group",
		Slug:      "test-group",
		GroupType: "team",
	}

	_, err := svc.CreateGroup(context.Background(), input, shared.NewID(), app.AuditContext{})
	if err == nil {
		t.Fatal("Expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

// =============================================================================
// Tests for GetGroup
// =============================================================================

func TestGetGroup_Success(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)
	tenantID := shared.NewID()

	g := createTestGroup(t, svc, tenantID, "Test Group", "test-group")

	result, err := svc.GetGroup(context.Background(), g.ID().String())
	if err != nil {
		t.Fatalf("GetGroup failed: %v", err)
	}

	if result.Name() != "Test Group" {
		t.Errorf("Expected name 'Test Group', got '%s'", result.Name())
	}
}

func TestGetGroup_NotFound(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)

	_, err := svc.GetGroup(context.Background(), shared.NewID().String())
	if err == nil {
		t.Fatal("Expected error for non-existent group")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got: %v", err)
	}
}

func TestGetGroup_InvalidID(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)

	_, err := svc.GetGroup(context.Background(), "not-a-uuid")
	if err == nil {
		t.Fatal("Expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

// =============================================================================
// Tests for UpdateGroup
// =============================================================================

func TestUpdateGroup_Success(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)
	tenantID := shared.NewID()

	g := createTestGroup(t, svc, tenantID, "Original Name", "original-slug")

	newName := "Updated Name"
	newDesc := "Updated description"
	input := app.UpdateGroupInput{
		Name:        &newName,
		Description: &newDesc,
	}

	result, err := svc.UpdateGroup(context.Background(), g.ID().String(), input, app.AuditContext{})
	if err != nil {
		t.Fatalf("UpdateGroup failed: %v", err)
	}

	if result.Name() != "Updated Name" {
		t.Errorf("Expected name 'Updated Name', got '%s'", result.Name())
	}
	if result.Description() != "Updated description" {
		t.Errorf("Expected description 'Updated description', got '%s'", result.Description())
	}
}

func TestUpdateGroup_NotFound(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)

	newName := "Updated"
	input := app.UpdateGroupInput{
		Name: &newName,
	}

	_, err := svc.UpdateGroup(context.Background(), shared.NewID().String(), input, app.AuditContext{})
	if err == nil {
		t.Fatal("Expected error for non-existent group")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got: %v", err)
	}
}

func TestUpdateGroup_ActivateDeactivate(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)
	tenantID := shared.NewID()

	g := createTestGroup(t, svc, tenantID, "Toggle Group", "toggle-group")

	// Deactivate
	inactive := false
	input := app.UpdateGroupInput{IsActive: &inactive}
	result, err := svc.UpdateGroup(context.Background(), g.ID().String(), input, app.AuditContext{})
	if err != nil {
		t.Fatalf("Deactivate failed: %v", err)
	}
	if result.IsActive() {
		t.Error("Expected group to be inactive")
	}

	// Activate
	active := true
	input = app.UpdateGroupInput{IsActive: &active}
	result, err = svc.UpdateGroup(context.Background(), g.ID().String(), input, app.AuditContext{})
	if err != nil {
		t.Fatalf("Activate failed: %v", err)
	}
	if !result.IsActive() {
		t.Error("Expected group to be active")
	}
}

// =============================================================================
// Tests for DeleteGroup
// =============================================================================

func TestDeleteGroup_Success(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)
	tenantID := shared.NewID()

	g := createTestGroup(t, svc, tenantID, "To Delete", "to-delete")

	err := svc.DeleteGroup(context.Background(), g.ID().String(), app.AuditContext{})
	if err != nil {
		t.Fatalf("DeleteGroup failed: %v", err)
	}

	// Verify group was deleted
	_, err = svc.GetGroup(context.Background(), g.ID().String())
	if err == nil {
		t.Fatal("Expected group to be deleted")
	}
}

func TestDeleteGroup_NotFound(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)

	err := svc.DeleteGroup(context.Background(), shared.NewID().String(), app.AuditContext{})
	if err == nil {
		t.Fatal("Expected error for non-existent group")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got: %v", err)
	}
}

func TestDeleteGroup_InvalidID(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)

	err := svc.DeleteGroup(context.Background(), "not-a-uuid", app.AuditContext{})
	if err == nil {
		t.Fatal("Expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

// =============================================================================
// Tests for ListGroups
// =============================================================================

func TestListGroups_WithFilters(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)
	tenantID := shared.NewID()
	otherTenantID := shared.NewID()

	createTestGroup(t, svc, tenantID, "Group A", "group-a")
	createTestGroup(t, svc, tenantID, "Group B", "group-b")
	createTestGroup(t, svc, otherTenantID, "Other Group", "other-group")

	result, err := svc.ListGroups(context.Background(), app.ListGroupsInput{
		TenantID: tenantID.String(),
		Limit:    50,
	})
	if err != nil {
		t.Fatalf("ListGroups failed: %v", err)
	}

	if len(result.Groups) != 2 {
		t.Errorf("Expected 2 groups, got %d", len(result.Groups))
	}
	if result.TotalCount != 2 {
		t.Errorf("Expected total count 2, got %d", result.TotalCount)
	}
}

func TestListGroups_Pagination(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)
	tenantID := shared.NewID()

	for i := 0; i < 5; i++ {
		createTestGroup(t, svc, tenantID, "Group "+string(rune('A'+i)), "group-"+string(rune('a'+i)))
	}

	result, err := svc.ListGroups(context.Background(), app.ListGroupsInput{
		TenantID: tenantID.String(),
		Limit:    10,
		Offset:   0,
	})
	if err != nil {
		t.Fatalf("ListGroups failed: %v", err)
	}

	if result.TotalCount != 5 {
		t.Errorf("Expected total 5, got %d", result.TotalCount)
	}
}

func TestListGroups_EmptyResult(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)
	tenantID := shared.NewID()

	result, err := svc.ListGroups(context.Background(), app.ListGroupsInput{
		TenantID: tenantID.String(),
		Limit:    50,
	})
	if err != nil {
		t.Fatalf("ListGroups failed: %v", err)
	}

	if len(result.Groups) != 0 {
		t.Errorf("Expected 0 groups, got %d", len(result.Groups))
	}
}

func TestListGroups_InvalidTenantID(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)

	_, err := svc.ListGroups(context.Background(), app.ListGroupsInput{
		TenantID: "not-a-uuid",
	})
	if err == nil {
		t.Fatal("Expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

// =============================================================================
// Tests for AddMember
// =============================================================================

func TestAddMember_Success(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)
	tenantID := shared.NewID()
	userID := shared.NewID()

	g := createTestGroup(t, svc, tenantID, "Team Alpha", "team-alpha")

	input := app.AddGroupMemberInput{
		GroupID: g.ID().String(),
		UserID:  userID,
		Role:    "member",
	}

	member, err := svc.AddMember(context.Background(), input, app.AuditContext{})
	if err != nil {
		t.Fatalf("AddMember failed: %v", err)
	}

	if member == nil {
		t.Fatal("Expected non-nil member")
	}
	if member.UserID() != userID {
		t.Errorf("Expected user ID %s, got %s", userID, member.UserID())
	}
	if member.Role() != group.MemberRoleMember {
		t.Errorf("Expected role 'member', got '%s'", member.Role())
	}
}

func TestAddMember_AlreadyAMember(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)
	tenantID := shared.NewID()
	userID := shared.NewID()

	g := createTestGroup(t, svc, tenantID, "Team Beta", "team-beta")

	// Add member first time
	input := app.AddGroupMemberInput{
		GroupID: g.ID().String(),
		UserID:  userID,
		Role:    "member",
	}

	_, err := svc.AddMember(context.Background(), input, app.AuditContext{})
	if err != nil {
		t.Fatalf("First AddMember failed: %v", err)
	}

	// Try adding same member again
	_, err = svc.AddMember(context.Background(), input, app.AuditContext{})
	if err == nil {
		t.Fatal("Expected error for duplicate member")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestAddMember_InvalidRole(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)
	tenantID := shared.NewID()

	g := createTestGroup(t, svc, tenantID, "Team Gamma", "team-gamma")

	input := app.AddGroupMemberInput{
		GroupID: g.ID().String(),
		UserID:  shared.NewID(),
		Role:    "invalid_role",
	}

	_, err := svc.AddMember(context.Background(), input, app.AuditContext{})
	if err == nil {
		t.Fatal("Expected error for invalid role")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestAddMember_InvalidGroupID(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)

	input := app.AddGroupMemberInput{
		GroupID: "not-a-uuid",
		UserID:  shared.NewID(),
		Role:    "member",
	}

	_, err := svc.AddMember(context.Background(), input, app.AuditContext{})
	if err == nil {
		t.Fatal("Expected error for invalid group ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

// =============================================================================
// Tests for RemoveMember
// =============================================================================

func TestRemoveMember_Success(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)
	tenantID := shared.NewID()
	ownerID := shared.NewID()
	memberID := shared.NewID()

	g := createTestGroup(t, svc, tenantID, "Team Delta", "team-delta")

	// Add an extra owner (so creator is not the last owner)
	ownerInput := app.AddGroupMemberInput{
		GroupID: g.ID().String(),
		UserID:  ownerID,
		Role:    "owner",
	}
	_, err := svc.AddMember(context.Background(), ownerInput, app.AuditContext{})
	if err != nil {
		t.Fatalf("Failed to add owner: %v", err)
	}

	// Add a regular member
	memberInput := app.AddGroupMemberInput{
		GroupID: g.ID().String(),
		UserID:  memberID,
		Role:    "member",
	}
	_, err = svc.AddMember(context.Background(), memberInput, app.AuditContext{})
	if err != nil {
		t.Fatalf("Failed to add member: %v", err)
	}

	// Remove the regular member
	err = svc.RemoveMember(context.Background(), g.ID().String(), memberID, app.AuditContext{})
	if err != nil {
		t.Fatalf("RemoveMember failed: %v", err)
	}

	// Verify member was removed
	members := repo.members[g.ID()]
	if _, exists := members[memberID]; exists {
		t.Error("Expected member to be removed")
	}
}

func TestRemoveMember_NotAMember(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)
	tenantID := shared.NewID()

	g := createTestGroup(t, svc, tenantID, "Team Epsilon", "team-epsilon")

	// Try to remove non-existent member
	err := svc.RemoveMember(context.Background(), g.ID().String(), shared.NewID(), app.AuditContext{})
	if err == nil {
		t.Fatal("Expected error for non-existent member")
	}
}

func TestRemoveMember_LastOwner(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)
	tenantID := shared.NewID()
	creatorID := shared.NewID()

	input := app.CreateGroupInput{
		TenantID:  tenantID.String(),
		Name:      "Team Zeta",
		Slug:      "team-zeta",
		GroupType: "team",
	}
	g, err := svc.CreateGroup(context.Background(), input, creatorID, app.AuditContext{})
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}

	// Try to remove the sole owner
	err = svc.RemoveMember(context.Background(), g.ID().String(), creatorID, app.AuditContext{})
	if err == nil {
		t.Fatal("Expected error when removing last owner")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

// =============================================================================
// Tests for ListGroupMembers
// =============================================================================

func TestListGroupMembers_Success(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)
	tenantID := shared.NewID()

	g := createTestGroup(t, svc, tenantID, "Team Theta", "team-theta")

	// Add extra members
	for i := 0; i < 3; i++ {
		input := app.AddGroupMemberInput{
			GroupID: g.ID().String(),
			UserID:  shared.NewID(),
			Role:    "member",
		}
		_, err := svc.AddMember(context.Background(), input, app.AuditContext{})
		if err != nil {
			t.Fatalf("AddMember failed: %v", err)
		}
	}

	members, err := svc.ListGroupMembers(context.Background(), g.ID().String())
	if err != nil {
		t.Fatalf("ListGroupMembers failed: %v", err)
	}

	// Creator (owner) + 3 members = 4
	if len(members) != 4 {
		t.Errorf("Expected 4 members, got %d", len(members))
	}
}

func TestListGroupMembers_Empty(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)

	// Use a group ID that has no members
	members, err := svc.ListGroupMembers(context.Background(), shared.NewID().String())
	if err != nil {
		t.Fatalf("ListGroupMembers failed: %v", err)
	}

	if len(members) != 0 {
		t.Errorf("Expected 0 members, got %d", len(members))
	}
}

func TestListGroupMembers_InvalidID(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo)

	_, err := svc.ListGroupMembers(context.Background(), "not-a-uuid")
	if err == nil {
		t.Fatal("Expected error for invalid group ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

// =============================================================================
// Tests for AssignAsset / UnassignAsset
// =============================================================================

func TestAssignAsset_NoAccessControlRepo(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo) // no access control repo
	tenantID := shared.NewID()

	g := createTestGroup(t, svc, tenantID, "Asset Team", "asset-team")

	input := app.AssignAssetInput{
		GroupID:       g.ID().String(),
		AssetID:       shared.NewID().String(),
		OwnershipType: "primary",
	}

	err := svc.AssignAsset(context.Background(), input, shared.NewID(), app.AuditContext{})
	if err == nil {
		t.Fatal("Expected error when access control repo is not configured")
	}
}

func TestUnassignAsset_NoAccessControlRepo(t *testing.T) {
	repo := newMockGroupRepo()
	svc := newTestGroupService(repo) // no access control repo
	tenantID := shared.NewID()

	g := createTestGroup(t, svc, tenantID, "Unassign Team", "unassign-team")

	input := app.UnassignAssetInput{
		GroupID: g.ID().String(),
		AssetID: shared.NewID().String(),
	}

	err := svc.UnassignAsset(context.Background(), input, app.AuditContext{})
	if err == nil {
		t.Fatal("Expected error when access control repo is not configured")
	}
}

func TestAssignAsset_InvalidGroupID(t *testing.T) {
	repo := newMockGroupRepo()
	log := logger.NewNop()
	acRepo := &mockACRepoForBulk{}
	svc := app.NewGroupService(repo, log, app.WithAccessControlRepository(acRepo))

	input := app.AssignAssetInput{
		GroupID:       "not-a-uuid",
		AssetID:       shared.NewID().String(),
		OwnershipType: "primary",
	}

	err := svc.AssignAsset(context.Background(), input, shared.NewID(), app.AuditContext{})
	if err == nil {
		t.Fatal("Expected error for invalid group ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestAssignAsset_InvalidOwnershipType(t *testing.T) {
	repo := newMockGroupRepo()
	log := logger.NewNop()
	acRepo := &mockACRepoForBulk{}
	svc := app.NewGroupService(repo, log, app.WithAccessControlRepository(acRepo))
	tenantID := shared.NewID()

	g := createTestGroup(t, svc, tenantID, "Test OT", "test-ot")

	input := app.AssignAssetInput{
		GroupID:       g.ID().String(),
		AssetID:       shared.NewID().String(),
		OwnershipType: "invalid_type",
	}

	err := svc.AssignAsset(context.Background(), input, shared.NewID(), app.AuditContext{})
	if err == nil {
		t.Fatal("Expected error for invalid ownership type")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}
