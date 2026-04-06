package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/accesscontrol"
	"github.com/openctemio/api/pkg/domain/group"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// =============================================================================
// Mock for GroupService bulk/incremental tests
// =============================================================================

// mockACRepoForBulk extends mockAccessControlRepo with bulk-specific tracking.
type mockACRepoForBulk struct {
	mockAccessControlRepo // embed full stub

	// BulkCreateAssetOwners
	bulkCreateResult int
	bulkCreateErr    error
	bulkCreateCalls  int
	bulkCreateOwners []*accesscontrol.AssetOwner // track what was passed

	// RefreshAccessForAssetAssign
	refreshAssignCalls int
	refreshAssignErr   error

	// RefreshAccessForAssetUnassign
	refreshUnassignCalls int
	refreshUnassignErr   error

	// RefreshAccessForMemberAdd
	refreshMemberAddCalls int
	refreshMemberAddErr   error

	// RefreshAccessForMemberRemove
	refreshMemberRemoveCalls int
	refreshMemberRemoveErr   error

	// CreateAssetOwner
	createAssetOwnerErr   error
	createAssetOwnerCalls int

	// DeleteAssetOwner
	deleteAssetOwnerErr   error
	deleteAssetOwnerCalls int
}

func (m *mockACRepoForBulk) BulkCreateAssetOwners(_ context.Context, owners []*accesscontrol.AssetOwner) (int, error) {
	m.bulkCreateCalls++
	m.bulkCreateOwners = owners
	if m.bulkCreateErr != nil {
		return 0, m.bulkCreateErr
	}
	if m.bulkCreateResult > 0 {
		return m.bulkCreateResult, nil
	}
	return len(owners), nil
}

func (m *mockACRepoForBulk) RefreshAccessForAssetAssign(_ context.Context, _, _ shared.ID, _ string) error {
	m.refreshAssignCalls++
	return m.refreshAssignErr
}

func (m *mockACRepoForBulk) RefreshAccessForAssetUnassign(_ context.Context, _, _ shared.ID) error {
	m.refreshUnassignCalls++
	return m.refreshUnassignErr
}

func (m *mockACRepoForBulk) RefreshAccessForMemberAdd(_ context.Context, _, _ shared.ID) error {
	m.refreshMemberAddCalls++
	return m.refreshMemberAddErr
}

func (m *mockACRepoForBulk) RefreshAccessForMemberRemove(_ context.Context, _, _ shared.ID) error {
	m.refreshMemberRemoveCalls++
	return m.refreshMemberRemoveErr
}

func (m *mockACRepoForBulk) CreateAssetOwner(_ context.Context, _ *accesscontrol.AssetOwner) error {
	m.createAssetOwnerCalls++
	return m.createAssetOwnerErr
}

func (m *mockACRepoForBulk) DeleteAssetOwner(_ context.Context, _, _ shared.ID) error {
	m.deleteAssetOwnerCalls++
	return m.deleteAssetOwnerErr
}
func (m *mockACRepoForBulk) GetAssetOwnerByID(_ context.Context, _ shared.ID) (*accesscontrol.AssetOwner, error) {
	return nil, nil
}
func (m *mockACRepoForBulk) GetAssetOwnerByUser(_ context.Context, _, _ shared.ID) (*accesscontrol.AssetOwner, error) {
	return nil, nil
}
func (m *mockACRepoForBulk) DeleteAssetOwnerByID(_ context.Context, _ shared.ID) error {
	return nil
}
func (m *mockACRepoForBulk) DeleteAssetOwnerByUser(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockACRepoForBulk) ListAssetOwnersWithNames(_ context.Context, _, _ shared.ID) ([]*accesscontrol.AssetOwnerWithNames, error) {
	return nil, nil
}
func (m *mockACRepoForBulk) GetPrimaryOwnerBrief(_ context.Context, _, _ shared.ID) (*accesscontrol.OwnerBrief, error) {
	return nil, nil
}
func (m *mockACRepoForBulk) RefreshAccessForDirectOwnerAdd(_ context.Context, _, _ shared.ID, _ string) error {
	return nil
}
func (m *mockACRepoForBulk) RefreshAccessForDirectOwnerRemove(_ context.Context, _, _ shared.ID) error {
	return nil
}

// mockGroupRepoForBulk is a group.Repository mock for bulk tests.
type mockGroupRepoForBulk struct {
	groups     map[shared.ID]*group.Group
	members    map[shared.ID][]*group.Member // groupID -> members
	getMemberResult *group.Member
	getMemberErr    error
}

func newMockGroupRepoForBulk() *mockGroupRepoForBulk {
	return &mockGroupRepoForBulk{
		groups:  make(map[shared.ID]*group.Group),
		members: make(map[shared.ID][]*group.Member),
	}
}

func (m *mockGroupRepoForBulk) addGroup(g *group.Group) {
	m.groups[g.ID()] = g
}

func (m *mockGroupRepoForBulk) GetByID(_ context.Context, id shared.ID) (*group.Group, error) {
	g, ok := m.groups[id]
	if !ok {
		return nil, group.ErrGroupNotFound
	}
	return g, nil
}

func (m *mockGroupRepoForBulk) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*group.Group, error) {
	g, ok := m.groups[id]
	if !ok {
		return nil, group.ErrGroupNotFound
	}
	if g.TenantID() != tenantID {
		return nil, group.ErrGroupNotFound
	}
	return g, nil
}

func (m *mockGroupRepoForBulk) GetMember(_ context.Context, _, _ shared.ID) (*group.Member, error) {
	if m.getMemberErr != nil {
		return nil, m.getMemberErr
	}
	return m.getMemberResult, nil
}

func (m *mockGroupRepoForBulk) AddMember(_ context.Context, member *group.Member) error {
	return nil
}

func (m *mockGroupRepoForBulk) RemoveMember(_ context.Context, _, _ shared.ID) error {
	return nil
}

func (m *mockGroupRepoForBulk) ListMembers(_ context.Context, groupID shared.ID) ([]*group.Member, error) {
	return m.members[groupID], nil
}

// Stubs for remaining interface methods
func (m *mockGroupRepoForBulk) Create(_ context.Context, _ *group.Group) error { return nil }
func (m *mockGroupRepoForBulk) GetBySlug(_ context.Context, _ shared.ID, _ string) (*group.Group, error) {
	return nil, nil
}
func (m *mockGroupRepoForBulk) Update(_ context.Context, _ *group.Group) error  { return nil }
func (m *mockGroupRepoForBulk) Delete(_ context.Context, _ shared.ID) error     { return nil }
func (m *mockGroupRepoForBulk) List(_ context.Context, _ shared.ID, _ group.ListFilter) ([]*group.Group, error) {
	return nil, nil
}
func (m *mockGroupRepoForBulk) Count(_ context.Context, _ shared.ID, _ group.ListFilter) (int64, error) {
	return 0, nil
}
func (m *mockGroupRepoForBulk) ExistsBySlug(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}
func (m *mockGroupRepoForBulk) ListByIDs(_ context.Context, _ []shared.ID) ([]*group.Group, error) {
	return nil, nil
}
func (m *mockGroupRepoForBulk) GetByExternalID(_ context.Context, _ shared.ID, _ group.ExternalSource, _ string) (*group.Group, error) {
	return nil, nil
}
func (m *mockGroupRepoForBulk) UpdateMember(_ context.Context, _ *group.Member) error { return nil }
func (m *mockGroupRepoForBulk) ListMembersWithUserInfo(_ context.Context, _ shared.ID, _, _ int) ([]*group.MemberWithUser, int64, error) {
	return nil, 0, nil
}
func (m *mockGroupRepoForBulk) CountMembers(_ context.Context, _ shared.ID) (int64, error) {
	return 0, nil
}
func (m *mockGroupRepoForBulk) CountMembersByGroups(_ context.Context, _ []shared.ID) (map[shared.ID]int, error) {
	return nil, nil
}
func (m *mockGroupRepoForBulk) CountUniqueMembers(_ context.Context, _ []shared.ID) (int, error) {
	return 0, nil
}
func (m *mockGroupRepoForBulk) GetMemberStats(_ context.Context, _ shared.ID) (*group.MemberStats, error) {
	return nil, nil
}
func (m *mockGroupRepoForBulk) IsMember(_ context.Context, _, _ shared.ID) (bool, error) {
	return false, nil
}
func (m *mockGroupRepoForBulk) ListGroupsByUser(_ context.Context, _, _ shared.ID) ([]*group.GroupWithRole, error) {
	return nil, nil
}
func (m *mockGroupRepoForBulk) ListGroupIDsByUser(_ context.Context, _, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockGroupRepoForBulk) AssignPermissionSet(_ context.Context, _, _ shared.ID, _ *shared.ID) error {
	return nil
}
func (m *mockGroupRepoForBulk) RemovePermissionSet(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockGroupRepoForBulk) ListPermissionSetIDs(_ context.Context, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockGroupRepoForBulk) ListGroupsWithPermissionSet(_ context.Context, _ shared.ID) ([]*group.Group, error) {
	return nil, nil
}

// =============================================================================
// Helpers
// =============================================================================

func newGroupServiceForBulk(groupRepo group.Repository, acRepo accesscontrol.Repository) *app.GroupService {
	log := logger.New(logger.Config{Level: "error"})
	return app.NewGroupService(groupRepo, log, app.WithAccessControlRepository(acRepo))
}

func makeTestGroup(tenantID shared.ID) *group.Group {
	g, _ := group.NewGroup(tenantID, "Bulk Test Group", "bulk-test-group", group.GroupTypeTeam)
	return g
}

func generateAssetIDs(n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = shared.NewID().String()
	}
	return ids
}

// =============================================================================
// BulkAssignAssets Tests
// =============================================================================

func TestBulkAssignAssets_Success(t *testing.T) {
	tenantID := shared.NewID()
	g := makeTestGroup(tenantID)
	assetIDs := generateAssetIDs(5)

	groupRepo := newMockGroupRepoForBulk()
	groupRepo.addGroup(g)
	acRepo := &mockACRepoForBulk{}
	svc := newGroupServiceForBulk(groupRepo, acRepo)

	input := app.BulkAssignAssetsInput{
		GroupID:       g.ID().String(),
		AssetIDs:      assetIDs,
		OwnershipType: "primary",
	}

	result, err := svc.BulkAssignAssets(context.Background(), input, shared.NewID(), app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if result.SuccessCount != 5 {
		t.Errorf("expected 5 successes, got %d", result.SuccessCount)
	}
	if result.FailedCount != 0 {
		t.Errorf("expected 0 failures, got %d", result.FailedCount)
	}
	if len(result.FailedAssets) != 0 {
		t.Errorf("expected no failed assets, got %v", result.FailedAssets)
	}

	// Verify bulk create was called once
	if acRepo.bulkCreateCalls != 1 {
		t.Errorf("expected 1 bulk create call, got %d", acRepo.bulkCreateCalls)
	}

	// Verify 5 owners were passed
	if len(acRepo.bulkCreateOwners) != 5 {
		t.Errorf("expected 5 owners, got %d", len(acRepo.bulkCreateOwners))
	}

	// Verify incremental refresh was called for each asset
	if acRepo.refreshAssignCalls != 5 {
		t.Errorf("expected 5 refresh calls, got %d", acRepo.refreshAssignCalls)
	}
}

func TestBulkAssignAssets_AllOwnershipTypes(t *testing.T) {
	ownershipTypes := []string{"primary", "secondary", "stakeholder", "informed"}

	for _, ot := range ownershipTypes {
		t.Run(ot, func(t *testing.T) {
			tenantID := shared.NewID()
			g := makeTestGroup(tenantID)

			groupRepo := newMockGroupRepoForBulk()
			groupRepo.addGroup(g)
			acRepo := &mockACRepoForBulk{}
			svc := newGroupServiceForBulk(groupRepo, acRepo)

			input := app.BulkAssignAssetsInput{
				GroupID:       g.ID().String(),
				AssetIDs:      generateAssetIDs(2),
				OwnershipType: ot,
			}

			result, err := svc.BulkAssignAssets(context.Background(), input, shared.NewID(), app.AuditContext{})
			if err != nil {
				t.Fatalf("expected no error for ownership type %s, got: %v", ot, err)
			}
			if result.SuccessCount != 2 {
				t.Errorf("expected 2 successes, got %d", result.SuccessCount)
			}
		})
	}
}

func TestBulkAssignAssets_InvalidGroupID(t *testing.T) {
	acRepo := &mockACRepoForBulk{}
	groupRepo := newMockGroupRepoForBulk()
	svc := newGroupServiceForBulk(groupRepo, acRepo)

	input := app.BulkAssignAssetsInput{
		GroupID:       "not-a-uuid",
		AssetIDs:      generateAssetIDs(3),
		OwnershipType: "primary",
	}

	_, err := svc.BulkAssignAssets(context.Background(), input, shared.NewID(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for invalid group ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestBulkAssignAssets_InvalidOwnershipType(t *testing.T) {
	tenantID := shared.NewID()
	g := makeTestGroup(tenantID)

	groupRepo := newMockGroupRepoForBulk()
	groupRepo.addGroup(g)
	acRepo := &mockACRepoForBulk{}
	svc := newGroupServiceForBulk(groupRepo, acRepo)

	input := app.BulkAssignAssetsInput{
		GroupID:       g.ID().String(),
		AssetIDs:      generateAssetIDs(3),
		OwnershipType: "invalid_type",
	}

	_, err := svc.BulkAssignAssets(context.Background(), input, shared.NewID(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for invalid ownership type")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestBulkAssignAssets_GroupNotFound(t *testing.T) {
	groupRepo := newMockGroupRepoForBulk() // empty, no groups
	acRepo := &mockACRepoForBulk{}
	svc := newGroupServiceForBulk(groupRepo, acRepo)

	input := app.BulkAssignAssetsInput{
		GroupID:       shared.NewID().String(),
		AssetIDs:      generateAssetIDs(3),
		OwnershipType: "primary",
	}

	_, err := svc.BulkAssignAssets(context.Background(), input, shared.NewID(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for missing group")
	}
	if !errors.Is(err, group.ErrGroupNotFound) {
		t.Errorf("expected ErrGroupNotFound, got: %v", err)
	}
}

func TestBulkAssignAssets_MixedValidInvalidAssetIDs(t *testing.T) {
	tenantID := shared.NewID()
	g := makeTestGroup(tenantID)

	groupRepo := newMockGroupRepoForBulk()
	groupRepo.addGroup(g)
	acRepo := &mockACRepoForBulk{}
	svc := newGroupServiceForBulk(groupRepo, acRepo)

	validIDs := generateAssetIDs(3)
	invalidIDs := []string{"not-a-uuid", "also-invalid", "bad"}
	allIDs := append(validIDs, invalidIDs...)

	input := app.BulkAssignAssetsInput{
		GroupID:       g.ID().String(),
		AssetIDs:      allIDs,
		OwnershipType: "primary",
	}

	result, err := svc.BulkAssignAssets(context.Background(), input, shared.NewID(), app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error (partial success), got: %v", err)
	}

	// 3 valid should be inserted, 3 invalid should fail
	if result.SuccessCount != 3 {
		t.Errorf("expected 3 successes, got %d", result.SuccessCount)
	}
	if len(result.FailedAssets) != 3 {
		t.Errorf("expected 3 failed assets, got %d: %v", len(result.FailedAssets), result.FailedAssets)
	}

	// Only 3 valid owners should be passed to bulk create
	if len(acRepo.bulkCreateOwners) != 3 {
		t.Errorf("expected 3 owners in bulk create, got %d", len(acRepo.bulkCreateOwners))
	}

	// Incremental refresh only for successful inserts
	if acRepo.refreshAssignCalls != 3 {
		t.Errorf("expected 3 refresh calls, got %d", acRepo.refreshAssignCalls)
	}
}

func TestBulkAssignAssets_RepoError(t *testing.T) {
	tenantID := shared.NewID()
	g := makeTestGroup(tenantID)

	groupRepo := newMockGroupRepoForBulk()
	groupRepo.addGroup(g)
	acRepo := &mockACRepoForBulk{
		bulkCreateErr: errors.New("database connection lost"),
	}
	svc := newGroupServiceForBulk(groupRepo, acRepo)

	input := app.BulkAssignAssetsInput{
		GroupID:       g.ID().String(),
		AssetIDs:      generateAssetIDs(5),
		OwnershipType: "primary",
	}

	_, err := svc.BulkAssignAssets(context.Background(), input, shared.NewID(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error on repo failure")
	}
}

func TestBulkAssignAssets_RefreshErrorNonBlocking(t *testing.T) {
	tenantID := shared.NewID()
	g := makeTestGroup(tenantID)

	groupRepo := newMockGroupRepoForBulk()
	groupRepo.addGroup(g)
	acRepo := &mockACRepoForBulk{
		refreshAssignErr: errors.New("refresh failed"),
	}
	svc := newGroupServiceForBulk(groupRepo, acRepo)

	input := app.BulkAssignAssetsInput{
		GroupID:       g.ID().String(),
		AssetIDs:      generateAssetIDs(3),
		OwnershipType: "primary",
	}

	// Refresh errors should NOT block the bulk assign operation
	result, err := svc.BulkAssignAssets(context.Background(), input, shared.NewID(), app.AuditContext{})
	if err != nil {
		t.Fatalf("refresh errors should not block, got: %v", err)
	}
	if result.SuccessCount != 3 {
		t.Errorf("expected 3 successes even with refresh errors, got %d", result.SuccessCount)
	}
	// Refresh was still attempted for each
	if acRepo.refreshAssignCalls != 3 {
		t.Errorf("expected 3 refresh attempts, got %d", acRepo.refreshAssignCalls)
	}
}

func TestBulkAssignAssets_AccessControlRepoNotConfigured(t *testing.T) {
	tenantID := shared.NewID()
	g := makeTestGroup(tenantID)

	groupRepo := newMockGroupRepoForBulk()
	groupRepo.addGroup(g)
	// Create service WITHOUT access control repo
	log := logger.New(logger.Config{Level: "error"})
	svc := app.NewGroupService(groupRepo, log) // no WithAccessControlRepository

	input := app.BulkAssignAssetsInput{
		GroupID:       g.ID().String(),
		AssetIDs:      generateAssetIDs(3),
		OwnershipType: "primary",
	}

	_, err := svc.BulkAssignAssets(context.Background(), input, shared.NewID(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error when access control repo not configured")
	}
}

func TestBulkAssignAssets_LargeDataset(t *testing.T) {
	tenantID := shared.NewID()
	g := makeTestGroup(tenantID)

	groupRepo := newMockGroupRepoForBulk()
	groupRepo.addGroup(g)
	acRepo := &mockACRepoForBulk{}
	svc := newGroupServiceForBulk(groupRepo, acRepo)

	// Test with 100 assets (reasonable for unit test)
	input := app.BulkAssignAssetsInput{
		GroupID:       g.ID().String(),
		AssetIDs:      generateAssetIDs(100),
		OwnershipType: "secondary",
	}

	result, err := svc.BulkAssignAssets(context.Background(), input, shared.NewID(), app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error for 100 assets, got: %v", err)
	}
	if result.SuccessCount != 100 {
		t.Errorf("expected 100 successes, got %d", result.SuccessCount)
	}
	if acRepo.refreshAssignCalls != 100 {
		t.Errorf("expected 100 refresh calls, got %d", acRepo.refreshAssignCalls)
	}
}

func TestBulkAssignAssets_PartialBulkInsert(t *testing.T) {
	tenantID := shared.NewID()
	g := makeTestGroup(tenantID)

	groupRepo := newMockGroupRepoForBulk()
	groupRepo.addGroup(g)
	// Simulate ON CONFLICT DO NOTHING: bulk insert returns fewer rows than submitted
	acRepo := &mockACRepoForBulk{
		bulkCreateResult: 3, // only 3 of 5 were new
	}
	svc := newGroupServiceForBulk(groupRepo, acRepo)

	input := app.BulkAssignAssetsInput{
		GroupID:       g.ID().String(),
		AssetIDs:      generateAssetIDs(5),
		OwnershipType: "primary",
	}

	result, err := svc.BulkAssignAssets(context.Background(), input, shared.NewID(), app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result.SuccessCount != 3 {
		t.Errorf("expected 3 successes (partial insert), got %d", result.SuccessCount)
	}
	if result.FailedCount != 2 {
		t.Errorf("expected 2 failures (duplicates), got %d", result.FailedCount)
	}
}

// =============================================================================
// Incremental Refresh - AssignAsset Tests
// =============================================================================

func TestAssignAsset_UsesIncrementalRefresh(t *testing.T) {
	tenantID := shared.NewID()
	g := makeTestGroup(tenantID)

	groupRepo := newMockGroupRepoForBulk()
	groupRepo.addGroup(g)
	acRepo := &mockACRepoForBulk{}
	svc := newGroupServiceForBulk(groupRepo, acRepo)

	input := app.AssignAssetInput{
		GroupID:       g.ID().String(),
		AssetID:       shared.NewID().String(),
		OwnershipType: "primary",
	}

	err := svc.AssignAsset(context.Background(), input, shared.NewID(), app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Should use incremental refresh, not full refresh
	if acRepo.refreshAssignCalls != 1 {
		t.Errorf("expected 1 incremental refresh call, got %d", acRepo.refreshAssignCalls)
	}
}

func TestAssignAsset_RefreshErrorNonBlocking(t *testing.T) {
	tenantID := shared.NewID()
	g := makeTestGroup(tenantID)

	groupRepo := newMockGroupRepoForBulk()
	groupRepo.addGroup(g)
	acRepo := &mockACRepoForBulk{
		refreshAssignErr: errors.New("refresh failed"),
	}
	svc := newGroupServiceForBulk(groupRepo, acRepo)

	input := app.AssignAssetInput{
		GroupID:       g.ID().String(),
		AssetID:       shared.NewID().String(),
		OwnershipType: "primary",
	}

	// Refresh error should NOT block the assign operation
	err := svc.AssignAsset(context.Background(), input, shared.NewID(), app.AuditContext{})
	if err != nil {
		t.Fatalf("refresh error should not block assign, got: %v", err)
	}
}

// =============================================================================
// Incremental Refresh - UnassignAsset Tests
// =============================================================================

func TestUnassignAsset_UsesIncrementalRefresh(t *testing.T) {
	tenantID := shared.NewID()
	g := makeTestGroup(tenantID)

	groupRepo := newMockGroupRepoForBulk()
	groupRepo.addGroup(g)
	acRepo := &mockACRepoForBulk{}
	svc := newGroupServiceForBulk(groupRepo, acRepo)

	input := app.UnassignAssetInput{
		GroupID: g.ID().String(),
		AssetID: shared.NewID().String(),
	}

	err := svc.UnassignAsset(context.Background(), input, app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Should use incremental unassign refresh
	if acRepo.refreshUnassignCalls != 1 {
		t.Errorf("expected 1 unassign refresh call, got %d", acRepo.refreshUnassignCalls)
	}
}

func TestUnassignAsset_RefreshErrorNonBlocking(t *testing.T) {
	tenantID := shared.NewID()
	g := makeTestGroup(tenantID)

	groupRepo := newMockGroupRepoForBulk()
	groupRepo.addGroup(g)
	acRepo := &mockACRepoForBulk{
		refreshUnassignErr: errors.New("refresh failed"),
	}
	svc := newGroupServiceForBulk(groupRepo, acRepo)

	input := app.UnassignAssetInput{
		GroupID: g.ID().String(),
		AssetID: shared.NewID().String(),
	}

	err := svc.UnassignAsset(context.Background(), input, app.AuditContext{})
	if err != nil {
		t.Fatalf("refresh error should not block unassign, got: %v", err)
	}
}

// =============================================================================
// Incremental Refresh - AddMember Tests
// =============================================================================

func TestAddMember_UsesIncrementalRefresh(t *testing.T) {
	tenantID := shared.NewID()
	g := makeTestGroup(tenantID)
	userID := shared.NewID()

	groupRepo := newMockGroupRepoForBulk()
	groupRepo.addGroup(g)
	groupRepo.getMemberErr = group.ErrMemberNotFound // user not yet a member
	acRepo := &mockACRepoForBulk{}
	svc := newGroupServiceForBulk(groupRepo, acRepo)

	input := app.AddGroupMemberInput{
		GroupID: g.ID().String(),
		UserID:  userID,
		Role:    "member",
	}

	_, err := svc.AddMember(context.Background(), input, app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Should refresh access for the new member
	if acRepo.refreshMemberAddCalls != 1 {
		t.Errorf("expected 1 member add refresh call, got %d", acRepo.refreshMemberAddCalls)
	}
}

func TestAddMember_RefreshErrorNonBlocking(t *testing.T) {
	tenantID := shared.NewID()
	g := makeTestGroup(tenantID)

	groupRepo := newMockGroupRepoForBulk()
	groupRepo.addGroup(g)
	groupRepo.getMemberErr = group.ErrMemberNotFound
	acRepo := &mockACRepoForBulk{
		refreshMemberAddErr: errors.New("refresh failed"),
	}
	svc := newGroupServiceForBulk(groupRepo, acRepo)

	input := app.AddGroupMemberInput{
		GroupID: g.ID().String(),
		UserID:  shared.NewID(),
		Role:    "member",
	}

	_, err := svc.AddMember(context.Background(), input, app.AuditContext{})
	if err != nil {
		t.Fatalf("refresh error should not block member add, got: %v", err)
	}
}

// =============================================================================
// Incremental Refresh - RemoveMember Tests
// =============================================================================

func TestRemoveMember_UsesIncrementalRefresh(t *testing.T) {
	tenantID := shared.NewID()
	g := makeTestGroup(tenantID)
	ownerID := shared.NewID()
	memberID := shared.NewID()

	groupRepo := newMockGroupRepoForBulk()
	groupRepo.addGroup(g)

	// Return a member role (not owner, so no last-owner check blocks)
	member, _ := group.NewMember(g.ID(), memberID, group.MemberRoleMember, nil)
	groupRepo.getMemberResult = member

	acRepo := &mockACRepoForBulk{}
	svc := newGroupServiceForBulk(groupRepo, acRepo)

	// Add an owner to the members list so owner check passes
	ownerMember, _ := group.NewMember(g.ID(), ownerID, group.MemberRoleOwner, nil)
	groupRepo.members[g.ID()] = []*group.Member{ownerMember, member}

	err := svc.RemoveMember(context.Background(), g.ID().String(), memberID, app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Should refresh access for removed member
	if acRepo.refreshMemberRemoveCalls != 1 {
		t.Errorf("expected 1 member remove refresh call, got %d", acRepo.refreshMemberRemoveCalls)
	}
}

// =============================================================================
// AssignmentRule Entity Tests
// =============================================================================

func TestAssignmentRule_NewRule_Success(t *testing.T) {
	tenantID := shared.NewID()
	targetGroupID := shared.NewID()
	createdBy := shared.NewID()

	conditions := accesscontrol.AssignmentConditions{
		AssetTypes:      []string{"host", "website"},
		FindingSeverity: []string{"critical", "high"},
	}

	rule, err := accesscontrol.NewAssignmentRule(tenantID, "Test Rule", conditions, targetGroupID, &createdBy)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if rule.Name() != "Test Rule" {
		t.Errorf("expected name 'Test Rule', got '%s'", rule.Name())
	}
	if rule.TenantID() != tenantID {
		t.Errorf("expected tenant ID %s, got %s", tenantID, rule.TenantID())
	}
	if rule.TargetGroupID() != targetGroupID {
		t.Errorf("expected target group ID %s, got %s", targetGroupID, rule.TargetGroupID())
	}
	if !rule.IsActive() {
		t.Error("new rule should be active by default")
	}
	if rule.Priority() != 0 {
		t.Errorf("default priority should be 0, got %d", rule.Priority())
	}
	if rule.CreatedBy() == nil {
		t.Fatal("expected CreatedBy to be set")
	}
	if *rule.CreatedBy() != createdBy {
		t.Errorf("expected CreatedBy %s, got %s", createdBy, *rule.CreatedBy())
	}
}

func TestAssignmentRule_NewRule_MissingTenantID(t *testing.T) {
	_, err := accesscontrol.NewAssignmentRule(shared.ID{}, "Test", accesscontrol.AssignmentConditions{}, shared.NewID(), nil)
	if err == nil {
		t.Fatal("expected error for zero tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestAssignmentRule_NewRule_EmptyName(t *testing.T) {
	_, err := accesscontrol.NewAssignmentRule(shared.NewID(), "", accesscontrol.AssignmentConditions{}, shared.NewID(), nil)
	if err == nil {
		t.Fatal("expected error for empty name")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestAssignmentRule_NewRule_MissingTargetGroup(t *testing.T) {
	_, err := accesscontrol.NewAssignmentRule(shared.NewID(), "Test", accesscontrol.AssignmentConditions{}, shared.ID{}, nil)
	if err == nil {
		t.Fatal("expected error for zero target group ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestAssignmentRule_UpdateMethods(t *testing.T) {
	rule := makeExistingRule(shared.NewID(), shared.NewID())

	// Test UpdateName
	err := rule.UpdateName("New Name")
	if err != nil {
		t.Fatalf("UpdateName failed: %v", err)
	}
	if rule.Name() != "New Name" {
		t.Errorf("expected 'New Name', got '%s'", rule.Name())
	}

	// Test UpdateName empty
	err = rule.UpdateName("")
	if err == nil {
		t.Fatal("expected error for empty name")
	}

	// Test UpdateDescription
	rule.UpdateDescription("New Description")
	if rule.Description() != "New Description" {
		t.Errorf("expected 'New Description', got '%s'", rule.Description())
	}

	// Test UpdatePriority
	rule.UpdatePriority(99)
	if rule.Priority() != 99 {
		t.Errorf("expected priority 99, got %d", rule.Priority())
	}

	// Test Activate/Deactivate
	rule.Deactivate()
	if rule.IsActive() {
		t.Error("expected rule to be inactive after Deactivate()")
	}
	rule.Activate()
	if !rule.IsActive() {
		t.Error("expected rule to be active after Activate()")
	}

	// Test UpdateConditions
	newConditions := accesscontrol.AssignmentConditions{
		AssetTypes:      []string{"container"},
		FindingSeverity: []string{"critical"},
		AssetTags:       []string{"production"},
	}
	rule.UpdateConditions(newConditions)
	if len(rule.Conditions().AssetTypes) != 1 || rule.Conditions().AssetTypes[0] != "container" {
		t.Error("expected conditions to be updated")
	}

	// Test UpdateTargetGroup
	newGroupID := shared.NewID()
	err = rule.UpdateTargetGroup(newGroupID)
	if err != nil {
		t.Fatalf("UpdateTargetGroup failed: %v", err)
	}
	if rule.TargetGroupID() != newGroupID {
		t.Errorf("expected target group %s, got %s", newGroupID, rule.TargetGroupID())
	}

	// Test UpdateTargetGroup zero
	err = rule.UpdateTargetGroup(shared.ID{})
	if err == nil {
		t.Fatal("expected error for zero target group ID")
	}

	// Test UpdateOptions
	options := accesscontrol.AssignmentOptions{
		NotifyGroup:        true,
		SetFindingPriority: "critical",
	}
	rule.UpdateOptions(options)
	if !rule.Options().NotifyGroup {
		t.Error("expected NotifyGroup to be true")
	}
	if rule.Options().SetFindingPriority != "critical" {
		t.Errorf("expected SetFindingPriority 'critical', got '%s'", rule.Options().SetFindingPriority)
	}
}

func TestAssignmentRule_Reconstitute(t *testing.T) {
	id := shared.NewID()
	tenantID := shared.NewID()
	targetGroupID := shared.NewID()
	createdBy := shared.NewID()
	now := time.Now().UTC()

	rule := accesscontrol.ReconstituteAssignmentRule(
		id, tenantID,
		"Reconstituted Rule", "Some description",
		5, false,
		accesscontrol.AssignmentConditions{AssetTypes: []string{"website"}},
		targetGroupID,
		accesscontrol.AssignmentOptions{NotifyGroup: true},
		now, now,
		&createdBy,
	)

	if rule.ID() != id {
		t.Errorf("expected ID %s, got %s", id, rule.ID())
	}
	if rule.TenantID() != tenantID {
		t.Errorf("expected tenant ID %s, got %s", tenantID, rule.TenantID())
	}
	if rule.Name() != "Reconstituted Rule" {
		t.Errorf("expected name 'Reconstituted Rule', got '%s'", rule.Name())
	}
	if rule.Description() != "Some description" {
		t.Errorf("expected description 'Some description', got '%s'", rule.Description())
	}
	if rule.Priority() != 5 {
		t.Errorf("expected priority 5, got %d", rule.Priority())
	}
	if rule.IsActive() {
		t.Error("expected inactive")
	}
	if rule.TargetGroupID() != targetGroupID {
		t.Errorf("expected target group ID %s, got %s", targetGroupID, rule.TargetGroupID())
	}
	if !rule.Options().NotifyGroup {
		t.Error("expected NotifyGroup true")
	}
	if rule.CreatedBy() == nil || *rule.CreatedBy() != createdBy {
		t.Error("expected CreatedBy to be set correctly")
	}
	if !rule.CreatedAt().Equal(now) {
		t.Errorf("expected CreatedAt %v, got %v", now, rule.CreatedAt())
	}
}

func (m *mockACRepoForBulk) BatchListFindingGroupIDs(_ context.Context, _ shared.ID, _ []shared.ID) (map[shared.ID][]shared.ID, error) {
	return make(map[shared.ID][]shared.ID), nil
}
