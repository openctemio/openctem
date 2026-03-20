package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/accesscontrol"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// =============================================================================
// Mock AccessControl Repository
// =============================================================================

// mockAccessControlRepo implements accesscontrol.Repository for testing data scope.
type mockAccessControlRepo struct {
	// HasAnyScopeAssignment behavior
	hasAnyScopeResult bool
	hasAnyScopeErr    error
	hasAnyScopeCalls  int

	// CanAccessAsset behavior
	canAccessResult bool
	canAccessErr    error
	canAccessCalls  int

	// Track call parameters
	lastUserID  shared.ID
	lastAssetID shared.ID
}

func (m *mockAccessControlRepo) HasAnyScopeAssignment(_ context.Context, _, userID shared.ID) (bool, error) {
	m.hasAnyScopeCalls++
	m.lastUserID = userID
	return m.hasAnyScopeResult, m.hasAnyScopeErr
}

func (m *mockAccessControlRepo) CanAccessAsset(_ context.Context, userID, assetID shared.ID) (bool, error) {
	m.canAccessCalls++
	m.lastUserID = userID
	m.lastAssetID = assetID
	return m.canAccessResult, m.canAccessErr
}

// Stub remaining interface methods (not used in data scope tests)
func (m *mockAccessControlRepo) CreateAssetOwner(_ context.Context, _ *accesscontrol.AssetOwner) error {
	return nil
}
func (m *mockAccessControlRepo) GetAssetOwner(_ context.Context, _, _ shared.ID) (*accesscontrol.AssetOwner, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) UpdateAssetOwner(_ context.Context, _ *accesscontrol.AssetOwner) error {
	return nil
}
func (m *mockAccessControlRepo) DeleteAssetOwner(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockAccessControlRepo) ListAssetOwners(_ context.Context, _ shared.ID) ([]*accesscontrol.AssetOwner, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) ListAssetsByGroup(_ context.Context, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) ListGroupsByAsset(_ context.Context, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) CountAssetOwners(_ context.Context, _ shared.ID) (int64, error) {
	return 0, nil
}
func (m *mockAccessControlRepo) CountAssetsByGroups(_ context.Context, _ []shared.ID) (map[shared.ID]int, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) ListAssetOwnersByGroupWithDetails(_ context.Context, _ shared.ID, _, _ int) ([]*accesscontrol.AssetOwnerWithAsset, int64, error) {
	return nil, 0, nil
}
func (m *mockAccessControlRepo) HasPrimaryOwner(_ context.Context, _ shared.ID) (bool, error) {
	return false, nil
}
func (m *mockAccessControlRepo) ListAccessibleAssets(_ context.Context, _, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) GetUserAssetAccess(_ context.Context, _, _ shared.ID) (*accesscontrol.UserAssetAccess, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) CreateGroupPermission(_ context.Context, _ *accesscontrol.GroupPermission) error {
	return nil
}
func (m *mockAccessControlRepo) GetGroupPermission(_ context.Context, _ shared.ID, _ string) (*accesscontrol.GroupPermission, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) UpdateGroupPermission(_ context.Context, _ *accesscontrol.GroupPermission) error {
	return nil
}
func (m *mockAccessControlRepo) DeleteGroupPermission(_ context.Context, _ shared.ID, _ string) error {
	return nil
}
func (m *mockAccessControlRepo) ListGroupPermissions(_ context.Context, _ shared.ID) ([]*accesscontrol.GroupPermission, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) ListGroupPermissionsByEffect(_ context.Context, _ shared.ID, _ accesscontrol.PermissionEffect) ([]*accesscontrol.GroupPermission, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) CreateAssignmentRule(_ context.Context, _ *accesscontrol.AssignmentRule) error {
	return nil
}
func (m *mockAccessControlRepo) GetAssignmentRule(_ context.Context, _, _ shared.ID) (*accesscontrol.AssignmentRule, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) UpdateAssignmentRule(_ context.Context, _ shared.ID, _ *accesscontrol.AssignmentRule) error {
	return nil
}
func (m *mockAccessControlRepo) DeleteAssignmentRule(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockAccessControlRepo) ListAssignmentRules(_ context.Context, _ shared.ID, _ accesscontrol.AssignmentRuleFilter) ([]*accesscontrol.AssignmentRule, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) CountAssignmentRules(_ context.Context, _ shared.ID, _ accesscontrol.AssignmentRuleFilter) (int64, error) {
	return 0, nil
}
func (m *mockAccessControlRepo) ListActiveRulesByPriority(_ context.Context, _ shared.ID) ([]*accesscontrol.AssignmentRule, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) BulkCreateAssetOwners(_ context.Context, _ []*accesscontrol.AssetOwner) (int, error) {
	return 0, nil
}
func (m *mockAccessControlRepo) RefreshUserAccessibleAssets(_ context.Context) error {
	return nil
}
func (m *mockAccessControlRepo) RefreshAccessForAssetAssign(_ context.Context, _, _ shared.ID, _ string) error {
	return nil
}
func (m *mockAccessControlRepo) RefreshAccessForAssetUnassign(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockAccessControlRepo) RefreshAccessForMemberAdd(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockAccessControlRepo) RefreshAccessForMemberRemove(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockAccessControlRepo) CreateScopeRule(_ context.Context, _ *accesscontrol.ScopeRule) error {
	return nil
}
func (m *mockAccessControlRepo) GetScopeRule(_ context.Context, _, _ shared.ID) (*accesscontrol.ScopeRule, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) UpdateScopeRule(_ context.Context, _ shared.ID, _ *accesscontrol.ScopeRule) error {
	return nil
}
func (m *mockAccessControlRepo) DeleteScopeRule(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockAccessControlRepo) ListScopeRules(_ context.Context, _, _ shared.ID, _ accesscontrol.ScopeRuleFilter) ([]*accesscontrol.ScopeRule, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) CountScopeRules(_ context.Context, _, _ shared.ID, _ accesscontrol.ScopeRuleFilter) (int64, error) {
	return 0, nil
}
func (m *mockAccessControlRepo) ListActiveScopeRulesByTenant(_ context.Context, _ shared.ID) ([]*accesscontrol.ScopeRule, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) ListActiveScopeRulesByGroup(_ context.Context, _, _ shared.ID) ([]*accesscontrol.ScopeRule, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) CreateAssetOwnerWithSource(_ context.Context, _ *accesscontrol.AssetOwner, _ string, _ *shared.ID) error {
	return nil
}
func (m *mockAccessControlRepo) BulkCreateAssetOwnersWithSource(_ context.Context, _ []*accesscontrol.AssetOwner, _ string, _ *shared.ID) (int, error) {
	return 0, nil
}
func (m *mockAccessControlRepo) DeleteAutoAssignedByRule(_ context.Context, _, _ shared.ID) (int, error) {
	return 0, nil
}
func (m *mockAccessControlRepo) DeleteAutoAssignedForAsset(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockAccessControlRepo) BulkDeleteAutoAssignedForAssets(_ context.Context, _ []shared.ID, _ shared.ID) (int, error) {
	return 0, nil
}
func (m *mockAccessControlRepo) ListAutoAssignedAssets(_ context.Context, _, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) ListAutoAssignedGroupsForAsset(_ context.Context, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) DeleteScopeRuleWithCleanup(_ context.Context, _, _ shared.ID) (int, error) {
	return 0, nil
}
func (m *mockAccessControlRepo) FindAssetsByTagMatch(_ context.Context, _ shared.ID, _ []string, _ accesscontrol.MatchLogic) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) FindAssetsByAssetGroupMatch(_ context.Context, _ shared.ID, _ []shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) BulkCreateFindingGroupAssignments(_ context.Context, _ []*accesscontrol.FindingGroupAssignment) (int, error) {
	return 0, nil
}
func (m *mockAccessControlRepo) ListFindingGroupAssignments(_ context.Context, _, _ shared.ID) ([]*accesscontrol.FindingGroupAssignment, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) CountFindingsByGroupFromRules(_ context.Context, _, _ shared.ID) (int64, error) {
	return 0, nil
}
func (m *mockAccessControlRepo) GetAssetOwnerByID(_ context.Context, _ shared.ID) (*accesscontrol.AssetOwner, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) GetAssetOwnerByUser(_ context.Context, _, _ shared.ID) (*accesscontrol.AssetOwner, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) DeleteAssetOwnerByID(_ context.Context, _ shared.ID) error {
	return nil
}
func (m *mockAccessControlRepo) DeleteAssetOwnerByUser(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockAccessControlRepo) ListAssetOwnersWithNames(_ context.Context, _, _ shared.ID) ([]*accesscontrol.AssetOwnerWithNames, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) GetPrimaryOwnerBrief(_ context.Context, _, _ shared.ID) (*accesscontrol.OwnerBrief, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) RefreshAccessForDirectOwnerAdd(_ context.Context, _, _ shared.ID, _ string) error {
	return nil
}
func (m *mockAccessControlRepo) RefreshAccessForDirectOwnerRemove(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockAccessControlRepo) GetPrimaryOwnersByAssetIDs(_ context.Context, _ shared.ID, _ []shared.ID) (map[string]*accesscontrol.OwnerBrief, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) ListTenantsWithActiveScopeRules(_ context.Context) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) ListGroupsWithActiveScopeRules(_ context.Context, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockAccessControlRepo) ListGroupsWithAssetGroupMatchRule(_ context.Context, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}

// =============================================================================
// Mock Finding Repository (for VulnerabilityService data scope tests)
// =============================================================================

// mockFindingRepoForScope implements vulnerability.FindingRepository for scope tests.
type mockFindingRepoForScope struct {
	stubFindingRepo // embed the full stub

	// Override GetByID
	findingByID    *vulnerability.Finding
	findingByIDErr error

	// Override GetStats
	statsResult *vulnerability.FindingStats
	statsErr    error

	// Track calls
	getStatsCalls         int
	getStatsDataScopeUser *shared.ID
}

func (m *mockFindingRepoForScope) GetByID(_ context.Context, _, _ shared.ID) (*vulnerability.Finding, error) {
	return m.findingByID, m.findingByIDErr
}

func (m *mockFindingRepoForScope) GetStats(_ context.Context, _ shared.ID, dataScopeUserID *shared.ID) (*vulnerability.FindingStats, error) {
	m.getStatsCalls++
	m.getStatsDataScopeUser = dataScopeUserID
	return m.statsResult, m.statsErr
}

// =============================================================================
// Helper: create test asset via service
// =============================================================================

func createTestAsset(t *testing.T, svc *app.AssetService, tenantID string) (string, string) {
	t.Helper()
	input := app.CreateAssetInput{
		TenantID:    tenantID,
		Name:        "Test Asset " + shared.NewID().String()[:8],
		Type:        "host",
		Criticality: "high",
	}
	a, err := svc.CreateAsset(context.Background(), input)
	if err != nil {
		t.Fatalf("failed to create test asset: %v", err)
	}
	return a.ID().String(), tenantID
}

// =============================================================================
// AssetService.GetAssetWithScope Tests
// =============================================================================

func TestGetAssetWithScope_AdminBypass(t *testing.T) {
	svc, _ := newTestService()
	tenantID := shared.NewID().String()
	assetID, _ := createTestAsset(t, svc, tenantID)

	acRepo := &mockAccessControlRepo{}
	svc.SetAccessControlRepository(acRepo)

	// Admin should bypass scope checks entirely
	a, err := svc.GetAssetWithScope(context.Background(), tenantID, assetID, shared.NewID().String(), true)
	if err != nil {
		t.Fatalf("admin should access asset, got error: %v", err)
	}
	if a == nil {
		t.Fatal("expected asset, got nil")
	}

	// Verify no access control calls were made
	if acRepo.hasAnyScopeCalls != 0 {
		t.Errorf("expected 0 HasAnyScopeAssignment calls for admin, got %d", acRepo.hasAnyScopeCalls)
	}
	if acRepo.canAccessCalls != 0 {
		t.Errorf("expected 0 CanAccessAsset calls for admin, got %d", acRepo.canAccessCalls)
	}
}

func TestGetAssetWithScope_NonAdmin_NoScopeAssignment(t *testing.T) {
	svc, _ := newTestService()
	tenantID := shared.NewID().String()
	assetID, _ := createTestAsset(t, svc, tenantID)

	acRepo := &mockAccessControlRepo{
		hasAnyScopeResult: false, // user has no group assignments
	}
	svc.SetAccessControlRepository(acRepo)

	// Non-admin without scope assignments → backward compat → sees all
	a, err := svc.GetAssetWithScope(context.Background(), tenantID, assetID, shared.NewID().String(), false)
	if err != nil {
		t.Fatalf("non-admin without scope should access asset, got error: %v", err)
	}
	if a == nil {
		t.Fatal("expected asset, got nil")
	}

	if acRepo.hasAnyScopeCalls != 1 {
		t.Errorf("expected 1 HasAnyScopeAssignment call, got %d", acRepo.hasAnyScopeCalls)
	}
	// CanAccessAsset should NOT be called (no scope → all visible)
	if acRepo.canAccessCalls != 0 {
		t.Errorf("expected 0 CanAccessAsset calls, got %d", acRepo.canAccessCalls)
	}
}

func TestGetAssetWithScope_NonAdmin_HasScope_CanAccess(t *testing.T) {
	svc, _ := newTestService()
	tenantID := shared.NewID().String()
	assetID, _ := createTestAsset(t, svc, tenantID)

	acRepo := &mockAccessControlRepo{
		hasAnyScopeResult: true,
		canAccessResult:   true,
	}
	svc.SetAccessControlRepository(acRepo)

	a, err := svc.GetAssetWithScope(context.Background(), tenantID, assetID, shared.NewID().String(), false)
	if err != nil {
		t.Fatalf("non-admin with access should see asset, got error: %v", err)
	}
	if a == nil {
		t.Fatal("expected asset, got nil")
	}

	if acRepo.hasAnyScopeCalls != 1 {
		t.Errorf("expected 1 HasAnyScopeAssignment call, got %d", acRepo.hasAnyScopeCalls)
	}
	if acRepo.canAccessCalls != 1 {
		t.Errorf("expected 1 CanAccessAsset call, got %d", acRepo.canAccessCalls)
	}
}

func TestGetAssetWithScope_NonAdmin_HasScope_Denied(t *testing.T) {
	svc, _ := newTestService()
	tenantID := shared.NewID().String()
	assetID, _ := createTestAsset(t, svc, tenantID)

	acRepo := &mockAccessControlRepo{
		hasAnyScopeResult: true,
		canAccessResult:   false, // access denied
	}
	svc.SetAccessControlRepository(acRepo)

	_, err := svc.GetAssetWithScope(context.Background(), tenantID, assetID, shared.NewID().String(), false)
	if err == nil {
		t.Fatal("expected error for denied access")
	}
	// Should return ErrNotFound (not ErrForbidden) to prevent info disclosure
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestGetAssetWithScope_NonAdmin_HasScopeError_FailClosed(t *testing.T) {
	svc, _ := newTestService()
	tenantID := shared.NewID().String()
	assetID, _ := createTestAsset(t, svc, tenantID)

	acRepo := &mockAccessControlRepo{
		hasAnyScopeErr: errors.New("db connection failed"),
	}
	svc.SetAccessControlRepository(acRepo)

	_, err := svc.GetAssetWithScope(context.Background(), tenantID, assetID, shared.NewID().String(), false)
	if err == nil {
		t.Fatal("expected error when HasAnyScopeAssignment fails (fail-closed)")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound on scope check error, got %v", err)
	}
}

func TestGetAssetWithScope_NonAdmin_CanAccessError_FailClosed(t *testing.T) {
	svc, _ := newTestService()
	tenantID := shared.NewID().String()
	assetID, _ := createTestAsset(t, svc, tenantID)

	acRepo := &mockAccessControlRepo{
		hasAnyScopeResult: true,
		canAccessErr:      errors.New("db connection failed"),
	}
	svc.SetAccessControlRepository(acRepo)

	_, err := svc.GetAssetWithScope(context.Background(), tenantID, assetID, shared.NewID().String(), false)
	if err == nil {
		t.Fatal("expected error when CanAccessAsset fails (fail-closed)")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound on access check error, got %v", err)
	}
}

func TestGetAssetWithScope_NonAdmin_InvalidUserID_FailClosed(t *testing.T) {
	svc, _ := newTestService()
	tenantID := shared.NewID().String()
	assetID, _ := createTestAsset(t, svc, tenantID)

	acRepo := &mockAccessControlRepo{}
	svc.SetAccessControlRepository(acRepo)

	// Invalid (non-UUID) acting user ID
	_, err := svc.GetAssetWithScope(context.Background(), tenantID, assetID, "not-a-uuid", false)
	if err == nil {
		t.Fatal("expected error for invalid user ID (fail-closed)")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound for invalid user ID, got %v", err)
	}

	// No access control calls should be made
	if acRepo.hasAnyScopeCalls != 0 {
		t.Errorf("expected 0 HasAnyScopeAssignment calls for invalid user ID, got %d", acRepo.hasAnyScopeCalls)
	}
}

func TestGetAssetWithScope_NonAdmin_EmptyUserID_NoScopeCheck(t *testing.T) {
	svc, _ := newTestService()
	tenantID := shared.NewID().String()
	assetID, _ := createTestAsset(t, svc, tenantID)

	acRepo := &mockAccessControlRepo{}
	svc.SetAccessControlRepository(acRepo)

	// Empty acting user ID → no scope check (legacy behavior)
	a, err := svc.GetAssetWithScope(context.Background(), tenantID, assetID, "", false)
	if err != nil {
		t.Fatalf("empty user ID should bypass scope, got error: %v", err)
	}
	if a == nil {
		t.Fatal("expected asset, got nil")
	}

	if acRepo.hasAnyScopeCalls != 0 {
		t.Errorf("expected 0 scope calls for empty user ID, got %d", acRepo.hasAnyScopeCalls)
	}
}

func TestGetAssetWithScope_NoAccessControlRepo_NoScopeCheck(t *testing.T) {
	svc, _ := newTestService()
	tenantID := shared.NewID().String()
	assetID, _ := createTestAsset(t, svc, tenantID)

	// Don't set access control repo (nil)
	a, err := svc.GetAssetWithScope(context.Background(), tenantID, assetID, shared.NewID().String(), false)
	if err != nil {
		t.Fatalf("nil access control repo should bypass scope, got error: %v", err)
	}
	if a == nil {
		t.Fatal("expected asset, got nil")
	}
}

func TestGetAssetWithScope_AssetNotFound(t *testing.T) {
	svc, _ := newTestService()
	tenantID := shared.NewID().String()

	acRepo := &mockAccessControlRepo{}
	svc.SetAccessControlRepository(acRepo)

	_, err := svc.GetAssetWithScope(context.Background(), tenantID, shared.NewID().String(), shared.NewID().String(), false)
	if err == nil {
		t.Fatal("expected error for non-existent asset")
	}

	// No scope checks if asset doesn't exist
	if acRepo.hasAnyScopeCalls != 0 {
		t.Errorf("expected 0 scope calls for non-existent asset, got %d", acRepo.hasAnyScopeCalls)
	}
}

// =============================================================================
// AssetService.ListAssets Data Scope Tests
// =============================================================================

func TestListAssets_Admin_NoDataScopeFilter(t *testing.T) {
	svc, _ := newTestService()
	tenantID := shared.NewID().String()

	// Create some test assets with unique names
	for _, name := range []string{"Server-Alpha", "Server-Beta", "Server-Gamma"} {
		input := app.CreateAssetInput{
			TenantID:    tenantID,
			Name:        name,
			Type:        "host",
			Criticality: "high",
		}
		_, err := svc.CreateAsset(context.Background(), input)
		if err != nil {
			t.Fatalf("failed to create asset %s: %v", name, err)
		}
	}

	input := app.ListAssetsInput{
		TenantID:     tenantID,
		Page:         1,
		PerPage:      10,
		IsAdmin:      true,
		ActingUserID: shared.NewID().String(),
	}

	result, err := svc.ListAssets(context.Background(), input)
	if err != nil {
		t.Fatalf("admin list should work, got error: %v", err)
	}
	if len(result.Data) != 3 {
		t.Errorf("admin should see all 3 assets, got %d", len(result.Data))
	}
}

func TestListAssets_NonAdmin_WithUserID(t *testing.T) {
	svc, _ := newTestService()
	tenantID := shared.NewID().String()
	userID := shared.NewID()

	createTestAsset(t, svc, tenantID)

	// The DataScopeUserID is set on the filter and passed to the repository.
	// Since MockAssetRepository doesn't filter by DataScopeUserID, we can only
	// verify the service doesn't error out. Real filtering is tested at the repo level.
	input := app.ListAssetsInput{
		TenantID:     tenantID,
		Page:         1,
		PerPage:      10,
		IsAdmin:      false,
		ActingUserID: userID.String(),
	}

	_, err := svc.ListAssets(context.Background(), input)
	if err != nil {
		t.Fatalf("non-admin list should work, got error: %v", err)
	}
}

func TestListAssets_NonAdmin_EmptyUserID_NoScope(t *testing.T) {
	svc, _ := newTestService()
	tenantID := shared.NewID().String()

	createTestAsset(t, svc, tenantID)

	input := app.ListAssetsInput{
		TenantID:     tenantID,
		Page:         1,
		PerPage:      10,
		IsAdmin:      false,
		ActingUserID: "", // empty → no scope
	}

	_, err := svc.ListAssets(context.Background(), input)
	if err != nil {
		t.Fatalf("empty user ID list should work, got error: %v", err)
	}
}

// =============================================================================
// VulnerabilityService.GetFindingWithScope Tests
// =============================================================================

func newTestVulnService(findingRepo vulnerability.FindingRepository) *app.VulnerabilityService {
	log := logger.NewNop()
	svc := app.NewVulnerabilityService(nil, findingRepo, log)
	return svc
}

func TestGetFindingWithScope_AdminBypass(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()
	findingID := shared.NewID()

	finding, err := vulnerability.NewFinding(tenantID, assetID, vulnerability.FindingSourceSAST, "test-tool", vulnerability.SeverityHigh, "Test finding")
	if err != nil {
		t.Fatalf("failed to create finding: %v", err)
	}

	findingRepo := &mockFindingRepoForScope{findingByID: finding}
	svc := newTestVulnService(findingRepo)

	acRepo := &mockAccessControlRepo{}
	svc.SetAccessControlRepository(acRepo)

	// Admin bypasses scope check - note: findingID won't match but the mock returns any finding
	f, err := svc.GetFindingWithScope(context.Background(), tenantID.String(), findingID.String(), shared.NewID().String(), true)
	if err != nil {
		t.Fatalf("admin should access finding, got error: %v", err)
	}
	if f == nil {
		t.Fatal("expected finding, got nil")
	}

	if acRepo.hasAnyScopeCalls != 0 {
		t.Errorf("expected 0 scope calls for admin, got %d", acRepo.hasAnyScopeCalls)
	}
}

func TestGetFindingWithScope_NonAdmin_NoScope_BackwardCompat(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()
	findingID := shared.NewID()

	finding, _ := vulnerability.NewFinding(tenantID, assetID, vulnerability.FindingSourceSAST, "test-tool", vulnerability.SeverityHigh, "Test finding")

	findingRepo := &mockFindingRepoForScope{findingByID: finding}
	svc := newTestVulnService(findingRepo)

	acRepo := &mockAccessControlRepo{
		hasAnyScopeResult: false, // no group assignments
	}
	svc.SetAccessControlRepository(acRepo)

	f, err := svc.GetFindingWithScope(context.Background(), tenantID.String(), findingID.String(), shared.NewID().String(), false)
	if err != nil {
		t.Fatalf("non-admin without scope should access finding, got error: %v", err)
	}
	if f == nil {
		t.Fatal("expected finding, got nil")
	}

	if acRepo.canAccessCalls != 0 {
		t.Errorf("expected 0 CanAccessAsset calls for backward compat, got %d", acRepo.canAccessCalls)
	}
}

func TestGetFindingWithScope_NonAdmin_HasScope_CanAccess(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()
	findingID := shared.NewID()

	finding, _ := vulnerability.NewFinding(tenantID, assetID, vulnerability.FindingSourceSAST, "test-tool", vulnerability.SeverityHigh, "Test finding")

	findingRepo := &mockFindingRepoForScope{findingByID: finding}
	svc := newTestVulnService(findingRepo)

	acRepo := &mockAccessControlRepo{
		hasAnyScopeResult: true,
		canAccessResult:   true, // user can access this asset
	}
	svc.SetAccessControlRepository(acRepo)

	f, err := svc.GetFindingWithScope(context.Background(), tenantID.String(), findingID.String(), shared.NewID().String(), false)
	if err != nil {
		t.Fatalf("non-admin with access should see finding, got error: %v", err)
	}
	if f == nil {
		t.Fatal("expected finding, got nil")
	}
}

func TestGetFindingWithScope_NonAdmin_HasScope_Denied(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()
	findingID := shared.NewID()

	finding, _ := vulnerability.NewFinding(tenantID, assetID, vulnerability.FindingSourceSAST, "test-tool", vulnerability.SeverityHigh, "Test finding")

	findingRepo := &mockFindingRepoForScope{findingByID: finding}
	svc := newTestVulnService(findingRepo)

	acRepo := &mockAccessControlRepo{
		hasAnyScopeResult: true,
		canAccessResult:   false, // access denied
	}
	svc.SetAccessControlRepository(acRepo)

	_, err := svc.GetFindingWithScope(context.Background(), tenantID.String(), findingID.String(), shared.NewID().String(), false)
	if err == nil {
		t.Fatal("expected error for denied access")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestGetFindingWithScope_NonAdmin_ScopeCheckError_FailClosed(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()
	findingID := shared.NewID()

	finding, _ := vulnerability.NewFinding(tenantID, assetID, vulnerability.FindingSourceSAST, "test-tool", vulnerability.SeverityHigh, "Test finding")

	findingRepo := &mockFindingRepoForScope{findingByID: finding}
	svc := newTestVulnService(findingRepo)

	acRepo := &mockAccessControlRepo{
		hasAnyScopeErr: errors.New("db error"),
	}
	svc.SetAccessControlRepository(acRepo)

	_, err := svc.GetFindingWithScope(context.Background(), tenantID.String(), findingID.String(), shared.NewID().String(), false)
	if err == nil {
		t.Fatal("expected error on scope check failure (fail-closed)")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound on scope error, got %v", err)
	}
}

func TestGetFindingWithScope_NonAdmin_AccessCheckError_FailClosed(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()
	findingID := shared.NewID()

	finding, _ := vulnerability.NewFinding(tenantID, assetID, vulnerability.FindingSourceSAST, "test-tool", vulnerability.SeverityHigh, "Test finding")

	findingRepo := &mockFindingRepoForScope{findingByID: finding}
	svc := newTestVulnService(findingRepo)

	acRepo := &mockAccessControlRepo{
		hasAnyScopeResult: true,
		canAccessErr:      errors.New("db error"),
	}
	svc.SetAccessControlRepository(acRepo)

	_, err := svc.GetFindingWithScope(context.Background(), tenantID.String(), findingID.String(), shared.NewID().String(), false)
	if err == nil {
		t.Fatal("expected error on access check failure (fail-closed)")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound on access error, got %v", err)
	}
}

// =============================================================================
// VulnerabilityService.GetFindingStatsWithScope Tests
// =============================================================================

func TestGetFindingStatsWithScope_Admin_NoDataScope(t *testing.T) {
	stats := vulnerability.NewFindingStats()
	stats.Total = 42

	findingRepo := &mockFindingRepoForScope{statsResult: stats}
	svc := newTestVulnService(findingRepo)

	result, err := svc.GetFindingStatsWithScope(context.Background(), app.GetFindingStatsInput{
		TenantID:     shared.NewID().String(),
		ActingUserID: shared.NewID().String(),
		IsAdmin:      true,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 42 {
		t.Errorf("expected total 42, got %d", result.Total)
	}

	// dataScopeUserID should be nil for admin
	if findingRepo.getStatsDataScopeUser != nil {
		t.Error("expected nil dataScopeUserID for admin")
	}
}

func TestGetFindingStatsWithScope_NonAdmin_WithUserID(t *testing.T) {
	stats := vulnerability.NewFindingStats()
	stats.Total = 10

	findingRepo := &mockFindingRepoForScope{statsResult: stats}
	svc := newTestVulnService(findingRepo)
	userID := shared.NewID()

	result, err := svc.GetFindingStatsWithScope(context.Background(), app.GetFindingStatsInput{
		TenantID:     shared.NewID().String(),
		ActingUserID: userID.String(),
		IsAdmin:      false,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 10 {
		t.Errorf("expected total 10, got %d", result.Total)
	}

	// dataScopeUserID should be set for non-admin
	if findingRepo.getStatsDataScopeUser == nil {
		t.Fatal("expected dataScopeUserID to be set for non-admin")
	}
	if *findingRepo.getStatsDataScopeUser != userID {
		t.Errorf("expected dataScopeUserID %s, got %s", userID, *findingRepo.getStatsDataScopeUser)
	}
}

func TestGetFindingStatsWithScope_NonAdmin_EmptyUserID(t *testing.T) {
	stats := vulnerability.NewFindingStats()
	findingRepo := &mockFindingRepoForScope{statsResult: stats}
	svc := newTestVulnService(findingRepo)

	_, err := svc.GetFindingStatsWithScope(context.Background(), app.GetFindingStatsInput{
		TenantID:     shared.NewID().String(),
		ActingUserID: "", // empty
		IsAdmin:      false,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// dataScopeUserID should be nil (empty user ID)
	if findingRepo.getStatsDataScopeUser != nil {
		t.Error("expected nil dataScopeUserID for empty user ID")
	}
}

func TestGetFindingStats_BackwardCompat(t *testing.T) {
	stats := vulnerability.NewFindingStats()
	stats.Total = 99

	findingRepo := &mockFindingRepoForScope{statsResult: stats}
	svc := newTestVulnService(findingRepo)

	// GetFindingStats (old API) should delegate with isAdmin=true
	result, err := svc.GetFindingStats(context.Background(), shared.NewID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 99 {
		t.Errorf("expected total 99, got %d", result.Total)
	}

	// Should pass nil dataScopeUserID (admin mode)
	if findingRepo.getStatsDataScopeUser != nil {
		t.Error("expected nil dataScopeUserID for backward compat GetFindingStats")
	}
}

// =============================================================================
// Filter Builder Tests
// =============================================================================

func TestAssetFilter_WithDataScopeUserID(t *testing.T) {
	userID := shared.NewID()
	f := asset.NewFilter().WithDataScopeUserID(userID)

	if f.DataScopeUserID == nil {
		t.Fatal("expected DataScopeUserID to be set")
	}
	if *f.DataScopeUserID != userID {
		t.Errorf("expected %s, got %s", userID, *f.DataScopeUserID)
	}
}

func TestAssetFilter_IsEmpty_WithDataScope(t *testing.T) {
	f := asset.NewFilter()
	if !f.IsEmpty() {
		t.Error("new filter should be empty")
	}

	userID := shared.NewID()
	f = f.WithDataScopeUserID(userID)
	if f.IsEmpty() {
		t.Error("filter with DataScopeUserID should not be empty")
	}
}

func TestFindingFilter_WithDataScopeUserID(t *testing.T) {
	userID := shared.NewID()
	tenantID := shared.NewID()
	f := vulnerability.NewFindingFilter().WithTenantID(tenantID).WithDataScopeUserID(userID)

	if f.DataScopeUserID == nil {
		t.Fatal("expected DataScopeUserID to be set")
	}
	if *f.DataScopeUserID != userID {
		t.Errorf("expected %s, got %s", userID, *f.DataScopeUserID)
	}
}

func (m *mockAccessControlRepo) BatchListFindingGroupIDs(_ context.Context, _ shared.ID, _ []shared.ID) (map[shared.ID][]shared.ID, error) {
	return make(map[shared.ID][]shared.ID), nil
}
