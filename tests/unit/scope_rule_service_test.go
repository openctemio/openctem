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
// Mock AccessControl Repository for Scope Rule Tests
// =============================================================================

// mockACRepoForScope implements accesscontrol.Repository for scope rule tests.
type mockACRepoForScope struct {
	mockAccessControlRepo // embed full stub

	// Scope rule storage
	scopeRules map[shared.ID]*accesscontrol.ScopeRule

	// CreateScopeRule
	createScopeRuleErr   error
	createScopeRuleCalls int

	// GetScopeRule
	getScopeRuleErr   error
	getScopeRuleCalls int

	// UpdateScopeRule
	updateScopeRuleErr   error
	updateScopeRuleCalls int

	// DeleteScopeRuleWithCleanup
	deleteScopeRuleCleanupResult int
	deleteScopeRuleCleanupErr    error
	deleteScopeRuleCleanupCalls  int

	// ListScopeRules
	listScopeRulesResult []*accesscontrol.ScopeRule
	listScopeRulesErr    error
	listScopeRulesCalls  int

	// CountScopeRules
	countScopeRulesResult int64
	countScopeRulesErr    error
	countScopeRulesCalls  int

	// ListActiveScopeRulesByGroup
	listActiveScopeRulesResult []*accesscontrol.ScopeRule
	listActiveScopeRulesErr    error
	listActiveScopeRulesCalls  int

	// FindAssetsByTagMatch
	findAssetsByTagResult []shared.ID
	findAssetsByTagErr    error
	findAssetsByTagCalls  int

	// FindAssetsByAssetGroupMatch
	findAssetsByGroupResult []shared.ID
	findAssetsByGroupErr    error
	findAssetsByGroupCalls  int

	// ListAssetsByGroup
	listAssetsByGroupResult []shared.ID
	listAssetsByGroupErr    error
	listAssetsByGroupCalls  int

	// BulkCreateAssetOwnersWithSource
	bulkCreateWithSourceResult int
	bulkCreateWithSourceErr    error
	bulkCreateWithSourceCalls  int

	// RefreshUserAccessibleAssets
	refreshAccessCalls int
	refreshAccessErr   error

	// ListAutoAssignedAssets
	listAutoAssignedResult []shared.ID
	listAutoAssignedErr    error
	listAutoAssignedCalls  int

	// BulkDeleteAutoAssignedForAssets
	bulkDeleteAutoResult int
	bulkDeleteAutoErr    error
	bulkDeleteAutoCalls  int
}

func newMockACRepoForScope() *mockACRepoForScope {
	return &mockACRepoForScope{
		scopeRules: make(map[shared.ID]*accesscontrol.ScopeRule),
	}
}

func (m *mockACRepoForScope) CreateScopeRule(_ context.Context, rule *accesscontrol.ScopeRule) error {
	m.createScopeRuleCalls++
	if m.createScopeRuleErr != nil {
		return m.createScopeRuleErr
	}
	m.scopeRules[rule.ID()] = rule
	return nil
}

func (m *mockACRepoForScope) GetScopeRule(_ context.Context, tenantID, id shared.ID) (*accesscontrol.ScopeRule, error) {
	m.getScopeRuleCalls++
	if m.getScopeRuleErr != nil {
		return nil, m.getScopeRuleErr
	}
	rule, ok := m.scopeRules[id]
	if !ok {
		return nil, shared.ErrNotFound
	}
	if rule.TenantID() != tenantID {
		return nil, shared.ErrNotFound
	}
	return rule, nil
}

func (m *mockACRepoForScope) UpdateScopeRule(_ context.Context, tenantID shared.ID, rule *accesscontrol.ScopeRule) error {
	m.updateScopeRuleCalls++
	if m.updateScopeRuleErr != nil {
		return m.updateScopeRuleErr
	}
	m.scopeRules[rule.ID()] = rule
	return nil
}

func (m *mockACRepoForScope) DeleteScopeRuleWithCleanup(_ context.Context, _, ruleID shared.ID) (int, error) {
	m.deleteScopeRuleCleanupCalls++
	if m.deleteScopeRuleCleanupErr != nil {
		return 0, m.deleteScopeRuleCleanupErr
	}
	delete(m.scopeRules, ruleID)
	return m.deleteScopeRuleCleanupResult, nil
}

func (m *mockACRepoForScope) ListScopeRules(_ context.Context, _, _ shared.ID, _ accesscontrol.ScopeRuleFilter) ([]*accesscontrol.ScopeRule, error) {
	m.listScopeRulesCalls++
	if m.listScopeRulesErr != nil {
		return nil, m.listScopeRulesErr
	}
	return m.listScopeRulesResult, nil
}

func (m *mockACRepoForScope) CountScopeRules(_ context.Context, _, _ shared.ID, _ accesscontrol.ScopeRuleFilter) (int64, error) {
	m.countScopeRulesCalls++
	if m.countScopeRulesErr != nil {
		return 0, m.countScopeRulesErr
	}
	return m.countScopeRulesResult, nil
}

func (m *mockACRepoForScope) ListActiveScopeRulesByGroup(_ context.Context, _, _ shared.ID) ([]*accesscontrol.ScopeRule, error) {
	m.listActiveScopeRulesCalls++
	if m.listActiveScopeRulesErr != nil {
		return nil, m.listActiveScopeRulesErr
	}
	return m.listActiveScopeRulesResult, nil
}

func (m *mockACRepoForScope) FindAssetsByTagMatch(_ context.Context, _ shared.ID, _ []string, _ accesscontrol.MatchLogic) ([]shared.ID, error) {
	m.findAssetsByTagCalls++
	if m.findAssetsByTagErr != nil {
		return nil, m.findAssetsByTagErr
	}
	return m.findAssetsByTagResult, nil
}

func (m *mockACRepoForScope) FindAssetsByAssetGroupMatch(_ context.Context, _ shared.ID, _ []shared.ID) ([]shared.ID, error) {
	m.findAssetsByGroupCalls++
	if m.findAssetsByGroupErr != nil {
		return nil, m.findAssetsByGroupErr
	}
	return m.findAssetsByGroupResult, nil
}

func (m *mockACRepoForScope) ListAssetsByGroup(_ context.Context, _ shared.ID) ([]shared.ID, error) {
	m.listAssetsByGroupCalls++
	if m.listAssetsByGroupErr != nil {
		return nil, m.listAssetsByGroupErr
	}
	return m.listAssetsByGroupResult, nil
}
func (m *mockACRepoForScope) GetAssetOwnerByID(_ context.Context, _ shared.ID) (*accesscontrol.AssetOwner, error) {
	return nil, nil
}
func (m *mockACRepoForScope) GetAssetOwnerByUser(_ context.Context, _, _ shared.ID) (*accesscontrol.AssetOwner, error) {
	return nil, nil
}
func (m *mockACRepoForScope) DeleteAssetOwnerByID(_ context.Context, _ shared.ID) error {
	return nil
}
func (m *mockACRepoForScope) DeleteAssetOwnerByUser(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockACRepoForScope) ListAssetOwnersWithNames(_ context.Context, _, _ shared.ID) ([]*accesscontrol.AssetOwnerWithNames, error) {
	return nil, nil
}
func (m *mockACRepoForScope) GetPrimaryOwnerBrief(_ context.Context, _, _ shared.ID) (*accesscontrol.OwnerBrief, error) {
	return nil, nil
}
func (m *mockACRepoForScope) RefreshAccessForDirectOwnerAdd(_ context.Context, _, _ shared.ID, _ string) error {
	return nil
}
func (m *mockACRepoForScope) RefreshAccessForDirectOwnerRemove(_ context.Context, _, _ shared.ID) error {
	return nil
}

func (m *mockACRepoForScope) BulkCreateAssetOwnersWithSource(_ context.Context, owners []*accesscontrol.AssetOwner, _ string, _ *shared.ID) (int, error) {
	m.bulkCreateWithSourceCalls++
	if m.bulkCreateWithSourceErr != nil {
		return 0, m.bulkCreateWithSourceErr
	}
	if m.bulkCreateWithSourceResult > 0 {
		return m.bulkCreateWithSourceResult, nil
	}
	return len(owners), nil
}

func (m *mockACRepoForScope) RefreshUserAccessibleAssets(_ context.Context) error {
	m.refreshAccessCalls++
	return m.refreshAccessErr
}

func (m *mockACRepoForScope) ListAutoAssignedAssets(_ context.Context, _, _ shared.ID) ([]shared.ID, error) {
	m.listAutoAssignedCalls++
	if m.listAutoAssignedErr != nil {
		return nil, m.listAutoAssignedErr
	}
	return m.listAutoAssignedResult, nil
}

func (m *mockACRepoForScope) BulkDeleteAutoAssignedForAssets(_ context.Context, assetIDs []shared.ID, _ shared.ID) (int, error) {
	m.bulkDeleteAutoCalls++
	if m.bulkDeleteAutoErr != nil {
		return 0, m.bulkDeleteAutoErr
	}
	if m.bulkDeleteAutoResult > 0 {
		return m.bulkDeleteAutoResult, nil
	}
	return len(assetIDs), nil
}

// =============================================================================
// Mock Group Repository for Scope Rule Tests
// =============================================================================

// mockGroupRepoForScope implements group.Repository for scope rule tests.
type mockGroupRepoForScope struct {
	groups map[shared.ID]*group.Group
}

func newMockGroupRepoForScope() *mockGroupRepoForScope {
	return &mockGroupRepoForScope{
		groups: make(map[shared.ID]*group.Group),
	}
}

func (m *mockGroupRepoForScope) addGroup(g *group.Group) {
	m.groups[g.ID()] = g
}

func (m *mockGroupRepoForScope) GetByID(_ context.Context, id shared.ID) (*group.Group, error) {
	g, ok := m.groups[id]
	if !ok {
		return nil, group.ErrGroupNotFound
	}
	return g, nil
}

// Stubs for remaining interface methods
func (m *mockGroupRepoForScope) Create(_ context.Context, _ *group.Group) error { return nil }
func (m *mockGroupRepoForScope) GetBySlug(_ context.Context, _ shared.ID, _ string) (*group.Group, error) {
	return nil, nil
}
func (m *mockGroupRepoForScope) Update(_ context.Context, _ *group.Group) error  { return nil }
func (m *mockGroupRepoForScope) Delete(_ context.Context, _ shared.ID) error     { return nil }
func (m *mockGroupRepoForScope) List(_ context.Context, _ shared.ID, _ group.ListFilter) ([]*group.Group, error) {
	return nil, nil
}
func (m *mockGroupRepoForScope) Count(_ context.Context, _ shared.ID, _ group.ListFilter) (int64, error) {
	return 0, nil
}
func (m *mockGroupRepoForScope) ExistsBySlug(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}
func (m *mockGroupRepoForScope) ListByIDs(_ context.Context, _ []shared.ID) ([]*group.Group, error) {
	return nil, nil
}
func (m *mockGroupRepoForScope) GetByExternalID(_ context.Context, _ shared.ID, _ group.ExternalSource, _ string) (*group.Group, error) {
	return nil, nil
}
func (m *mockGroupRepoForScope) AddMember(_ context.Context, _ *group.Member) error { return nil }
func (m *mockGroupRepoForScope) GetMember(_ context.Context, _, _ shared.ID) (*group.Member, error) {
	return nil, nil
}
func (m *mockGroupRepoForScope) UpdateMember(_ context.Context, _ *group.Member) error { return nil }
func (m *mockGroupRepoForScope) RemoveMember(_ context.Context, _, _ shared.ID) error  { return nil }
func (m *mockGroupRepoForScope) ListMembers(_ context.Context, _ shared.ID) ([]*group.Member, error) {
	return nil, nil
}
func (m *mockGroupRepoForScope) ListMembersWithUserInfo(_ context.Context, _ shared.ID) ([]*group.MemberWithUser, error) {
	return nil, nil
}
func (m *mockGroupRepoForScope) CountMembers(_ context.Context, _ shared.ID) (int64, error) {
	return 0, nil
}
func (m *mockGroupRepoForScope) GetMemberStats(_ context.Context, _ shared.ID) (*group.MemberStats, error) {
	return nil, nil
}
func (m *mockGroupRepoForScope) IsMember(_ context.Context, _, _ shared.ID) (bool, error) {
	return false, nil
}
func (m *mockGroupRepoForScope) ListGroupsByUser(_ context.Context, _, _ shared.ID) ([]*group.GroupWithRole, error) {
	return nil, nil
}
func (m *mockGroupRepoForScope) ListGroupIDsByUser(_ context.Context, _, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockGroupRepoForScope) AssignPermissionSet(_ context.Context, _, _ shared.ID, _ *shared.ID) error {
	return nil
}
func (m *mockGroupRepoForScope) RemovePermissionSet(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockGroupRepoForScope) ListPermissionSetIDs(_ context.Context, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockGroupRepoForScope) ListGroupsWithPermissionSet(_ context.Context, _ shared.ID) ([]*group.Group, error) {
	return nil, nil
}

// =============================================================================
// Helpers
// =============================================================================

func newTestScopeRuleService(acRepo accesscontrol.Repository, groupRepo group.Repository) *app.ScopeRuleService {
	log := logger.NewNop()
	return app.NewScopeRuleService(acRepo, groupRepo, log)
}

func makeScopeTestGroup(tenantID shared.ID) *group.Group {
	g, _ := group.NewGroup(tenantID, "Scope Test Group", "scope-test-group", group.GroupTypeTeam)
	return g
}

func makeInactiveScopeTestGroup(tenantID shared.ID) *group.Group {
	g, _ := group.NewGroup(tenantID, "Inactive Group", "inactive-group", group.GroupTypeTeam)
	g.Deactivate()
	return g
}

func makeExistingScopeRule(tenantID, groupID shared.ID, ruleType accesscontrol.ScopeRuleType) *accesscontrol.ScopeRule {
	now := time.Now().UTC()
	var matchTags []string
	var matchAssetGroupIDs []shared.ID
	if ruleType == accesscontrol.ScopeRuleTagMatch {
		matchTags = []string{"production", "critical"}
	} else {
		matchAssetGroupIDs = []shared.ID{shared.NewID()}
	}
	return accesscontrol.ReconstituteScopeRule(
		shared.NewID(), tenantID, groupID,
		"Existing Rule", "An existing scope rule",
		ruleType,
		matchTags,
		accesscontrol.MatchLogicAny,
		matchAssetGroupIDs,
		accesscontrol.OwnershipSecondary,
		10, true,
		now, now,
		nil,
	)
}

// =============================================================================
// Tests for CreateScopeRule
// =============================================================================

func TestCreateScopeRule_SuccessTagMatch(t *testing.T) {
	tenantID := shared.NewID()
	g := makeScopeTestGroup(tenantID)

	acRepo := newMockACRepoForScope()
	groupRepo := newMockGroupRepoForScope()
	groupRepo.addGroup(g)

	svc := newTestScopeRuleService(acRepo, groupRepo)

	input := app.CreateScopeRuleInput{
		TenantID:      tenantID.String(),
		GroupID:       g.ID().String(),
		Name:          "Tag Match Rule",
		Description:   "Matches assets by tags",
		RuleType:      "tag_match",
		MatchTags:     []string{"production", "critical"},
		MatchLogic:    "any",
		OwnershipType: "primary",
		Priority:      5,
	}

	rule, err := svc.CreateScopeRule(context.Background(), input, shared.NewID().String())
	if err != nil {
		t.Fatalf("CreateScopeRule failed: %v", err)
	}

	if rule == nil {
		t.Fatal("expected non-nil rule")
	}
	if rule.Name() != "Tag Match Rule" {
		t.Errorf("expected name 'Tag Match Rule', got '%s'", rule.Name())
	}
	if rule.RuleType() != accesscontrol.ScopeRuleTagMatch {
		t.Errorf("expected rule type tag_match, got '%s'", rule.RuleType())
	}
	if len(rule.MatchTags()) != 2 {
		t.Errorf("expected 2 match tags, got %d", len(rule.MatchTags()))
	}
	if rule.OwnershipType() != accesscontrol.OwnershipPrimary {
		t.Errorf("expected ownership type primary, got '%s'", rule.OwnershipType())
	}
	if rule.Priority() != 5 {
		t.Errorf("expected priority 5, got %d", rule.Priority())
	}
	if !rule.IsActive() {
		t.Error("expected rule to be active by default")
	}

	if acRepo.createScopeRuleCalls != 1 {
		t.Errorf("expected 1 CreateScopeRule call, got %d", acRepo.createScopeRuleCalls)
	}
}

func TestCreateScopeRule_SuccessAssetGroupMatch(t *testing.T) {
	tenantID := shared.NewID()
	g := makeScopeTestGroup(tenantID)
	assetGroupID := shared.NewID()

	acRepo := newMockACRepoForScope()
	groupRepo := newMockGroupRepoForScope()
	groupRepo.addGroup(g)

	svc := newTestScopeRuleService(acRepo, groupRepo)

	input := app.CreateScopeRuleInput{
		TenantID:           tenantID.String(),
		GroupID:            g.ID().String(),
		Name:               "Asset Group Match Rule",
		RuleType:           "asset_group_match",
		MatchAssetGroupIDs: []string{assetGroupID.String()},
		OwnershipType:      "secondary",
	}

	rule, err := svc.CreateScopeRule(context.Background(), input, shared.NewID().String())
	if err != nil {
		t.Fatalf("CreateScopeRule failed: %v", err)
	}

	if rule == nil {
		t.Fatal("expected non-nil rule")
	}
	if rule.RuleType() != accesscontrol.ScopeRuleAssetGroupMatch {
		t.Errorf("expected rule type asset_group_match, got '%s'", rule.RuleType())
	}
	if len(rule.MatchAssetGroupIDs()) != 1 {
		t.Errorf("expected 1 match asset group ID, got %d", len(rule.MatchAssetGroupIDs()))
	}
	if rule.OwnershipType() != accesscontrol.OwnershipSecondary {
		t.Errorf("expected ownership type secondary, got '%s'", rule.OwnershipType())
	}
}

func TestCreateScopeRule_GroupNotFound(t *testing.T) {
	tenantID := shared.NewID()

	acRepo := newMockACRepoForScope()
	groupRepo := newMockGroupRepoForScope() // empty, no groups

	svc := newTestScopeRuleService(acRepo, groupRepo)

	input := app.CreateScopeRuleInput{
		TenantID:  tenantID.String(),
		GroupID:   shared.NewID().String(), // non-existent
		Name:      "Test Rule",
		RuleType:  "tag_match",
		MatchTags: []string{"env:prod"},
	}

	_, err := svc.CreateScopeRule(context.Background(), input, shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent group")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestCreateScopeRule_GroupBelongsToDifferentTenant(t *testing.T) {
	tenantA := shared.NewID()
	tenantB := shared.NewID()

	g := makeScopeTestGroup(tenantA) // group belongs to tenant A

	acRepo := newMockACRepoForScope()
	groupRepo := newMockGroupRepoForScope()
	groupRepo.addGroup(g)

	svc := newTestScopeRuleService(acRepo, groupRepo)

	input := app.CreateScopeRuleInput{
		TenantID:  tenantB.String(), // tenant B tries to use tenant A's group
		GroupID:   g.ID().String(),
		Name:      "Cross-Tenant Rule",
		RuleType:  "tag_match",
		MatchTags: []string{"env:prod"},
	}

	_, err := svc.CreateScopeRule(context.Background(), input, shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for cross-tenant group access")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestCreateScopeRule_InactiveGroupRejected(t *testing.T) {
	tenantID := shared.NewID()
	g := makeInactiveScopeTestGroup(tenantID)

	acRepo := newMockACRepoForScope()
	groupRepo := newMockGroupRepoForScope()
	groupRepo.addGroup(g)

	svc := newTestScopeRuleService(acRepo, groupRepo)

	input := app.CreateScopeRuleInput{
		TenantID:  tenantID.String(),
		GroupID:   g.ID().String(),
		Name:      "Rule For Inactive Group",
		RuleType:  "tag_match",
		MatchTags: []string{"env:prod"},
	}

	_, err := svc.CreateScopeRule(context.Background(), input, shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for inactive group")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestCreateScopeRule_ExceedsMaxRulesPerGroup(t *testing.T) {
	tenantID := shared.NewID()
	g := makeScopeTestGroup(tenantID)

	acRepo := newMockACRepoForScope()
	acRepo.countScopeRulesResult = int64(accesscontrol.MaxScopeRulesPerGroup) // already at max

	groupRepo := newMockGroupRepoForScope()
	groupRepo.addGroup(g)

	svc := newTestScopeRuleService(acRepo, groupRepo)

	input := app.CreateScopeRuleInput{
		TenantID:  tenantID.String(),
		GroupID:   g.ID().String(),
		Name:      "One Too Many",
		RuleType:  "tag_match",
		MatchTags: []string{"env:prod"},
	}

	_, err := svc.CreateScopeRule(context.Background(), input, shared.NewID().String())
	if err == nil {
		t.Fatal("expected error when max rules exceeded")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestCreateScopeRule_TagMatchWithoutTagsFails(t *testing.T) {
	tenantID := shared.NewID()
	g := makeScopeTestGroup(tenantID)

	acRepo := newMockACRepoForScope()
	groupRepo := newMockGroupRepoForScope()
	groupRepo.addGroup(g)

	svc := newTestScopeRuleService(acRepo, groupRepo)

	input := app.CreateScopeRuleInput{
		TenantID:  tenantID.String(),
		GroupID:   g.ID().String(),
		Name:      "Missing Tags",
		RuleType:  "tag_match",
		MatchTags: []string{}, // empty tags
	}

	_, err := svc.CreateScopeRule(context.Background(), input, shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for tag_match without tags")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestCreateScopeRule_AssetGroupMatchWithoutGroupIDsFails(t *testing.T) {
	tenantID := shared.NewID()
	g := makeScopeTestGroup(tenantID)

	acRepo := newMockACRepoForScope()
	groupRepo := newMockGroupRepoForScope()
	groupRepo.addGroup(g)

	svc := newTestScopeRuleService(acRepo, groupRepo)

	input := app.CreateScopeRuleInput{
		TenantID:           tenantID.String(),
		GroupID:            g.ID().String(),
		Name:               "Missing Group IDs",
		RuleType:           "asset_group_match",
		MatchAssetGroupIDs: []string{}, // empty group IDs
	}

	_, err := svc.CreateScopeRule(context.Background(), input, shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for asset_group_match without group IDs")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestCreateScopeRule_DefaultOwnershipTypeIsSecondary(t *testing.T) {
	tenantID := shared.NewID()
	g := makeScopeTestGroup(tenantID)

	acRepo := newMockACRepoForScope()
	groupRepo := newMockGroupRepoForScope()
	groupRepo.addGroup(g)

	svc := newTestScopeRuleService(acRepo, groupRepo)

	input := app.CreateScopeRuleInput{
		TenantID:  tenantID.String(),
		GroupID:   g.ID().String(),
		Name:      "Default Ownership",
		RuleType:  "tag_match",
		MatchTags: []string{"env:prod"},
		// OwnershipType not set
	}

	rule, err := svc.CreateScopeRule(context.Background(), input, shared.NewID().String())
	if err != nil {
		t.Fatalf("CreateScopeRule failed: %v", err)
	}

	if rule.OwnershipType() != accesscontrol.OwnershipSecondary {
		t.Errorf("expected default ownership type secondary, got '%s'", rule.OwnershipType())
	}
}

func TestCreateScopeRule_ReconciliationRunsOnCreate(t *testing.T) {
	tenantID := shared.NewID()
	g := makeScopeTestGroup(tenantID)
	matchingAssets := []shared.ID{shared.NewID(), shared.NewID(), shared.NewID()}

	acRepo := newMockACRepoForScope()
	acRepo.findAssetsByTagResult = matchingAssets

	groupRepo := newMockGroupRepoForScope()
	groupRepo.addGroup(g)

	svc := newTestScopeRuleService(acRepo, groupRepo)

	input := app.CreateScopeRuleInput{
		TenantID:  tenantID.String(),
		GroupID:   g.ID().String(),
		Name:      "Reconcile On Create",
		RuleType:  "tag_match",
		MatchTags: []string{"env:prod"},
	}

	_, err := svc.CreateScopeRule(context.Background(), input, shared.NewID().String())
	if err != nil {
		t.Fatalf("CreateScopeRule failed: %v", err)
	}

	// Should have called FindAssetsByTagMatch for reconciliation
	if acRepo.findAssetsByTagCalls != 1 {
		t.Errorf("expected 1 FindAssetsByTagMatch call, got %d", acRepo.findAssetsByTagCalls)
	}
	// Should have called BulkCreateAssetOwnersWithSource
	if acRepo.bulkCreateWithSourceCalls != 1 {
		t.Errorf("expected 1 BulkCreateAssetOwnersWithSource call, got %d", acRepo.bulkCreateWithSourceCalls)
	}
	// Should have refreshed access
	if acRepo.refreshAccessCalls != 1 {
		t.Errorf("expected 1 RefreshUserAccessibleAssets call, got %d", acRepo.refreshAccessCalls)
	}
}

// =============================================================================
// Tests for GetScopeRule
// =============================================================================

func TestGetScopeRule_Success(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()

	rule := makeExistingScopeRule(tenantID, groupID, accesscontrol.ScopeRuleTagMatch)

	acRepo := newMockACRepoForScope()
	acRepo.scopeRules[rule.ID()] = rule

	groupRepo := newMockGroupRepoForScope()
	svc := newTestScopeRuleService(acRepo, groupRepo)

	result, err := svc.GetScopeRule(context.Background(), tenantID.String(), rule.ID().String())
	if err != nil {
		t.Fatalf("GetScopeRule failed: %v", err)
	}

	if result.Name() != "Existing Rule" {
		t.Errorf("expected name 'Existing Rule', got '%s'", result.Name())
	}
	if result.ID() != rule.ID() {
		t.Errorf("expected ID %s, got %s", rule.ID(), result.ID())
	}
}

func TestGetScopeRule_NotFound(t *testing.T) {
	acRepo := newMockACRepoForScope()
	groupRepo := newMockGroupRepoForScope()
	svc := newTestScopeRuleService(acRepo, groupRepo)

	_, err := svc.GetScopeRule(context.Background(), shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent rule")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestGetScopeRule_InvalidTenantID(t *testing.T) {
	acRepo := newMockACRepoForScope()
	groupRepo := newMockGroupRepoForScope()
	svc := newTestScopeRuleService(acRepo, groupRepo)

	_, err := svc.GetScopeRule(context.Background(), "not-a-uuid", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestGetScopeRule_InvalidRuleID(t *testing.T) {
	acRepo := newMockACRepoForScope()
	groupRepo := newMockGroupRepoForScope()
	svc := newTestScopeRuleService(acRepo, groupRepo)

	_, err := svc.GetScopeRule(context.Background(), shared.NewID().String(), "not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid rule ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

// =============================================================================
// Tests for UpdateScopeRule
// =============================================================================

func TestUpdateScopeRule_SuccessNameChangeOnly(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()

	rule := makeExistingScopeRule(tenantID, groupID, accesscontrol.ScopeRuleTagMatch)

	acRepo := newMockACRepoForScope()
	acRepo.scopeRules[rule.ID()] = rule

	groupRepo := newMockGroupRepoForScope()
	svc := newTestScopeRuleService(acRepo, groupRepo)

	newName := "Updated Rule Name"
	input := app.UpdateScopeRuleInput{
		Name: &newName,
	}

	result, err := svc.UpdateScopeRule(context.Background(), tenantID.String(), rule.ID().String(), input)
	if err != nil {
		t.Fatalf("UpdateScopeRule failed: %v", err)
	}

	if result.Name() != "Updated Rule Name" {
		t.Errorf("expected name 'Updated Rule Name', got '%s'", result.Name())
	}

	// Name change only - no re-reconciliation needed
	if acRepo.findAssetsByTagCalls != 0 {
		t.Errorf("expected 0 FindAssetsByTagMatch calls for name-only change, got %d", acRepo.findAssetsByTagCalls)
	}
	if acRepo.refreshAccessCalls != 0 {
		t.Errorf("expected 0 refresh calls for name-only change, got %d", acRepo.refreshAccessCalls)
	}
}

func TestUpdateScopeRule_SuccessWithReReconciliation(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()

	rule := makeExistingScopeRule(tenantID, groupID, accesscontrol.ScopeRuleTagMatch)
	matchingAssets := []shared.ID{shared.NewID(), shared.NewID()}

	acRepo := newMockACRepoForScope()
	acRepo.scopeRules[rule.ID()] = rule
	acRepo.findAssetsByTagResult = matchingAssets

	groupRepo := newMockGroupRepoForScope()
	svc := newTestScopeRuleService(acRepo, groupRepo)

	newTags := []string{"new-tag-1", "new-tag-2"}
	input := app.UpdateScopeRuleInput{
		MatchTags: newTags,
	}

	result, err := svc.UpdateScopeRule(context.Background(), tenantID.String(), rule.ID().String(), input)
	if err != nil {
		t.Fatalf("UpdateScopeRule failed: %v", err)
	}

	if len(result.MatchTags()) != 2 {
		t.Errorf("expected 2 match tags, got %d", len(result.MatchTags()))
	}

	// Tag change triggers re-reconciliation
	if acRepo.findAssetsByTagCalls != 1 {
		t.Errorf("expected 1 FindAssetsByTagMatch call for tag change, got %d", acRepo.findAssetsByTagCalls)
	}
}

func TestUpdateScopeRule_DeactivateTriggersReconciliation(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()

	rule := makeExistingScopeRule(tenantID, groupID, accesscontrol.ScopeRuleTagMatch)

	acRepo := newMockACRepoForScope()
	acRepo.scopeRules[rule.ID()] = rule

	groupRepo := newMockGroupRepoForScope()
	svc := newTestScopeRuleService(acRepo, groupRepo)

	inactive := false
	input := app.UpdateScopeRuleInput{
		IsActive: &inactive,
	}

	result, err := svc.UpdateScopeRule(context.Background(), tenantID.String(), rule.ID().String(), input)
	if err != nil {
		t.Fatalf("UpdateScopeRule failed: %v", err)
	}

	if result.IsActive() {
		t.Error("expected rule to be deactivated")
	}

	// Deactivation changes matching but rule is now inactive,
	// so reconciliation runs but doesn't add assets (matchingChanged && rule.IsActive() is false)
	if acRepo.findAssetsByTagCalls != 0 {
		t.Errorf("expected 0 FindAssetsByTagMatch calls for deactivated rule, got %d", acRepo.findAssetsByTagCalls)
	}
}

func TestUpdateScopeRule_NotFound(t *testing.T) {
	acRepo := newMockACRepoForScope()
	groupRepo := newMockGroupRepoForScope()
	svc := newTestScopeRuleService(acRepo, groupRepo)

	newName := "Updated"
	input := app.UpdateScopeRuleInput{
		Name: &newName,
	}

	_, err := svc.UpdateScopeRule(context.Background(), shared.NewID().String(), shared.NewID().String(), input)
	if err == nil {
		t.Fatal("expected error for non-existent rule")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

// =============================================================================
// Tests for DeleteScopeRule
// =============================================================================

func TestDeleteScopeRule_Success(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()

	rule := makeExistingScopeRule(tenantID, groupID, accesscontrol.ScopeRuleTagMatch)

	acRepo := newMockACRepoForScope()
	acRepo.scopeRules[rule.ID()] = rule
	acRepo.deleteScopeRuleCleanupResult = 5 // 5 auto-assigned assets removed

	groupRepo := newMockGroupRepoForScope()
	svc := newTestScopeRuleService(acRepo, groupRepo)

	err := svc.DeleteScopeRule(context.Background(), tenantID.String(), rule.ID().String())
	if err != nil {
		t.Fatalf("DeleteScopeRule failed: %v", err)
	}

	if acRepo.deleteScopeRuleCleanupCalls != 1 {
		t.Errorf("expected 1 DeleteScopeRuleWithCleanup call, got %d", acRepo.deleteScopeRuleCleanupCalls)
	}
	// Since 5 assets were removed, access should be refreshed
	if acRepo.refreshAccessCalls != 1 {
		t.Errorf("expected 1 refresh call, got %d", acRepo.refreshAccessCalls)
	}
}

func TestDeleteScopeRule_SuccessNoAssetsRemoved(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()

	rule := makeExistingScopeRule(tenantID, groupID, accesscontrol.ScopeRuleTagMatch)

	acRepo := newMockACRepoForScope()
	acRepo.scopeRules[rule.ID()] = rule
	acRepo.deleteScopeRuleCleanupResult = 0 // no assets removed

	groupRepo := newMockGroupRepoForScope()
	svc := newTestScopeRuleService(acRepo, groupRepo)

	err := svc.DeleteScopeRule(context.Background(), tenantID.String(), rule.ID().String())
	if err != nil {
		t.Fatalf("DeleteScopeRule failed: %v", err)
	}

	// No assets removed, so no refresh
	if acRepo.refreshAccessCalls != 0 {
		t.Errorf("expected 0 refresh calls when no assets removed, got %d", acRepo.refreshAccessCalls)
	}
}

func TestDeleteScopeRule_NotFound(t *testing.T) {
	acRepo := newMockACRepoForScope()
	groupRepo := newMockGroupRepoForScope()
	svc := newTestScopeRuleService(acRepo, groupRepo)

	err := svc.DeleteScopeRule(context.Background(), shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent rule")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestDeleteScopeRule_InvalidIDs(t *testing.T) {
	acRepo := newMockACRepoForScope()
	groupRepo := newMockGroupRepoForScope()
	svc := newTestScopeRuleService(acRepo, groupRepo)

	err := svc.DeleteScopeRule(context.Background(), "not-a-uuid", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}

	err = svc.DeleteScopeRule(context.Background(), shared.NewID().String(), "not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid rule ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

// =============================================================================
// Tests for ListScopeRules
// =============================================================================

func TestListScopeRules_SuccessWithPagination(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()

	rules := []*accesscontrol.ScopeRule{
		makeExistingScopeRule(tenantID, groupID, accesscontrol.ScopeRuleTagMatch),
		makeExistingScopeRule(tenantID, groupID, accesscontrol.ScopeRuleAssetGroupMatch),
	}

	acRepo := newMockACRepoForScope()
	acRepo.listScopeRulesResult = rules
	acRepo.countScopeRulesResult = 2

	groupRepo := newMockGroupRepoForScope()
	svc := newTestScopeRuleService(acRepo, groupRepo)

	filter := accesscontrol.ScopeRuleFilter{
		Limit:  10,
		Offset: 0,
	}

	result, count, err := svc.ListScopeRules(context.Background(), tenantID.String(), groupID.String(), filter)
	if err != nil {
		t.Fatalf("ListScopeRules failed: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 rules, got %d", len(result))
	}
	if count != 2 {
		t.Errorf("expected count 2, got %d", count)
	}
}

func TestListScopeRules_DefaultLimit(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()

	acRepo := newMockACRepoForScope()
	groupRepo := newMockGroupRepoForScope()
	svc := newTestScopeRuleService(acRepo, groupRepo)

	// Limit = 0 should be defaulted to 50
	filter := accesscontrol.ScopeRuleFilter{
		Limit: 0,
	}

	_, _, err := svc.ListScopeRules(context.Background(), tenantID.String(), groupID.String(), filter)
	if err != nil {
		t.Fatalf("ListScopeRules failed: %v", err)
	}

	if acRepo.listScopeRulesCalls != 1 {
		t.Errorf("expected 1 list call, got %d", acRepo.listScopeRulesCalls)
	}
}

func TestListScopeRules_InvalidIDs(t *testing.T) {
	acRepo := newMockACRepoForScope()
	groupRepo := newMockGroupRepoForScope()
	svc := newTestScopeRuleService(acRepo, groupRepo)

	filter := accesscontrol.ScopeRuleFilter{Limit: 10}

	_, _, err := svc.ListScopeRules(context.Background(), "not-a-uuid", shared.NewID().String(), filter)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}

	_, _, err = svc.ListScopeRules(context.Background(), shared.NewID().String(), "not-a-uuid", filter)
	if err == nil {
		t.Fatal("expected error for invalid group ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

// =============================================================================
// Tests for PreviewScopeRule
// =============================================================================

func TestPreviewScopeRule_Success(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()

	rule := makeExistingScopeRule(tenantID, groupID, accesscontrol.ScopeRuleTagMatch)

	asset1 := shared.NewID()
	asset2 := shared.NewID()
	asset3 := shared.NewID()

	acRepo := newMockACRepoForScope()
	acRepo.scopeRules[rule.ID()] = rule
	acRepo.findAssetsByTagResult = []shared.ID{asset1, asset2, asset3}
	acRepo.listAssetsByGroupResult = []shared.ID{asset1} // asset1 already assigned

	groupRepo := newMockGroupRepoForScope()
	svc := newTestScopeRuleService(acRepo, groupRepo)

	result, err := svc.PreviewScopeRule(context.Background(), tenantID.String(), rule.ID().String())
	if err != nil {
		t.Fatalf("PreviewScopeRule failed: %v", err)
	}

	if result.MatchingAssets != 3 {
		t.Errorf("expected 3 matching assets, got %d", result.MatchingAssets)
	}
	if result.AlreadyAssigned != 1 {
		t.Errorf("expected 1 already assigned, got %d", result.AlreadyAssigned)
	}
	if result.WouldAdd != 2 {
		t.Errorf("expected 2 would add, got %d", result.WouldAdd)
	}
	if result.RuleName != "Existing Rule" {
		t.Errorf("expected rule name 'Existing Rule', got '%s'", result.RuleName)
	}
	if result.RuleID != rule.ID().String() {
		t.Errorf("expected rule ID %s, got '%s'", rule.ID(), result.RuleID)
	}
}

func TestPreviewScopeRule_AllAlreadyAssigned(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()

	rule := makeExistingScopeRule(tenantID, groupID, accesscontrol.ScopeRuleTagMatch)

	asset1 := shared.NewID()
	asset2 := shared.NewID()

	acRepo := newMockACRepoForScope()
	acRepo.scopeRules[rule.ID()] = rule
	acRepo.findAssetsByTagResult = []shared.ID{asset1, asset2}
	acRepo.listAssetsByGroupResult = []shared.ID{asset1, asset2} // all already assigned

	groupRepo := newMockGroupRepoForScope()
	svc := newTestScopeRuleService(acRepo, groupRepo)

	result, err := svc.PreviewScopeRule(context.Background(), tenantID.String(), rule.ID().String())
	if err != nil {
		t.Fatalf("PreviewScopeRule failed: %v", err)
	}

	if result.MatchingAssets != 2 {
		t.Errorf("expected 2 matching assets, got %d", result.MatchingAssets)
	}
	if result.AlreadyAssigned != 2 {
		t.Errorf("expected 2 already assigned, got %d", result.AlreadyAssigned)
	}
	if result.WouldAdd != 0 {
		t.Errorf("expected 0 would add, got %d", result.WouldAdd)
	}
}

func TestPreviewScopeRule_NotFound(t *testing.T) {
	acRepo := newMockACRepoForScope()
	groupRepo := newMockGroupRepoForScope()
	svc := newTestScopeRuleService(acRepo, groupRepo)

	_, err := svc.PreviewScopeRule(context.Background(), shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent rule")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

// =============================================================================
// Tests for ReconcileGroup
// =============================================================================

func TestReconcileGroup_SuccessWithMultipleRules(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()

	rule1 := makeExistingScopeRule(tenantID, groupID, accesscontrol.ScopeRuleTagMatch)
	rule2 := makeExistingScopeRule(tenantID, groupID, accesscontrol.ScopeRuleTagMatch)

	asset1 := shared.NewID()
	asset2 := shared.NewID()
	asset3 := shared.NewID()

	acRepo := newMockACRepoForScope()
	acRepo.listActiveScopeRulesResult = []*accesscontrol.ScopeRule{rule1, rule2}
	acRepo.findAssetsByTagResult = []shared.ID{asset1, asset2, asset3}
	// No existing assets assigned
	acRepo.listAssetsByGroupResult = nil
	// No stale auto-assigned assets
	acRepo.listAutoAssignedResult = nil

	groupRepo := newMockGroupRepoForScope()
	svc := newTestScopeRuleService(acRepo, groupRepo)

	result, err := svc.ReconcileGroup(context.Background(), tenantID.String(), groupID.String())
	if err != nil {
		t.Fatalf("ReconcileGroup failed: %v", err)
	}

	if result.RulesEvaluated != 2 {
		t.Errorf("expected 2 rules evaluated, got %d", result.RulesEvaluated)
	}
	// Both rules find 3 assets each, but since they both reconcile against the same existingSet,
	// each call should create 3 owners
	if result.AssetsAdded < 3 {
		t.Errorf("expected at least 3 assets added, got %d", result.AssetsAdded)
	}
}

func TestReconcileGroup_NoActiveRules(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()

	acRepo := newMockACRepoForScope()
	acRepo.listActiveScopeRulesResult = []*accesscontrol.ScopeRule{} // no active rules

	groupRepo := newMockGroupRepoForScope()
	svc := newTestScopeRuleService(acRepo, groupRepo)

	result, err := svc.ReconcileGroup(context.Background(), tenantID.String(), groupID.String())
	if err != nil {
		t.Fatalf("ReconcileGroup failed: %v", err)
	}

	if result.RulesEvaluated != 0 {
		t.Errorf("expected 0 rules evaluated, got %d", result.RulesEvaluated)
	}
	if result.AssetsAdded != 0 {
		t.Errorf("expected 0 assets added, got %d", result.AssetsAdded)
	}
	if result.AssetsRemoved != 0 {
		t.Errorf("expected 0 assets removed, got %d", result.AssetsRemoved)
	}

	// Should not refresh access when nothing changed
	if acRepo.refreshAccessCalls != 0 {
		t.Errorf("expected 0 refresh calls when nothing changed, got %d", acRepo.refreshAccessCalls)
	}
}

func TestReconcileGroup_RemovesStaleAssignments(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()

	rule := makeExistingScopeRule(tenantID, groupID, accesscontrol.ScopeRuleTagMatch)

	// Rule now matches only asset1
	asset1 := shared.NewID()
	// asset2 and asset3 were previously auto-assigned but no longer match
	asset2 := shared.NewID()
	asset3 := shared.NewID()

	acRepo := newMockACRepoForScope()
	acRepo.listActiveScopeRulesResult = []*accesscontrol.ScopeRule{rule}
	acRepo.findAssetsByTagResult = []shared.ID{asset1}                   // only asset1 matches now
	acRepo.listAssetsByGroupResult = []shared.ID{asset1, asset2, asset3} // all 3 currently assigned
	acRepo.listAutoAssignedResult = []shared.ID{asset1, asset2, asset3}  // all 3 auto-assigned
	acRepo.bulkDeleteAutoResult = 2

	groupRepo := newMockGroupRepoForScope()
	svc := newTestScopeRuleService(acRepo, groupRepo)

	result, err := svc.ReconcileGroup(context.Background(), tenantID.String(), groupID.String())
	if err != nil {
		t.Fatalf("ReconcileGroup failed: %v", err)
	}

	if result.AssetsRemoved != 2 {
		t.Errorf("expected 2 stale assets removed, got %d", result.AssetsRemoved)
	}
	if acRepo.bulkDeleteAutoCalls != 1 {
		t.Errorf("expected 1 BulkDeleteAutoAssignedForAssets call, got %d", acRepo.bulkDeleteAutoCalls)
	}
}

func TestReconcileGroup_InvalidIDs(t *testing.T) {
	acRepo := newMockACRepoForScope()
	groupRepo := newMockGroupRepoForScope()
	svc := newTestScopeRuleService(acRepo, groupRepo)

	_, err := svc.ReconcileGroup(context.Background(), "not-a-uuid", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}

	_, err = svc.ReconcileGroup(context.Background(), shared.NewID().String(), "not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid group ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestReconcileGroup_ListActiveRulesError(t *testing.T) {
	acRepo := newMockACRepoForScope()
	acRepo.listActiveScopeRulesErr = errors.New("database error")

	groupRepo := newMockGroupRepoForScope()
	svc := newTestScopeRuleService(acRepo, groupRepo)

	_, err := svc.ReconcileGroup(context.Background(), shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error when listing active rules fails")
	}
}

// =============================================================================
// Tests for ScopeRule Entity
// =============================================================================

func TestScopeRule_NewScopeRule_Success(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()
	createdBy := shared.NewID()

	rule, err := accesscontrol.NewScopeRule(tenantID, groupID, "Test Rule", accesscontrol.ScopeRuleTagMatch, &createdBy)
	if err != nil {
		t.Fatalf("NewScopeRule failed: %v", err)
	}

	if rule.TenantID() != tenantID {
		t.Errorf("expected tenant ID %s, got %s", tenantID, rule.TenantID())
	}
	if rule.GroupID() != groupID {
		t.Errorf("expected group ID %s, got %s", groupID, rule.GroupID())
	}
	if rule.Name() != "Test Rule" {
		t.Errorf("expected name 'Test Rule', got '%s'", rule.Name())
	}
	if rule.RuleType() != accesscontrol.ScopeRuleTagMatch {
		t.Errorf("expected type tag_match, got '%s'", rule.RuleType())
	}
	if !rule.IsActive() {
		t.Error("new rule should be active")
	}
	if rule.MatchLogic() != accesscontrol.MatchLogicAny {
		t.Errorf("default match logic should be 'any', got '%s'", rule.MatchLogic())
	}
	if rule.OwnershipType() != accesscontrol.OwnershipSecondary {
		t.Errorf("default ownership should be secondary, got '%s'", rule.OwnershipType())
	}
}

func TestScopeRule_NewScopeRule_InvalidRuleType(t *testing.T) {
	_, err := accesscontrol.NewScopeRule(shared.NewID(), shared.NewID(), "Test", accesscontrol.ScopeRuleType("invalid"), nil)
	if err == nil {
		t.Fatal("expected error for invalid rule type")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestScopeRule_SetMatchTags_WrongRuleType(t *testing.T) {
	rule, _ := accesscontrol.NewScopeRule(shared.NewID(), shared.NewID(), "Test", accesscontrol.ScopeRuleAssetGroupMatch, nil)

	err := rule.SetMatchTags([]string{"tag1"}, accesscontrol.MatchLogicAny)
	if err == nil {
		t.Fatal("expected error for setting tags on asset_group_match rule")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestScopeRule_SetMatchAssetGroupIDs_WrongRuleType(t *testing.T) {
	rule, _ := accesscontrol.NewScopeRule(shared.NewID(), shared.NewID(), "Test", accesscontrol.ScopeRuleTagMatch, nil)

	err := rule.SetMatchAssetGroupIDs([]shared.ID{shared.NewID()})
	if err == nil {
		t.Fatal("expected error for setting asset group IDs on tag_match rule")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}
