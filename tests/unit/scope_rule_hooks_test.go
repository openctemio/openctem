package unit

import (
	"github.com/openctemio/api/internal/app/scope"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/accesscontrol"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// =============================================================================
// Mock AccessControl Repository for Hook Tests
// =============================================================================

// mockACRepoForHooks extends mockACRepoForScope with methods used by EvaluateAsset
// and ReconcileByAssetGroup.
type mockACRepoForHooks struct {
	mockACRepoForScope

	// ListActiveScopeRulesByTenant
	listActiveRulesByTenantResult []*accesscontrol.ScopeRule
	listActiveRulesByTenantErr    error
	listActiveRulesByTenantCalls  int

	// ListAutoAssignedGroupsForAsset
	listAutoGroupsForAssetResult []shared.ID
	listAutoGroupsForAssetErr    error
	listAutoGroupsForAssetCalls  int

	// DeleteAutoAssignedForAsset
	deleteAutoForAssetErr   error
	deleteAutoForAssetCalls int

	// ListGroupsWithAssetGroupMatchRule
	listGroupsWithMatchResult []shared.ID
	listGroupsWithMatchErr    error
	listGroupsWithMatchCalls  int
}

func newMockACRepoForHooks() *mockACRepoForHooks {
	return &mockACRepoForHooks{
		mockACRepoForScope: mockACRepoForScope{
			scopeRules: make(map[shared.ID]*accesscontrol.ScopeRule),
		},
	}
}

func (m *mockACRepoForHooks) ListActiveScopeRulesByTenant(_ context.Context, _ shared.ID) ([]*accesscontrol.ScopeRule, error) {
	m.listActiveRulesByTenantCalls++
	if m.listActiveRulesByTenantErr != nil {
		return nil, m.listActiveRulesByTenantErr
	}
	return m.listActiveRulesByTenantResult, nil
}

func (m *mockACRepoForHooks) ListAutoAssignedGroupsForAsset(_ context.Context, _ shared.ID) ([]shared.ID, error) {
	m.listAutoGroupsForAssetCalls++
	if m.listAutoGroupsForAssetErr != nil {
		return nil, m.listAutoGroupsForAssetErr
	}
	return m.listAutoGroupsForAssetResult, nil
}

func (m *mockACRepoForHooks) DeleteAutoAssignedForAsset(_ context.Context, _, _ shared.ID) error {
	m.deleteAutoForAssetCalls++
	return m.deleteAutoForAssetErr
}

func (m *mockACRepoForHooks) ListGroupsWithAssetGroupMatchRule(_ context.Context, _ shared.ID) ([]shared.ID, error) {
	m.listGroupsWithMatchCalls++
	if m.listGroupsWithMatchErr != nil {
		return nil, m.listGroupsWithMatchErr
	}
	return m.listGroupsWithMatchResult, nil
}

// =============================================================================
// Helpers
// =============================================================================

func makeActiveScopeRule(tenantID, groupID shared.ID, ruleType accesscontrol.ScopeRuleType, tags []string, matchGroupIDs []shared.ID) *accesscontrol.ScopeRule {
	now := time.Now().UTC()
	logic := accesscontrol.MatchLogicAny
	ownership := accesscontrol.OwnershipSecondary
	return accesscontrol.ReconstituteScopeRule(
		shared.NewID(), tenantID, groupID,
		"Hook Test Rule", "A rule for hook testing",
		ruleType,
		tags,
		logic,
		matchGroupIDs,
		ownership,
		10, true, // priority, isActive
		now, now,
		nil,
	)
}

// =============================================================================
// Tests for EvaluateAsset
// =============================================================================

func TestEvaluateAsset_NoActiveRules(t *testing.T) {
	acRepo := newMockACRepoForHooks()
	acRepo.listActiveRulesByTenantResult = nil // no rules
	acRepo.listAutoGroupsForAssetResult = nil  // no current auto-assignments

	groupRepo := newMockGroupRepoForScope()
	svc := scope.NewRuleService(acRepo, groupRepo, logger.NewNop())

	tenantID := shared.NewID()
	assetID := shared.NewID()

	err := svc.EvaluateAsset(context.Background(), tenantID, assetID, []string{"env:prod"}, nil)
	if err != nil {
		t.Fatalf("EvaluateAsset should return nil when no active rules, got: %v", err)
	}

	if acRepo.listActiveRulesByTenantCalls != 1 {
		t.Errorf("expected 1 ListActiveScopeRulesByTenant call, got %d", acRepo.listActiveRulesByTenantCalls)
	}
	// No rules and no auto-assignments means fast return, no bulk operations
	if acRepo.bulkCreateWithSourceCalls != 0 {
		t.Errorf("expected 0 BulkCreateAssetOwnersWithSource calls, got %d", acRepo.bulkCreateWithSourceCalls)
	}
}

func TestEvaluateAsset_TagMatch_SingleRule(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()
	assetID := shared.NewID()

	rule := makeActiveScopeRule(tenantID, groupID, accesscontrol.ScopeRuleTagMatch, []string{"env:prod"}, nil)

	acRepo := newMockACRepoForHooks()
	acRepo.listActiveRulesByTenantResult = []*accesscontrol.ScopeRule{rule}
	acRepo.listAutoGroupsForAssetResult = nil // no prior auto-assignments

	groupRepo := newMockGroupRepoForScope()
	svc := scope.NewRuleService(acRepo, groupRepo, logger.NewNop())

	// Asset has matching tag
	err := svc.EvaluateAsset(context.Background(), tenantID, assetID, []string{"env:prod", "team:alpha"}, nil)
	if err != nil {
		t.Fatalf("EvaluateAsset failed: %v", err)
	}

	// Should have created an auto-assignment via BulkCreateAssetOwnersWithSource
	if acRepo.bulkCreateWithSourceCalls != 1 {
		t.Errorf("expected 1 BulkCreateAssetOwnersWithSource call, got %d", acRepo.bulkCreateWithSourceCalls)
	}
	// Should have done incremental refresh for the single asset
	if acRepo.refreshAssetAssignCalls != 1 {
		t.Errorf("expected 1 RefreshAccessForAssetAssign call, got %d", acRepo.refreshAssetAssignCalls)
	}
}

func TestEvaluateAsset_TagMatch_NoMatch(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()
	assetID := shared.NewID()

	rule := makeActiveScopeRule(tenantID, groupID, accesscontrol.ScopeRuleTagMatch, []string{"env:staging"}, nil)

	acRepo := newMockACRepoForHooks()
	acRepo.listActiveRulesByTenantResult = []*accesscontrol.ScopeRule{rule}
	acRepo.listAutoGroupsForAssetResult = nil

	groupRepo := newMockGroupRepoForScope()
	svc := scope.NewRuleService(acRepo, groupRepo, logger.NewNop())

	// Asset does NOT have the required tag
	err := svc.EvaluateAsset(context.Background(), tenantID, assetID, []string{"env:prod"}, nil)
	if err != nil {
		t.Fatalf("EvaluateAsset failed: %v", err)
	}

	// No match means no auto-assignment created
	if acRepo.bulkCreateWithSourceCalls != 0 {
		t.Errorf("expected 0 BulkCreateAssetOwnersWithSource calls, got %d", acRepo.bulkCreateWithSourceCalls)
	}
	if acRepo.refreshAssetAssignCalls != 0 {
		t.Errorf("expected 0 RefreshAccessForAssetAssign calls, got %d", acRepo.refreshAssetAssignCalls)
	}
}

func TestEvaluateAsset_AssetGroupMatch(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()
	assetID := shared.NewID()
	assetGroupID := shared.NewID()

	rule := makeActiveScopeRule(tenantID, groupID, accesscontrol.ScopeRuleAssetGroupMatch, nil, []shared.ID{assetGroupID})

	acRepo := newMockACRepoForHooks()
	acRepo.listActiveRulesByTenantResult = []*accesscontrol.ScopeRule{rule}
	acRepo.listAutoGroupsForAssetResult = nil

	groupRepo := newMockGroupRepoForScope()
	svc := scope.NewRuleService(acRepo, groupRepo, logger.NewNop())

	// Asset is in the matching asset group
	err := svc.EvaluateAsset(context.Background(), tenantID, assetID, nil, []shared.ID{assetGroupID})
	if err != nil {
		t.Fatalf("EvaluateAsset failed: %v", err)
	}

	if acRepo.bulkCreateWithSourceCalls != 1 {
		t.Errorf("expected 1 BulkCreateAssetOwnersWithSource call, got %d", acRepo.bulkCreateWithSourceCalls)
	}
}

func TestEvaluateAsset_MultipleRulesMatch(t *testing.T) {
	tenantID := shared.NewID()
	groupA := shared.NewID()
	groupB := shared.NewID()
	assetID := shared.NewID()

	rule1 := makeActiveScopeRule(tenantID, groupA, accesscontrol.ScopeRuleTagMatch, []string{"env:prod"}, nil)
	rule2 := makeActiveScopeRule(tenantID, groupB, accesscontrol.ScopeRuleTagMatch, []string{"team:alpha"}, nil)

	acRepo := newMockACRepoForHooks()
	acRepo.listActiveRulesByTenantResult = []*accesscontrol.ScopeRule{rule1, rule2}
	acRepo.listAutoGroupsForAssetResult = nil

	groupRepo := newMockGroupRepoForScope()
	svc := scope.NewRuleService(acRepo, groupRepo, logger.NewNop())

	// Asset has both tags, so both rules match
	err := svc.EvaluateAsset(context.Background(), tenantID, assetID, []string{"env:prod", "team:alpha"}, nil)
	if err != nil {
		t.Fatalf("EvaluateAsset failed: %v", err)
	}

	// Two rules with different IDs means two bulk insert calls (one per rule)
	if acRepo.bulkCreateWithSourceCalls != 2 {
		t.Errorf("expected 2 BulkCreateAssetOwnersWithSource calls (one per rule), got %d", acRepo.bulkCreateWithSourceCalls)
	}
	// Incremental refresh for 2 groups
	if acRepo.refreshAssetAssignCalls != 2 {
		t.Errorf("expected 2 RefreshAccessForAssetAssign calls (one per group), got %d", acRepo.refreshAssetAssignCalls)
	}
}

func TestEvaluateAsset_StaleCleanup(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()
	assetID := shared.NewID()

	// Rule requires tag "env:staging" but asset no longer has it
	rule := makeActiveScopeRule(tenantID, groupID, accesscontrol.ScopeRuleTagMatch, []string{"env:staging"}, nil)

	acRepo := newMockACRepoForHooks()
	acRepo.listActiveRulesByTenantResult = []*accesscontrol.ScopeRule{rule}
	// Asset was previously auto-assigned to groupID
	acRepo.listAutoGroupsForAssetResult = []shared.ID{groupID}

	groupRepo := newMockGroupRepoForScope()
	svc := scope.NewRuleService(acRepo, groupRepo, logger.NewNop())

	// Asset now has different tags, no longer matches
	err := svc.EvaluateAsset(context.Background(), tenantID, assetID, []string{"env:prod"}, nil)
	if err != nil {
		t.Fatalf("EvaluateAsset failed: %v", err)
	}

	// Stale auto-assignment should be deleted
	if acRepo.deleteAutoForAssetCalls != 1 {
		t.Errorf("expected 1 DeleteAutoAssignedForAsset call for stale cleanup, got %d", acRepo.deleteAutoForAssetCalls)
	}
	// Incremental refresh for unassign
	if acRepo.refreshAssetUnassignCalls != 1 {
		t.Errorf("expected 1 RefreshAccessForAssetUnassign call, got %d", acRepo.refreshAssetUnassignCalls)
	}
	// No new assignments
	if acRepo.bulkCreateWithSourceCalls != 0 {
		t.Errorf("expected 0 BulkCreateAssetOwnersWithSource calls, got %d", acRepo.bulkCreateWithSourceCalls)
	}
}

func TestEvaluateAsset_NoStaleNoMatch(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()

	acRepo := newMockACRepoForHooks()
	acRepo.listActiveRulesByTenantResult = nil // no rules
	acRepo.listAutoGroupsForAssetResult = nil  // no current auto-assignments

	groupRepo := newMockGroupRepoForScope()
	svc := scope.NewRuleService(acRepo, groupRepo, logger.NewNop())

	err := svc.EvaluateAsset(context.Background(), tenantID, assetID, []string{"env:prod"}, nil)
	if err != nil {
		t.Fatalf("EvaluateAsset failed: %v", err)
	}

	// Fast return path: no rules, no auto-assignments
	if acRepo.bulkCreateWithSourceCalls != 0 {
		t.Errorf("expected 0 BulkCreateAssetOwnersWithSource calls, got %d", acRepo.bulkCreateWithSourceCalls)
	}
	if acRepo.deleteAutoForAssetCalls != 0 {
		t.Errorf("expected 0 DeleteAutoAssignedForAsset calls, got %d", acRepo.deleteAutoForAssetCalls)
	}
}

func TestEvaluateAsset_ListRulesError(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()

	acRepo := newMockACRepoForHooks()
	acRepo.listActiveRulesByTenantErr = errors.New("database connection lost")

	groupRepo := newMockGroupRepoForScope()
	svc := scope.NewRuleService(acRepo, groupRepo, logger.NewNop())

	err := svc.EvaluateAsset(context.Background(), tenantID, assetID, []string{"env:prod"}, nil)
	if err == nil {
		t.Fatal("expected error when listing rules fails")
	}

	// No downstream calls should be made
	if acRepo.bulkCreateWithSourceCalls != 0 {
		t.Errorf("expected 0 BulkCreateAssetOwnersWithSource calls, got %d", acRepo.bulkCreateWithSourceCalls)
	}
}

// =============================================================================
// Tests for ReconcileByAssetGroup
// =============================================================================

func TestReconcileByAssetGroup_NoReferencingRules(t *testing.T) {
	assetGroupID := shared.NewID()

	acRepo := newMockACRepoForHooks()
	acRepo.listGroupsWithMatchResult = nil // no groups reference this asset group

	groupRepo := newMockGroupRepoForScope()
	svc := scope.NewRuleService(acRepo, groupRepo, logger.NewNop())

	// Should be a no-op, no panic
	svc.ReconcileByAssetGroup(context.Background(), assetGroupID)

	if acRepo.listGroupsWithMatchCalls != 1 {
		t.Errorf("expected 1 ListGroupsWithAssetGroupMatchRule call, got %d", acRepo.listGroupsWithMatchCalls)
	}
	// No reconciliation should be triggered
	if acRepo.listActiveScopeRulesCalls != 0 {
		t.Errorf("expected 0 ListActiveScopeRulesByGroup calls, got %d", acRepo.listActiveScopeRulesCalls)
	}
}

func TestReconcileByAssetGroup_TriggersReconcile(t *testing.T) {
	tenantID := shared.NewID()
	targetGroupID := shared.NewID()
	assetGroupID := shared.NewID()

	// Create a rule that references the asset group
	rule := makeActiveScopeRule(tenantID, targetGroupID, accesscontrol.ScopeRuleAssetGroupMatch, nil, []shared.ID{assetGroupID})

	acRepo := newMockACRepoForHooks()
	// ListGroupsWithAssetGroupMatchRule returns the target group
	acRepo.listGroupsWithMatchResult = []shared.ID{targetGroupID}
	// ListActiveScopeRulesByGroup returns the rule (so ReconcileByAssetGroup can get tenantID)
	acRepo.listActiveScopeRulesResult = []*accesscontrol.ScopeRule{rule}
	// FindAssetsByAssetGroupMatch returns some matching assets
	matchedAsset := shared.NewID()
	acRepo.findAssetsByGroupResult = []shared.ID{matchedAsset}
	// No existing assets in the group
	acRepo.listAssetsByGroupResult = nil
	// No stale auto-assigned assets
	acRepo.listAutoAssignedResult = nil

	groupRepo := newMockGroupRepoForScope()
	svc := scope.NewRuleService(acRepo, groupRepo, logger.NewNop())

	svc.ReconcileByAssetGroup(context.Background(), assetGroupID)

	if acRepo.listGroupsWithMatchCalls != 1 {
		t.Errorf("expected 1 ListGroupsWithAssetGroupMatchRule call, got %d", acRepo.listGroupsWithMatchCalls)
	}
	// ListActiveScopeRulesByGroup should be called:
	// once by ReconcileByAssetGroup to get tenantID, once by ReconcileGroup
	if acRepo.listActiveScopeRulesCalls < 1 {
		t.Errorf("expected at least 1 ListActiveScopeRulesByGroup call, got %d", acRepo.listActiveScopeRulesCalls)
	}
	// Reconciliation should have triggered bulk create
	if acRepo.bulkCreateWithSourceCalls < 1 {
		t.Errorf("expected at least 1 BulkCreateAssetOwnersWithSource call, got %d", acRepo.bulkCreateWithSourceCalls)
	}
}

func TestReconcileByAssetGroup_ListError(t *testing.T) {
	assetGroupID := shared.NewID()

	acRepo := newMockACRepoForHooks()
	acRepo.listGroupsWithMatchErr = errors.New("database error")

	groupRepo := newMockGroupRepoForScope()
	svc := scope.NewRuleService(acRepo, groupRepo, logger.NewNop())

	// Should not panic, error is logged
	svc.ReconcileByAssetGroup(context.Background(), assetGroupID)

	if acRepo.listGroupsWithMatchCalls != 1 {
		t.Errorf("expected 1 ListGroupsWithAssetGroupMatchRule call, got %d", acRepo.listGroupsWithMatchCalls)
	}
	// No reconciliation should be triggered on error
	if acRepo.listActiveScopeRulesCalls != 0 {
		t.Errorf("expected 0 ListActiveScopeRulesByGroup calls after error, got %d", acRepo.listActiveScopeRulesCalls)
	}
}

func TestReconcileByAssetGroup_MultipleGroups(t *testing.T) {
	tenantID := shared.NewID()
	groupA := shared.NewID()
	groupB := shared.NewID()
	assetGroupID := shared.NewID()

	ruleA := makeActiveScopeRule(tenantID, groupA, accesscontrol.ScopeRuleAssetGroupMatch, nil, []shared.ID{assetGroupID})
	ruleB := makeActiveScopeRule(tenantID, groupB, accesscontrol.ScopeRuleAssetGroupMatch, nil, []shared.ID{assetGroupID})
	_ = ruleB // ruleB is used via listActiveScopeRulesResult

	acRepo := newMockACRepoForHooks()
	// Two groups reference this asset group
	acRepo.listGroupsWithMatchResult = []shared.ID{groupA, groupB}
	// ListActiveScopeRulesByGroup returns the rules in order
	// Since the mock returns the same result for all calls, both groups will get ruleA
	// which is fine for verifying the call count pattern
	acRepo.listActiveScopeRulesResult = []*accesscontrol.ScopeRule{ruleA}
	acRepo.findAssetsByGroupResult = []shared.ID{shared.NewID()}
	acRepo.listAssetsByGroupResult = nil
	acRepo.listAutoAssignedResult = nil

	groupRepo := newMockGroupRepoForScope()
	svc := scope.NewRuleService(acRepo, groupRepo, logger.NewNop())

	svc.ReconcileByAssetGroup(context.Background(), assetGroupID)

	if acRepo.listGroupsWithMatchCalls != 1 {
		t.Errorf("expected 1 ListGroupsWithAssetGroupMatchRule call, got %d", acRepo.listGroupsWithMatchCalls)
	}
	// ListActiveScopeRulesByGroup called for each group:
	// once by ReconcileByAssetGroup to get tenantID, once by ReconcileGroup = 2 per group
	// With 2 groups: at least 2 calls from ReconcileByAssetGroup + 2 from ReconcileGroup
	if acRepo.listActiveScopeRulesCalls < 2 {
		t.Errorf("expected at least 2 ListActiveScopeRulesByGroup calls for 2 groups, got %d", acRepo.listActiveScopeRulesCalls)
	}
}

// =============================================================================
// Tests for ReconcileGroupByIDs
// =============================================================================

func TestReconcileGroupByIDs_DelegatesToReconcileGroup(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()

	rule := makeActiveScopeRule(tenantID, groupID, accesscontrol.ScopeRuleTagMatch, []string{"env:prod"}, nil)

	acRepo := newMockACRepoForHooks()
	acRepo.listActiveScopeRulesResult = []*accesscontrol.ScopeRule{rule}
	acRepo.findAssetsByTagResult = []shared.ID{shared.NewID()}
	acRepo.listAssetsByGroupResult = nil
	acRepo.listAutoAssignedResult = nil

	groupRepo := newMockGroupRepoForScope()
	svc := scope.NewRuleService(acRepo, groupRepo, logger.NewNop())

	err := svc.ReconcileGroupByIDs(context.Background(), tenantID, groupID)
	if err != nil {
		t.Fatalf("ReconcileGroupByIDs failed: %v", err)
	}

	// Verify it delegated to ReconcileGroup (which calls ListActiveScopeRulesByGroup)
	if acRepo.listActiveScopeRulesCalls != 1 {
		t.Errorf("expected 1 ListActiveScopeRulesByGroup call (via ReconcileGroup), got %d", acRepo.listActiveScopeRulesCalls)
	}
	// Should have processed the rule and created assignments
	if acRepo.bulkCreateWithSourceCalls != 1 {
		t.Errorf("expected 1 BulkCreateAssetOwnersWithSource call, got %d", acRepo.bulkCreateWithSourceCalls)
	}
}

func (m *mockACRepoForHooks) BatchListFindingGroupIDs(_ context.Context, _ shared.ID, _ []shared.ID) (map[shared.ID][]shared.ID, error) {
	return make(map[shared.ID][]shared.ID), nil
}
