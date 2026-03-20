package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/infra/controller"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// =============================================================================
// Mocks for ScopeReconciliationController
// =============================================================================

// mockACRepoForController embeds the base stub and overrides the two methods
// used by the reconciliation controller.
type mockACRepoForController struct {
	mockAccessControlRepo // embed base stub

	tenantsResult []shared.ID
	tenantsErr    error
	tenantsCalls  int

	groupsResult map[string][]shared.ID // keyed by tenantID string
	groupsErr    error
	groupsCalls  int
}

func (m *mockACRepoForController) ListTenantsWithActiveScopeRules(_ context.Context) ([]shared.ID, error) {
	m.tenantsCalls++
	return m.tenantsResult, m.tenantsErr
}

func (m *mockACRepoForController) ListGroupsWithActiveScopeRules(_ context.Context, tenantID shared.ID) ([]shared.ID, error) {
	m.groupsCalls++
	if m.groupsErr != nil {
		return nil, m.groupsErr
	}
	return m.groupsResult[tenantID.String()], nil
}

// reconcileCall tracks a single reconciliation invocation.
type reconcileCall struct {
	tenantID shared.ID
	groupID  shared.ID
}

// mockScopeReconciler implements the scopeGroupReconciler interface.
type mockScopeReconciler struct {
	calls []reconcileCall
	err   error
	// failGroupIDs allows specific groups to fail while others succeed
	failGroupIDs map[string]bool
}

func (m *mockScopeReconciler) ReconcileGroupByIDs(_ context.Context, tenantID, groupID shared.ID) error {
	m.calls = append(m.calls, reconcileCall{tenantID: tenantID, groupID: groupID})
	if m.failGroupIDs != nil && m.failGroupIDs[groupID.String()] {
		return m.err
	}
	if m.failGroupIDs == nil && m.err != nil {
		return m.err
	}
	return nil
}

// =============================================================================
// Tests
// =============================================================================

func TestScopeReconciliation_Name(t *testing.T) {
	c := controller.NewScopeReconciliationController(
		&mockACRepoForController{},
		&mockScopeReconciler{},
		nil,
	)
	if c.Name() != "scope-reconciliation" {
		t.Errorf("expected name %q, got %q", "scope-reconciliation", c.Name())
	}
}

func TestScopeReconciliation_Interval(t *testing.T) {
	c := controller.NewScopeReconciliationController(
		&mockACRepoForController{},
		&mockScopeReconciler{},
		nil,
	)
	expected := 30 * time.Minute
	if c.Interval() != expected {
		t.Errorf("expected default interval %v, got %v", expected, c.Interval())
	}
}

func TestScopeReconciliation_CustomInterval(t *testing.T) {
	custom := 5 * time.Minute
	c := controller.NewScopeReconciliationController(
		&mockACRepoForController{},
		&mockScopeReconciler{},
		&controller.ScopeReconciliationControllerConfig{Interval: custom},
	)
	if c.Interval() != custom {
		t.Errorf("expected custom interval %v, got %v", custom, c.Interval())
	}
}

func TestScopeReconciliation_NoActiveRules(t *testing.T) {
	acRepo := &mockACRepoForController{
		tenantsResult: []shared.ID{}, // no tenants with active rules
	}
	reconciler := &mockScopeReconciler{}

	c := controller.NewScopeReconciliationController(acRepo, reconciler, &controller.ScopeReconciliationControllerConfig{
		Logger: logger.NewNop(),
	})

	count, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 groups reconciled, got %d", count)
	}
	if acRepo.tenantsCalls != 1 {
		t.Errorf("expected 1 ListTenantsWithActiveScopeRules call, got %d", acRepo.tenantsCalls)
	}
	if acRepo.groupsCalls != 0 {
		t.Errorf("expected 0 ListGroupsWithActiveScopeRules calls, got %d", acRepo.groupsCalls)
	}
	if len(reconciler.calls) != 0 {
		t.Errorf("expected 0 reconcile calls, got %d", len(reconciler.calls))
	}
}

func TestScopeReconciliation_SingleTenantSingleGroup(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()

	acRepo := &mockACRepoForController{
		tenantsResult: []shared.ID{tenantID},
		groupsResult: map[string][]shared.ID{
			tenantID.String(): {groupID},
		},
	}
	reconciler := &mockScopeReconciler{}

	c := controller.NewScopeReconciliationController(acRepo, reconciler, &controller.ScopeReconciliationControllerConfig{
		Logger: logger.NewNop(),
	})

	count, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 group reconciled, got %d", count)
	}
	if acRepo.tenantsCalls != 1 {
		t.Errorf("expected 1 ListTenantsWithActiveScopeRules call, got %d", acRepo.tenantsCalls)
	}
	if acRepo.groupsCalls != 1 {
		t.Errorf("expected 1 ListGroupsWithActiveScopeRules call, got %d", acRepo.groupsCalls)
	}
	if len(reconciler.calls) != 1 {
		t.Errorf("expected 1 reconcile call, got %d", len(reconciler.calls))
	}
	if len(reconciler.calls) == 1 {
		if reconciler.calls[0].tenantID != tenantID {
			t.Errorf("expected tenantID %s, got %s", tenantID, reconciler.calls[0].tenantID)
		}
		if reconciler.calls[0].groupID != groupID {
			t.Errorf("expected groupID %s, got %s", groupID, reconciler.calls[0].groupID)
		}
	}
}

func TestScopeReconciliation_MultiTenantMultiGroup(t *testing.T) {
	tenant1 := shared.NewID()
	tenant2 := shared.NewID()
	group1a := shared.NewID()
	group1b := shared.NewID()
	group2a := shared.NewID()

	acRepo := &mockACRepoForController{
		tenantsResult: []shared.ID{tenant1, tenant2},
		groupsResult: map[string][]shared.ID{
			tenant1.String(): {group1a, group1b},
			tenant2.String(): {group2a},
		},
	}
	reconciler := &mockScopeReconciler{}

	c := controller.NewScopeReconciliationController(acRepo, reconciler, &controller.ScopeReconciliationControllerConfig{
		Logger: logger.NewNop(),
	})

	count, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 groups reconciled, got %d", count)
	}
	if acRepo.tenantsCalls != 1 {
		t.Errorf("expected 1 ListTenantsWithActiveScopeRules call, got %d", acRepo.tenantsCalls)
	}
	if acRepo.groupsCalls != 2 {
		t.Errorf("expected 2 ListGroupsWithActiveScopeRules calls, got %d", acRepo.groupsCalls)
	}
	if len(reconciler.calls) != 3 {
		t.Errorf("expected 3 reconcile calls, got %d", len(reconciler.calls))
	}

	// Verify all expected (tenantID, groupID) pairs were reconciled
	expectedCalls := map[string]bool{
		tenant1.String() + ":" + group1a.String(): true,
		tenant1.String() + ":" + group1b.String(): true,
		tenant2.String() + ":" + group2a.String(): true,
	}
	for _, call := range reconciler.calls {
		key := call.tenantID.String() + ":" + call.groupID.String()
		if !expectedCalls[key] {
			t.Errorf("unexpected reconcile call: tenant=%s, group=%s", call.tenantID, call.groupID)
		}
		delete(expectedCalls, key)
	}
	for key := range expectedCalls {
		t.Errorf("missing expected reconcile call: %s", key)
	}
}

func TestScopeReconciliation_ListTenantsError(t *testing.T) {
	expectedErr := errors.New("database connection failed")
	acRepo := &mockACRepoForController{
		tenantsErr: expectedErr,
	}
	reconciler := &mockScopeReconciler{}

	c := controller.NewScopeReconciliationController(acRepo, reconciler, &controller.ScopeReconciliationControllerConfig{
		Logger: logger.NewNop(),
	})

	count, err := c.Reconcile(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
	if count != 0 {
		t.Errorf("expected 0 groups reconciled on error, got %d", count)
	}
	if len(reconciler.calls) != 0 {
		t.Errorf("expected 0 reconcile calls on error, got %d", len(reconciler.calls))
	}
}

func TestScopeReconciliation_ListGroupsError(t *testing.T) {
	tenant1 := shared.NewID()
	tenant2 := shared.NewID()
	group2a := shared.NewID()

	// Create a mock that fails for tenant1 but succeeds for tenant2
	acRepo := &mockACRepoForController{
		tenantsResult: []shared.ID{tenant1, tenant2},
		groupsResult: map[string][]shared.ID{
			// tenant1 has no entry => will use groupsErr
			tenant2.String(): {group2a},
		},
	}

	// We need a more nuanced mock that fails for specific tenants.
	// Override with a custom mock that tracks per-tenant errors.
	customACRepo := &mockACRepoForControllerWithPerTenantErr{
		mockACRepoForController: mockACRepoForController{
			tenantsResult: []shared.ID{tenant1, tenant2},
		},
		groupsByTenant: map[string]groupsResponse{
			tenant1.String(): {err: errors.New("tenant1 db error")},
			tenant2.String(): {ids: []shared.ID{group2a}},
		},
	}
	_ = acRepo // not used

	reconciler := &mockScopeReconciler{}

	c := controller.NewScopeReconciliationController(customACRepo, reconciler, &controller.ScopeReconciliationControllerConfig{
		Logger: logger.NewNop(),
	})

	count, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("expected no error (should continue past failed tenant), got %v", err)
	}
	// Only tenant2's group should be reconciled
	if count != 1 {
		t.Errorf("expected 1 group reconciled (skipping failed tenant), got %d", count)
	}
	if len(reconciler.calls) != 1 {
		t.Errorf("expected 1 reconcile call, got %d", len(reconciler.calls))
	}
	if len(reconciler.calls) == 1 {
		if reconciler.calls[0].tenantID != tenant2 {
			t.Errorf("expected reconcile call for tenant2 %s, got %s", tenant2, reconciler.calls[0].tenantID)
		}
		if reconciler.calls[0].groupID != group2a {
			t.Errorf("expected reconcile call for group %s, got %s", group2a, reconciler.calls[0].groupID)
		}
	}
}

func TestScopeReconciliation_ReconcileError(t *testing.T) {
	tenantID := shared.NewID()
	group1 := shared.NewID()
	group2 := shared.NewID()
	group3 := shared.NewID()

	acRepo := &mockACRepoForController{
		tenantsResult: []shared.ID{tenantID},
		groupsResult: map[string][]shared.ID{
			tenantID.String(): {group1, group2, group3},
		},
	}

	// group2 will fail, group1 and group3 should succeed
	reconciler := &mockScopeReconciler{
		err:          errors.New("reconciliation failed"),
		failGroupIDs: map[string]bool{group2.String(): true},
	}

	c := controller.NewScopeReconciliationController(acRepo, reconciler, &controller.ScopeReconciliationControllerConfig{
		Logger: logger.NewNop(),
	})

	count, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("expected no error (should continue past failed group), got %v", err)
	}
	// Only group1 and group3 should count as reconciled
	if count != 2 {
		t.Errorf("expected 2 groups reconciled (1 failed), got %d", count)
	}
	// All 3 groups should have been attempted
	if len(reconciler.calls) != 3 {
		t.Errorf("expected 3 reconcile attempts, got %d", len(reconciler.calls))
	}
}

// =============================================================================
// Helper mock for per-tenant ListGroupsWithActiveScopeRules errors
// =============================================================================

type groupsResponse struct {
	ids []shared.ID
	err error
}

type mockACRepoForControllerWithPerTenantErr struct {
	mockACRepoForController
	groupsByTenant map[string]groupsResponse
	groupsCalls    int
}

func (m *mockACRepoForControllerWithPerTenantErr) ListGroupsWithActiveScopeRules(_ context.Context, tenantID shared.ID) ([]shared.ID, error) {
	m.groupsCalls++
	resp, ok := m.groupsByTenant[tenantID.String()]
	if !ok {
		return nil, nil
	}
	return resp.ids, resp.err
}

func (m *mockACRepoForController) BatchListFindingGroupIDs(_ context.Context, _ shared.ID, _ []shared.ID) (map[shared.ID][]shared.ID, error) {
	return make(map[shared.ID][]shared.ID), nil
}

func (m *mockACRepoForControllerWithPerTenantErr) BatchListFindingGroupIDs(_ context.Context, _ shared.ID, _ []shared.ID) (map[shared.ID][]shared.ID, error) {
	return make(map[shared.ID][]shared.ID), nil
}
