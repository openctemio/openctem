package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scope"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// =============================================================================
// Mock Repositories
// =============================================================================

type mockTargetRepo struct {
	targets     map[string]*scopedom.Target
	createErr   error
	updateErr   error
	deleteErr   error
	countResult int64
	countErr    error
}

func newMockTargetRepo() *mockTargetRepo {
	return &mockTargetRepo{targets: make(map[string]*scopedom.Target)}
}

func (m *mockTargetRepo) Create(_ context.Context, target *scopedom.Target) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.targets[target.ID().String()] = target
	return nil
}

func (m *mockTargetRepo) GetByID(_ context.Context, tenantID, id shared.ID) (*scopedom.Target, error) {
	t, ok := m.targets[id.String()]
	if !ok {
		return nil, scopedom.ErrTargetNotFound
	}
	if t.TenantID() != tenantID {
		return nil, scopedom.ErrTargetNotFound
	}
	return t, nil
}

func (m *mockTargetRepo) Update(_ context.Context, target *scopedom.Target) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.targets[target.ID().String()] = target
	return nil
}

func (m *mockTargetRepo) Delete(_ context.Context, tenantID, id shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	t, ok := m.targets[id.String()]
	if !ok || t.TenantID() != tenantID {
		return scopedom.ErrTargetNotFound
	}
	delete(m.targets, id.String())
	return nil
}

func (m *mockTargetRepo) List(_ context.Context, _ scopedom.TargetFilter, page pagination.Pagination) (pagination.Result[*scopedom.Target], error) {
	targets := make([]*scopedom.Target, 0, len(m.targets))
	for _, t := range m.targets {
		targets = append(targets, t)
	}
	total := int64(len(targets))
	return pagination.NewResult(targets, total, page), nil
}

func (m *mockTargetRepo) ListActive(_ context.Context, tenantID shared.ID) ([]*scopedom.Target, error) {
	var targets []*scopedom.Target
	for _, t := range m.targets {
		if t.TenantID() == tenantID && t.IsActive() {
			targets = append(targets, t)
		}
	}
	return targets, nil
}

func (m *mockTargetRepo) Count(_ context.Context, _ scopedom.TargetFilter) (int64, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	if m.countResult > 0 {
		return m.countResult, nil
	}
	return int64(len(m.targets)), nil
}

func (m *mockTargetRepo) ExistsByPattern(_ context.Context, tenantID shared.ID, targetType scopedom.TargetType, pattern string) (bool, error) {
	for _, t := range m.targets {
		if t.TenantID() == tenantID && t.TargetType() == targetType && t.Pattern() == pattern {
			return true, nil
		}
	}
	return false, nil
}

type mockExclusionRepo struct {
	exclusions map[string]*scopedom.Exclusion
	createErr  error
	updateErr  error
	deleteErr  error
}

func newMockExclusionRepo() *mockExclusionRepo {
	return &mockExclusionRepo{exclusions: make(map[string]*scopedom.Exclusion)}
}

func (m *mockExclusionRepo) Create(_ context.Context, exclusion *scopedom.Exclusion) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.exclusions[exclusion.ID().String()] = exclusion
	return nil
}

func (m *mockExclusionRepo) GetByID(_ context.Context, tenantID, id shared.ID) (*scopedom.Exclusion, error) {
	e, ok := m.exclusions[id.String()]
	if !ok {
		return nil, scopedom.ErrExclusionNotFound
	}
	if e.TenantID() != tenantID {
		return nil, scopedom.ErrExclusionNotFound
	}
	return e, nil
}

func (m *mockExclusionRepo) Update(_ context.Context, exclusion *scopedom.Exclusion) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.exclusions[exclusion.ID().String()] = exclusion
	return nil
}

func (m *mockExclusionRepo) Delete(_ context.Context, tenantID, id shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	e, ok := m.exclusions[id.String()]
	if !ok || e.TenantID() != tenantID {
		return scopedom.ErrExclusionNotFound
	}
	delete(m.exclusions, id.String())
	return nil
}

func (m *mockExclusionRepo) List(_ context.Context, _ scopedom.ExclusionFilter, page pagination.Pagination) (pagination.Result[*scopedom.Exclusion], error) {
	exclusions := make([]*scopedom.Exclusion, 0, len(m.exclusions))
	for _, e := range m.exclusions {
		exclusions = append(exclusions, e)
	}
	total := int64(len(exclusions))
	return pagination.NewResult(exclusions, total, page), nil
}

func (m *mockExclusionRepo) ListActive(_ context.Context, tenantID shared.ID) ([]*scopedom.Exclusion, error) {
	var exclusions []*scopedom.Exclusion
	for _, e := range m.exclusions {
		if e.TenantID() == tenantID && e.IsActive() {
			exclusions = append(exclusions, e)
		}
	}
	return exclusions, nil
}

func (m *mockExclusionRepo) Count(_ context.Context, _ scopedom.ExclusionFilter) (int64, error) {
	return int64(len(m.exclusions)), nil
}

func (m *mockExclusionRepo) ExpireOld(_ context.Context) error {
	return nil
}

// Minimal mock for asset.Repository - only used by coverage calculation.
type mockAssetRepo struct {
	assets   []*asset.Asset
	countVal int64
}

func newMockAssetRepo() *mockAssetRepo {
	return &mockAssetRepo{}
}

func (m *mockAssetRepo) Create(_ context.Context, _ *asset.Asset) error { return nil }
func (m *mockAssetRepo) GetDisplayInfoByIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]asset.DisplayInfo, error) {
	out := make(map[shared.ID]asset.DisplayInfo, len(ids))
	for _, id := range ids {
		a, err := m.GetByID(ctx, tenantID, id)
		if err != nil || a == nil {
			continue
		}
		out[id] = asset.DisplayInfo{ID: a.ID(), Name: a.Name(), Type: a.Type()}
	}
	return out, nil
}

func (m *mockAssetRepo) GetByID(_ context.Context, _, _ shared.ID) (*asset.Asset, error) {
	return nil, shared.ErrNotFound
}
func (m *mockAssetRepo) Update(_ context.Context, _ *asset.Asset) error               { return nil }
func (m *mockAssetRepo) Delete(_ context.Context, _, _ shared.ID, _ *shared.ID) error { return nil }
func (m *mockAssetRepo) List(_ context.Context, _ asset.Filter, _ asset.ListOptions, page pagination.Pagination) (pagination.Result[*asset.Asset], error) {
	total := int64(len(m.assets))
	return pagination.NewResult(m.assets, total, page), nil
}
func (m *mockAssetRepo) Count(_ context.Context, _ asset.Filter) (int64, error) {
	return m.countVal, nil
}
func (m *mockAssetRepo) ExistsByName(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}
func (m *mockAssetRepo) GetByExternalID(_ context.Context, _ shared.ID, _ asset.Provider, _ string) (*asset.Asset, error) {
	return nil, shared.ErrNotFound
}
func (m *mockAssetRepo) GetByName(_ context.Context, _ shared.ID, _ string) (*asset.Asset, error) {
	return nil, shared.ErrNotFound
}
func (m *mockAssetRepo) FindRepositoryByRepoName(_ context.Context, _ shared.ID, _ string) (*asset.Asset, error) {
	return nil, shared.ErrNotFound
}
func (m *mockAssetRepo) FindRepositoryByFullName(_ context.Context, _ shared.ID, _ string) (*asset.Asset, error) {
	return nil, shared.ErrNotFound
}

func (m *mockAssetRepo) FindByIP(_ context.Context, _ shared.ID, _ string) (*asset.Asset, error) {
	return nil, nil
}

func (m *mockAssetRepo) FindByHostname(_ context.Context, _ shared.ID, _ string) (*asset.Asset, error) {
	return nil, nil
}
func (m *mockAssetRepo) GetByNames(_ context.Context, _ shared.ID, _ []string) (map[string]*asset.Asset, error) {
	return nil, nil
}
func (m *mockAssetRepo) UpsertBatch(_ context.Context, _ []*asset.Asset) (int, int, map[string]shared.ID, error) {
	return 0, 0, nil, nil
}
func (m *mockAssetRepo) UpdateFindingCounts(_ context.Context, _ shared.ID, _ []shared.ID) error {
	return nil
}

func (m *mockAssetRepo) ListDistinctTags(_ context.Context, _ shared.ID, _ string, _ []string, _ int) ([]string, error) {
	return []string{}, nil
}

func (m *mockAssetRepo) GetAssetTypeBreakdown(_ context.Context, _ shared.ID) (map[string]asset.AssetTypeStats, error) {
	return make(map[string]asset.AssetTypeStats), nil
}

func (m *mockAssetRepo) GetAverageRiskScore(_ context.Context, _ shared.ID) (float64, error) {
	return 0, nil
}

func (m *mockAssetRepo) BatchUpdateRiskScores(_ context.Context, _ shared.ID, _ []*asset.Asset) error {
	return nil
}

func (m *mockAssetRepo) BulkUpdateStatus(_ context.Context, _ shared.ID, _ []shared.ID, _ asset.Status) (int64, error) {
	return 0, nil
}

func (m *mockAssetRepo) GetAggregateStats(_ context.Context, _ shared.ID, _ asset.AccessScope, _ []string, _ []string, _ string, _ ...string) (*asset.AggregateStats, error) {
	return &asset.AggregateStats{
		ByType:        make(map[string]int),
		ByStatus:      make(map[string]int),
		ByCriticality: make(map[string]int),
		ByScope:       make(map[string]int),
		ByExposure:    make(map[string]int),
	}, nil
}

func (m *mockAssetRepo) GetPropertyFacets(_ context.Context, _ shared.ID, _ asset.AccessScope, _ []string, _ string) ([]asset.PropertyFacet, error) {
	return nil, nil
}

func (m *mockAssetRepo) SetCrownJewel(_ context.Context, _, _ shared.ID, _ bool, _ float64, _ string) error {
	return nil
}

func (m *mockAssetRepo) ListAllNodes(_ context.Context, _ shared.ID) ([]asset.AssetNode, error) {
	return nil, nil
}

// =============================================================================
// Helpers
// =============================================================================

func newTestScopeService() (*scope.Service, *mockTargetRepo, *mockExclusionRepo, *mockAssetRepo) {
	tr := newMockTargetRepo()
	er := newMockExclusionRepo()
	ar := newMockAssetRepo()
	log := logger.NewDevelopment()
	svc := scope.NewService(tr, er, ar, log)
	// No user in the test context: a real gate passes system calls too.
	svc.SetStepUpGate(passGate{})
	return svc, tr, er, ar
}

// =============================================================================
// Target Service Tests
// =============================================================================

// TestScopeServiceCreateTarget tests target creation through the service layer.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceCreateTarget
func TestScopeServiceCreateTarget(t *testing.T) {
	tenantID := shared.NewID()

	t.Run("Success", func(t *testing.T) {
		svc, tr, _, _ := newTestScopeService()
		ctx := context.Background()

		target, err := svc.CreateTarget(ctx, scope.CreateTargetInput{
			TenantID:    tenantID.String(),
			TargetType:  "domain",
			Pattern:     "*.example.com",
			Description: "Test domain",
			Priority:    5,
			Tags:        []string{"web"},
			CreatedBy:   "user1",
		})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if target == nil {
			t.Fatal("expected non-nil target")
		}
		if target.Pattern() != "*.example.com" {
			t.Errorf("expected pattern *.example.com, got %s", target.Pattern())
		}
		if target.Priority() != 5 {
			t.Errorf("expected priority 5, got %d", target.Priority())
		}
		if len(target.Tags()) != 1 || target.Tags()[0] != "web" {
			t.Errorf("expected [web], got %v", target.Tags())
		}
		if len(tr.targets) != 1 {
			t.Errorf("expected 1 target in repo, got %d", len(tr.targets))
		}
	})

	t.Run("InvalidTenantID", func(t *testing.T) {
		svc, _, _, _ := newTestScopeService()
		_, err := svc.CreateTarget(context.Background(), scope.CreateTargetInput{
			TenantID:   "not-a-uuid",
			TargetType: "domain",
			Pattern:    "example.com",
		})
		if err == nil {
			t.Fatal("expected error for invalid tenant ID")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got: %v", err)
		}
	})

	t.Run("InvalidTargetType", func(t *testing.T) {
		svc, _, _, _ := newTestScopeService()
		_, err := svc.CreateTarget(context.Background(), scope.CreateTargetInput{
			TenantID:   tenantID.String(),
			TargetType: "invalid_type",
			Pattern:    "example.com",
		})
		if err == nil {
			t.Fatal("expected error for invalid target type")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got: %v", err)
		}
	})

	t.Run("DuplicatePattern", func(t *testing.T) {
		svc, _, _, _ := newTestScopeService()
		ctx := context.Background()

		_, err := svc.CreateTarget(ctx, scope.CreateTargetInput{
			TenantID:   tenantID.String(),
			TargetType: "domain",
			Pattern:    "example.com",
		})
		if err != nil {
			t.Fatalf("first create failed: %v", err)
		}

		_, err = svc.CreateTarget(ctx, scope.CreateTargetInput{
			TenantID:   tenantID.String(),
			TargetType: "domain",
			Pattern:    "example.com",
		})
		if err == nil {
			t.Fatal("expected error for duplicate pattern")
		}
		if !errors.Is(err, scopedom.ErrTargetAlreadyExists) {
			t.Errorf("expected ErrTargetAlreadyExists, got: %v", err)
		}
	})

	t.Run("RepoCreateError", func(t *testing.T) {
		svc, tr, _, _ := newTestScopeService()
		tr.createErr = errors.New("db connection lost")

		_, err := svc.CreateTarget(context.Background(), scope.CreateTargetInput{
			TenantID:   tenantID.String(),
			TargetType: "domain",
			Pattern:    "example.com",
		})
		if err == nil {
			t.Fatal("expected error from repo")
		}
	})
}

// TestScopeServiceGetTarget tests target retrieval.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceGetTarget
func TestScopeServiceGetTarget(t *testing.T) {
	svc, tr, _, _ := newTestScopeService()
	tenantID := shared.NewID()

	// Seed a target
	target, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "example.com", "", "user1")
	tr.targets[target.ID().String()] = target

	t.Run("Found", func(t *testing.T) {
		got, err := svc.GetTarget(context.Background(), tenantID.String(), target.ID().String())
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if got.ID() != target.ID() {
			t.Errorf("expected ID %s, got %s", target.ID(), got.ID())
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		_, err := svc.GetTarget(context.Background(), tenantID.String(), shared.NewID().String())
		if err == nil {
			t.Fatal("expected error for not found")
		}
		if !errors.Is(err, scopedom.ErrTargetNotFound) {
			t.Errorf("expected ErrTargetNotFound, got: %v", err)
		}
	})

	t.Run("InvalidID", func(t *testing.T) {
		_, err := svc.GetTarget(context.Background(), tenantID.String(), "not-a-uuid")
		if err == nil {
			t.Fatal("expected error for invalid ID")
		}
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got: %v", err)
		}
	})
}

// TestScopeServiceUpdateTarget tests target updates with tenant isolation.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceUpdateTarget
func TestScopeServiceUpdateTarget(t *testing.T) {
	tenantID := shared.NewID()
	otherTenantID := shared.NewID()

	t.Run("Success", func(t *testing.T) {
		svc, tr, _, _ := newTestScopeService()
		target, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "example.com", "orig", "user1")
		tr.targets[target.ID().String()] = target

		desc := "updated"
		priority := 8
		updated, err := svc.UpdateTarget(context.Background(), target.ID().String(), tenantID.String(), scope.UpdateTargetInput{
			Description: &desc,
			Priority:    &priority,
			Tags:        []string{"new-tag"},
		})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if updated.Description() != "updated" {
			t.Errorf("expected description 'updated', got %s", updated.Description())
		}
		if updated.Priority() != 8 {
			t.Errorf("expected priority 8, got %d", updated.Priority())
		}
		if len(updated.Tags()) != 1 || updated.Tags()[0] != "new-tag" {
			t.Errorf("expected [new-tag], got %v", updated.Tags())
		}
	})

	t.Run("WrongTenant", func(t *testing.T) {
		svc, tr, _, _ := newTestScopeService()
		target, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "example.com", "", "user1")
		tr.targets[target.ID().String()] = target

		desc := "hacked"
		_, err := svc.UpdateTarget(context.Background(), target.ID().String(), otherTenantID.String(), scope.UpdateTargetInput{
			Description: &desc,
		})
		if err == nil {
			t.Fatal("expected error for wrong tenant")
		}
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got: %v", err)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		svc, _, _, _ := newTestScopeService()
		desc := "test"
		_, err := svc.UpdateTarget(context.Background(), shared.NewID().String(), tenantID.String(), scope.UpdateTargetInput{
			Description: &desc,
		})
		if err == nil {
			t.Fatal("expected error for not found")
		}
	})
}

// TestScopeServiceDeleteTarget tests target deletion with tenant isolation.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceDeleteTarget
func TestScopeServiceDeleteTarget(t *testing.T) {
	tenantID := shared.NewID()
	otherTenantID := shared.NewID()

	t.Run("Success", func(t *testing.T) {
		svc, tr, _, _ := newTestScopeService()
		target, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "example.com", "", "user1")
		tr.targets[target.ID().String()] = target

		err := svc.DeleteTarget(context.Background(), target.ID().String(), tenantID.String())
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if len(tr.targets) != 0 {
			t.Errorf("expected 0 targets, got %d", len(tr.targets))
		}
	})

	t.Run("WrongTenant", func(t *testing.T) {
		svc, tr, _, _ := newTestScopeService()
		target, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "example.com", "", "user1")
		tr.targets[target.ID().String()] = target

		err := svc.DeleteTarget(context.Background(), target.ID().String(), otherTenantID.String())
		if err == nil {
			t.Fatal("expected error for wrong tenant")
		}
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got: %v", err)
		}
		// Target should still exist
		if len(tr.targets) != 1 {
			t.Errorf("target should not be deleted")
		}
	})
}

// TestScopeServiceActivateDeactivateTarget tests target status changes.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceActivateDeactivateTarget
func TestScopeServiceActivateDeactivateTarget(t *testing.T) {
	svc, tr, _, _ := newTestScopeService()
	tenantID := shared.NewID()
	target, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "example.com", "", "user1")
	tr.targets[target.ID().String()] = target

	t.Run("Deactivate", func(t *testing.T) {
		result, err := svc.DeactivateTarget(context.Background(), target.ID().String(), tenantID.String())
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if result.Status() != scopedom.StatusInactive {
			t.Errorf("expected inactive, got %s", result.Status())
		}
	})

	t.Run("Activate", func(t *testing.T) {
		result, err := svc.ActivateTarget(context.Background(), target.ID().String(), tenantID.String(), scope.Actor{})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if result.Status() != scopedom.StatusActive {
			t.Errorf("expected active, got %s", result.Status())
		}
	})

	t.Run("ActivateNotFound", func(t *testing.T) {
		_, err := svc.ActivateTarget(context.Background(), shared.NewID().String(), tenantID.String(), scope.Actor{})
		if err == nil {
			t.Fatal("expected error for not found")
		}
	})
}

// =============================================================================
// Exclusion Service Tests
// =============================================================================

// TestScopeServiceCreateExclusion tests exclusion creation.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceCreateExclusion
func TestScopeServiceCreateExclusion(t *testing.T) {
	tenantID := shared.NewID()

	t.Run("Success", func(t *testing.T) {
		svc, _, er, _ := newTestScopeService()
		exclusion, err := svc.CreateExclusion(context.Background(), scope.CreateExclusionInput{
			TenantID:      tenantID.String(),
			ExclusionType: "domain",
			Pattern:       "internal.example.com",
			Reason:        "Internal only",
			CreatedBy:     "user1",
		})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if exclusion.Pattern() != "internal.example.com" {
			t.Errorf("expected pattern internal.example.com, got %s", exclusion.Pattern())
		}
		if exclusion.Reason() != "Internal only" {
			t.Errorf("expected reason 'Internal only', got %s", exclusion.Reason())
		}
		if len(er.exclusions) != 1 {
			t.Errorf("expected 1 exclusion in repo, got %d", len(er.exclusions))
		}
	})

	t.Run("WithExpiration", func(t *testing.T) {
		svc, _, _, _ := newTestScopeService()
		future := time.Now().Add(24 * time.Hour)
		exclusion, err := svc.CreateExclusion(context.Background(), scope.CreateExclusionInput{
			TenantID:      tenantID.String(),
			ExclusionType: "cidr",
			Pattern:       "10.0.0.0/8",
			Reason:        "Temporary exclusion",
			ExpiresAt:     &future,
		})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if exclusion.ExpiresAt() == nil {
			t.Error("expected non-nil ExpiresAt")
		}
	})

	t.Run("InvalidTenantID", func(t *testing.T) {
		svc, _, _, _ := newTestScopeService()
		_, err := svc.CreateExclusion(context.Background(), scope.CreateExclusionInput{
			TenantID:      "invalid",
			ExclusionType: "domain",
			Pattern:       "test.com",
			Reason:        "reason",
		})
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got: %v", err)
		}
	})

	t.Run("InvalidExclusionType", func(t *testing.T) {
		svc, _, _, _ := newTestScopeService()
		_, err := svc.CreateExclusion(context.Background(), scope.CreateExclusionInput{
			TenantID:      tenantID.String(),
			ExclusionType: "invalid",
			Pattern:       "test.com",
			Reason:        "reason",
		})
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got: %v", err)
		}
	})

	t.Run("EmptyReason", func(t *testing.T) {
		svc, _, _, _ := newTestScopeService()
		_, err := svc.CreateExclusion(context.Background(), scope.CreateExclusionInput{
			TenantID:      tenantID.String(),
			ExclusionType: "domain",
			Pattern:       "test.com",
			Reason:        "",
		})
		if err == nil {
			t.Fatal("expected error for empty reason")
		}
	})
}

// TestScopeServiceUpdateExclusion tests exclusion updates with tenant isolation.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceUpdateExclusion
func TestScopeServiceUpdateExclusion(t *testing.T) {
	tenantID := shared.NewID()
	otherTenantID := shared.NewID()

	t.Run("Success", func(t *testing.T) {
		svc, _, er, _ := newTestScopeService()
		exc, _ := scopedom.NewExclusion(tenantID, scopedom.ExclusionTypeDomain, "test.com", "orig", nil, "user1")
		er.exclusions[exc.ID().String()] = exc

		reason := "updated reason"
		updated, err := svc.UpdateExclusion(context.Background(), exc.ID().String(), tenantID.String(), scope.UpdateExclusionInput{
			Reason: &reason,
		})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if updated.Reason() != "updated reason" {
			t.Errorf("expected 'updated reason', got %s", updated.Reason())
		}
	})

	t.Run("WrongTenant", func(t *testing.T) {
		svc, _, er, _ := newTestScopeService()
		exc, _ := scopedom.NewExclusion(tenantID, scopedom.ExclusionTypeDomain, "test.com", "orig", nil, "user1")
		er.exclusions[exc.ID().String()] = exc

		reason := "hacked"
		_, err := svc.UpdateExclusion(context.Background(), exc.ID().String(), otherTenantID.String(), scope.UpdateExclusionInput{
			Reason: &reason,
		})
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got: %v", err)
		}
	})
}

// TestScopeServiceApproveExclusion tests exclusion approval flow.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceApproveExclusion
func TestScopeServiceApproveExclusion(t *testing.T) {
	svc, _, er, _ := newTestScopeService()
	tenantID := shared.NewID()
	exc, _ := scopedom.NewExclusion(tenantID, scopedom.ExclusionTypeDomain, "test.com", "reason", nil, "user1")
	er.exclusions[exc.ID().String()] = exc

	t.Run("Approve", func(t *testing.T) {
		approved, err := svc.ApproveExclusion(context.Background(), exc.ID().String(), tenantID.String(), "admin1")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if !approved.IsApproved() {
			t.Error("expected approved")
		}
		if approved.ApprovedBy() != "admin1" {
			t.Errorf("expected approved by admin1, got %s", approved.ApprovedBy())
		}
	})

	t.Run("ApproveNotFound", func(t *testing.T) {
		_, err := svc.ApproveExclusion(context.Background(), shared.NewID().String(), tenantID.String(), "admin1")
		if err == nil {
			t.Fatal("expected error for not found")
		}
	})
}

// The user who requested a scope exclusion cannot approve it themselves
// (separation of duties, as for finding status approvals).
func TestScopeServiceApproveExclusion_RequesterCannotSelfApprove(t *testing.T) {
	svc, _, er, _ := newTestScopeService()
	tenantID := shared.NewID()
	requester := shared.NewID().String()
	exc, _ := scopedom.NewExclusion(tenantID, scopedom.ExclusionTypeDomain, "prod.example.com", "maintenance window", nil, requester)
	er.exclusions[exc.ID().String()] = exc

	_, err := svc.ApproveExclusion(context.Background(), exc.ID().String(), tenantID.String(), requester)
	if !errors.Is(err, scopedom.ErrExclusionSelfApproval) || !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("self-approval: got %v, want ErrExclusionSelfApproval (forbidden)", err)
	}
	if er.exclusions[exc.ID().String()].IsApproved() {
		t.Fatal("exclusion marked approved after a refused self-approval")
	}

	other := shared.NewID().String()
	approved, err := svc.ApproveExclusion(context.Background(), exc.ID().String(), tenantID.String(), other)
	if err != nil {
		t.Fatalf("approval by another user: %v", err)
	}
	if approved.ApprovedBy() != other {
		t.Fatalf("approved by %q, want %q", approved.ApprovedBy(), other)
	}

	if _, err := svc.ApproveExclusion(context.Background(), exc.ID().String(), tenantID.String(), ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("approval without an approver: got %v, want a validation error", err)
	}
}

// A new exclusion is a request. Until someone other than the requester
// approves it, it suppresses nothing: not scan target selection, not scope
// checks. Approval puts it into effect; a rejected one never takes effect.
func TestScopeServiceExclusion_PendingUntilApproved(t *testing.T) {
	ctx := context.Background()
	svc, tr, _, _ := newTestScopeService()
	tenantID := shared.NewID()
	target, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "*.example.com", "", "user1")
	tr.targets[target.ID().String()] = target
	assetID := shared.NewID()
	candidates := []scope.ExclusionCandidate{{ID: assetID, Values: []string{"prod.example.com"}}}

	excluded := func(t *testing.T) bool {
		t.Helper()
		set, err := svc.ExcludedTargets(ctx, tenantID.String(), candidates)
		if err != nil {
			t.Fatalf("ExcludedTargets: %v", err)
		}
		res, err := svc.CheckScope(ctx, tenantID.String(), "domain", "prod.example.com")
		if err != nil {
			t.Fatalf("CheckScope: %v", err)
		}
		if set[assetID] != res.Excluded {
			t.Fatalf("scan filter (%v) and scope check (%v) disagree", set[assetID], res.Excluded)
		}
		if fe := svc.FilterExcludedTargets(ctx, tenantID.String(), candidates); fe[assetID] != set[assetID] {
			t.Fatalf("FilterExcludedTargets (%v) and ExcludedTargets (%v) disagree", fe[assetID], set[assetID])
		}
		return set[assetID]
	}

	member := shared.NewID().String()
	exc, err := svc.CreateExclusion(ctx, scope.CreateExclusionInput{
		TenantID: tenantID.String(), ExclusionType: "domain", Pattern: "prod.example.com",
		Reason: "noisy", CreatedBy: member,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if exc.Status() != scopedom.StatusPending || exc.IsApproved() {
		t.Fatalf("new exclusion: status %s approved %v, want pending and unapproved", exc.Status(), exc.IsApproved())
	}
	if excluded(t) {
		t.Fatal("a pending exclusion suppressed scanning")
	}
	if active, _ := svc.ListActiveExclusions(ctx, tenantID.String()); len(active) != 0 {
		t.Fatalf("ListActiveExclusions returned %d pending exclusions", len(active))
	}

	// The requester cannot approve their own exclusion.
	if _, err := svc.ApproveExclusion(ctx, exc.ID().String(), tenantID.String(), member); !errors.Is(err, scopedom.ErrExclusionSelfApproval) {
		t.Fatalf("self-approval: got %v", err)
	}
	if excluded(t) {
		t.Fatal("a refused self-approval put the exclusion into effect")
	}

	admin := shared.NewID().String()
	if _, err := svc.ApproveExclusion(ctx, exc.ID().String(), tenantID.String(), admin); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if !excluded(t) {
		t.Fatal("an approved exclusion is not applied")
	}
	if _, err := svc.ApproveExclusion(ctx, exc.ID().String(), tenantID.String(), admin); !errors.Is(err, scopedom.ErrExclusionNotPending) {
		t.Fatalf("second approval: got %v, want ErrExclusionNotPending", err)
	}
	if _, err := svc.RejectExclusion(ctx, exc.ID().String(), tenantID.String(), admin); !errors.Is(err, scopedom.ErrExclusionNotPending) {
		t.Fatalf("reject an approved exclusion: got %v, want ErrExclusionNotPending", err)
	}
}

func TestScopeServiceExclusion_RejectedNeverApplies(t *testing.T) {
	ctx := context.Background()
	svc, _, er, _ := newTestScopeService()
	tenantID := shared.NewID()
	exc, _ := scopedom.NewExclusion(tenantID, scopedom.ExclusionTypeDomain, "prod.example.com", "noisy", nil, "member1")
	er.exclusions[exc.ID().String()] = exc
	candidates := []scope.ExclusionCandidate{{ID: shared.NewID(), Values: []string{"prod.example.com"}}}

	rejected, err := svc.RejectExclusion(ctx, exc.ID().String(), tenantID.String(), "admin1")
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if rejected.Status() != scopedom.StatusRejected || rejected.RejectedBy() != "admin1" || rejected.RejectedAt() == nil {
		t.Fatalf("rejected: status %s by %q at %v", rejected.Status(), rejected.RejectedBy(), rejected.RejectedAt())
	}
	id, tid := exc.ID().String(), tenantID.String()
	for name, try := range map[string]func() error{
		"approve": func() error {
			_, err := svc.ApproveExclusion(ctx, id, tid, "admin2")
			return err
		},
		"activate": func() error {
			_, err := svc.ActivateExclusion(ctx, id, tid)
			return err
		},
		"deactivate": func() error {
			_, err := svc.DeactivateExclusion(ctx, id, tid, exclusionApprover)
			return err
		},
		"reject": func() error {
			_, err := svc.RejectExclusion(ctx, id, tid, "admin2")
			return err
		},
	} {
		if err := try(); err == nil || !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("%s a rejected exclusion: got %v, want a conflict", name, err)
		}
	}
	set, err := svc.ExcludedTargets(ctx, tenantID.String(), candidates)
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 0 {
		t.Fatal("a rejected exclusion suppressed scanning")
	}
}

// An approval covers the window that was approved: extending it with
// scope:write alone sends the exclusion back for review.
func TestScopeServiceExclusion_ExtendingAnApprovedWindowNeedsReapproval(t *testing.T) {
	ctx := context.Background()
	svc, _, er, _ := newTestScopeService()
	tenantID := shared.NewID()
	week := time.Now().Add(7 * 24 * time.Hour)
	exc, _ := scopedom.NewExclusion(tenantID, scopedom.ExclusionTypeDomain, "prod.example.com", "window", &week, "member1")
	_ = exc.Approve("admin1")
	er.exclusions[exc.ID().String()] = exc

	day := time.Now().Add(24 * time.Hour)
	got, err := svc.UpdateExclusion(ctx, exc.ID().String(), tenantID.String(), scope.UpdateExclusionInput{ExpiresAt: &day, Reviewer: exclusionApprover})
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsActive() {
		t.Fatal("shortening an approved window dropped the approval")
	}

	year := time.Now().Add(365 * 24 * time.Hour)
	got, err = svc.UpdateExclusion(ctx, exc.ID().String(), tenantID.String(), scope.UpdateExclusionInput{ExpiresAt: &year})
	if err != nil {
		t.Fatal(err)
	}
	if got.IsActive() || got.IsApproved() || got.Status() != scopedom.StatusPending {
		t.Fatalf("extended window: status %s approved %v, want pending and unapproved", got.Status(), got.IsApproved())
	}
}

// TestScopeServiceActivateDeactivateExclusion tests exclusion status changes.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceActivateDeactivateExclusion
func TestScopeServiceActivateDeactivateExclusion(t *testing.T) {
	svc, _, er, _ := newTestScopeService()
	tenantID := shared.NewID()
	exc, _ := scopedom.NewExclusion(tenantID, scopedom.ExclusionTypeDomain, "test.com", "reason", nil, "user1")
	er.exclusions[exc.ID().String()] = exc

	t.Run("PendingCannotBeActivated", func(t *testing.T) {
		_, err := svc.ActivateExclusion(context.Background(), exc.ID().String(), tenantID.String())
		if !errors.Is(err, scopedom.ErrExclusionNotApproved) {
			t.Fatalf("activate pending: got %v, want ErrExclusionNotApproved", err)
		}
		if exc.Status() != scopedom.StatusPending {
			t.Fatalf("status = %s, want pending", exc.Status())
		}
	})

	if err := exc.Approve("admin1"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	t.Run("Deactivate", func(t *testing.T) {
		result, err := svc.DeactivateExclusion(context.Background(), exc.ID().String(), tenantID.String(), exclusionApprover)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if result.Status() != scopedom.StatusInactive {
			t.Errorf("expected inactive, got %s", result.Status())
		}
	})

	t.Run("Activate", func(t *testing.T) {
		result, err := svc.ActivateExclusion(context.Background(), exc.ID().String(), tenantID.String())
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if result.Status() != scopedom.StatusActive {
			t.Errorf("expected active, got %s", result.Status())
		}
	})
}

// TestScopeServiceDeleteExclusion tests exclusion deletion with tenant isolation.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceDeleteExclusion
func TestScopeServiceDeleteExclusion(t *testing.T) {
	tenantID := shared.NewID()

	t.Run("Success", func(t *testing.T) {
		svc, _, er, _ := newTestScopeService()
		exc, _ := scopedom.NewExclusion(tenantID, scopedom.ExclusionTypeDomain, "test.com", "reason", nil, "user1")
		er.exclusions[exc.ID().String()] = exc

		err := svc.DeleteExclusion(context.Background(), exc.ID().String(), tenantID.String(), exclusionApprover)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if len(er.exclusions) != 0 {
			t.Errorf("expected 0 exclusions, got %d", len(er.exclusions))
		}
	})

	t.Run("WrongTenant", func(t *testing.T) {
		svc, _, er, _ := newTestScopeService()
		exc, _ := scopedom.NewExclusion(tenantID, scopedom.ExclusionTypeDomain, "test.com", "reason", nil, "user1")
		er.exclusions[exc.ID().String()] = exc

		err := svc.DeleteExclusion(context.Background(), exc.ID().String(), shared.NewID().String(), exclusionApprover)
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got: %v", err)
		}
		if len(er.exclusions) != 1 {
			t.Error("exclusion should not be deleted")
		}
	})
}

// =============================================================================
// CheckScope Tests
// =============================================================================

// TestScopeServiceCheckScope tests the scope check functionality.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceCheckScope
func TestScopeServiceCheckScope(t *testing.T) {
	tenantID := shared.NewID()

	t.Run("InScopeNotExcluded", func(t *testing.T) {
		svc, tr, er, _ := newTestScopeService()
		target, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "*.example.com", "", "user1")
		tr.targets[target.ID().String()] = target

		// No exclusions
		_ = er

		result, err := svc.CheckScope(context.Background(), tenantID.String(), "domain", "api.example.com")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if !result.InScope {
			t.Error("expected in scope")
		}
		if result.Excluded {
			t.Error("expected not excluded")
		}
		if len(result.MatchedTargetIDs) != 1 {
			t.Errorf("expected 1 matched target, got %d", len(result.MatchedTargetIDs))
		}
	})

	t.Run("InScopeAndExcluded", func(t *testing.T) {
		svc, tr, er, _ := newTestScopeService()
		target, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "*.example.com", "", "user1")
		tr.targets[target.ID().String()] = target

		exc, _ := scopedom.NewExclusion(tenantID, scopedom.ExclusionTypeDomain, "internal.example.com", "Internal", nil, "user1")
		_ = exc.Approve("admin1")
		er.exclusions[exc.ID().String()] = exc

		result, err := svc.CheckScope(context.Background(), tenantID.String(), "domain", "internal.example.com")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if !result.InScope {
			t.Error("expected in scope")
		}
		if !result.Excluded {
			t.Error("expected excluded")
		}
		if len(result.MatchedExclusionIDs) != 1 {
			t.Errorf("expected 1 matched exclusion, got %d", len(result.MatchedExclusionIDs))
		}
	})

	t.Run("NotInScope", func(t *testing.T) {
		svc, tr, _, _ := newTestScopeService()
		target, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "*.example.com", "", "user1")
		tr.targets[target.ID().String()] = target

		result, err := svc.CheckScope(context.Background(), tenantID.String(), "domain", "other.com")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if result.InScope {
			t.Error("expected not in scope")
		}
		if result.Excluded {
			t.Error("expected not excluded when not in scope")
		}
	})

	t.Run("NoTargets", func(t *testing.T) {
		svc, _, _, _ := newTestScopeService()
		result, err := svc.CheckScope(context.Background(), tenantID.String(), "domain", "anything.com")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if result.InScope {
			t.Error("expected not in scope when no targets defined")
		}
	})

	t.Run("MultipleTargetsMatch", func(t *testing.T) {
		svc, tr, _, _ := newTestScopeService()
		t1, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "*.example.com", "", "user1")
		t2, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "api.example.com", "", "user1")
		tr.targets[t1.ID().String()] = t1
		tr.targets[t2.ID().String()] = t2

		result, err := svc.CheckScope(context.Background(), tenantID.String(), "domain", "api.example.com")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if !result.InScope {
			t.Error("expected in scope")
		}
		if len(result.MatchedTargetIDs) != 2 {
			t.Errorf("expected 2 matched targets, got %d", len(result.MatchedTargetIDs))
		}
	})

	t.Run("CIDRCheck", func(t *testing.T) {
		svc, tr, _, _ := newTestScopeService()
		target, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeCIDR, "10.0.0.0/8", "", "user1")
		tr.targets[target.ID().String()] = target

		result, err := svc.CheckScope(context.Background(), tenantID.String(), "ip", "10.50.100.200")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if !result.InScope {
			t.Error("expected in scope for IP within CIDR")
		}
	})

	t.Run("InvalidTenantID", func(t *testing.T) {
		svc, _, _, _ := newTestScopeService()
		_, err := svc.CheckScope(context.Background(), "invalid", "domain", "test.com")
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got: %v", err)
		}
	})
}

// =============================================================================
// Stats Tests
// =============================================================================

// TestScopeServiceGetStats tests statistics retrieval.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceGetStats
func TestScopeServiceGetStats(t *testing.T) {
	tenantID := shared.NewID()
	svc, tr, er, _ := newTestScopeService()

	// Seed data
	t1, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "example.com", "", "user1")
	t2, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "test.com", "", "user1")
	t2.Deactivate()
	tr.targets[t1.ID().String()] = t1
	tr.targets[t2.ID().String()] = t2

	e1, _ := scopedom.NewExclusion(tenantID, scopedom.ExclusionTypeDomain, "internal.com", "reason", nil, "user1")
	er.exclusions[e1.ID().String()] = e1

	stats, err := svc.GetStats(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if stats == nil {
		t.Fatal("expected non-nil stats")
	}
	// Counts come from Count() which returns len(targets) in our mock
	if stats.TotalTargets != 2 {
		t.Errorf("expected 2 total targets, got %d", stats.TotalTargets)
	}
	if stats.TotalExclusions != 1 {
		t.Errorf("expected 1 total exclusion, got %d", stats.TotalExclusions)
	}
}

// =============================================================================
// CheckPatternOverlaps Tests
// =============================================================================

// TestScopeServiceCheckPatternOverlaps tests pattern conflict detection.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceCheckPatternOverlaps
func TestScopeServiceCheckPatternOverlaps(t *testing.T) {
	tenantID := shared.NewID()

	t.Run("NoOverlaps", func(t *testing.T) {
		svc, tr, _, _ := newTestScopeService()
		// Add existing target
		target, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "example.com", "", "user1")
		tr.targets[target.ID().String()] = target

		// Check a completely different domain
		warnings, err := svc.CheckPatternOverlaps(context.Background(), tenantID.String(), "domain", "other.com")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if len(warnings) != 0 {
			t.Errorf("expected no warnings, got: %v", warnings)
		}
	})

	t.Run("WildcardSupersetDetection", func(t *testing.T) {
		svc, tr, _, _ := newTestScopeService()
		// Add existing specific target
		target, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "sub.example.com", "", "user1")
		tr.targets[target.ID().String()] = target

		// New wildcard pattern is superset of existing
		warnings, err := svc.CheckPatternOverlaps(context.Background(), tenantID.String(), "domain", "*.example.com")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if len(warnings) == 0 {
			t.Error("expected warnings for wildcard superset, got none")
		}
	})

	t.Run("SubsetDetection", func(t *testing.T) {
		svc, tr, _, _ := newTestScopeService()
		// Add existing wildcard target
		target, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "*.example.com", "", "user1")
		tr.targets[target.ID().String()] = target

		// New specific pattern is subset of existing wildcard
		warnings, err := svc.CheckPatternOverlaps(context.Background(), tenantID.String(), "domain", "sub.example.com")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if len(warnings) == 0 {
			t.Error("expected warnings for subset pattern, got none")
		}
	})

	t.Run("ExactDuplicateIgnored", func(t *testing.T) {
		svc, tr, _, _ := newTestScopeService()
		// Add existing target
		target, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "example.com", "", "user1")
		tr.targets[target.ID().String()] = target

		// Exact same pattern should be ignored (handled by ExistsByPattern separately)
		warnings, err := svc.CheckPatternOverlaps(context.Background(), tenantID.String(), "domain", "example.com")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if len(warnings) != 0 {
			t.Errorf("expected no warnings for exact duplicate, got: %v", warnings)
		}
	})

	t.Run("DifferentTypeNoOverlap", func(t *testing.T) {
		svc, tr, _, _ := newTestScopeService()
		// Add domain target
		target, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "example.com", "", "user1")
		tr.targets[target.ID().String()] = target

		// Check IP type - should not overlap with domain
		warnings, err := svc.CheckPatternOverlaps(context.Background(), tenantID.String(), "ip_address", "192.168.1.1")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if len(warnings) != 0 {
			t.Errorf("expected no warnings for different type, got: %v", warnings)
		}
	})

	t.Run("InvalidTenantID", func(t *testing.T) {
		svc, _, _, _ := newTestScopeService()

		_, err := svc.CheckPatternOverlaps(context.Background(), "not-a-uuid", "domain", "example.com")
		if err == nil {
			t.Fatal("expected error for invalid tenant ID")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got: %v", err)
		}
	})

	t.Run("InvalidTargetType", func(t *testing.T) {
		svc, _, _, _ := newTestScopeService()

		_, err := svc.CheckPatternOverlaps(context.Background(), tenantID.String(), "invalid_type", "something")
		if err == nil {
			t.Fatal("expected error for invalid target type")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got: %v", err)
		}
	})

	t.Run("InactiveTargetsIgnored", func(t *testing.T) {
		svc, tr, _, _ := newTestScopeService()
		// Add inactive target
		target, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "*.example.com", "", "user1")
		target.Deactivate()
		tr.targets[target.ID().String()] = target

		// Active wildcard check: inactive target should not be returned by ListActive mock
		warnings, err := svc.CheckPatternOverlaps(context.Background(), tenantID.String(), "domain", "sub.example.com")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if len(warnings) != 0 {
			t.Errorf("expected no warnings for inactive target, got: %v", warnings)
		}
	})

	t.Run("MultipleOverlaps", func(t *testing.T) {
		svc, tr, _, _ := newTestScopeService()
		// Add multiple existing targets
		t1, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "api.example.com", "", "user1")
		tr.targets[t1.ID().String()] = t1
		t2, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "web.example.com", "", "user1")
		tr.targets[t2.ID().String()] = t2

		// Wildcard that covers both
		warnings, err := svc.CheckPatternOverlaps(context.Background(), tenantID.String(), "domain", "*.example.com")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if len(warnings) < 2 {
			t.Errorf("expected at least 2 warnings for multiple overlaps, got %d: %v", len(warnings), warnings)
		}
	})
}

// =============================================================================
// Tenant Isolation Tests (Activate/Deactivate/Approve)
// =============================================================================

// TestScopeServiceActivateTargetTenantIsolation tests tenant isolation for target activation.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceActivateTargetTenantIsolation
func TestScopeServiceActivateTargetTenantIsolation(t *testing.T) {
	tenantID := shared.NewID()

	t.Run("Success", func(t *testing.T) {
		svc, tr, _, _ := newTestScopeService()
		target, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "example.com", "", "user1")
		target.Deactivate()
		tr.targets[target.ID().String()] = target

		result, err := svc.ActivateTarget(context.Background(), target.ID().String(), tenantID.String(), scope.Actor{})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if !result.IsActive() {
			t.Error("expected target to be active")
		}
	})

	t.Run("WrongTenant", func(t *testing.T) {
		svc, tr, _, _ := newTestScopeService()
		target, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "example.com", "", "user1")
		target.Deactivate()
		tr.targets[target.ID().String()] = target

		_, err := svc.ActivateTarget(context.Background(), target.ID().String(), shared.NewID().String(), scope.Actor{})
		if err == nil {
			t.Fatal("expected error for wrong tenant")
		}
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got: %v", err)
		}
	})
}

// TestScopeServiceDeactivateTargetTenantIsolation tests tenant isolation for target deactivation.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceDeactivateTargetTenantIsolation
func TestScopeServiceDeactivateTargetTenantIsolation(t *testing.T) {
	tenantID := shared.NewID()

	t.Run("Success", func(t *testing.T) {
		svc, tr, _, _ := newTestScopeService()
		target, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "example.com", "", "user1")
		tr.targets[target.ID().String()] = target

		result, err := svc.DeactivateTarget(context.Background(), target.ID().String(), tenantID.String())
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if result.IsActive() {
			t.Error("expected target to be inactive")
		}
	})

	t.Run("WrongTenant", func(t *testing.T) {
		svc, tr, _, _ := newTestScopeService()
		target, _ := scopedom.NewTarget(tenantID, scopedom.TargetTypeDomain, "example.com", "", "user1")
		tr.targets[target.ID().String()] = target

		_, err := svc.DeactivateTarget(context.Background(), target.ID().String(), shared.NewID().String())
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got: %v", err)
		}
	})
}

// TestScopeServiceApproveExclusionTenantIsolation tests tenant isolation for exclusion approval.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceApproveExclusionTenantIsolation
func TestScopeServiceApproveExclusionTenantIsolation(t *testing.T) {
	tenantID := shared.NewID()

	t.Run("Success", func(t *testing.T) {
		svc, _, er, _ := newTestScopeService()
		exc, _ := scopedom.NewExclusion(tenantID, scopedom.ExclusionTypeDomain, "test.com", "reason", nil, "user1")
		er.exclusions[exc.ID().String()] = exc

		result, err := svc.ApproveExclusion(context.Background(), exc.ID().String(), tenantID.String(), "admin1")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if !result.IsApproved() {
			t.Error("expected exclusion to be approved")
		}
		if result.ApprovedBy() != "admin1" {
			t.Errorf("expected approvedBy 'admin1', got %q", result.ApprovedBy())
		}
	})

	t.Run("WrongTenant", func(t *testing.T) {
		svc, _, er, _ := newTestScopeService()
		exc, _ := scopedom.NewExclusion(tenantID, scopedom.ExclusionTypeDomain, "test.com", "reason", nil, "user1")
		er.exclusions[exc.ID().String()] = exc

		_, err := svc.ApproveExclusion(context.Background(), exc.ID().String(), shared.NewID().String(), "admin1")
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got: %v", err)
		}
	})
}

// TestScopeServiceActivateExclusionTenantIsolation tests tenant isolation for exclusion activation.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceActivateExclusionTenantIsolation
func TestScopeServiceActivateExclusionTenantIsolation(t *testing.T) {
	tenantID := shared.NewID()

	t.Run("WrongTenant", func(t *testing.T) {
		svc, _, er, _ := newTestScopeService()
		exc, _ := scopedom.NewExclusion(tenantID, scopedom.ExclusionTypeDomain, "test.com", "reason", nil, "user1")
		exc.Deactivate()
		er.exclusions[exc.ID().String()] = exc

		_, err := svc.ActivateExclusion(context.Background(), exc.ID().String(), shared.NewID().String())
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got: %v", err)
		}
	})
}

// TestScopeServiceDeactivateExclusionTenantIsolation tests tenant isolation for exclusion deactivation.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceDeactivateExclusionTenantIsolation
func TestScopeServiceDeactivateExclusionTenantIsolation(t *testing.T) {
	tenantID := shared.NewID()

	t.Run("WrongTenant", func(t *testing.T) {
		svc, _, er, _ := newTestScopeService()
		exc, _ := scopedom.NewExclusion(tenantID, scopedom.ExclusionTypeDomain, "test.com", "reason", nil, "user1")
		er.exclusions[exc.ID().String()] = exc

		_, err := svc.DeactivateExclusion(context.Background(), exc.ID().String(), shared.NewID().String(), exclusionApprover)
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got: %v", err)
		}
	})
}

func (m *mockAssetRepo) PurgeDeleted(_ context.Context, _ time.Time, _ int) (int, error) {
	return 0, nil
}

// exclusionApprover holds the exclusion approval permission and requested
// none of the test exclusions.
var exclusionApprover = scopedom.Reviewer{UserID: "approver2", CanApprove: true}

// Taking an approved exclusion out of effect (deactivate, delete, shorten
// its window, a past date included) needs the approval permission and
// someone other than the requester, like approving it. Research doc 15, L-07.
func TestScopeServiceExclusion_ReducingProtectionNeedsSecondApprover(t *testing.T) {
	ctx := context.Background()
	member := scopedom.Reviewer{UserID: "member9", CanApprove: false}
	requester := scopedom.Reviewer{UserID: "member1", CanApprove: true}
	week := time.Now().Add(7 * 24 * time.Hour)

	newApproved := func(t *testing.T) (*scope.Service, *scopedom.Exclusion, string, string) {
		t.Helper()
		svc, _, er, _ := newTestScopeService()
		tenantID := shared.NewID()
		exc, _ := scopedom.NewExclusion(tenantID, scopedom.ExclusionTypeDomain, "payments.prod", "prod", &week, "member1")
		if err := exc.Approve("admin1"); err != nil {
			t.Fatal(err)
		}
		er.exclusions[exc.ID().String()] = exc
		return svc, exc, exc.ID().String(), tenantID.String()
	}
	past := time.Now().Add(-time.Hour)
	day := time.Now().Add(24 * time.Hour)
	reason := "edited"

	type op func(svc *scope.Service, id, tid string, r scopedom.Reviewer) error
	ops := map[string]op{
		"deactivate": func(svc *scope.Service, id, tid string, r scopedom.Reviewer) error {
			_, err := svc.DeactivateExclusion(ctx, id, tid, r)
			return err
		},
		"delete": func(svc *scope.Service, id, tid string, r scopedom.Reviewer) error {
			return svc.DeleteExclusion(ctx, id, tid, r)
		},
		"expire in the past": func(svc *scope.Service, id, tid string, r scopedom.Reviewer) error {
			_, err := svc.UpdateExclusion(ctx, id, tid, scope.UpdateExclusionInput{ExpiresAt: &past, Reviewer: r})
			return err
		},
		"shorten": func(svc *scope.Service, id, tid string, r scopedom.Reviewer) error {
			_, err := svc.UpdateExclusion(ctx, id, tid, scope.UpdateExclusionInput{ExpiresAt: &day, Reviewer: r})
			return err
		},
	}
	for name, do := range ops {
		t.Run(name, func(t *testing.T) {
			svc, exc, id, tid := newApproved(t)
			if err := do(svc, id, tid, member); !errors.Is(err, scopedom.ErrExclusionReduceNeedsApprover) {
				t.Fatalf("scope:write only: got %v, want ErrExclusionReduceNeedsApprover", err)
			}
			if err := do(svc, id, tid, requester); !errors.Is(err, scopedom.ErrExclusionSelfReduce) {
				t.Fatalf("the requester: got %v, want ErrExclusionSelfReduce", err)
			}
			if !exc.InEffect() || !exc.ExpiresAt().Equal(week) {
				t.Fatal("a refused reduction changed the exclusion")
			}
			if err := do(svc, id, tid, exclusionApprover); err != nil {
				t.Fatalf("a second approver: %v", err)
			}
		})
	}

	t.Run("protection-neutral changes stay on scope:write", func(t *testing.T) {
		svc, _, id, tid := newApproved(t)
		later := week.Add(time.Hour)
		if _, err := svc.UpdateExclusion(ctx, id, tid, scope.UpdateExclusionInput{Reason: &reason, Reviewer: member}); err != nil {
			t.Fatalf("editing the reason: %v", err)
		}
		// Extending sends it back for approval (already covered elsewhere).
		if _, err := svc.UpdateExclusion(ctx, id, tid, scope.UpdateExclusionInput{ExpiresAt: &later, Reviewer: member}); err != nil {
			t.Fatalf("extending: %v", err)
		}
	})

	t.Run("an exclusion not in effect can be removed with scope rights", func(t *testing.T) {
		svc, _, er, _ := newTestScopeService()
		tenantID := shared.NewID()
		pending, _ := scopedom.NewExclusion(tenantID, scopedom.ExclusionTypeDomain, "pending.prod", "p", nil, "member9")
		er.exclusions[pending.ID().String()] = pending
		if err := svc.DeleteExclusion(ctx, pending.ID().String(), tenantID.String(), member); err != nil {
			t.Fatalf("deleting a pending exclusion: %v", err)
		}
	})
}

func (m *mockAssetRepo) GetInventoryOverview(_ context.Context, _ shared.ID, _ asset.AccessScope) ([]asset.InventoryOverviewRow, error) {
	return nil, nil
}
