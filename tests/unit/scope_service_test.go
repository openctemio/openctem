package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/scope"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock Repositories
// =============================================================================

type mockTargetRepo struct {
	targets     map[string]*scope.Target
	createErr   error
	updateErr   error
	deleteErr   error
	countResult int64
	countErr    error
}

func newMockTargetRepo() *mockTargetRepo {
	return &mockTargetRepo{targets: make(map[string]*scope.Target)}
}

func (m *mockTargetRepo) Create(_ context.Context, target *scope.Target) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.targets[target.ID().String()] = target
	return nil
}

func (m *mockTargetRepo) GetByID(_ context.Context, id shared.ID) (*scope.Target, error) {
	t, ok := m.targets[id.String()]
	if !ok {
		return nil, scope.ErrTargetNotFound
	}
	return t, nil
}

func (m *mockTargetRepo) Update(_ context.Context, target *scope.Target) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.targets[target.ID().String()] = target
	return nil
}

func (m *mockTargetRepo) Delete(_ context.Context, id shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if _, ok := m.targets[id.String()]; !ok {
		return scope.ErrTargetNotFound
	}
	delete(m.targets, id.String())
	return nil
}

func (m *mockTargetRepo) List(_ context.Context, _ scope.TargetFilter, page pagination.Pagination) (pagination.Result[*scope.Target], error) {
	targets := make([]*scope.Target, 0, len(m.targets))
	for _, t := range m.targets {
		targets = append(targets, t)
	}
	total := int64(len(targets))
	return pagination.NewResult(targets, total, page), nil
}

func (m *mockTargetRepo) ListActive(_ context.Context, tenantID shared.ID) ([]*scope.Target, error) {
	var targets []*scope.Target
	for _, t := range m.targets {
		if t.TenantID() == tenantID && t.IsActive() {
			targets = append(targets, t)
		}
	}
	return targets, nil
}

func (m *mockTargetRepo) Count(_ context.Context, _ scope.TargetFilter) (int64, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	if m.countResult > 0 {
		return m.countResult, nil
	}
	return int64(len(m.targets)), nil
}

func (m *mockTargetRepo) ExistsByPattern(_ context.Context, tenantID shared.ID, targetType scope.TargetType, pattern string) (bool, error) {
	for _, t := range m.targets {
		if t.TenantID() == tenantID && t.TargetType() == targetType && t.Pattern() == pattern {
			return true, nil
		}
	}
	return false, nil
}

type mockExclusionRepo struct {
	exclusions map[string]*scope.Exclusion
	createErr  error
	updateErr  error
	deleteErr  error
}

func newMockExclusionRepo() *mockExclusionRepo {
	return &mockExclusionRepo{exclusions: make(map[string]*scope.Exclusion)}
}

func (m *mockExclusionRepo) Create(_ context.Context, exclusion *scope.Exclusion) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.exclusions[exclusion.ID().String()] = exclusion
	return nil
}

func (m *mockExclusionRepo) GetByID(_ context.Context, id shared.ID) (*scope.Exclusion, error) {
	e, ok := m.exclusions[id.String()]
	if !ok {
		return nil, scope.ErrExclusionNotFound
	}
	return e, nil
}

func (m *mockExclusionRepo) Update(_ context.Context, exclusion *scope.Exclusion) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.exclusions[exclusion.ID().String()] = exclusion
	return nil
}

func (m *mockExclusionRepo) Delete(_ context.Context, id shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if _, ok := m.exclusions[id.String()]; !ok {
		return scope.ErrExclusionNotFound
	}
	delete(m.exclusions, id.String())
	return nil
}

func (m *mockExclusionRepo) List(_ context.Context, _ scope.ExclusionFilter, page pagination.Pagination) (pagination.Result[*scope.Exclusion], error) {
	exclusions := make([]*scope.Exclusion, 0, len(m.exclusions))
	for _, e := range m.exclusions {
		exclusions = append(exclusions, e)
	}
	total := int64(len(exclusions))
	return pagination.NewResult(exclusions, total, page), nil
}

func (m *mockExclusionRepo) ListActive(_ context.Context, tenantID shared.ID) ([]*scope.Exclusion, error) {
	var exclusions []*scope.Exclusion
	for _, e := range m.exclusions {
		if e.TenantID() == tenantID && e.IsActive() {
			exclusions = append(exclusions, e)
		}
	}
	return exclusions, nil
}

func (m *mockExclusionRepo) Count(_ context.Context, _ scope.ExclusionFilter) (int64, error) {
	return int64(len(m.exclusions)), nil
}

func (m *mockExclusionRepo) ExpireOld(_ context.Context) error {
	return nil
}

type mockScheduleRepo struct {
	schedules map[string]*scope.Schedule
	createErr error
	updateErr error
	deleteErr error
}

func newMockScheduleRepo() *mockScheduleRepo {
	return &mockScheduleRepo{schedules: make(map[string]*scope.Schedule)}
}

func (m *mockScheduleRepo) Create(_ context.Context, schedule *scope.Schedule) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.schedules[schedule.ID().String()] = schedule
	return nil
}

func (m *mockScheduleRepo) GetByID(_ context.Context, id shared.ID) (*scope.Schedule, error) {
	s, ok := m.schedules[id.String()]
	if !ok {
		return nil, scope.ErrScheduleNotFound
	}
	return s, nil
}

func (m *mockScheduleRepo) Update(_ context.Context, schedule *scope.Schedule) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.schedules[schedule.ID().String()] = schedule
	return nil
}

func (m *mockScheduleRepo) Delete(_ context.Context, id shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if _, ok := m.schedules[id.String()]; !ok {
		return scope.ErrScheduleNotFound
	}
	delete(m.schedules, id.String())
	return nil
}

func (m *mockScheduleRepo) List(_ context.Context, _ scope.ScheduleFilter, page pagination.Pagination) (pagination.Result[*scope.Schedule], error) {
	schedules := make([]*scope.Schedule, 0, len(m.schedules))
	for _, s := range m.schedules {
		schedules = append(schedules, s)
	}
	total := int64(len(schedules))
	return pagination.NewResult(schedules, total, page), nil
}

func (m *mockScheduleRepo) ListDue(_ context.Context) ([]*scope.Schedule, error) {
	var due []*scope.Schedule
	for _, s := range m.schedules {
		if s.Enabled() {
			due = append(due, s)
		}
	}
	return due, nil
}

func (m *mockScheduleRepo) Count(_ context.Context, _ scope.ScheduleFilter) (int64, error) {
	return int64(len(m.schedules)), nil
}

// Minimal mock for asset.Repository - only used by coverage calculation.
type mockAssetRepo struct {
	assets   []*asset.Asset
	countVal int64
}

func newMockAssetRepo() *mockAssetRepo {
	return &mockAssetRepo{}
}

func (m *mockAssetRepo) Create(_ context.Context, _ *asset.Asset) error  { return nil }
func (m *mockAssetRepo) GetByID(_ context.Context, _, _ shared.ID) (*asset.Asset, error) {
	return nil, shared.ErrNotFound
}
func (m *mockAssetRepo) Update(_ context.Context, _ *asset.Asset) error  { return nil }
func (m *mockAssetRepo) Delete(_ context.Context, _, _ shared.ID) error  { return nil }
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
func (m *mockAssetRepo) GetByNames(_ context.Context, _ shared.ID, _ []string) (map[string]*asset.Asset, error) {
	return nil, nil
}
func (m *mockAssetRepo) UpsertBatch(_ context.Context, _ []*asset.Asset) (int, int, error) {
	return 0, 0, nil
}
func (m *mockAssetRepo) UpdateFindingCounts(_ context.Context, _ shared.ID, _ []shared.ID) error {
	return nil
}

// =============================================================================
// Helpers
// =============================================================================

func newTestScopeService() (*app.ScopeService, *mockTargetRepo, *mockExclusionRepo, *mockScheduleRepo, *mockAssetRepo) {
	tr := newMockTargetRepo()
	er := newMockExclusionRepo()
	sr := newMockScheduleRepo()
	ar := newMockAssetRepo()
	log := logger.NewDevelopment()
	svc := app.NewScopeService(tr, er, sr, ar, log)
	return svc, tr, er, sr, ar
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
		svc, tr, _, _, _ := newTestScopeService()
		ctx := context.Background()

		target, err := svc.CreateTarget(ctx, app.CreateTargetInput{
			TenantID:    tenantID.String(),
			TargetType:  "domain",
			Pattern:     "*.example.com",
			Description: "Test domain",
			Priority:    50,
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
		if target.Priority() != 50 {
			t.Errorf("expected priority 50, got %d", target.Priority())
		}
		if len(target.Tags()) != 1 || target.Tags()[0] != "web" {
			t.Errorf("expected [web], got %v", target.Tags())
		}
		if len(tr.targets) != 1 {
			t.Errorf("expected 1 target in repo, got %d", len(tr.targets))
		}
	})

	t.Run("InvalidTenantID", func(t *testing.T) {
		svc, _, _, _, _ := newTestScopeService()
		_, err := svc.CreateTarget(context.Background(), app.CreateTargetInput{
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
		svc, _, _, _, _ := newTestScopeService()
		_, err := svc.CreateTarget(context.Background(), app.CreateTargetInput{
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
		svc, _, _, _, _ := newTestScopeService()
		ctx := context.Background()

		_, err := svc.CreateTarget(ctx, app.CreateTargetInput{
			TenantID:   tenantID.String(),
			TargetType: "domain",
			Pattern:    "example.com",
		})
		if err != nil {
			t.Fatalf("first create failed: %v", err)
		}

		_, err = svc.CreateTarget(ctx, app.CreateTargetInput{
			TenantID:   tenantID.String(),
			TargetType: "domain",
			Pattern:    "example.com",
		})
		if err == nil {
			t.Fatal("expected error for duplicate pattern")
		}
		if !errors.Is(err, scope.ErrTargetAlreadyExists) {
			t.Errorf("expected ErrTargetAlreadyExists, got: %v", err)
		}
	})

	t.Run("RepoCreateError", func(t *testing.T) {
		svc, tr, _, _, _ := newTestScopeService()
		tr.createErr = errors.New("db connection lost")

		_, err := svc.CreateTarget(context.Background(), app.CreateTargetInput{
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
	svc, tr, _, _, _ := newTestScopeService()
	tenantID := shared.NewID()

	// Seed a target
	target, _ := scope.NewTarget(tenantID, scope.TargetTypeDomain, "example.com", "", "user1")
	tr.targets[target.ID().String()] = target

	t.Run("Found", func(t *testing.T) {
		got, err := svc.GetTarget(context.Background(), target.ID().String())
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if got.ID() != target.ID() {
			t.Errorf("expected ID %s, got %s", target.ID(), got.ID())
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		_, err := svc.GetTarget(context.Background(), shared.NewID().String())
		if err == nil {
			t.Fatal("expected error for not found")
		}
		if !errors.Is(err, scope.ErrTargetNotFound) {
			t.Errorf("expected ErrTargetNotFound, got: %v", err)
		}
	})

	t.Run("InvalidID", func(t *testing.T) {
		_, err := svc.GetTarget(context.Background(), "not-a-uuid")
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
		svc, tr, _, _, _ := newTestScopeService()
		target, _ := scope.NewTarget(tenantID, scope.TargetTypeDomain, "example.com", "orig", "user1")
		tr.targets[target.ID().String()] = target

		desc := "updated"
		priority := 80
		updated, err := svc.UpdateTarget(context.Background(), target.ID().String(), tenantID.String(), app.UpdateTargetInput{
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
		if updated.Priority() != 80 {
			t.Errorf("expected priority 80, got %d", updated.Priority())
		}
		if len(updated.Tags()) != 1 || updated.Tags()[0] != "new-tag" {
			t.Errorf("expected [new-tag], got %v", updated.Tags())
		}
	})

	t.Run("WrongTenant", func(t *testing.T) {
		svc, tr, _, _, _ := newTestScopeService()
		target, _ := scope.NewTarget(tenantID, scope.TargetTypeDomain, "example.com", "", "user1")
		tr.targets[target.ID().String()] = target

		desc := "hacked"
		_, err := svc.UpdateTarget(context.Background(), target.ID().String(), otherTenantID.String(), app.UpdateTargetInput{
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
		svc, _, _, _, _ := newTestScopeService()
		desc := "test"
		_, err := svc.UpdateTarget(context.Background(), shared.NewID().String(), tenantID.String(), app.UpdateTargetInput{
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
		svc, tr, _, _, _ := newTestScopeService()
		target, _ := scope.NewTarget(tenantID, scope.TargetTypeDomain, "example.com", "", "user1")
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
		svc, tr, _, _, _ := newTestScopeService()
		target, _ := scope.NewTarget(tenantID, scope.TargetTypeDomain, "example.com", "", "user1")
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
	svc, tr, _, _, _ := newTestScopeService()
	tenantID := shared.NewID()
	target, _ := scope.NewTarget(tenantID, scope.TargetTypeDomain, "example.com", "", "user1")
	tr.targets[target.ID().String()] = target

	t.Run("Deactivate", func(t *testing.T) {
		result, err := svc.DeactivateTarget(context.Background(), target.ID().String())
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if result.Status() != scope.StatusInactive {
			t.Errorf("expected inactive, got %s", result.Status())
		}
	})

	t.Run("Activate", func(t *testing.T) {
		result, err := svc.ActivateTarget(context.Background(), target.ID().String())
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if result.Status() != scope.StatusActive {
			t.Errorf("expected active, got %s", result.Status())
		}
	})

	t.Run("ActivateNotFound", func(t *testing.T) {
		_, err := svc.ActivateTarget(context.Background(), shared.NewID().String())
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
		svc, _, er, _, _ := newTestScopeService()
		exclusion, err := svc.CreateExclusion(context.Background(), app.CreateExclusionInput{
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
		svc, _, _, _, _ := newTestScopeService()
		future := time.Now().Add(24 * time.Hour)
		exclusion, err := svc.CreateExclusion(context.Background(), app.CreateExclusionInput{
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
		svc, _, _, _, _ := newTestScopeService()
		_, err := svc.CreateExclusion(context.Background(), app.CreateExclusionInput{
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
		svc, _, _, _, _ := newTestScopeService()
		_, err := svc.CreateExclusion(context.Background(), app.CreateExclusionInput{
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
		svc, _, _, _, _ := newTestScopeService()
		_, err := svc.CreateExclusion(context.Background(), app.CreateExclusionInput{
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
		svc, _, er, _, _ := newTestScopeService()
		exc, _ := scope.NewExclusion(tenantID, scope.ExclusionTypeDomain, "test.com", "orig", nil, "user1")
		er.exclusions[exc.ID().String()] = exc

		reason := "updated reason"
		updated, err := svc.UpdateExclusion(context.Background(), exc.ID().String(), tenantID.String(), app.UpdateExclusionInput{
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
		svc, _, er, _, _ := newTestScopeService()
		exc, _ := scope.NewExclusion(tenantID, scope.ExclusionTypeDomain, "test.com", "orig", nil, "user1")
		er.exclusions[exc.ID().String()] = exc

		reason := "hacked"
		_, err := svc.UpdateExclusion(context.Background(), exc.ID().String(), otherTenantID.String(), app.UpdateExclusionInput{
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
	svc, _, er, _, _ := newTestScopeService()
	tenantID := shared.NewID()
	exc, _ := scope.NewExclusion(tenantID, scope.ExclusionTypeDomain, "test.com", "reason", nil, "user1")
	er.exclusions[exc.ID().String()] = exc

	t.Run("Approve", func(t *testing.T) {
		approved, err := svc.ApproveExclusion(context.Background(), exc.ID().String(), "admin1")
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
		_, err := svc.ApproveExclusion(context.Background(), shared.NewID().String(), "admin1")
		if err == nil {
			t.Fatal("expected error for not found")
		}
	})
}

// TestScopeServiceActivateDeactivateExclusion tests exclusion status changes.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceActivateDeactivateExclusion
func TestScopeServiceActivateDeactivateExclusion(t *testing.T) {
	svc, _, er, _, _ := newTestScopeService()
	tenantID := shared.NewID()
	exc, _ := scope.NewExclusion(tenantID, scope.ExclusionTypeDomain, "test.com", "reason", nil, "user1")
	er.exclusions[exc.ID().String()] = exc

	t.Run("Deactivate", func(t *testing.T) {
		result, err := svc.DeactivateExclusion(context.Background(), exc.ID().String())
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if result.Status() != scope.StatusInactive {
			t.Errorf("expected inactive, got %s", result.Status())
		}
	})

	t.Run("Activate", func(t *testing.T) {
		result, err := svc.ActivateExclusion(context.Background(), exc.ID().String())
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if result.Status() != scope.StatusActive {
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
		svc, _, er, _, _ := newTestScopeService()
		exc, _ := scope.NewExclusion(tenantID, scope.ExclusionTypeDomain, "test.com", "reason", nil, "user1")
		er.exclusions[exc.ID().String()] = exc

		err := svc.DeleteExclusion(context.Background(), exc.ID().String(), tenantID.String())
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if len(er.exclusions) != 0 {
			t.Errorf("expected 0 exclusions, got %d", len(er.exclusions))
		}
	})

	t.Run("WrongTenant", func(t *testing.T) {
		svc, _, er, _, _ := newTestScopeService()
		exc, _ := scope.NewExclusion(tenantID, scope.ExclusionTypeDomain, "test.com", "reason", nil, "user1")
		er.exclusions[exc.ID().String()] = exc

		err := svc.DeleteExclusion(context.Background(), exc.ID().String(), shared.NewID().String())
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got: %v", err)
		}
		if len(er.exclusions) != 1 {
			t.Error("exclusion should not be deleted")
		}
	})
}

// =============================================================================
// Schedule Service Tests
// =============================================================================

// TestScopeServiceCreateSchedule tests schedule creation.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceCreateSchedule
func TestScopeServiceCreateSchedule(t *testing.T) {
	tenantID := shared.NewID()

	t.Run("Success", func(t *testing.T) {
		svc, _, _, sr, _ := newTestScopeService()
		schedule, err := svc.CreateSchedule(context.Background(), app.CreateScheduleInput{
			TenantID:     tenantID.String(),
			Name:         "Daily Scan",
			Description:  "Run every day",
			ScanType:     "full",
			ScheduleType: "cron",
			CronExpression: "0 2 * * *",
			CreatedBy:    "user1",
		})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if schedule.Name() != "Daily Scan" {
			t.Errorf("expected name 'Daily Scan', got %s", schedule.Name())
		}
		if schedule.CronExpression() != "0 2 * * *" {
			t.Errorf("expected cron '0 2 * * *', got %s", schedule.CronExpression())
		}
		if len(sr.schedules) != 1 {
			t.Errorf("expected 1 schedule in repo, got %d", len(sr.schedules))
		}
	})

	t.Run("IntervalSchedule", func(t *testing.T) {
		svc, _, _, _, _ := newTestScopeService()
		schedule, err := svc.CreateSchedule(context.Background(), app.CreateScheduleInput{
			TenantID:      tenantID.String(),
			Name:          "Hourly Scan",
			ScanType:      "incremental",
			ScheduleType:  "interval",
			IntervalHours: 6,
		})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if schedule.IntervalHours() != 6 {
			t.Errorf("expected 6 hours, got %d", schedule.IntervalHours())
		}
	})

	t.Run("WithTargetScope", func(t *testing.T) {
		svc, _, _, _, _ := newTestScopeService()
		targetID := shared.NewID()
		schedule, err := svc.CreateSchedule(context.Background(), app.CreateScheduleInput{
			TenantID:     tenantID.String(),
			Name:         "Tagged Scan",
			ScanType:     "targeted",
			ScheduleType: "manual",
			TargetScope:  "tag",
			TargetIDs:    []string{targetID.String()},
			TargetTags:   []string{"production"},
		})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if schedule.TargetScope() != scope.TargetScopeTag {
			t.Errorf("expected scope tag, got %s", schedule.TargetScope())
		}
	})

	t.Run("InvalidTenantID", func(t *testing.T) {
		svc, _, _, _, _ := newTestScopeService()
		_, err := svc.CreateSchedule(context.Background(), app.CreateScheduleInput{
			TenantID:     "invalid",
			Name:         "Test",
			ScanType:     "full",
			ScheduleType: "manual",
		})
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got: %v", err)
		}
	})

	t.Run("InvalidScanType", func(t *testing.T) {
		svc, _, _, _, _ := newTestScopeService()
		_, err := svc.CreateSchedule(context.Background(), app.CreateScheduleInput{
			TenantID:     tenantID.String(),
			Name:         "Test",
			ScanType:     "invalid",
			ScheduleType: "manual",
		})
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got: %v", err)
		}
	})

	t.Run("InvalidScheduleType", func(t *testing.T) {
		svc, _, _, _, _ := newTestScopeService()
		_, err := svc.CreateSchedule(context.Background(), app.CreateScheduleInput{
			TenantID:     tenantID.String(),
			Name:         "Test",
			ScanType:     "full",
			ScheduleType: "invalid",
		})
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got: %v", err)
		}
	})

	t.Run("EmptyName", func(t *testing.T) {
		svc, _, _, _, _ := newTestScopeService()
		_, err := svc.CreateSchedule(context.Background(), app.CreateScheduleInput{
			TenantID:     tenantID.String(),
			Name:         "",
			ScanType:     "full",
			ScheduleType: "manual",
		})
		if err == nil {
			t.Fatal("expected error for empty name")
		}
	})
}

// TestScopeServiceUpdateSchedule tests schedule updates with tenant isolation.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceUpdateSchedule
func TestScopeServiceUpdateSchedule(t *testing.T) {
	tenantID := shared.NewID()

	t.Run("Success", func(t *testing.T) {
		svc, _, _, sr, _ := newTestScopeService()
		sched, _ := scope.NewSchedule(tenantID, "Test", scope.ScanTypeFull, scope.ScheduleTypeManual, "user1")
		sr.schedules[sched.ID().String()] = sched

		name := "Updated Name"
		desc := "Updated desc"
		updated, err := svc.UpdateSchedule(context.Background(), sched.ID().String(), tenantID.String(), app.UpdateScheduleInput{
			Name:        &name,
			Description: &desc,
		})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if updated.Name() != "Updated Name" {
			t.Errorf("expected 'Updated Name', got %s", updated.Name())
		}
		if updated.Description() != "Updated desc" {
			t.Errorf("expected 'Updated desc', got %s", updated.Description())
		}
	})

	t.Run("WrongTenant", func(t *testing.T) {
		svc, _, _, sr, _ := newTestScopeService()
		sched, _ := scope.NewSchedule(tenantID, "Test", scope.ScanTypeFull, scope.ScheduleTypeManual, "user1")
		sr.schedules[sched.ID().String()] = sched

		name := "hacked"
		_, err := svc.UpdateSchedule(context.Background(), sched.ID().String(), shared.NewID().String(), app.UpdateScheduleInput{
			Name: &name,
		})
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got: %v", err)
		}
	})
}

// TestScopeServiceEnableDisableSchedule tests schedule enable/disable.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceEnableDisableSchedule
func TestScopeServiceEnableDisableSchedule(t *testing.T) {
	svc, _, _, sr, _ := newTestScopeService()
	tenantID := shared.NewID()
	sched, _ := scope.NewSchedule(tenantID, "Test", scope.ScanTypeFull, scope.ScheduleTypeCron, "user1")
	sr.schedules[sched.ID().String()] = sched

	t.Run("Disable", func(t *testing.T) {
		result, err := svc.DisableSchedule(context.Background(), sched.ID().String())
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if result.Enabled() {
			t.Error("expected disabled")
		}
	})

	t.Run("Enable", func(t *testing.T) {
		result, err := svc.EnableSchedule(context.Background(), sched.ID().String())
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if !result.Enabled() {
			t.Error("expected enabled")
		}
	})

	t.Run("DisableNotFound", func(t *testing.T) {
		_, err := svc.DisableSchedule(context.Background(), shared.NewID().String())
		if err == nil {
			t.Fatal("expected error for not found")
		}
	})
}

// TestScopeServiceDeleteSchedule tests schedule deletion.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceDeleteSchedule
func TestScopeServiceDeleteSchedule(t *testing.T) {
	tenantID := shared.NewID()

	t.Run("Success", func(t *testing.T) {
		svc, _, _, sr, _ := newTestScopeService()
		sched, _ := scope.NewSchedule(tenantID, "Test", scope.ScanTypeFull, scope.ScheduleTypeManual, "user1")
		sr.schedules[sched.ID().String()] = sched

		err := svc.DeleteSchedule(context.Background(), sched.ID().String(), tenantID.String())
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if len(sr.schedules) != 0 {
			t.Errorf("expected 0 schedules, got %d", len(sr.schedules))
		}
	})

	t.Run("WrongTenant", func(t *testing.T) {
		svc, _, _, sr, _ := newTestScopeService()
		sched, _ := scope.NewSchedule(tenantID, "Test", scope.ScanTypeFull, scope.ScheduleTypeManual, "user1")
		sr.schedules[sched.ID().String()] = sched

		err := svc.DeleteSchedule(context.Background(), sched.ID().String(), shared.NewID().String())
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got: %v", err)
		}
	})
}

// TestScopeServiceRecordScheduleRun tests recording a run for a schedule.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceRecordScheduleRun
func TestScopeServiceRecordScheduleRun(t *testing.T) {
	svc, _, _, sr, _ := newTestScopeService()
	tenantID := shared.NewID()
	sched, _ := scope.NewSchedule(tenantID, "Test", scope.ScanTypeFull, scope.ScheduleTypeCron, "user1")
	sr.schedules[sched.ID().String()] = sched

	nextRun := time.Now().Add(6 * time.Hour)
	result, err := svc.RecordScheduleRun(context.Background(), sched.ID().String(), "completed", &nextRun)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result.LastRunStatus() != "completed" {
		t.Errorf("expected 'completed', got %s", result.LastRunStatus())
	}
	if result.LastRunAt() == nil {
		t.Error("expected non-nil LastRunAt")
	}
	if result.NextRunAt() == nil {
		t.Error("expected non-nil NextRunAt")
	}
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
		svc, tr, er, _, _ := newTestScopeService()
		target, _ := scope.NewTarget(tenantID, scope.TargetTypeDomain, "*.example.com", "", "user1")
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
		svc, tr, er, _, _ := newTestScopeService()
		target, _ := scope.NewTarget(tenantID, scope.TargetTypeDomain, "*.example.com", "", "user1")
		tr.targets[target.ID().String()] = target

		exc, _ := scope.NewExclusion(tenantID, scope.ExclusionTypeDomain, "internal.example.com", "Internal", nil, "user1")
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
		svc, tr, _, _, _ := newTestScopeService()
		target, _ := scope.NewTarget(tenantID, scope.TargetTypeDomain, "*.example.com", "", "user1")
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
		svc, _, _, _, _ := newTestScopeService()
		result, err := svc.CheckScope(context.Background(), tenantID.String(), "domain", "anything.com")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if result.InScope {
			t.Error("expected not in scope when no targets defined")
		}
	})

	t.Run("MultipleTargetsMatch", func(t *testing.T) {
		svc, tr, _, _, _ := newTestScopeService()
		t1, _ := scope.NewTarget(tenantID, scope.TargetTypeDomain, "*.example.com", "", "user1")
		t2, _ := scope.NewTarget(tenantID, scope.TargetTypeDomain, "api.example.com", "", "user1")
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
		svc, tr, _, _, _ := newTestScopeService()
		target, _ := scope.NewTarget(tenantID, scope.TargetTypeCIDR, "10.0.0.0/8", "", "user1")
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
		svc, _, _, _, _ := newTestScopeService()
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
	svc, tr, er, sr, _ := newTestScopeService()

	// Seed data
	t1, _ := scope.NewTarget(tenantID, scope.TargetTypeDomain, "example.com", "", "user1")
	t2, _ := scope.NewTarget(tenantID, scope.TargetTypeDomain, "test.com", "", "user1")
	t2.Deactivate()
	tr.targets[t1.ID().String()] = t1
	tr.targets[t2.ID().String()] = t2

	e1, _ := scope.NewExclusion(tenantID, scope.ExclusionTypeDomain, "internal.com", "reason", nil, "user1")
	er.exclusions[e1.ID().String()] = e1

	s1, _ := scope.NewSchedule(tenantID, "Schedule", scope.ScanTypeFull, scope.ScheduleTypeCron, "user1")
	sr.schedules[s1.ID().String()] = s1

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
	if stats.TotalSchedules != 1 {
		t.Errorf("expected 1 total schedule, got %d", stats.TotalSchedules)
	}
}

// TestScopeServiceListDueSchedules tests retrieving due schedules.
//
// Run with: go test -v ./tests/unit -run TestScopeServiceListDueSchedules
func TestScopeServiceListDueSchedules(t *testing.T) {
	svc, _, _, sr, _ := newTestScopeService()
	tenantID := shared.NewID()

	// Enabled schedule
	s1, _ := scope.NewSchedule(tenantID, "Active", scope.ScanTypeFull, scope.ScheduleTypeCron, "user1")
	sr.schedules[s1.ID().String()] = s1

	// Disabled schedule
	s2, _ := scope.NewSchedule(tenantID, "Disabled", scope.ScanTypeFull, scope.ScheduleTypeCron, "user1")
	s2.Disable()
	sr.schedules[s2.ID().String()] = s2

	due, err := svc.ListDueSchedules(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(due) != 1 {
		t.Errorf("expected 1 due schedule, got %d", len(due))
	}
}
