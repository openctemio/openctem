package unit

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// =============================================================================
// Mock Relationship Repository
// =============================================================================

// MockRelationshipRepository implements asset.RelationshipRepository for testing.
type MockRelationshipRepository struct {
	relationships map[string]*asset.Relationship
	withAssets    map[string]*asset.RelationshipWithAssets

	// Configurable errors
	createErr    error
	getByIDErr   error
	updateErr    error
	deleteErr    error
	listErr      error
	existsErr    error
	countErr     error
	batchErr     error
	existsResult *bool

	// Configurable returns
	listResult  []*asset.RelationshipWithAssets
	listTotal   int64
	countResult int64
	batchResult int

	// Call tracking
	createCalls  int
	getByIDCalls int
	updateCalls  int
	deleteCalls  int
	listCalls    int
	existsCalls  int
	countCalls   int
	batchCalls   int

	// Capture last call args
	lastCreateRel  *asset.Relationship
	lastUpdateRel  *asset.Relationship
	lastListFilter asset.RelationshipFilter
}

func NewMockRelationshipRepository() *MockRelationshipRepository {
	return &MockRelationshipRepository{
		relationships: make(map[string]*asset.Relationship),
		withAssets:    make(map[string]*asset.RelationshipWithAssets),
	}
}

func (m *MockRelationshipRepository) Create(_ context.Context, rel *asset.Relationship) error {
	m.createCalls++
	m.lastCreateRel = rel
	if m.createErr != nil {
		return m.createErr
	}
	m.relationships[rel.ID().String()] = rel
	// Auto-generate a RelationshipWithAssets for GetByID
	m.withAssets[rel.ID().String()] = &asset.RelationshipWithAssets{
		Relationship:    rel,
		SourceAssetName: "source-asset",
		SourceAssetType: asset.AssetTypeWebsite,
		TargetAssetName: "target-asset",
		TargetAssetType: asset.AssetTypeDomain,
	}
	return nil
}

func (m *MockRelationshipRepository) GetByID(_ context.Context, tenantID, id shared.ID) (*asset.RelationshipWithAssets, error) {
	m.getByIDCalls++
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	rwa, ok := m.withAssets[id.String()]
	if !ok {
		return nil, asset.ErrRelationshipNotFound
	}
	if rwa.Relationship.TenantID() != tenantID {
		return nil, asset.ErrRelationshipNotFound
	}
	return rwa, nil
}

func (m *MockRelationshipRepository) Update(_ context.Context, rel *asset.Relationship) error {
	m.updateCalls++
	m.lastUpdateRel = rel
	if m.updateErr != nil {
		return m.updateErr
	}
	m.relationships[rel.ID().String()] = rel
	return nil
}

func (m *MockRelationshipRepository) Delete(_ context.Context, tenantID, id shared.ID) error {
	m.deleteCalls++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	rwa, ok := m.withAssets[id.String()]
	if !ok {
		return asset.ErrRelationshipNotFound
	}
	if rwa.Relationship.TenantID() != tenantID {
		return asset.ErrRelationshipNotFound
	}
	delete(m.relationships, id.String())
	delete(m.withAssets, id.String())
	return nil
}

func (m *MockRelationshipRepository) ListByAsset(_ context.Context, tenantID, assetID shared.ID, filter asset.RelationshipFilter) ([]*asset.RelationshipWithAssets, int64, error) {
	m.listCalls++
	m.lastListFilter = filter
	if m.listErr != nil {
		return nil, 0, m.listErr
	}
	if m.listResult != nil {
		return m.listResult, m.listTotal, nil
	}
	// Return all relationships matching the asset
	result := make([]*asset.RelationshipWithAssets, 0)
	for _, rwa := range m.withAssets {
		rel := rwa.Relationship
		if rel.TenantID() != tenantID {
			continue
		}
		if rel.SourceAssetID() == assetID || rel.TargetAssetID() == assetID {
			result = append(result, rwa)
		}
	}
	return result, int64(len(result)), nil
}

func (m *MockRelationshipRepository) Exists(_ context.Context, _, _, _ shared.ID, _ asset.RelationshipType) (bool, error) {
	m.existsCalls++
	if m.existsErr != nil {
		return false, m.existsErr
	}
	if m.existsResult != nil {
		return *m.existsResult, nil
	}
	return false, nil
}

func (m *MockRelationshipRepository) CountByAsset(_ context.Context, _, _ shared.ID) (int64, error) {
	m.countCalls++
	if m.countErr != nil {
		return 0, m.countErr
	}
	return m.countResult, nil
}

func (m *MockRelationshipRepository) CreateBatchIgnoreConflicts(_ context.Context, rels []*asset.Relationship) (int, error) {
	m.batchCalls++
	if m.batchErr != nil {
		return 0, m.batchErr
	}
	for _, rel := range rels {
		m.relationships[rel.ID().String()] = rel
		m.withAssets[rel.ID().String()] = &asset.RelationshipWithAssets{
			Relationship:    rel,
			SourceAssetName: "batch-source",
			SourceAssetType: asset.AssetTypeWebsite,
			TargetAssetName: "batch-target",
			TargetAssetType: asset.AssetTypeDomain,
		}
	}
	if m.batchResult > 0 {
		return m.batchResult, nil
	}
	return len(rels), nil
}

// AddRelationshipWithAssets adds a pre-built RelationshipWithAssets to the mock store.
func (m *MockRelationshipRepository) AddRelationshipWithAssets(rwa *asset.RelationshipWithAssets) {
	m.relationships[rwa.Relationship.ID().String()] = rwa.Relationship
	m.withAssets[rwa.Relationship.ID().String()] = rwa
}

// =============================================================================
// Helpers
// =============================================================================

// relTestTenantID is a dedicated tenant ID for relationship tests (avoid conflict with serviceTenantID).
var relTestTenantID = shared.NewID()

func newRelTestLogger() *logger.Logger {
	return logger.NewNop()
}

// createRelTestAsset creates a test asset and adds it to the mock repo.
func createRelTestAsset(t *testing.T, repo *MockAssetRepository, tenantID shared.ID, name string) *asset.Asset {
	t.Helper()
	a, err := asset.NewAssetWithTenant(tenantID, name, asset.AssetTypeWebsite, asset.CriticalityMedium)
	if err != nil {
		t.Fatalf("failed to create test asset %q: %v", name, err)
	}
	repo.assets[a.ID().String()] = a
	return a
}

// buildRelationshipWithAssets builds a RelationshipWithAssets for testing.
func buildRelationshipWithAssets(
	tenantID, sourceID, targetID shared.ID,
	relType asset.RelationshipType,
) *asset.RelationshipWithAssets {
	now := time.Now().UTC()
	rel := asset.ReconstituteRelationship(
		shared.NewID(), tenantID, sourceID, targetID,
		relType, "test description",
		asset.ConfidenceMedium, asset.DiscoveryManual,
		5, []string{"test"}, nil, now, now,
	)
	return &asset.RelationshipWithAssets{
		Relationship:    rel,
		SourceAssetName: "source-asset",
		SourceAssetType: asset.AssetTypeWebsite,
		TargetAssetName: "target-asset",
		TargetAssetType: asset.AssetTypeDomain,
	}
}

// =============================================================================
// Tests: CreateRelationship
// =============================================================================

func TestAssetRelationshipService_CreateRelationship(t *testing.T) {
	ctx := context.Background()

	tenantID := relTestTenantID

	tests := []struct {
		name        string
		setupMocks  func(*MockRelationshipRepository, *MockAssetRepository)
		input       app.CreateRelationshipInput
		wantErr     bool
		errContains string
	}{
		{
			name: "success - basic relationship creation",
			setupMocks: func(relRepo *MockRelationshipRepository, assetRepo *MockAssetRepository) {
				createRelTestAsset(t, assetRepo, tenantID, "source-server")
				createRelTestAsset(t, assetRepo, tenantID, "target-server")
			},
			input: func() app.CreateRelationshipInput {
				assetRepo := NewMockAssetRepository()
				src := createRelTestAsset(t, assetRepo, tenantID, "source-server")
				tgt := createRelTestAsset(t, assetRepo, tenantID, "target-server")
				return app.CreateRelationshipInput{
					TenantID:      tenantID.String(),
					SourceAssetID: src.ID().String(),
					TargetAssetID: tgt.ID().String(),
					Type:          "runs_on",
				}
			}(),
			wantErr: true, // Assets won't be found because input uses different assets than setupMocks
		},
		{
			name: "success - all relationship types are accepted",
		},
		{
			name: "error - invalid tenant ID",
			input: app.CreateRelationshipInput{
				TenantID:      "not-a-uuid",
				SourceAssetID: shared.NewID().String(),
				TargetAssetID: shared.NewID().String(),
				Type:          "runs_on",
			},
			wantErr:     true,
			errContains: "invalid tenant ID",
		},
		{
			name: "error - invalid source asset ID",
			input: app.CreateRelationshipInput{
				TenantID:      tenantID.String(),
				SourceAssetID: "bad-id",
				TargetAssetID: shared.NewID().String(),
				Type:          "runs_on",
			},
			wantErr:     true,
			errContains: "invalid source asset ID",
		},
		{
			name: "error - invalid target asset ID",
			input: app.CreateRelationshipInput{
				TenantID:      tenantID.String(),
				SourceAssetID: shared.NewID().String(),
				TargetAssetID: "bad-id",
				Type:          "runs_on",
			},
			wantErr:     true,
			errContains: "invalid target asset ID",
		},
		{
			name: "error - invalid relationship type",
			input: app.CreateRelationshipInput{
				TenantID:      tenantID.String(),
				SourceAssetID: shared.NewID().String(),
				TargetAssetID: shared.NewID().String(),
				Type:          "invalid_type",
			},
			wantErr:     true,
			errContains: "invalid relationship type",
		},
		{
			name: "error - source asset not found",
			input: app.CreateRelationshipInput{
				TenantID:      tenantID.String(),
				SourceAssetID: shared.NewID().String(),
				TargetAssetID: shared.NewID().String(),
				Type:          "runs_on",
			},
			wantErr:     true,
			errContains: "source asset",
		},
		{
			name: "error - repo create failure",
			setupMocks: func(relRepo *MockRelationshipRepository, _ *MockAssetRepository) {
				relRepo.createErr = fmt.Errorf("db connection lost")
			},
			wantErr:     true,
			errContains: "failed to create relationship",
		},
		{
			name: "error - repo GetByID failure after create",
			setupMocks: func(relRepo *MockRelationshipRepository, _ *MockAssetRepository) {
				relRepo.getByIDErr = fmt.Errorf("fetch error after create")
			},
			wantErr:     true,
			errContains: "failed to fetch created relationship",
		},
		{
			name:    "error - invalid confidence",
			wantErr: true,
		},
		{
			name:    "error - invalid discovery method",
			wantErr: true,
		},
		{
			name:    "error - invalid impact weight (too low)",
			wantErr: true,
		},
		{
			name:    "error - invalid impact weight (too high)",
			wantErr: true,
		},
	}

	// Skip placeholder test cases and run the detailed ones
	_ = tests

	// =========================================================================
	// Detailed table-driven tests with proper setup
	// =========================================================================

	t.Run("success/basic_creation", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		src := createRelTestAsset(t, assetRepo, tenantID, "web-app")
		tgt := createRelTestAsset(t, assetRepo, tenantID, "db-server")

		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		result, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
			TenantID:      tenantID.String(),
			SourceAssetID: src.ID().String(),
			TargetAssetID: tgt.ID().String(),
			Type:          "depends_on",
			Description:   "Web app depends on database",
			Confidence:    "high",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if relRepo.createCalls != 1 {
			t.Errorf("expected 1 create call, got %d", relRepo.createCalls)
		}
		if relRepo.getByIDCalls != 1 {
			t.Errorf("expected 1 getByID call, got %d", relRepo.getByIDCalls)
		}
	})

	t.Run("success/all_optional_fields", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		src := createRelTestAsset(t, assetRepo, tenantID, "api-service")
		tgt := createRelTestAsset(t, assetRepo, tenantID, "auth-service")

		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		weight := 8
		result, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
			TenantID:        tenantID.String(),
			SourceAssetID:   src.ID().String(),
			TargetAssetID:   tgt.ID().String(),
			Type:            "authenticates_to",
			Description:     "API authenticates via auth service",
			Confidence:      "high",
			DiscoveryMethod: "automatic",
			ImpactWeight:    &weight,
			Tags:            []string{"auth", "critical-path"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		// Verify the created relationship has the correct fields
		createdRel := relRepo.lastCreateRel
		if createdRel == nil {
			t.Fatal("expected lastCreateRel to be set")
		}
		if createdRel.Confidence() != asset.ConfidenceHigh {
			t.Errorf("expected confidence high, got %s", createdRel.Confidence())
		}
		if createdRel.DiscoveryMethod() != asset.DiscoveryAutomatic {
			t.Errorf("expected discovery automatic, got %s", createdRel.DiscoveryMethod())
		}
		if createdRel.ImpactWeight() != 8 {
			t.Errorf("expected impact weight 8, got %d", createdRel.ImpactWeight())
		}
		tags := createdRel.Tags()
		if len(tags) != 2 {
			t.Errorf("expected 2 tags, got %d", len(tags))
		}
	})

	t.Run("error/invalid_tenant_id", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		_, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
			TenantID:      "not-a-uuid",
			SourceAssetID: shared.NewID().String(),
			TargetAssetID: shared.NewID().String(),
			Type:          "runs_on",
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got %v", err)
		}
	})

	t.Run("error/invalid_source_asset_id", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		_, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
			TenantID:      tenantID.String(),
			SourceAssetID: "bad-uuid",
			TargetAssetID: shared.NewID().String(),
			Type:          "runs_on",
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got %v", err)
		}
	})

	t.Run("error/invalid_target_asset_id", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		_, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
			TenantID:      tenantID.String(),
			SourceAssetID: shared.NewID().String(),
			TargetAssetID: "bad-uuid",
			Type:          "runs_on",
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got %v", err)
		}
	})

	t.Run("error/invalid_relationship_type", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		_, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
			TenantID:      tenantID.String(),
			SourceAssetID: shared.NewID().String(),
			TargetAssetID: shared.NewID().String(),
			Type:          "invalid_type_xyz",
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got %v", err)
		}
	})

	t.Run("error/source_asset_not_found", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		_, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
			TenantID:      tenantID.String(),
			SourceAssetID: shared.NewID().String(), // does not exist in repo
			TargetAssetID: shared.NewID().String(),
			Type:          "runs_on",
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if assetRepo.getCalls != 1 {
			t.Errorf("expected 1 GetByID call for source, got %d", assetRepo.getCalls)
		}
	})

	t.Run("error/target_asset_not_found", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		src := createRelTestAsset(t, assetRepo, tenantID, "existing-source")
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		_, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
			TenantID:      tenantID.String(),
			SourceAssetID: src.ID().String(),
			TargetAssetID: shared.NewID().String(), // does not exist
			Type:          "runs_on",
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if assetRepo.getCalls != 2 {
			t.Errorf("expected 2 GetByID calls (source + target), got %d", assetRepo.getCalls)
		}
	})

	t.Run("error/repo_create_failure", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		relRepo.createErr = fmt.Errorf("database connection lost")
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		src := createRelTestAsset(t, assetRepo, tenantID, "src-asset")
		tgt := createRelTestAsset(t, assetRepo, tenantID, "tgt-asset")
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		_, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
			TenantID:      tenantID.String(),
			SourceAssetID: src.ID().String(),
			TargetAssetID: tgt.ID().String(),
			Type:          "depends_on",
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("error/repo_fetch_after_create_failure", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		src := createRelTestAsset(t, assetRepo, tenantID, "src-post-create")
		tgt := createRelTestAsset(t, assetRepo, tenantID, "tgt-post-create")

		// Let create succeed, but GetByID fails
		relRepo.getByIDErr = fmt.Errorf("fetch error")
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		_, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
			TenantID:      tenantID.String(),
			SourceAssetID: src.ID().String(),
			TargetAssetID: tgt.ID().String(),
			Type:          "exposes",
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("error/invalid_confidence", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		src := createRelTestAsset(t, assetRepo, tenantID, "src-conf")
		tgt := createRelTestAsset(t, assetRepo, tenantID, "tgt-conf")
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		_, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
			TenantID:      tenantID.String(),
			SourceAssetID: src.ID().String(),
			TargetAssetID: tgt.ID().String(),
			Type:          "runs_on",
			Confidence:    "super_high",
		})
		if err == nil {
			t.Fatal("expected error for invalid confidence")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got %v", err)
		}
	})

	t.Run("error/invalid_discovery_method", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		src := createRelTestAsset(t, assetRepo, tenantID, "src-disc")
		tgt := createRelTestAsset(t, assetRepo, tenantID, "tgt-disc")
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		_, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
			TenantID:        tenantID.String(),
			SourceAssetID:   src.ID().String(),
			TargetAssetID:   tgt.ID().String(),
			Type:             "runs_on",
			DiscoveryMethod: "telepathy",
		})
		if err == nil {
			t.Fatal("expected error for invalid discovery method")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got %v", err)
		}
	})

	t.Run("error/impact_weight_too_low", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		src := createRelTestAsset(t, assetRepo, tenantID, "src-wt-low")
		tgt := createRelTestAsset(t, assetRepo, tenantID, "tgt-wt-low")
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		weight := 0
		_, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
			TenantID:      tenantID.String(),
			SourceAssetID: src.ID().String(),
			TargetAssetID: tgt.ID().String(),
			Type:          "runs_on",
			ImpactWeight:  &weight,
		})
		if err == nil {
			t.Fatal("expected error for impact weight 0")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got %v", err)
		}
	})

	t.Run("error/impact_weight_too_high", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		src := createRelTestAsset(t, assetRepo, tenantID, "src-wt-high")
		tgt := createRelTestAsset(t, assetRepo, tenantID, "tgt-wt-high")
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		weight := 11
		_, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
			TenantID:      tenantID.String(),
			SourceAssetID: src.ID().String(),
			TargetAssetID: tgt.ID().String(),
			Type:          "runs_on",
			ImpactWeight:  &weight,
		})
		if err == nil {
			t.Fatal("expected error for impact weight 11")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got %v", err)
		}
	})

	t.Run("error/cross_tenant_source_asset", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		otherTenant := shared.NewID()
		src := createRelTestAsset(t, assetRepo, otherTenant, "other-tenant-asset")
		tgt := createRelTestAsset(t, assetRepo, tenantID, "my-asset")
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		_, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
			TenantID:      tenantID.String(),
			SourceAssetID: src.ID().String(),
			TargetAssetID: tgt.ID().String(),
			Type:          "depends_on",
		})
		if err == nil {
			t.Fatal("expected error for cross-tenant asset access")
		}
	})

	t.Run("error/cross_tenant_target_asset", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		otherTenant := shared.NewID()
		src := createRelTestAsset(t, assetRepo, tenantID, "my-source")
		tgt := createRelTestAsset(t, assetRepo, otherTenant, "other-target")
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		_, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
			TenantID:      tenantID.String(),
			SourceAssetID: src.ID().String(),
			TargetAssetID: tgt.ID().String(),
			Type:          "depends_on",
		})
		if err == nil {
			t.Fatal("expected error for cross-tenant target asset access")
		}
	})
}

// =============================================================================
// Tests: All 16 CTEM Relationship Types
// =============================================================================

func TestAssetRelationshipService_AllRelationshipTypes(t *testing.T) {
	ctx := context.Background()
	tenantID := relTestTenantID

	allTypes := []struct {
		name    string
		relType string
	}{
		// Attack Surface Mapping
		{"runs_on", "runs_on"},
		{"deployed_to", "deployed_to"},
		{"contains", "contains"},
		{"exposes", "exposes"},
		{"member_of", "member_of"},
		{"resolves_to", "resolves_to"},
		// Attack Path Analysis
		{"depends_on", "depends_on"},
		{"sends_data_to", "sends_data_to"},
		{"stores_data_in", "stores_data_in"},
		{"authenticates_to", "authenticates_to"},
		{"granted_to", "granted_to"},
		{"load_balances", "load_balances"},
		// Control & Ownership
		{"protected_by", "protected_by"},
		{"monitors", "monitors"},
		{"manages", "manages"},
		{"owned_by", "owned_by"},
	}

	for _, tc := range allTypes {
		t.Run(tc.name, func(t *testing.T) {
			relRepo := NewMockRelationshipRepository()
			assetRepo := NewMockAssetRepository()
			log := newRelTestLogger()

			src := createRelTestAsset(t, assetRepo, tenantID, fmt.Sprintf("src-%s", tc.name))
			tgt := createRelTestAsset(t, assetRepo, tenantID, fmt.Sprintf("tgt-%s", tc.name))
			svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

			result, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
				TenantID:      tenantID.String(),
				SourceAssetID: src.ID().String(),
				TargetAssetID: tgt.ID().String(),
				Type:          tc.relType,
			})
			if err != nil {
				t.Fatalf("relationship type %q should be valid, got error: %v", tc.relType, err)
			}
			if result == nil {
				t.Fatalf("expected non-nil result for type %q", tc.relType)
			}
			if relRepo.createCalls != 1 {
				t.Errorf("expected 1 create call for type %q, got %d", tc.relType, relRepo.createCalls)
			}
		})
	}

	// Verify exactly 16 types tested
	if len(allTypes) != 16 {
		t.Errorf("expected 16 relationship types, got %d", len(allTypes))
	}
}

// =============================================================================
// Tests: GetRelationship
// =============================================================================

func TestAssetRelationshipService_GetRelationship(t *testing.T) {
	ctx := context.Background()
	tenantID := relTestTenantID

	t.Run("success", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		sourceID := shared.NewID()
		targetID := shared.NewID()
		rwa := buildRelationshipWithAssets(tenantID, sourceID, targetID, asset.RelTypeDependsOn)
		relRepo.AddRelationshipWithAssets(rwa)

		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		result, err := svc.GetRelationship(ctx, tenantID.String(), rwa.Relationship.ID().String())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Relationship.ID() != rwa.Relationship.ID() {
			t.Errorf("expected ID %s, got %s", rwa.Relationship.ID(), result.Relationship.ID())
		}
	})

	t.Run("error/invalid_tenant_id", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		_, err := svc.GetRelationship(ctx, "bad-uuid", shared.NewID().String())
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got %v", err)
		}
	})

	t.Run("error/invalid_relationship_id", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		_, err := svc.GetRelationship(ctx, tenantID.String(), "bad-uuid")
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("error/not_found", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		_, err := svc.GetRelationship(ctx, tenantID.String(), shared.NewID().String())
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("error/cross_tenant_isolation", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		otherTenantID := shared.NewID()
		rwa := buildRelationshipWithAssets(otherTenantID, shared.NewID(), shared.NewID(), asset.RelTypeContains)
		relRepo.AddRelationshipWithAssets(rwa)

		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		// Try to access with a different tenant ID
		_, err := svc.GetRelationship(ctx, tenantID.String(), rwa.Relationship.ID().String())
		if err == nil {
			t.Fatal("expected error for cross-tenant access")
		}
	})

	t.Run("error/repo_failure", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		relRepo.getByIDErr = fmt.Errorf("database timeout")
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		_, err := svc.GetRelationship(ctx, tenantID.String(), shared.NewID().String())
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

// =============================================================================
// Tests: UpdateRelationship
// =============================================================================

func TestAssetRelationshipService_UpdateRelationship(t *testing.T) {
	ctx := context.Background()
	tenantID := relTestTenantID

	t.Run("success/update_description", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		rwa := buildRelationshipWithAssets(tenantID, shared.NewID(), shared.NewID(), asset.RelTypeDependsOn)
		relRepo.AddRelationshipWithAssets(rwa)

		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		desc := "updated description"
		result, err := svc.UpdateRelationship(ctx, tenantID.String(), rwa.Relationship.ID().String(), app.UpdateRelationshipInput{
			Description: &desc,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if relRepo.updateCalls != 1 {
			t.Errorf("expected 1 update call, got %d", relRepo.updateCalls)
		}
	})

	t.Run("success/update_confidence", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		rwa := buildRelationshipWithAssets(tenantID, shared.NewID(), shared.NewID(), asset.RelTypeExposes)
		relRepo.AddRelationshipWithAssets(rwa)

		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		confidence := "high"
		result, err := svc.UpdateRelationship(ctx, tenantID.String(), rwa.Relationship.ID().String(), app.UpdateRelationshipInput{
			Confidence: &confidence,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})

	t.Run("success/update_impact_weight", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		rwa := buildRelationshipWithAssets(tenantID, shared.NewID(), shared.NewID(), asset.RelTypeRunsOn)
		relRepo.AddRelationshipWithAssets(rwa)

		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		weight := 9
		result, err := svc.UpdateRelationship(ctx, tenantID.String(), rwa.Relationship.ID().String(), app.UpdateRelationshipInput{
			ImpactWeight: &weight,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})

	t.Run("success/update_tags", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		rwa := buildRelationshipWithAssets(tenantID, shared.NewID(), shared.NewID(), asset.RelTypeMonitors)
		relRepo.AddRelationshipWithAssets(rwa)

		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		result, err := svc.UpdateRelationship(ctx, tenantID.String(), rwa.Relationship.ID().String(), app.UpdateRelationshipInput{
			Tags: []string{"monitoring", "soc"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})

	t.Run("success/mark_verified", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		rwa := buildRelationshipWithAssets(tenantID, shared.NewID(), shared.NewID(), asset.RelTypeProtectedBy)
		relRepo.AddRelationshipWithAssets(rwa)

		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		result, err := svc.UpdateRelationship(ctx, tenantID.String(), rwa.Relationship.ID().String(), app.UpdateRelationshipInput{
			MarkVerified: true,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		// Verify that the relationship entity was verified
		updatedRel := relRepo.lastUpdateRel
		if updatedRel == nil {
			t.Fatal("expected lastUpdateRel to be set")
		}
		if updatedRel.LastVerified() == nil {
			t.Error("expected LastVerified to be set after MarkVerified")
		}
	})

	t.Run("success/update_all_fields_at_once", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		rwa := buildRelationshipWithAssets(tenantID, shared.NewID(), shared.NewID(), asset.RelTypeManages)
		relRepo.AddRelationshipWithAssets(rwa)

		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		desc := "fully updated"
		conf := "low"
		weight := 2
		result, err := svc.UpdateRelationship(ctx, tenantID.String(), rwa.Relationship.ID().String(), app.UpdateRelationshipInput{
			Description:  &desc,
			Confidence:   &conf,
			ImpactWeight: &weight,
			Tags:         []string{"new-tag"},
			MarkVerified: true,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})

	t.Run("error/invalid_tenant_id", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		_, err := svc.UpdateRelationship(ctx, "bad-uuid", shared.NewID().String(), app.UpdateRelationshipInput{})
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got %v", err)
		}
	})

	t.Run("error/invalid_relationship_id", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		_, err := svc.UpdateRelationship(ctx, tenantID.String(), "bad-uuid", app.UpdateRelationshipInput{})
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("error/relationship_not_found", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		desc := "nope"
		_, err := svc.UpdateRelationship(ctx, tenantID.String(), shared.NewID().String(), app.UpdateRelationshipInput{
			Description: &desc,
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("error/invalid_confidence_on_update", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		rwa := buildRelationshipWithAssets(tenantID, shared.NewID(), shared.NewID(), asset.RelTypeOwnedBy)
		relRepo.AddRelationshipWithAssets(rwa)

		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		badConf := "super_duper"
		_, err := svc.UpdateRelationship(ctx, tenantID.String(), rwa.Relationship.ID().String(), app.UpdateRelationshipInput{
			Confidence: &badConf,
		})
		if err == nil {
			t.Fatal("expected error for invalid confidence")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got %v", err)
		}
	})

	t.Run("error/invalid_impact_weight_on_update", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		rwa := buildRelationshipWithAssets(tenantID, shared.NewID(), shared.NewID(), asset.RelTypeGrantedTo)
		relRepo.AddRelationshipWithAssets(rwa)

		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		badWeight := 99
		_, err := svc.UpdateRelationship(ctx, tenantID.String(), rwa.Relationship.ID().String(), app.UpdateRelationshipInput{
			ImpactWeight: &badWeight,
		})
		if err == nil {
			t.Fatal("expected error for invalid impact weight")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got %v", err)
		}
	})

	t.Run("error/repo_update_failure", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		rwa := buildRelationshipWithAssets(tenantID, shared.NewID(), shared.NewID(), asset.RelTypeSendsDataTo)
		relRepo.AddRelationshipWithAssets(rwa)
		relRepo.updateErr = fmt.Errorf("write conflict")

		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		desc := "will fail"
		_, err := svc.UpdateRelationship(ctx, tenantID.String(), rwa.Relationship.ID().String(), app.UpdateRelationshipInput{
			Description: &desc,
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("error/cross_tenant_update", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		otherTenant := shared.NewID()
		rwa := buildRelationshipWithAssets(otherTenant, shared.NewID(), shared.NewID(), asset.RelTypeContains)
		relRepo.AddRelationshipWithAssets(rwa)

		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		desc := "cross tenant attempt"
		_, err := svc.UpdateRelationship(ctx, tenantID.String(), rwa.Relationship.ID().String(), app.UpdateRelationshipInput{
			Description: &desc,
		})
		if err == nil {
			t.Fatal("expected error for cross-tenant update")
		}
	})
}

// =============================================================================
// Tests: DeleteRelationship
// =============================================================================

func TestAssetRelationshipService_DeleteRelationship(t *testing.T) {
	ctx := context.Background()
	tenantID := relTestTenantID

	t.Run("success", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		rwa := buildRelationshipWithAssets(tenantID, shared.NewID(), shared.NewID(), asset.RelTypeDependsOn)
		relRepo.AddRelationshipWithAssets(rwa)

		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		err := svc.DeleteRelationship(ctx, tenantID.String(), rwa.Relationship.ID().String())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if relRepo.deleteCalls != 1 {
			t.Errorf("expected 1 delete call, got %d", relRepo.deleteCalls)
		}
	})

	t.Run("error/invalid_tenant_id", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		err := svc.DeleteRelationship(ctx, "bad-uuid", shared.NewID().String())
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got %v", err)
		}
	})

	t.Run("error/invalid_relationship_id", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		err := svc.DeleteRelationship(ctx, tenantID.String(), "bad-uuid")
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("error/not_found", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		err := svc.DeleteRelationship(ctx, tenantID.String(), shared.NewID().String())
		if err == nil {
			t.Fatal("expected error for non-existent relationship")
		}
	})

	t.Run("error/repo_failure", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		relRepo.deleteErr = fmt.Errorf("constraint violation")
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		err := svc.DeleteRelationship(ctx, tenantID.String(), shared.NewID().String())
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("error/cross_tenant_delete", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		otherTenant := shared.NewID()
		rwa := buildRelationshipWithAssets(otherTenant, shared.NewID(), shared.NewID(), asset.RelTypeLoadBalances)
		relRepo.AddRelationshipWithAssets(rwa)

		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		err := svc.DeleteRelationship(ctx, tenantID.String(), rwa.Relationship.ID().String())
		if err == nil {
			t.Fatal("expected error for cross-tenant delete")
		}
	})
}

// =============================================================================
// Tests: ListAssetRelationships
// =============================================================================

func TestAssetRelationshipService_ListAssetRelationships(t *testing.T) {
	ctx := context.Background()
	tenantID := relTestTenantID

	t.Run("success/returns_relationships", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		assetID := shared.NewID()
		targetID := shared.NewID()

		rwa1 := buildRelationshipWithAssets(tenantID, assetID, targetID, asset.RelTypeDependsOn)
		rwa2 := buildRelationshipWithAssets(tenantID, assetID, shared.NewID(), asset.RelTypeExposes)
		relRepo.AddRelationshipWithAssets(rwa1)
		relRepo.AddRelationshipWithAssets(rwa2)

		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		results, total, err := svc.ListAssetRelationships(ctx, tenantID.String(), assetID.String(), asset.RelationshipFilter{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if total != 2 {
			t.Errorf("expected total 2, got %d", total)
		}
		if len(results) != 2 {
			t.Errorf("expected 2 results, got %d", len(results))
		}
		if relRepo.listCalls != 1 {
			t.Errorf("expected 1 list call, got %d", relRepo.listCalls)
		}
	})

	t.Run("success/empty_result", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		results, total, err := svc.ListAssetRelationships(ctx, tenantID.String(), shared.NewID().String(), asset.RelationshipFilter{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if total != 0 {
			t.Errorf("expected total 0, got %d", total)
		}
		if len(results) != 0 {
			t.Errorf("expected 0 results, got %d", len(results))
		}
	})

	t.Run("success/with_filter", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		assetID := shared.NewID()
		rwa := buildRelationshipWithAssets(tenantID, assetID, shared.NewID(), asset.RelTypeRunsOn)
		relRepo.AddRelationshipWithAssets(rwa)

		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		filter := asset.RelationshipFilter{
			Types:       []asset.RelationshipType{asset.RelTypeRunsOn},
			Confidences: []asset.RelationshipConfidence{asset.ConfidenceMedium},
			Direction:   "outgoing",
			Page:        1,
			PerPage:     20,
		}

		_, _, err := svc.ListAssetRelationships(ctx, tenantID.String(), assetID.String(), filter)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify the filter was passed through
		if len(relRepo.lastListFilter.Types) != 1 || relRepo.lastListFilter.Types[0] != asset.RelTypeRunsOn {
			t.Errorf("expected filter type runs_on, got %v", relRepo.lastListFilter.Types)
		}
		if relRepo.lastListFilter.Direction != "outgoing" {
			t.Errorf("expected direction outgoing, got %s", relRepo.lastListFilter.Direction)
		}
	})

	t.Run("success/with_preconfigured_list_result", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		// Use preconfigured list result
		rwa := buildRelationshipWithAssets(tenantID, shared.NewID(), shared.NewID(), asset.RelTypeStoresDataIn)
		relRepo.listResult = []*asset.RelationshipWithAssets{rwa}
		relRepo.listTotal = 1

		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		results, total, err := svc.ListAssetRelationships(ctx, tenantID.String(), shared.NewID().String(), asset.RelationshipFilter{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if total != 1 {
			t.Errorf("expected total 1, got %d", total)
		}
		if len(results) != 1 {
			t.Errorf("expected 1 result, got %d", len(results))
		}
	})

	t.Run("error/invalid_tenant_id", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		_, _, err := svc.ListAssetRelationships(ctx, "bad-uuid", shared.NewID().String(), asset.RelationshipFilter{})
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected ErrValidation, got %v", err)
		}
	})

	t.Run("error/invalid_asset_id", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		_, _, err := svc.ListAssetRelationships(ctx, tenantID.String(), "bad-uuid", asset.RelationshipFilter{})
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("error/repo_failure", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		relRepo.listErr = fmt.Errorf("query timeout")
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		_, _, err := svc.ListAssetRelationships(ctx, tenantID.String(), shared.NewID().String(), asset.RelationshipFilter{})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

// =============================================================================
// Tests: Confidence and Discovery Method Validation
// =============================================================================

func TestAssetRelationshipService_ConfidenceLevels(t *testing.T) {
	ctx := context.Background()
	tenantID := relTestTenantID

	confidenceLevels := []struct {
		name  string
		value string
		valid bool
	}{
		{"high", "high", true},
		{"medium", "medium", true},
		{"low", "low", true},
		{"empty_string_uses_default", "", true},
		{"invalid", "extreme", false},
		{"numeric", "5", false},
		{"uppercase_accepted", "HIGH", true},
	}

	for _, tc := range confidenceLevels {
		t.Run(tc.name, func(t *testing.T) {
			relRepo := NewMockRelationshipRepository()
			assetRepo := NewMockAssetRepository()
			log := newRelTestLogger()

			src := createRelTestAsset(t, assetRepo, tenantID, fmt.Sprintf("src-conf-%s", tc.name))
			tgt := createRelTestAsset(t, assetRepo, tenantID, fmt.Sprintf("tgt-conf-%s", tc.name))
			svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

			_, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
				TenantID:      tenantID.String(),
				SourceAssetID: src.ID().String(),
				TargetAssetID: tgt.ID().String(),
				Type:          "depends_on",
				Confidence:    tc.value,
			})
			if tc.valid && err != nil {
				t.Errorf("expected confidence %q to be valid, got error: %v", tc.value, err)
			}
			if !tc.valid && err == nil {
				t.Errorf("expected confidence %q to be invalid, but got no error", tc.value)
			}
		})
	}
}

func TestAssetRelationshipService_DiscoveryMethods(t *testing.T) {
	ctx := context.Background()
	tenantID := relTestTenantID

	discoveryMethods := []struct {
		name  string
		value string
		valid bool
	}{
		{"automatic", "automatic", true},
		{"manual", "manual", true},
		{"imported", "imported", true},
		{"inferred", "inferred", true},
		{"empty_string_uses_default", "", true},
		{"invalid", "guessed", false},
		{"uppercase_accepted", "AUTOMATIC", true},
	}

	for _, tc := range discoveryMethods {
		t.Run(tc.name, func(t *testing.T) {
			relRepo := NewMockRelationshipRepository()
			assetRepo := NewMockAssetRepository()
			log := newRelTestLogger()

			src := createRelTestAsset(t, assetRepo, tenantID, fmt.Sprintf("src-disc-%s", tc.name))
			tgt := createRelTestAsset(t, assetRepo, tenantID, fmt.Sprintf("tgt-disc-%s", tc.name))
			svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

			_, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
				TenantID:        tenantID.String(),
				SourceAssetID:   src.ID().String(),
				TargetAssetID:   tgt.ID().String(),
				Type:            "monitors",
				DiscoveryMethod: tc.value,
			})
			if tc.valid && err != nil {
				t.Errorf("expected discovery method %q to be valid, got error: %v", tc.value, err)
			}
			if !tc.valid && err == nil {
				t.Errorf("expected discovery method %q to be invalid, but got no error", tc.value)
			}
		})
	}
}

// =============================================================================
// Tests: Impact Weight Boundary Values
// =============================================================================

func TestAssetRelationshipService_ImpactWeightBoundaries(t *testing.T) {
	ctx := context.Background()
	tenantID := relTestTenantID

	weights := []struct {
		name  string
		value int
		valid bool
	}{
		{"zero_invalid", 0, false},
		{"one_valid_min", 1, true},
		{"five_valid_mid", 5, true},
		{"ten_valid_max", 10, true},
		{"eleven_invalid", 11, false},
		{"negative_invalid", -1, false},
		{"hundred_invalid", 100, false},
	}

	for _, tc := range weights {
		t.Run(tc.name, func(t *testing.T) {
			relRepo := NewMockRelationshipRepository()
			assetRepo := NewMockAssetRepository()
			log := newRelTestLogger()

			src := createRelTestAsset(t, assetRepo, tenantID, fmt.Sprintf("src-wt-%s", tc.name))
			tgt := createRelTestAsset(t, assetRepo, tenantID, fmt.Sprintf("tgt-wt-%s", tc.name))
			svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

			_, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
				TenantID:      tenantID.String(),
				SourceAssetID: src.ID().String(),
				TargetAssetID: tgt.ID().String(),
				Type:          "contains",
				ImpactWeight:  &tc.value,
			})
			if tc.valid && err != nil {
				t.Errorf("expected weight %d to be valid, got error: %v", tc.value, err)
			}
			if !tc.valid && err == nil {
				t.Errorf("expected weight %d to be invalid, but got no error", tc.value)
			}
		})
	}
}

// =============================================================================
// Tests: Edge Cases
// =============================================================================

func TestAssetRelationshipService_EdgeCases(t *testing.T) {
	ctx := context.Background()
	tenantID := relTestTenantID

	t.Run("create_with_nil_tags", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		src := createRelTestAsset(t, assetRepo, tenantID, "src-nil-tags")
		tgt := createRelTestAsset(t, assetRepo, tenantID, "tgt-nil-tags")
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		result, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
			TenantID:      tenantID.String(),
			SourceAssetID: src.ID().String(),
			TargetAssetID: tgt.ID().String(),
			Type:          "runs_on",
			Tags:          nil,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})

	t.Run("create_with_empty_tags", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		src := createRelTestAsset(t, assetRepo, tenantID, "src-empty-tags")
		tgt := createRelTestAsset(t, assetRepo, tenantID, "tgt-empty-tags")
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		result, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
			TenantID:      tenantID.String(),
			SourceAssetID: src.ID().String(),
			TargetAssetID: tgt.ID().String(),
			Type:          "deployed_to",
			Tags:          []string{},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})

	t.Run("create_with_empty_description", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		src := createRelTestAsset(t, assetRepo, tenantID, "src-no-desc")
		tgt := createRelTestAsset(t, assetRepo, tenantID, "tgt-no-desc")
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		result, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
			TenantID:      tenantID.String(),
			SourceAssetID: src.ID().String(),
			TargetAssetID: tgt.ID().String(),
			Type:          "resolves_to",
			Description:   "",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})

	t.Run("update_with_empty_input_is_noop", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		rwa := buildRelationshipWithAssets(tenantID, shared.NewID(), shared.NewID(), asset.RelTypeMemberOf)
		relRepo.AddRelationshipWithAssets(rwa)

		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		result, err := svc.UpdateRelationship(ctx, tenantID.String(), rwa.Relationship.ID().String(), app.UpdateRelationshipInput{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		// Update should still be called (the service persists regardless)
		if relRepo.updateCalls != 1 {
			t.Errorf("expected 1 update call, got %d", relRepo.updateCalls)
		}
	})

	t.Run("list_with_all_filter_options", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		minWeight := 3
		maxWeight := 8
		filter := asset.RelationshipFilter{
			Types:            []asset.RelationshipType{asset.RelTypeDependsOn, asset.RelTypeRunsOn},
			Confidences:      []asset.RelationshipConfidence{asset.ConfidenceHigh, asset.ConfidenceMedium},
			DiscoveryMethods: []asset.RelationshipDiscoveryMethod{asset.DiscoveryAutomatic, asset.DiscoveryManual},
			Tags:             []string{"critical", "production"},
			MinImpactWeight:  &minWeight,
			MaxImpactWeight:  &maxWeight,
			Direction:        "incoming",
			Page:             2,
			PerPage:          50,
		}

		_, _, err := svc.ListAssetRelationships(ctx, tenantID.String(), shared.NewID().String(), filter)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify filter was passed through correctly
		lf := relRepo.lastListFilter
		if len(lf.Types) != 2 {
			t.Errorf("expected 2 types in filter, got %d", len(lf.Types))
		}
		if len(lf.Confidences) != 2 {
			t.Errorf("expected 2 confidences in filter, got %d", len(lf.Confidences))
		}
		if len(lf.DiscoveryMethods) != 2 {
			t.Errorf("expected 2 discovery methods in filter, got %d", len(lf.DiscoveryMethods))
		}
		if len(lf.Tags) != 2 {
			t.Errorf("expected 2 tags in filter, got %d", len(lf.Tags))
		}
		if lf.MinImpactWeight == nil || *lf.MinImpactWeight != 3 {
			t.Errorf("expected min impact weight 3, got %v", lf.MinImpactWeight)
		}
		if lf.MaxImpactWeight == nil || *lf.MaxImpactWeight != 8 {
			t.Errorf("expected max impact weight 8, got %v", lf.MaxImpactWeight)
		}
		if lf.Direction != "incoming" {
			t.Errorf("expected direction incoming, got %s", lf.Direction)
		}
		if lf.Page != 2 {
			t.Errorf("expected page 2, got %d", lf.Page)
		}
		if lf.PerPage != 50 {
			t.Errorf("expected per_page 50, got %d", lf.PerPage)
		}
	})

	t.Run("relationship_type_case_insensitive", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		src := createRelTestAsset(t, assetRepo, tenantID, "src-case")
		tgt := createRelTestAsset(t, assetRepo, tenantID, "tgt-case")
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		// Should accept UPPERCASE type and normalize to lowercase
		result, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
			TenantID:      tenantID.String(),
			SourceAssetID: src.ID().String(),
			TargetAssetID: tgt.ID().String(),
			Type:          "RUNS_ON",
		})
		if err != nil {
			t.Fatalf("expected uppercase type to be accepted, got error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})

	t.Run("relationship_type_with_whitespace", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		src := createRelTestAsset(t, assetRepo, tenantID, "src-ws")
		tgt := createRelTestAsset(t, assetRepo, tenantID, "tgt-ws")
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		// Should trim whitespace
		result, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
			TenantID:      tenantID.String(),
			SourceAssetID: src.ID().String(),
			TargetAssetID: tgt.ID().String(),
			Type:          "  depends_on  ",
		})
		if err != nil {
			t.Fatalf("expected trimmed type to be accepted, got error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})
}

// =============================================================================
// Tests: Multi-Tenant Isolation (comprehensive)
// =============================================================================

func TestAssetRelationshipService_TenantIsolation(t *testing.T) {
	ctx := context.Background()
	tenantA := shared.NewID()
	tenantB := shared.NewID()

	t.Run("cannot_create_relationship_between_different_tenant_assets", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		srcA := createRelTestAsset(t, assetRepo, tenantA, "tenant-a-asset")
		tgtB := createRelTestAsset(t, assetRepo, tenantB, "tenant-b-asset")
		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		// Source belongs to tenantA, but we query under tenantA
		// Target belongs to tenantB, so GetByID(tenantA, tgtB) should fail
		_, err := svc.CreateRelationship(ctx, app.CreateRelationshipInput{
			TenantID:      tenantA.String(),
			SourceAssetID: srcA.ID().String(),
			TargetAssetID: tgtB.ID().String(),
			Type:          "depends_on",
		})
		if err == nil {
			t.Fatal("expected error when creating relationship with cross-tenant assets")
		}
	})

	t.Run("cannot_get_other_tenants_relationship", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		rwa := buildRelationshipWithAssets(tenantA, shared.NewID(), shared.NewID(), asset.RelTypeDependsOn)
		relRepo.AddRelationshipWithAssets(rwa)

		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		_, err := svc.GetRelationship(ctx, tenantB.String(), rwa.Relationship.ID().String())
		if err == nil {
			t.Fatal("expected error when accessing another tenant's relationship")
		}
	})

	t.Run("cannot_update_other_tenants_relationship", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		rwa := buildRelationshipWithAssets(tenantA, shared.NewID(), shared.NewID(), asset.RelTypeContains)
		relRepo.AddRelationshipWithAssets(rwa)

		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		desc := "hacked"
		_, err := svc.UpdateRelationship(ctx, tenantB.String(), rwa.Relationship.ID().String(), app.UpdateRelationshipInput{
			Description: &desc,
		})
		if err == nil {
			t.Fatal("expected error when updating another tenant's relationship")
		}
	})

	t.Run("cannot_delete_other_tenants_relationship", func(t *testing.T) {
		relRepo := NewMockRelationshipRepository()
		assetRepo := NewMockAssetRepository()
		log := newRelTestLogger()

		rwa := buildRelationshipWithAssets(tenantA, shared.NewID(), shared.NewID(), asset.RelTypeExposes)
		relRepo.AddRelationshipWithAssets(rwa)

		svc := app.NewAssetRelationshipService(relRepo, assetRepo, log)

		err := svc.DeleteRelationship(ctx, tenantB.String(), rwa.Relationship.ID().String())
		if err == nil {
			t.Fatal("expected error when deleting another tenant's relationship")
		}
	})
}
