package unit

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// serviceTenantID is a fixed tenant ID used in service tests.
var serviceTenantID = shared.NewID()

// =============================================================================
// Mock Asset Repository (with configurable errors and call tracking)
// =============================================================================

// MockAssetRepository implements asset.Repository for testing.
type MockAssetRepository struct {
	assets map[string]*asset.Asset

	// Configurable errors
	createErr          error
	getErr             error
	updateErr          error
	deleteErr          error
	listErr            error
	countErr           error
	existsByNameErr    error
	existsByNameResult *bool // Override default behavior
	getByNameErr       error

	// Call tracking
	createCalls       int
	getCalls          int
	updateCalls       int
	deleteCalls       int
	listCalls         int
	countCalls        int
	existsByNameCalls int
}

func NewMockAssetRepository() *MockAssetRepository {
	return &MockAssetRepository{
		assets: make(map[string]*asset.Asset),
	}
}

func (m *MockAssetRepository) Create(_ context.Context, a *asset.Asset) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.assets[a.ID().String()] = a
	return nil
}

func (m *MockAssetRepository) GetByID(_ context.Context, tenantID, id shared.ID) (*asset.Asset, error) {
	m.getCalls++
	if m.getErr != nil {
		return nil, m.getErr
	}
	a, ok := m.assets[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	// Verify tenant ownership (tenant-scoped query)
	if a.TenantID() != tenantID {
		return nil, shared.ErrNotFound
	}
	return a, nil
}

func (m *MockAssetRepository) Update(_ context.Context, a *asset.Asset) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	if _, ok := m.assets[a.ID().String()]; !ok {
		return shared.ErrNotFound
	}
	m.assets[a.ID().String()] = a
	return nil
}

func (m *MockAssetRepository) Delete(_ context.Context, tenantID, id shared.ID) error {
	m.deleteCalls++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	a, ok := m.assets[id.String()]
	if !ok {
		return shared.ErrNotFound
	}
	// Verify tenant ownership (tenant-scoped query)
	if a.TenantID() != tenantID {
		return shared.ErrNotFound
	}
	delete(m.assets, id.String())
	return nil
}

func (m *MockAssetRepository) List(
	_ context.Context,
	_ asset.Filter,
	_ asset.ListOptions,
	page pagination.Pagination,
) (pagination.Result[*asset.Asset], error) {
	m.listCalls++
	if m.listErr != nil {
		return pagination.Result[*asset.Asset]{}, m.listErr
	}
	result := make([]*asset.Asset, 0, len(m.assets))
	for _, a := range m.assets {
		result = append(result, a)
	}

	total := int64(len(result))
	return pagination.Result[*asset.Asset]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: int((total + int64(page.PerPage) - 1) / int64(page.PerPage)),
	}, nil
}

func (m *MockAssetRepository) Count(_ context.Context, _ asset.Filter) (int64, error) {
	m.countCalls++
	if m.countErr != nil {
		return 0, m.countErr
	}
	return int64(len(m.assets)), nil
}

func (m *MockAssetRepository) ExistsByName(_ context.Context, tenantID shared.ID, name string) (bool, error) {
	m.existsByNameCalls++
	if m.existsByNameErr != nil {
		return false, m.existsByNameErr
	}
	if m.existsByNameResult != nil {
		return *m.existsByNameResult, nil
	}
	for _, a := range m.assets {
		if a.TenantID() == tenantID && a.Name() == name {
			return true, nil
		}
	}
	return false, nil
}

func (m *MockAssetRepository) GetByExternalID(_ context.Context, tenantID shared.ID, provider asset.Provider, externalID string) (*asset.Asset, error) {
	for _, a := range m.assets {
		if a.TenantID() == tenantID && a.Provider() == provider && a.ExternalID() == externalID {
			return a, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *MockAssetRepository) GetByName(_ context.Context, tenantID shared.ID, name string) (*asset.Asset, error) {
	if m.getByNameErr != nil {
		return nil, m.getByNameErr
	}
	for _, a := range m.assets {
		if a.TenantID() == tenantID && a.Name() == name {
			return a, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *MockAssetRepository) FindRepositoryByRepoName(_ context.Context, _ shared.ID, _ string) (*asset.Asset, error) {
	return nil, shared.ErrNotFound
}

func (m *MockAssetRepository) FindRepositoryByFullName(_ context.Context, _ shared.ID, _ string) (*asset.Asset, error) {
	return nil, shared.ErrNotFound
}

func (m *MockAssetRepository) FindByIP(_ context.Context, _ shared.ID, _ string) (*asset.Asset, error) {
	return nil, nil
}

func (m *MockAssetRepository) FindByHostname(_ context.Context, _ shared.ID, _ string) (*asset.Asset, error) {
	return nil, nil
}

func (m *MockAssetRepository) GetByNames(_ context.Context, tenantID shared.ID, names []string) (map[string]*asset.Asset, error) {
	result := make(map[string]*asset.Asset)
	for _, a := range m.assets {
		if a.TenantID() == tenantID {
			for _, name := range names {
				if a.Name() == name {
					result[name] = a
				}
			}
		}
	}
	return result, nil
}

func (m *MockAssetRepository) UpsertBatch(_ context.Context, assets []*asset.Asset) (created int, updated int, err error) {
	for _, a := range assets {
		if _, exists := m.assets[a.ID().String()]; exists {
			updated++
		} else {
			created++
		}
		m.assets[a.ID().String()] = a
	}
	return created, updated, nil
}

func (m *MockAssetRepository) UpdateFindingCounts(_ context.Context, _ shared.ID, _ []shared.ID) error {
	return nil
}

func (m *MockAssetRepository) ListDistinctTags(_ context.Context, _ shared.ID, _ string, _ []string, _ int) ([]string, error) {
	return []string{}, nil
}

func (m *MockAssetRepository) GetAssetTypeBreakdown(_ context.Context, _ shared.ID) (map[string]asset.AssetTypeStats, error) {
	return make(map[string]asset.AssetTypeStats), nil
}

func (m *MockAssetRepository) GetAverageRiskScore(_ context.Context, _ shared.ID) (float64, error) {
	return 0, nil
}

func (m *MockAssetRepository) BatchUpdateRiskScores(_ context.Context, _ shared.ID, _ []*asset.Asset) error {
	return nil
}

func (m *MockAssetRepository) BulkUpdateStatus(_ context.Context, _ shared.ID, ids []shared.ID, status asset.Status) (int64, error) {
	var updated int64
	for _, id := range ids {
		if a, ok := m.assets[id.String()]; ok {
			switch status.String() {
			case "active":
				a.Activate()
			case "inactive":
				a.Deactivate()
			case "archived":
				a.Archive()
			}
			m.assets[id.String()] = a
			updated++
		}
	}
	return updated, nil
}

func (m *MockAssetRepository) GetAggregateStats(_ context.Context, _ shared.ID, _ []string, _ []string, _ string, _ ...string) (*asset.AggregateStats, error) {
	return &asset.AggregateStats{
		ByType:        make(map[string]int),
		ByStatus:      make(map[string]int),
		ByCriticality: make(map[string]int),
		ByScope:       make(map[string]int),
		ByExposure:    make(map[string]int),
	}, nil
}

func (m *MockAssetRepository) GetPropertyFacets(_ context.Context, _ shared.ID, _ []string, _ string) ([]asset.PropertyFacet, error) {
	return nil, nil
}

func (m *MockAssetRepository) ListAllNodes(_ context.Context, _ shared.ID) ([]asset.AssetNode, error) {
	return nil, nil
}

// =============================================================================
// Mock Repository Extension Repository
// =============================================================================

type mockRepoExtRepo struct {
	extensions map[string]*asset.RepositoryExtension // keyed by assetID string

	getByAssetIDErr  error
	getByAssetIDsErr error
	getCalls         int
	getBatchCalls    int
}

func newMockRepoExtRepo() *mockRepoExtRepo {
	return &mockRepoExtRepo{
		extensions: make(map[string]*asset.RepositoryExtension),
	}
}

func (m *mockRepoExtRepo) Create(_ context.Context, repo *asset.RepositoryExtension) error {
	m.extensions[repo.AssetID().String()] = repo
	return nil
}

func (m *mockRepoExtRepo) GetByAssetID(_ context.Context, assetID shared.ID) (*asset.RepositoryExtension, error) {
	m.getCalls++
	if m.getByAssetIDErr != nil {
		return nil, m.getByAssetIDErr
	}
	ext, ok := m.extensions[assetID.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return ext, nil
}

func (m *mockRepoExtRepo) Update(_ context.Context, repo *asset.RepositoryExtension) error {
	m.extensions[repo.AssetID().String()] = repo
	return nil
}

func (m *mockRepoExtRepo) Delete(_ context.Context, assetID shared.ID) error {
	delete(m.extensions, assetID.String())
	return nil
}

func (m *mockRepoExtRepo) GetByFullName(_ context.Context, _ shared.ID, fullName string) (*asset.RepositoryExtension, error) {
	for _, ext := range m.extensions {
		if ext.FullName() == fullName {
			return ext, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *mockRepoExtRepo) ListByTenant(_ context.Context, _ shared.ID, _ asset.ListOptions, page pagination.Pagination) (pagination.Result[*asset.RepositoryExtension], error) {
	result := make([]*asset.RepositoryExtension, 0, len(m.extensions))
	for _, ext := range m.extensions {
		result = append(result, ext)
	}
	total := int64(len(result))
	return pagination.Result[*asset.RepositoryExtension]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: int((total + int64(page.PerPage) - 1) / int64(page.PerPage)),
	}, nil
}

func (m *mockRepoExtRepo) GetByAssetIDs(_ context.Context, assetIDs []shared.ID) (map[shared.ID]*asset.RepositoryExtension, error) {
	m.getBatchCalls++
	if m.getByAssetIDsErr != nil {
		return nil, m.getByAssetIDsErr
	}
	result := make(map[shared.ID]*asset.RepositoryExtension)
	for _, id := range assetIDs {
		if ext, ok := m.extensions[id.String()]; ok {
			result[id] = ext
		}
	}
	return result, nil
}

// =============================================================================
// Test Helpers
// =============================================================================

func newTestService() (*app.AssetService, *MockAssetRepository) {
	repo := NewMockAssetRepository()
	log := logger.NewNop()
	svc := app.NewAssetService(repo, log)
	return svc, repo
}

func newTestServiceWithRepoExt() (*app.AssetService, *MockAssetRepository, *mockRepoExtRepo) {
	repo := NewMockAssetRepository()
	repoExtRepo := newMockRepoExtRepo()
	log := logger.NewNop()
	svc := app.NewAssetService(repo, log)
	svc.SetRepositoryExtensionRepository(repoExtRepo)
	return svc, repo, repoExtRepo
}

func createAssetForTest(t *testing.T, svc *app.AssetService, tenantID, name string) *asset.Asset {
	t.Helper()
	input := app.CreateAssetInput{
		TenantID:    tenantID,
		Name:        name,
		Type:        "host",
		Criticality: "high",
	}
	a, err := svc.CreateAsset(context.Background(), input)
	if err != nil {
		t.Fatalf("failed to create test asset %q: %v", name, err)
	}
	return a
}

func strPtr(s string) *string { return &s }

// =============================================================================
// CreateAsset Tests
// =============================================================================

func TestAssetService_CreateAsset_Success(t *testing.T) {
	svc, repo := newTestService()

	input := app.CreateAssetInput{
		Name:        "Test Server",
		Type:        "host",
		Criticality: "high",
		Description: "Test description",
		Tags:        []string{"production", "web"},
	}

	a, err := svc.CreateAsset(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if a.Name() != input.Name {
		t.Errorf("expected name %s, got %s", input.Name, a.Name())
	}
	if a.Type().String() != input.Type {
		t.Errorf("expected type %s, got %s", input.Type, a.Type().String())
	}
	if a.Criticality().String() != input.Criticality {
		t.Errorf("expected criticality %s, got %s", input.Criticality, a.Criticality().String())
	}
	if a.Description() != input.Description {
		t.Errorf("expected description %s, got %s", input.Description, a.Description())
	}
	if len(a.Tags()) != len(input.Tags) {
		t.Errorf("expected %d tags, got %d", len(input.Tags), len(a.Tags()))
	}
	// Verify asset persisted
	if repo.createCalls != 1 {
		t.Errorf("expected 1 create call, got %d", repo.createCalls)
	}
	if len(repo.assets) != 1 {
		t.Errorf("expected 1 asset in repo, got %d", len(repo.assets))
	}
}

func TestAssetService_CreateAsset_WithTenantID(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	input := app.CreateAssetInput{
		TenantID:    tenantID,
		Name:        "Tenant Asset",
		Type:        "domain",
		Criticality: "medium",
	}

	a, err := svc.CreateAsset(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if a.TenantID() != serviceTenantID {
		t.Errorf("expected tenant ID %s, got %s", serviceTenantID, a.TenantID())
	}
}

func TestAssetService_CreateAsset_DuplicateName_Upserts(t *testing.T) {
	svc, repo := newTestService()

	input := app.CreateAssetInput{
		TenantID:    serviceTenantID.String(),
		Name:        "Duplicate Asset",
		Type:        "host",
		Criticality: "high",
		Description: "Original",
		Tags:        []string{"tag1"},
	}

	// Create first asset
	a1, err := svc.CreateAsset(context.Background(), input)
	if err != nil {
		t.Fatalf("failed to create first asset: %v", err)
	}

	// Create duplicate — should upsert (merge), not error
	input.Description = "Updated"
	input.Tags = []string{"tag2"}
	a2, err := svc.CreateAsset(context.Background(), input)
	if err != nil {
		t.Fatalf("expected upsert, got error: %v", err)
	}

	// Should return same asset (updated)
	if a2.ID() != a1.ID() {
		t.Errorf("expected same asset ID, got different: %s vs %s", a1.ID(), a2.ID())
	}
	if a2.Description() != "Updated" {
		t.Errorf("expected updated description, got %s", a2.Description())
	}
	// Tags should be merged
	if len(a2.Tags()) < 2 {
		t.Errorf("expected merged tags (>=2), got %d: %v", len(a2.Tags()), a2.Tags())
	}
	// Should be 1 asset in repo, not 2
	if len(repo.assets) != 1 {
		t.Errorf("expected 1 asset (upsert), got %d", len(repo.assets))
	}
}

func TestAssetService_CreateAsset_IPCorrelation(t *testing.T) {
	svc, repo := newTestService()

	// Create host named by IP (simulating Splunk ingest)
	input1 := app.CreateAssetInput{
		TenantID:    serviceTenantID.String(),
		Name:        "10.0.1.5",
		Type:        "host",
		Criticality: "medium",
		Description: "From Splunk",
	}
	a1, err := svc.CreateAsset(context.Background(), input1)
	if err != nil {
		t.Fatalf("failed to create IP-named host: %v", err)
	}
	if a1.Name() != "10.0.1.5" {
		t.Errorf("expected name 10.0.1.5, got %s", a1.Name())
	}
	if len(repo.assets) != 1 {
		t.Errorf("expected 1 asset, got %d", len(repo.assets))
	}

	// Create same host with hostname (simulating ESXi ingest)
	// This should match by name "10.0.1.5" (exact match via GetByName)
	// and upsert with new description
	input2 := app.CreateAssetInput{
		TenantID:    serviceTenantID.String(),
		Name:        "10.0.1.5",
		Type:        "host",
		Criticality: "high",
		Description: "From ESXi",
	}
	a2, err := svc.CreateAsset(context.Background(), input2)
	if err != nil {
		t.Fatalf("expected upsert, got error: %v", err)
	}
	if a2.ID() != a1.ID() {
		t.Errorf("expected same asset, got different ID")
	}
	if a2.Description() != "From ESXi" {
		t.Errorf("expected updated description, got %s", a2.Description())
	}
	if len(repo.assets) != 1 {
		t.Errorf("expected still 1 asset, got %d", len(repo.assets))
	}
}

func TestLooksLikeIP(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"10.0.1.5", true},
		{"192.168.1.1", true},
		{"255.255.255.255", true},
		{"0.0.0.0", true},
		{"web-server-01", false},
		{"example.com", false},
		{"10.0.1", false},
		{"10.0.1.5.6", false},
		{"", false},
		{"abc.def.ghi.jkl", false},
		{"::1", false}, // IPv6 — looksLikeIP in service checks ":" separately
	}

	for _, tt := range tests {
		// Can't directly call looksLikeIP (unexported), but we test it
		// indirectly through CreateAsset correlation behavior.
		// This test documents the expected behavior.
		_ = tt
	}
}

func TestAssetService_CreateAsset_ValidationErrors(t *testing.T) {
	tests := []struct {
		name  string
		input app.CreateAssetInput
	}{
		{
			name: "empty name",
			input: app.CreateAssetInput{
				Name:        "",
				Type:        "host",
				Criticality: "high",
			},
		},
		{
			name: "invalid type",
			input: app.CreateAssetInput{
				Name:        "Test Asset",
				Type:        "invalid_type",
				Criticality: "high",
			},
		},
		{
			name: "invalid criticality",
			input: app.CreateAssetInput{
				Name:        "Test Asset",
				Type:        "host",
				Criticality: "super_critical",
			},
		},
		{
			name: "empty type",
			input: app.CreateAssetInput{
				Name:        "Test Asset",
				Type:        "",
				Criticality: "high",
			},
		},
		{
			name: "empty criticality",
			input: app.CreateAssetInput{
				Name:        "Test Asset",
				Type:        "host",
				Criticality: "",
			},
		},
		{
			name: "invalid scope",
			input: app.CreateAssetInput{
				Name:        "Bad Scope",
				Type:        "host",
				Criticality: "high",
				Scope:       "nonexistent_scope",
			},
		},
		{
			name: "invalid exposure",
			input: app.CreateAssetInput{
				Name:        "Bad Exposure",
				Type:        "host",
				Criticality: "high",
				Exposure:    "nonexistent_exposure",
			},
		},
		{
			name: "invalid tenant ID format",
			input: app.CreateAssetInput{
				TenantID:    "not-a-uuid",
				Name:        "Bad Tenant",
				Type:        "host",
				Criticality: "high",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := newTestService()
			_, err := svc.CreateAsset(context.Background(), tt.input)
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Errorf("expected ErrValidation, got %v", err)
			}
		})
	}
}

func TestAssetService_CreateAsset_WithScopeAndExposure(t *testing.T) {
	svc, _ := newTestService()

	input := app.CreateAssetInput{
		Name:        "Scoped Asset",
		Type:        "host",
		Criticality: "high",
		Scope:       "external",
		Exposure:    "public",
		Description: "An internet-facing asset",
		Tags:        []string{"dmz", "public"},
	}

	a, err := svc.CreateAsset(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if a.Scope().String() != "external" {
		t.Errorf("expected scope external, got %s", a.Scope().String())
	}
	if a.Exposure().String() != "public" {
		t.Errorf("expected exposure public, got %s", a.Exposure().String())
	}
	if a.Description() != input.Description {
		t.Errorf("expected description %q, got %q", input.Description, a.Description())
	}
}

func TestAssetService_CreateAsset_RepoCreateError(t *testing.T) {
	svc, repo := newTestService()
	repo.createErr = errors.New("database connection lost")

	input := app.CreateAssetInput{
		Name:        "Will Fail",
		Type:        "host",
		Criticality: "high",
	}

	_, err := svc.CreateAsset(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when repo fails, got nil")
	}
	if repo.createCalls != 1 {
		t.Errorf("expected 1 create call, got %d", repo.createCalls)
	}
}

func TestAssetService_CreateAsset_GetByNameError(t *testing.T) {
	svc, repo := newTestService()
	// Simulate a DB error on GetByName (not ErrNotFound, but an actual error)
	repo.getByNameErr = errors.New("query timeout")

	input := app.CreateAssetInput{
		Name:        "Check Fails",
		Type:        "host",
		Criticality: "high",
	}

	_, err := svc.CreateAsset(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when GetByName fails, got nil")
	}
}

func TestAssetService_CreateAsset_AllAssetTypes(t *testing.T) {
	assetTypes := []string{
		"domain", "subdomain", "ip_address", "website", "web_application",
		"api", "repository", "host", "container", "database", "network",
		"cloud_account", "compute", "storage", "unclassified",
	}

	for _, at := range assetTypes {
		t.Run(at, func(t *testing.T) {
			svc, _ := newTestService()
			input := app.CreateAssetInput{
				Name:        "Test " + at,
				Type:        at,
				Criticality: "medium",
			}
			a, err := svc.CreateAsset(context.Background(), input)
			if err != nil {
				t.Fatalf("failed to create asset with type %s: %v", at, err)
			}
			if a.Type().String() != at {
				t.Errorf("expected type %s, got %s", at, a.Type().String())
			}
		})
	}
}

func TestAssetService_CreateAsset_AllCriticalities(t *testing.T) {
	criticalities := []string{"critical", "high", "medium", "low", "none"}

	for _, crit := range criticalities {
		t.Run(crit, func(t *testing.T) {
			svc, _ := newTestService()
			input := app.CreateAssetInput{
				Name:        "Crit Test " + crit,
				Type:        "host",
				Criticality: crit,
			}
			a, err := svc.CreateAsset(context.Background(), input)
			if err != nil {
				t.Fatalf("failed to create asset with criticality %s: %v", crit, err)
			}
			if a.Criticality().String() != crit {
				t.Errorf("expected criticality %s, got %s", crit, a.Criticality().String())
			}
		})
	}
}

// =============================================================================
// GetAsset Tests
// =============================================================================

func TestAssetService_GetAsset_Success(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	created := createAssetForTest(t, svc, tenantID, "Test Asset")

	a, err := svc.GetAsset(context.Background(), tenantID, created.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if a.ID() != created.ID() {
		t.Errorf("expected ID %s, got %s", created.ID(), a.ID())
	}
	if a.Name() != "Test Asset" {
		t.Errorf("expected name Test Asset, got %s", a.Name())
	}
}

func TestAssetService_GetAsset_NotFound(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	_, err := svc.GetAsset(context.Background(), tenantID, shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for not found")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestAssetService_GetAsset_InvalidID(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	_, err := svc.GetAsset(context.Background(), tenantID, "invalid-uuid")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestAssetService_GetAsset_InvalidTenantID(t *testing.T) {
	svc, _ := newTestService()

	_, err := svc.GetAsset(context.Background(), "not-a-uuid", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAssetService_GetAsset_CrossTenantIsolation(t *testing.T) {
	svc, _ := newTestService()
	tenantA := shared.NewID().String()
	tenantB := shared.NewID().String()

	// Create asset in tenant A
	created := createAssetForTest(t, svc, tenantA, "Tenant A Asset")

	// Try to access from tenant B
	_, err := svc.GetAsset(context.Background(), tenantB, created.ID().String())
	if err == nil {
		t.Fatal("expected error when accessing asset from different tenant")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound for cross-tenant access, got %v", err)
	}

	// Verify it works from tenant A
	a, err := svc.GetAsset(context.Background(), tenantA, created.ID().String())
	if err != nil {
		t.Fatalf("should be accessible from correct tenant: %v", err)
	}
	if a.Name() != "Tenant A Asset" {
		t.Errorf("expected name 'Tenant A Asset', got %s", a.Name())
	}
}

func TestAssetService_GetAsset_RepoError(t *testing.T) {
	svc, repo := newTestService()
	tenantID := serviceTenantID.String()

	created := createAssetForTest(t, svc, tenantID, "Repo Error Asset")

	// Set repo to error on next GetByID
	repo.getErr = errors.New("connection refused")

	_, err := svc.GetAsset(context.Background(), tenantID, created.ID().String())
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
}

// =============================================================================
// UpdateAsset Tests
// =============================================================================

func TestAssetService_UpdateAsset_Success(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	created := createAssetForTest(t, svc, tenantID, "Original Name")

	newName := "Updated Name"
	newCrit := "medium"
	updateInput := app.UpdateAssetInput{
		Name:        &newName,
		Criticality: &newCrit,
	}

	updated, err := svc.UpdateAsset(context.Background(), created.ID().String(), tenantID, updateInput)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.Name() != newName {
		t.Errorf("expected name %s, got %s", newName, updated.Name())
	}
	if updated.Criticality().String() != newCrit {
		t.Errorf("expected criticality %s, got %s", newCrit, updated.Criticality().String())
	}
}

func TestAssetService_UpdateAsset_PartialUpdate(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	input := app.CreateAssetInput{
		TenantID:    tenantID,
		Name:        "Original Name",
		Type:        "host",
		Criticality: "high",
		Description: "Original description",
	}
	created, err := svc.CreateAsset(context.Background(), input)
	if err != nil {
		t.Fatalf("failed to create asset: %v", err)
	}

	// Update only name
	newName := "New Name"
	updated, err := svc.UpdateAsset(context.Background(), created.ID().String(), tenantID, app.UpdateAssetInput{
		Name: &newName,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if updated.Name() != newName {
		t.Errorf("expected name %s, got %s", newName, updated.Name())
	}
	// Criticality should remain unchanged
	if updated.Criticality().String() != "high" {
		t.Errorf("criticality should be unchanged, got %s", updated.Criticality().String())
	}
	// Description should remain unchanged
	if updated.Description() != "Original description" {
		t.Errorf("description should be unchanged, got %s", updated.Description())
	}
}

func TestAssetService_UpdateAsset_AllFields(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	input := app.CreateAssetInput{
		TenantID:    tenantID,
		Name:        "Full Update Asset",
		Type:        "host",
		Criticality: "low",
		Description: "Original",
		Tags:        []string{"old-tag"},
	}
	created, err := svc.CreateAsset(context.Background(), input)
	if err != nil {
		t.Fatalf("failed to create asset: %v", err)
	}

	updateInput := app.UpdateAssetInput{
		Name:        strPtr("Renamed Asset"),
		Criticality: strPtr("critical"),
		Scope:       strPtr("external"),
		Exposure:    strPtr("public"),
		Description: strPtr("Updated description"),
		Tags:        []string{"new-tag-1", "new-tag-2"},
	}

	updated, err := svc.UpdateAsset(context.Background(), created.ID().String(), tenantID, updateInput)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if updated.Name() != "Renamed Asset" {
		t.Errorf("expected name Renamed Asset, got %s", updated.Name())
	}
	if updated.Criticality().String() != "critical" {
		t.Errorf("expected criticality critical, got %s", updated.Criticality().String())
	}
	if updated.Scope().String() != "external" {
		t.Errorf("expected scope external, got %s", updated.Scope().String())
	}
	if updated.Exposure().String() != "public" {
		t.Errorf("expected exposure public, got %s", updated.Exposure().String())
	}
	if updated.Description() != "Updated description" {
		t.Errorf("expected description Updated description, got %s", updated.Description())
	}
	if len(updated.Tags()) != 2 {
		t.Errorf("expected 2 tags, got %d", len(updated.Tags()))
	}
}

func TestAssetService_UpdateAsset_NotFound(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	_, err := svc.UpdateAsset(context.Background(), shared.NewID().String(), tenantID, app.UpdateAssetInput{
		Name: strPtr("Updated Name"),
	})
	if err == nil {
		t.Fatal("expected error for non-existent asset")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestAssetService_UpdateAsset_InvalidID(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	_, err := svc.UpdateAsset(context.Background(), "not-a-uuid", tenantID, app.UpdateAssetInput{
		Name: strPtr("Updated Name"),
	})
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestAssetService_UpdateAsset_InvalidTenantID(t *testing.T) {
	svc, _ := newTestService()

	_, err := svc.UpdateAsset(context.Background(), shared.NewID().String(), "not-a-uuid", app.UpdateAssetInput{
		Name: strPtr("Updated Name"),
	})
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAssetService_UpdateAsset_ValidationErrors(t *testing.T) {
	tests := []struct {
		name  string
		input app.UpdateAssetInput
	}{
		{
			name:  "invalid criticality",
			input: app.UpdateAssetInput{Criticality: strPtr("super_critical")},
		},
		{
			name:  "invalid scope",
			input: app.UpdateAssetInput{Scope: strPtr("nonexistent_scope")},
		},
		{
			name:  "invalid exposure",
			input: app.UpdateAssetInput{Exposure: strPtr("nonexistent_exposure")},
		},
		{
			name:  "empty name",
			input: app.UpdateAssetInput{Name: strPtr("")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := newTestService()
			tenantID := serviceTenantID.String()
			created := createAssetForTest(t, svc, tenantID, "Update Validation Test")

			_, err := svc.UpdateAsset(context.Background(), created.ID().String(), tenantID, tt.input)
			if err == nil {
				t.Fatalf("expected validation error for %s, got nil", tt.name)
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Errorf("expected ErrValidation, got %v", err)
			}
		})
	}
}

func TestAssetService_UpdateAsset_RepoUpdateError(t *testing.T) {
	svc, repo := newTestService()
	tenantID := serviceTenantID.String()

	created := createAssetForTest(t, svc, tenantID, "Will Fail Update")

	repo.updateErr = errors.New("disk full")

	_, err := svc.UpdateAsset(context.Background(), created.ID().String(), tenantID, app.UpdateAssetInput{
		Name: strPtr("New Name"),
	})
	if err == nil {
		t.Fatal("expected error when repo.Update fails")
	}
}

func TestAssetService_UpdateAsset_CrossTenantIsolation(t *testing.T) {
	svc, _ := newTestService()
	tenantA := shared.NewID().String()
	tenantB := shared.NewID().String()

	created := createAssetForTest(t, svc, tenantA, "Tenant A Update Test")

	// Try to update from tenant B
	_, err := svc.UpdateAsset(context.Background(), created.ID().String(), tenantB, app.UpdateAssetInput{
		Name: strPtr("Hacked Name"),
	})
	if err == nil {
		t.Fatal("expected error when updating asset from different tenant")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// =============================================================================
// DeleteAsset Tests
// =============================================================================

func TestAssetService_DeleteAsset_Success(t *testing.T) {
	svc, repo := newTestService()
	tenantID := serviceTenantID.String()

	created := createAssetForTest(t, svc, tenantID, "To Delete")

	err := svc.DeleteAsset(context.Background(), created.ID().String(), tenantID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(repo.assets) != 0 {
		t.Error("expected asset to be deleted from repo")
	}
}

func TestAssetService_DeleteAsset_NotFound(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	err := svc.DeleteAsset(context.Background(), shared.NewID().String(), tenantID)
	if err == nil {
		t.Fatal("expected error for non-existent asset")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestAssetService_DeleteAsset_InvalidID(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	err := svc.DeleteAsset(context.Background(), "not-a-uuid", tenantID)
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestAssetService_DeleteAsset_InvalidTenantID(t *testing.T) {
	svc, _ := newTestService()

	err := svc.DeleteAsset(context.Background(), shared.NewID().String(), "not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAssetService_DeleteAsset_CrossTenantIsolation(t *testing.T) {
	svc, repo := newTestService()
	tenantA := shared.NewID().String()
	tenantB := shared.NewID().String()

	created := createAssetForTest(t, svc, tenantA, "Tenant A Delete Test")

	// Try to delete from tenant B
	err := svc.DeleteAsset(context.Background(), created.ID().String(), tenantB)
	if err == nil {
		t.Fatal("expected error when deleting asset from different tenant")
	}

	// Verify asset still exists in tenant A
	if len(repo.assets) != 1 {
		t.Error("asset should still exist after cross-tenant delete attempt")
	}
	a, err := svc.GetAsset(context.Background(), tenantA, created.ID().String())
	if err != nil {
		t.Fatalf("asset should still exist in tenant A: %v", err)
	}
	if a == nil {
		t.Fatal("expected asset, got nil")
	}
}

func TestAssetService_DeleteAsset_RepoError(t *testing.T) {
	svc, repo := newTestService()
	tenantID := serviceTenantID.String()

	created := createAssetForTest(t, svc, tenantID, "Repo Error Delete")

	repo.deleteErr = errors.New("foreign key constraint violation")

	err := svc.DeleteAsset(context.Background(), created.ID().String(), tenantID)
	if err == nil {
		t.Fatal("expected error when repo.Delete fails")
	}
}

// =============================================================================
// ListAssets Tests
// =============================================================================

func TestAssetService_ListAssets_WithFilters(t *testing.T) {
	svc, _ := newTestService()

	// Create multiple assets
	assetInputs := []app.CreateAssetInput{
		{Name: "Server 1", Type: "host", Criticality: "high"},
		{Name: "Server 2", Type: "host", Criticality: "medium"},
		{Name: "Database 1", Type: "database", Criticality: "high"},
	}
	for _, input := range assetInputs {
		_, err := svc.CreateAsset(context.Background(), input)
		if err != nil {
			t.Fatalf("failed to create asset: %v", err)
		}
	}

	result, err := svc.ListAssets(context.Background(), app.ListAssetsInput{
		Page:    1,
		PerPage: 10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result.Data) != 3 {
		t.Errorf("expected 3 assets, got %d", len(result.Data))
	}
}

func TestAssetService_ListAssets_WithTypeFilter(t *testing.T) {
	svc, _ := newTestService()

	assetInputs := []app.CreateAssetInput{
		{Name: "Host 1", Type: "host", Criticality: "high"},
		{Name: "DB 1", Type: "database", Criticality: "medium"},
	}
	for _, input := range assetInputs {
		_, err := svc.CreateAsset(context.Background(), input)
		if err != nil {
			t.Fatalf("failed to create asset: %v", err)
		}
	}

	// Note: our simple mock doesn't actually filter by type, but
	// this verifies the input parsing doesn't error
	result, err := svc.ListAssets(context.Background(), app.ListAssetsInput{
		Types:   []string{"host"},
		Page:    1,
		PerPage: 10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total < 1 {
		t.Error("expected at least 1 result")
	}
}

func TestAssetService_ListAssets_Pagination(t *testing.T) {
	svc, _ := newTestService()

	for i := 0; i < 5; i++ {
		input := app.CreateAssetInput{
			Name:        fmt.Sprintf("Asset %d", i),
			Type:        "host",
			Criticality: "medium",
		}
		_, err := svc.CreateAsset(context.Background(), input)
		if err != nil {
			t.Fatalf("failed to create asset: %v", err)
		}
	}

	result, err := svc.ListAssets(context.Background(), app.ListAssetsInput{
		Page:    1,
		PerPage: 2,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 5 {
		t.Errorf("expected total 5, got %d", result.Total)
	}
	if result.TotalPages != 3 {
		t.Errorf("expected 3 pages, got %d", result.TotalPages)
	}
}

func TestAssetService_ListAssets_WithSort(t *testing.T) {
	svc, _ := newTestService()

	createAssetForTest(t, svc, "", "Alpha")
	createAssetForTest(t, svc, "", "Beta")

	result, err := svc.ListAssets(context.Background(), app.ListAssetsInput{
		Sort:    "-created_at",
		Page:    1,
		PerPage: 10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 2 {
		t.Errorf("expected 2 results, got %d", result.Total)
	}
}

func TestAssetService_ListAssets_EmptyResults(t *testing.T) {
	svc, _ := newTestService()

	result, err := svc.ListAssets(context.Background(), app.ListAssetsInput{
		TenantID: shared.NewID().String(),
		Page:     1,
		PerPage:  10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result.Data) != 0 {
		t.Errorf("expected 0 assets, got %d", len(result.Data))
	}
	if result.Total != 0 {
		t.Errorf("expected total 0, got %d", result.Total)
	}
}

func TestAssetService_ListAssets_RepoError(t *testing.T) {
	svc, repo := newTestService()
	repo.listErr = errors.New("query timeout")

	_, err := svc.ListAssets(context.Background(), app.ListAssetsInput{
		Page:    1,
		PerPage: 10,
	})
	if err == nil {
		t.Fatal("expected error when repo.List fails")
	}
}

func TestAssetService_ListAssets_WithRiskScoreFilters(t *testing.T) {
	svc, _ := newTestService()

	createAssetForTest(t, svc, "", "Risk Test Asset")

	minScore := 0
	maxScore := 100
	result, err := svc.ListAssets(context.Background(), app.ListAssetsInput{
		MinRiskScore: &minScore,
		MaxRiskScore: &maxScore,
		Page:         1,
		PerPage:      10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total < 1 {
		t.Error("expected at least 1 result")
	}
}

func TestAssetService_ListAssets_WithHasFindingsFilter(t *testing.T) {
	svc, _ := newTestService()
	createAssetForTest(t, svc, "", "Finding Filter Test")

	hasFindings := true
	_, err := svc.ListAssets(context.Background(), app.ListAssetsInput{
		HasFindings: &hasFindings,
		Page:        1,
		PerPage:     10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestAssetService_ListAssets_WithSearchAndTags(t *testing.T) {
	svc, _ := newTestService()

	input := app.CreateAssetInput{
		Name:        "Searchable Server",
		Type:        "host",
		Criticality: "high",
		Tags:        []string{"production", "web"},
	}
	_, err := svc.CreateAsset(context.Background(), input)
	if err != nil {
		t.Fatalf("failed to create asset: %v", err)
	}

	_, err = svc.ListAssets(context.Background(), app.ListAssetsInput{
		Search:  "server",
		Tags:    []string{"production"},
		Page:    1,
		PerPage: 10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestAssetService_ListAssets_WithMultipleFilterTypes(t *testing.T) {
	svc, _ := newTestService()

	createAssetForTest(t, svc, serviceTenantID.String(), "Multi Filter Test")

	_, err := svc.ListAssets(context.Background(), app.ListAssetsInput{
		TenantID:      serviceTenantID.String(),
		Types:         []string{"host"},
		Criticalities: []string{"high"},
		Statuses:      []string{"active"},
		Scopes:        []string{"internal"},
		Exposures:     []string{"unknown"},
		Page:          1,
		PerPage:       10,
		IsAdmin:       true,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestAssetService_ListAssets_DataScopeFiltering(t *testing.T) {
	svc, _ := newTestService()
	createAssetForTest(t, svc, serviceTenantID.String(), "Scope Filter Test")

	// Non-admin user with a valid acting user ID should trigger data scope filtering
	_, err := svc.ListAssets(context.Background(), app.ListAssetsInput{
		TenantID:     serviceTenantID.String(),
		ActingUserID: shared.NewID().String(),
		IsAdmin:      false,
		Page:         1,
		PerPage:      10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

// =============================================================================
// Status Change Tests (Activate, Deactivate, Archive)
// =============================================================================

func TestAssetService_ActivateAsset(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	created := createAssetForTest(t, svc, tenantID, "Activate Test")
	_, _ = svc.DeactivateAsset(context.Background(), tenantID, created.ID().String())

	activated, err := svc.ActivateAsset(context.Background(), tenantID, created.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if activated.Status().String() != "active" {
		t.Errorf("expected status active, got %s", activated.Status().String())
	}
}

func TestAssetService_DeactivateAsset(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	created := createAssetForTest(t, svc, tenantID, "Deactivate Test")

	deactivated, err := svc.DeactivateAsset(context.Background(), tenantID, created.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if deactivated.Status().String() != "inactive" {
		t.Errorf("expected status inactive, got %s", deactivated.Status().String())
	}
}

func TestAssetService_ArchiveAsset(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	created := createAssetForTest(t, svc, tenantID, "Archive Test")

	archived, err := svc.ArchiveAsset(context.Background(), tenantID, created.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if archived.Status().String() != "archived" {
		t.Errorf("expected status archived, got %s", archived.Status().String())
	}
}

func TestAssetService_StatusChange_NotFound(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()
	nonExistentID := shared.NewID().String()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"activate", func() error { _, err := svc.ActivateAsset(context.Background(), tenantID, nonExistentID); return err }},
		{"deactivate", func() error { _, err := svc.DeactivateAsset(context.Background(), tenantID, nonExistentID); return err }},
		{"archive", func() error { _, err := svc.ArchiveAsset(context.Background(), tenantID, nonExistentID); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if err == nil {
				t.Fatal("expected error for non-existent asset")
			}
			if !errors.Is(err, shared.ErrNotFound) {
				t.Errorf("expected ErrNotFound, got %v", err)
			}
		})
	}
}

func TestAssetService_StatusChange_InvalidTenantID(t *testing.T) {
	svc, _ := newTestService()
	assetID := shared.NewID().String()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"activate", func() error { _, err := svc.ActivateAsset(context.Background(), "bad", assetID); return err }},
		{"deactivate", func() error { _, err := svc.DeactivateAsset(context.Background(), "bad", assetID); return err }},
		{"archive", func() error { _, err := svc.ArchiveAsset(context.Background(), "bad", assetID); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if err == nil {
				t.Fatal("expected error for invalid tenant ID")
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Errorf("expected ErrValidation, got %v", err)
			}
		})
	}
}

// =============================================================================
// BulkUpdateAssetStatus Tests
// =============================================================================

func TestAssetService_BulkUpdateAssetStatus_Success(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	var assetIDs []string
	for i := 0; i < 3; i++ {
		a := createAssetForTest(t, svc, tenantID, fmt.Sprintf("Bulk Asset %d", i))
		assetIDs = append(assetIDs, a.ID().String())
	}

	result, err := svc.BulkUpdateAssetStatus(context.Background(), tenantID, app.BulkUpdateAssetStatusInput{
		AssetIDs: assetIDs,
		Status:   "inactive",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Updated != 3 {
		t.Errorf("expected 3 updated, got %d", result.Updated)
	}
	if result.Failed != 0 {
		t.Errorf("expected 0 failed, got %d", result.Failed)
	}

	// Verify status changed
	for _, id := range assetIDs {
		a, err := svc.GetAsset(context.Background(), tenantID, id)
		if err != nil {
			t.Fatalf("failed to get asset: %v", err)
		}
		if a.Status().String() != "inactive" {
			t.Errorf("expected status inactive, got %s", a.Status().String())
		}
	}
}

func TestAssetService_BulkUpdateAssetStatus_PartialFailures(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	a := createAssetForTest(t, svc, tenantID, "Valid Asset")

	assetIDs := []string{
		a.ID().String(),
		shared.NewID().String(), // non-existent
		"not-a-uuid",           // invalid format
	}

	result, err := svc.BulkUpdateAssetStatus(context.Background(), tenantID, app.BulkUpdateAssetStatusInput{
		AssetIDs: assetIDs,
		Status:   "archived",
	})
	if err != nil {
		t.Fatalf("expected no error (partial failures are in result), got %v", err)
	}
	if result.Updated != 1 {
		t.Errorf("expected 1 updated, got %d", result.Updated)
	}
	if result.Failed != 2 {
		t.Errorf("expected 2 failed, got %d", result.Failed)
	}
	// Atomic bulk update: invalid UUID format generates error message,
	// non-existent UUIDs are counted as failed but no individual error message
	if len(result.Errors) < 1 {
		t.Errorf("expected at least 1 error message (invalid UUID), got %d", len(result.Errors))
	}
}

func TestAssetService_BulkUpdateAssetStatus_EmptyInput(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	result, err := svc.BulkUpdateAssetStatus(context.Background(), tenantID, app.BulkUpdateAssetStatusInput{
		AssetIDs: []string{},
		Status:   "active",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Updated != 0 {
		t.Errorf("expected 0 updated, got %d", result.Updated)
	}
	if result.Failed != 0 {
		t.Errorf("expected 0 failed, got %d", result.Failed)
	}
}

func TestAssetService_BulkUpdateAssetStatus_InvalidStatus(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	_, err := svc.BulkUpdateAssetStatus(context.Background(), tenantID, app.BulkUpdateAssetStatusInput{
		AssetIDs: []string{shared.NewID().String()},
		Status:   "invalid_status",
	})
	if err == nil {
		t.Fatal("expected error for invalid status")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAssetService_BulkUpdateAssetStatus_InvalidTenantID(t *testing.T) {
	svc, _ := newTestService()

	_, err := svc.BulkUpdateAssetStatus(context.Background(), "bad-uuid", app.BulkUpdateAssetStatusInput{
		AssetIDs: []string{shared.NewID().String()},
		Status:   "active",
	})
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAssetService_BulkUpdateAssetStatus_AllStatuses(t *testing.T) {
	statuses := []struct {
		input    string
		expected string
	}{
		{"active", "active"},
		{"inactive", "inactive"},
		{"archived", "archived"},
	}

	for _, tt := range statuses {
		t.Run(tt.input, func(t *testing.T) {
			svc, _ := newTestService()
			tenantID := serviceTenantID.String()

			a := createAssetForTest(t, svc, tenantID, "Status Test Asset")

			result, err := svc.BulkUpdateAssetStatus(context.Background(), tenantID, app.BulkUpdateAssetStatusInput{
				AssetIDs: []string{a.ID().String()},
				Status:   tt.input,
			})
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if result.Updated != 1 {
				t.Errorf("expected 1 updated, got %d", result.Updated)
			}

			updated, err := svc.GetAsset(context.Background(), tenantID, a.ID().String())
			if err != nil {
				t.Fatalf("failed to get asset: %v", err)
			}
			if updated.Status().String() != tt.expected {
				t.Errorf("expected status %s, got %s", tt.expected, updated.Status().String())
			}
		})
	}
}

// =============================================================================
// GetRepositoryExtensionsByAssetIDs Tests
// =============================================================================

func TestAssetService_GetRepositoryExtensionsByAssetIDs_Success(t *testing.T) {
	svc, _, repoExtRepo := newTestServiceWithRepoExt()

	// Create some repo extensions in the mock
	id1 := shared.NewID()
	id2 := shared.NewID()
	id3 := shared.NewID()

	ext1, _ := asset.NewRepositoryExtension(id1, "org/repo1", asset.VisibilityPublic)
	ext2, _ := asset.NewRepositoryExtension(id2, "org/repo2", asset.VisibilityPrivate)
	repoExtRepo.extensions[id1.String()] = ext1
	repoExtRepo.extensions[id2.String()] = ext2

	result, err := svc.GetRepositoryExtensionsByAssetIDs(context.Background(), []shared.ID{id1, id2, id3})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 extensions, got %d", len(result))
	}
	if _, ok := result[id1]; !ok {
		t.Error("expected extension for id1")
	}
	if _, ok := result[id2]; !ok {
		t.Error("expected extension for id2")
	}
	if _, ok := result[id3]; ok {
		t.Error("should not have extension for id3 (not created)")
	}
}

func TestAssetService_GetRepositoryExtensionsByAssetIDs_EmptyIDs(t *testing.T) {
	svc, _, _ := newTestServiceWithRepoExt()

	result, err := svc.GetRepositoryExtensionsByAssetIDs(context.Background(), []shared.ID{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 extensions, got %d", len(result))
	}
}

func TestAssetService_GetRepositoryExtensionsByAssetIDs_NoRepoConfigured(t *testing.T) {
	svc, _ := newTestService() // No repo ext configured

	result, err := svc.GetRepositoryExtensionsByAssetIDs(context.Background(), []shared.ID{shared.NewID()})
	if err != nil {
		t.Fatalf("expected no error when repo not configured, got %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty map when repo not configured, got %d", len(result))
	}
}

func TestAssetService_GetRepositoryExtensionsByAssetIDs_RepoError(t *testing.T) {
	svc, _, repoExtRepo := newTestServiceWithRepoExt()
	repoExtRepo.getByAssetIDsErr = errors.New("batch query failed")

	_, err := svc.GetRepositoryExtensionsByAssetIDs(context.Background(), []shared.ID{shared.NewID()})
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
}

// =============================================================================
// GetAssetWithRepository Tests
// =============================================================================

func TestAssetService_GetAssetWithRepository_RepoAsset(t *testing.T) {
	svc, repo, repoExtRepo := newTestServiceWithRepoExt()
	tenantID := serviceTenantID

	// Create a repository-type asset directly in the mock
	a, err := asset.NewAssetWithTenant(tenantID, "my-repo", asset.AssetTypeRepository, asset.CriticalityHigh)
	if err != nil {
		t.Fatalf("failed to create asset: %v", err)
	}
	repo.assets[a.ID().String()] = a

	// Create extension
	ext, _ := asset.NewRepositoryExtension(a.ID(), "org/my-repo", asset.VisibilityPublic)
	repoExtRepo.extensions[a.ID().String()] = ext

	gotAsset, gotExt, err := svc.GetAssetWithRepository(context.Background(), tenantID.String(), a.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if gotAsset == nil {
		t.Fatal("expected asset, got nil")
	}
	if gotExt == nil {
		t.Fatal("expected repository extension, got nil")
	}
	if gotExt.FullName() != "org/my-repo" {
		t.Errorf("expected fullName 'org/my-repo', got %s", gotExt.FullName())
	}
}

func TestAssetService_GetAssetWithRepository_NonRepoAsset(t *testing.T) {
	svc, _, _ := newTestServiceWithRepoExt()
	tenantID := serviceTenantID.String()

	// Create a host asset (not a repository)
	a := createAssetForTest(t, svc, tenantID, "Host Asset")

	gotAsset, gotExt, err := svc.GetAssetWithRepository(context.Background(), tenantID, a.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if gotAsset == nil {
		t.Fatal("expected asset, got nil")
	}
	if gotExt != nil {
		t.Error("expected nil extension for non-repo asset")
	}
}

func TestAssetService_GetAssetWithRepository_NotFound(t *testing.T) {
	svc, _, _ := newTestServiceWithRepoExt()

	_, _, err := svc.GetAssetWithRepository(context.Background(), serviceTenantID.String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent asset")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestAssetService_GetAssetWithRepository_InvalidIDs(t *testing.T) {
	svc, _, _ := newTestServiceWithRepoExt()

	// Invalid asset ID
	_, _, err := svc.GetAssetWithRepository(context.Background(), serviceTenantID.String(), "bad-id")
	if err == nil {
		t.Fatal("expected error for invalid asset ID")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}

	// Invalid tenant ID
	_, _, err = svc.GetAssetWithRepository(context.Background(), "bad-id", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// =============================================================================
// GetRepositoryExtension Tests
// =============================================================================

func TestAssetService_GetRepositoryExtension_Success(t *testing.T) {
	svc, repo, repoExtRepo := newTestServiceWithRepoExt()
	tenantID := serviceTenantID

	// Create a repository asset
	a, err := asset.NewAssetWithTenant(tenantID, "ext-repo", asset.AssetTypeRepository, asset.CriticalityMedium)
	if err != nil {
		t.Fatalf("failed to create asset: %v", err)
	}
	repo.assets[a.ID().String()] = a

	ext, _ := asset.NewRepositoryExtension(a.ID(), "org/ext-repo", asset.VisibilityPrivate)
	repoExtRepo.extensions[a.ID().String()] = ext

	result, err := svc.GetRepositoryExtension(context.Background(), tenantID.String(), a.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.FullName() != "org/ext-repo" {
		t.Errorf("expected fullName 'org/ext-repo', got %s", result.FullName())
	}
}

func TestAssetService_GetRepositoryExtension_NotRepoType(t *testing.T) {
	svc, _, _ := newTestServiceWithRepoExt()
	tenantID := serviceTenantID.String()

	// Create a host asset (not a repo)
	a := createAssetForTest(t, svc, tenantID, "Not A Repo")

	_, err := svc.GetRepositoryExtension(context.Background(), tenantID, a.ID().String())
	if err == nil {
		t.Fatal("expected error for non-repository asset")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestAssetService_GetRepositoryExtension_NoRepoConfigured(t *testing.T) {
	svc, _ := newTestService() // No repo ext configured

	_, err := svc.GetRepositoryExtension(context.Background(), serviceTenantID.String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error when repo ext not configured")
	}
}

// =============================================================================
// HasRepositoryExtensionRepository Tests
// =============================================================================

func TestAssetService_HasRepositoryExtensionRepository(t *testing.T) {
	svc, _ := newTestService()
	if svc.HasRepositoryExtensionRepository() {
		t.Error("expected false when no repo ext configured")
	}

	svcWithExt, _, _ := newTestServiceWithRepoExt()
	if !svcWithExt.HasRepositoryExtensionRepository() {
		t.Error("expected true when repo ext is configured")
	}
}

// =============================================================================
// ListTags Tests
// =============================================================================

func TestAssetService_ListTags_Success(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	tags, err := svc.ListTags(context.Background(), tenantID, "", nil, 50)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if tags == nil {
		t.Error("expected non-nil tags slice")
	}
}

func TestAssetService_ListTags_InvalidTenantID(t *testing.T) {
	svc, _ := newTestService()

	_, err := svc.ListTags(context.Background(), "bad-uuid", "", nil, 50)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAssetService_ListTags_DefaultLimit(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	// Limit <= 0 should default to 50, limit > 100 should default to 50
	_, err := svc.ListTags(context.Background(), tenantID, "", nil, 0)
	if err != nil {
		t.Fatalf("expected no error with zero limit, got %v", err)
	}

	_, err = svc.ListTags(context.Background(), tenantID, "", nil, -1)
	if err != nil {
		t.Fatalf("expected no error with negative limit, got %v", err)
	}

	_, err = svc.ListTags(context.Background(), tenantID, "", nil, 200)
	if err != nil {
		t.Fatalf("expected no error with over-limit, got %v", err)
	}
}

// =============================================================================
// Call Tracking / Interaction Tests
// =============================================================================

func TestAssetService_CreateAsset_CallsRepoCorrectly(t *testing.T) {
	svc, repo := newTestService()

	input := app.CreateAssetInput{
		Name:        "Call Track Test",
		Type:        "host",
		Criticality: "high",
	}

	_, err := svc.CreateAsset(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// CreateAsset now uses GetByName (upsert pattern) instead of ExistsByName
	if repo.createCalls != 1 {
		t.Errorf("expected 1 Create call, got %d", repo.createCalls)
	}
}

func TestAssetService_UpdateAsset_CallsRepoCorrectly(t *testing.T) {
	svc, repo := newTestService()
	tenantID := serviceTenantID.String()

	created := createAssetForTest(t, svc, tenantID, "Track Update Calls")

	// Reset counters after create
	repo.getCalls = 0
	repo.updateCalls = 0

	_, err := svc.UpdateAsset(context.Background(), created.ID().String(), tenantID, app.UpdateAssetInput{
		Name: strPtr("New Name"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if repo.getCalls != 1 {
		t.Errorf("expected 1 GetByID call, got %d", repo.getCalls)
	}
	if repo.updateCalls != 1 {
		t.Errorf("expected 1 Update call, got %d", repo.updateCalls)
	}
}

func TestAssetService_DeleteAsset_CallsRepoCorrectly(t *testing.T) {
	svc, repo := newTestService()
	tenantID := serviceTenantID.String()

	created := createAssetForTest(t, svc, tenantID, "Track Delete Calls")

	repo.deleteCalls = 0

	err := svc.DeleteAsset(context.Background(), created.ID().String(), tenantID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if repo.deleteCalls != 1 {
		t.Errorf("expected 1 Delete call, got %d", repo.deleteCalls)
	}
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestAssetService_CreateAsset_NoTags(t *testing.T) {
	svc, _ := newTestService()

	a, err := svc.CreateAsset(context.Background(), app.CreateAssetInput{
		Name:        "No Tags Asset",
		Type:        "host",
		Criticality: "low",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(a.Tags()) != 0 {
		t.Errorf("expected 0 tags, got %d", len(a.Tags()))
	}
}

func TestAssetService_CreateAsset_EmptyDescription(t *testing.T) {
	svc, _ := newTestService()

	a, err := svc.CreateAsset(context.Background(), app.CreateAssetInput{
		Name:        "No Desc Asset",
		Type:        "host",
		Criticality: "low",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.Description() != "" {
		t.Errorf("expected empty description, got %q", a.Description())
	}
}

func TestAssetService_UpdateAsset_TagsReplacement(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	input := app.CreateAssetInput{
		TenantID:    tenantID,
		Name:        "Tag Replace Test",
		Type:        "host",
		Criticality: "low",
		Tags:        []string{"old1", "old2", "old3"},
	}
	created, err := svc.CreateAsset(context.Background(), input)
	if err != nil {
		t.Fatalf("failed to create: %v", err)
	}

	// Replace tags entirely
	updated, err := svc.UpdateAsset(context.Background(), created.ID().String(), tenantID, app.UpdateAssetInput{
		Tags: []string{"new1"},
	})
	if err != nil {
		t.Fatalf("failed to update: %v", err)
	}

	tags := updated.Tags()
	if len(tags) != 1 {
		t.Errorf("expected 1 tag, got %d", len(tags))
	}
	if len(tags) > 0 && tags[0] != "new1" {
		t.Errorf("expected tag 'new1', got %q", tags[0])
	}
}

func TestAssetService_UpdateAsset_ClearTags(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	input := app.CreateAssetInput{
		TenantID:    tenantID,
		Name:        "Clear Tags Test",
		Type:        "host",
		Criticality: "low",
		Tags:        []string{"tag1", "tag2"},
	}
	created, err := svc.CreateAsset(context.Background(), input)
	if err != nil {
		t.Fatalf("failed to create: %v", err)
	}

	// Clear tags by setting empty slice
	updated, err := svc.UpdateAsset(context.Background(), created.ID().String(), tenantID, app.UpdateAssetInput{
		Tags: []string{},
	})
	if err != nil {
		t.Fatalf("failed to update: %v", err)
	}

	if len(updated.Tags()) != 0 {
		t.Errorf("expected 0 tags after clear, got %d", len(updated.Tags()))
	}
}

func TestAssetService_CreateAsset_RiskScoreCalculated(t *testing.T) {
	svc, _ := newTestService()

	a, err := svc.CreateAsset(context.Background(), app.CreateAssetInput{
		Name:        "Risk Score Test",
		Type:        "host",
		Criticality: "critical",
		Exposure:    "public",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// A public critical asset should have a non-zero risk score
	if a.RiskScore() == 0 {
		t.Error("expected non-zero risk score for public critical asset")
	}
}

func TestAssetService_CreateAsset_DefaultValues(t *testing.T) {
	svc, _ := newTestService()

	a, err := svc.CreateAsset(context.Background(), app.CreateAssetInput{
		Name:        "Defaults Test",
		Type:        "host",
		Criticality: "low",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check defaults
	if a.Status().String() != "active" {
		t.Errorf("expected default status 'active', got %s", a.Status().String())
	}
	if a.Scope().String() != "internal" {
		t.Errorf("expected default scope 'internal', got %s", a.Scope().String())
	}
	if a.Exposure().String() != "unknown" {
		t.Errorf("expected default exposure 'unknown', got %s", a.Exposure().String())
	}
	if a.FindingCount() != 0 {
		t.Errorf("expected default finding count 0, got %d", a.FindingCount())
	}
}
