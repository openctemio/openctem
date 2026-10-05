package unit

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
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

func (m *MockAssetRepository) GetDisplayInfoByIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]asset.DisplayInfo, error) {
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

func (m *MockAssetRepository) Delete(_ context.Context, tenantID, id shared.ID, _ *shared.ID) error {
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

func (m *MockAssetRepository) UpsertBatch(_ context.Context, assets []*asset.Asset) (created int, updated int, persistedIDs map[string]shared.ID, err error) {
	persistedIDs = make(map[string]shared.ID, len(assets))
	for _, a := range assets {
		if _, exists := m.assets[a.ID().String()]; exists {
			updated++
		} else {
			created++
		}
		m.assets[a.ID().String()] = a
		persistedIDs[a.Name()] = a.ID()
	}
	return created, updated, persistedIDs, nil
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

func (m *MockAssetRepository) GetAggregateStats(_ context.Context, _ shared.ID, _ asset.AccessScope, _ []string, _ []string, _ string, _ ...string) (*asset.AggregateStats, error) {
	return &asset.AggregateStats{
		ByType:        make(map[string]int),
		ByStatus:      make(map[string]int),
		ByCriticality: make(map[string]int),
		ByScope:       make(map[string]int),
		ByExposure:    make(map[string]int),
	}, nil
}

func (m *MockAssetRepository) GetPropertyFacets(_ context.Context, _ shared.ID, _ asset.AccessScope, _ []string, _ string) ([]asset.PropertyFacet, error) {
	return nil, nil
}

func (m *MockAssetRepository) SetCrownJewel(_ context.Context, tenantID, id shared.ID, isCrownJewel bool, score float64, notes string) error {
	a, ok := m.assets[id.String()]
	if !ok || a.TenantID() != tenantID {
		return shared.ErrNotFound
	}
	a.SetCrownJewel(isCrownJewel)
	props := a.Properties()
	if props == nil {
		props = map[string]any{}
	}
	props["business_impact_score"] = score
	props["business_impact_notes"] = notes
	a.SetProperties(props)
	return nil
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

func newTestService() (*assetapp.AssetService, *MockAssetRepository) {
	repo := NewMockAssetRepository()
	log := logger.NewNop()
	svc := assetapp.NewAssetService(repo, log)
	return svc, repo
}

func newTestServiceWithRepoExt() (*assetapp.AssetService, *MockAssetRepository, *mockRepoExtRepo) {
	repo := NewMockAssetRepository()
	repoExtRepo := newMockRepoExtRepo()
	log := logger.NewNop()
	svc := assetapp.NewAssetService(repo, log)
	svc.SetRepositoryExtensionRepository(repoExtRepo)
	return svc, repo, repoExtRepo
}

func createAssetForTest(t *testing.T, svc *assetapp.AssetService, tenantID, name string) *asset.Asset {
	t.Helper()
	input := assetapp.CreateAssetInput{
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

	input := assetapp.CreateAssetInput{
		Name:        "test-server-01",
		Type:        "host",
		Criticality: "high",
		Description: "Test description",
		Tags:        []string{"production", "web"},
	}

	a, err := svc.CreateAsset(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if a.Name() != asset.NormalizeName(input.Name, asset.AssetType(input.Type), "") {
		t.Errorf("expected name %s, got %s", asset.NormalizeName(input.Name, asset.AssetType(input.Type), ""), a.Name())
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

	input := assetapp.CreateAssetInput{
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

func TestAssetService_CreateAsset_DuplicateName_IsConflict(t *testing.T) {
	svc, repo := newTestService()

	input := assetapp.CreateAssetInput{
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

	// A second create of the same name is a conflict that names the existing
	// asset (no data scope is wired: the caller sees everything) and changes
	// nothing.
	input.Description = "Updated"
	input.Tags = []string{"tag2"}
	_, err = svc.CreateAsset(context.Background(), input)
	var dup *assetapp.DuplicateAssetError
	if !errors.As(err, &dup) || !errors.Is(err, shared.ErrAlreadyExists) {
		t.Fatalf("duplicate create error = %v, want a DuplicateAssetError", err)
	}
	if dup.ExistingID != a1.ID() {
		t.Errorf("conflict names %s, want the existing asset %s", dup.ExistingID, a1.ID())
	}
	if got := repo.assets[a1.ID().String()]; got == nil || got.Description() == "Updated" || len(got.Tags()) != len(a1.Tags()) {
		t.Errorf("duplicate create changed the existing asset")
	}
	if len(repo.assets) != 1 {
		t.Errorf("expected 1 asset, got %d", len(repo.assets))
	}
}

func TestAssetService_CreateAsset_IPCorrelation_IsConflict(t *testing.T) {
	svc, repo := newTestService()

	// A host named by IP (for example from a Splunk import).
	a1, err := svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
		TenantID:    serviceTenantID.String(),
		Name:        "10.0.1.5",
		Type:        "host",
		Criticality: "medium",
		Description: "From Splunk",
	})
	if err != nil {
		t.Fatalf("failed to create IP-named host: %v", err)
	}

	// The same address again is the same asset: a conflict naming it.
	_, err = svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
		TenantID:    serviceTenantID.String(),
		Name:        "10.0.1.5",
		Type:        "host",
		Criticality: "high",
		Description: "From ESXi",
	})
	var dup *assetapp.DuplicateAssetError
	if !errors.As(err, &dup) || dup.ExistingID != a1.ID() {
		t.Fatalf("duplicate address create error = %v, want a conflict naming %s", err, a1.ID())
	}
	if len(repo.assets) != 1 || repo.assets[a1.ID().String()].Description() != "From Splunk" {
		t.Errorf("duplicate address create changed or added assets")
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
		input assetapp.CreateAssetInput
	}{
		{
			name: "empty name",
			input: assetapp.CreateAssetInput{
				Name:        "",
				Type:        "host",
				Criticality: "high",
			},
		},
		{
			name: "invalid type",
			input: assetapp.CreateAssetInput{
				Name:        "Test Asset",
				Type:        "invalid_type",
				Criticality: "high",
			},
		},
		{
			name: "invalid criticality",
			input: assetapp.CreateAssetInput{
				Name:        "Test Asset",
				Type:        "host",
				Criticality: "super_critical",
			},
		},
		{
			name: "empty type",
			input: assetapp.CreateAssetInput{
				Name:        "Test Asset",
				Type:        "",
				Criticality: "high",
			},
		},
		{
			name: "empty criticality",
			input: assetapp.CreateAssetInput{
				Name:        "Test Asset",
				Type:        "host",
				Criticality: "",
			},
		},
		{
			name: "invalid scope",
			input: assetapp.CreateAssetInput{
				Name:        "Bad Scope",
				Type:        "host",
				Criticality: "high",
				Scope:       "nonexistent_scope",
			},
		},
		{
			name: "invalid exposure",
			input: assetapp.CreateAssetInput{
				Name:        "Bad Exposure",
				Type:        "host",
				Criticality: "high",
				Exposure:    "nonexistent_exposure",
			},
		},
		{
			name: "invalid tenant ID format",
			input: assetapp.CreateAssetInput{
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

	input := assetapp.CreateAssetInput{
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

	input := assetapp.CreateAssetInput{
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

	input := assetapp.CreateAssetInput{
		Name:        "Check Fails",
		Type:        "host",
		Criticality: "high",
	}

	_, err := svc.CreateAsset(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when GetByName fails, got nil")
	}
}

// Every input name is accepted, and only the core type is stored: an alias
// becomes (core type, sub_type) (RFC-042 §6.3.8 R1).
func TestAssetService_CreateAsset_AllAssetTypes(t *testing.T) {
	stored := map[string][2]string{
		"domain": {"domain", ""}, "subdomain": {"subdomain", ""}, "ip_address": {"ip_address", ""},
		"website": {"application", "website"}, "web_application": {"application", "website"},
		"api": {"application", "api"}, "repository": {"repository", ""}, "host": {"host", ""},
		"container": {"container", ""}, "database": {"database", ""}, "network": {"network", ""},
		"cloud_account": {"cloud_account", ""}, "compute": {"host", "compute"}, "storage": {"storage", ""},
		"unclassified": {"unclassified", ""}, "s3_bucket": {"storage", "bucket"},
		"firewall": {"network", "firewall"}, "kubernetes_cluster": {"kubernetes", "cluster"},
	}

	for at, want := range stored {
		t.Run(at, func(t *testing.T) {
			svc, _ := newTestService()
			input := assetapp.CreateAssetInput{
				Name:        "test-" + at,
				Type:        at,
				Criticality: "medium",
			}
			a, err := svc.CreateAsset(context.Background(), input)
			if err != nil {
				t.Fatalf("failed to create asset with type %s: %v", at, err)
			}
			if a.Type().String() != want[0] || a.SubType() != want[1] {
				t.Errorf("input %s stored as (%s, %q), want (%s, %q)", at, a.Type(), a.SubType(), want[0], want[1])
			}
			if !a.Type().IsStored() {
				t.Errorf("stored type %s is not a core type", a.Type())
			}
		})
	}
}

func TestAssetService_CreateAsset_AllCriticalities(t *testing.T) {
	criticalities := []string{"critical", "high", "medium", "low", "none"}

	for _, crit := range criticalities {
		t.Run(crit, func(t *testing.T) {
			svc, _ := newTestService()
			input := assetapp.CreateAssetInput{
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
	if a.Name() != asset.NormalizeName("Test Asset", asset.AssetTypeHost, "") {
		t.Errorf("expected name test asset, got %s", a.Name())
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
	created := createAssetForTest(t, svc, tenantA, "tenant-a-asset")

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
	if a.Name() != "tenant-a-asset" {
		t.Errorf("expected name 'tenant-a-asset', got %s", a.Name())
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

	newName := "updated-name"
	newCrit := "medium"
	updateInput := assetapp.UpdateAssetInput{
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

	input := assetapp.CreateAssetInput{
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
	newName := "new name"
	updated, err := svc.UpdateAsset(context.Background(), created.ID().String(), tenantID, assetapp.UpdateAssetInput{
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

	input := assetapp.CreateAssetInput{
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

	updateInput := assetapp.UpdateAssetInput{
		Name:        strPtr("renamed asset"),
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

	if updated.Name() != "renamed asset" {
		t.Errorf("expected name renamed asset, got %s", updated.Name())
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

	_, err := svc.UpdateAsset(context.Background(), shared.NewID().String(), tenantID, assetapp.UpdateAssetInput{
		Name: strPtr("updated-name"),
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

	_, err := svc.UpdateAsset(context.Background(), "not-a-uuid", tenantID, assetapp.UpdateAssetInput{
		Name: strPtr("updated-name"),
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

	_, err := svc.UpdateAsset(context.Background(), shared.NewID().String(), "not-a-uuid", assetapp.UpdateAssetInput{
		Name: strPtr("updated-name"),
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
		input assetapp.UpdateAssetInput
	}{
		{
			name:  "invalid criticality",
			input: assetapp.UpdateAssetInput{Criticality: strPtr("super_critical")},
		},
		{
			name:  "invalid scope",
			input: assetapp.UpdateAssetInput{Scope: strPtr("nonexistent_scope")},
		},
		{
			name:  "invalid exposure",
			input: assetapp.UpdateAssetInput{Exposure: strPtr("nonexistent_exposure")},
		},
		{
			name:  "empty name",
			input: assetapp.UpdateAssetInput{Name: strPtr("")},
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

	_, err := svc.UpdateAsset(context.Background(), created.ID().String(), tenantID, assetapp.UpdateAssetInput{
		Name: strPtr("new name"),
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
	_, err := svc.UpdateAsset(context.Background(), created.ID().String(), tenantB, assetapp.UpdateAssetInput{
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

	err := svc.DeleteAsset(context.Background(), created.ID().String(), tenantID, "")
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

	err := svc.DeleteAsset(context.Background(), shared.NewID().String(), tenantID, "")
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

	err := svc.DeleteAsset(context.Background(), "not-a-uuid", tenantID, "")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestAssetService_DeleteAsset_InvalidTenantID(t *testing.T) {
	svc, _ := newTestService()

	err := svc.DeleteAsset(context.Background(), shared.NewID().String(), "not-a-uuid", "")
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
	err := svc.DeleteAsset(context.Background(), created.ID().String(), tenantB, "")
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

	err := svc.DeleteAsset(context.Background(), created.ID().String(), tenantID, "")
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
	assetInputs := []assetapp.CreateAssetInput{
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

	result, err := svc.ListAssets(context.Background(), assetapp.ListAssetsInput{
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

	assetInputs := []assetapp.CreateAssetInput{
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
	result, err := svc.ListAssets(context.Background(), assetapp.ListAssetsInput{
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
		input := assetapp.CreateAssetInput{
			Name:        fmt.Sprintf("Asset %d", i),
			Type:        "host",
			Criticality: "medium",
		}
		_, err := svc.CreateAsset(context.Background(), input)
		if err != nil {
			t.Fatalf("failed to create asset: %v", err)
		}
	}

	result, err := svc.ListAssets(context.Background(), assetapp.ListAssetsInput{
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

	result, err := svc.ListAssets(context.Background(), assetapp.ListAssetsInput{
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

	result, err := svc.ListAssets(context.Background(), assetapp.ListAssetsInput{
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

	_, err := svc.ListAssets(context.Background(), assetapp.ListAssetsInput{
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
	result, err := svc.ListAssets(context.Background(), assetapp.ListAssetsInput{
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
	_, err := svc.ListAssets(context.Background(), assetapp.ListAssetsInput{
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

	input := assetapp.CreateAssetInput{
		Name:        "Searchable Server",
		Type:        "host",
		Criticality: "high",
		Tags:        []string{"production", "web"},
	}
	_, err := svc.CreateAsset(context.Background(), input)
	if err != nil {
		t.Fatalf("failed to create asset: %v", err)
	}

	_, err = svc.ListAssets(context.Background(), assetapp.ListAssetsInput{
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

	_, err := svc.ListAssets(context.Background(), assetapp.ListAssetsInput{
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
	_, err := svc.ListAssets(context.Background(), assetapp.ListAssetsInput{
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

	result, err := svc.BulkUpdateAssetStatus(context.Background(), tenantID, assetapp.BulkUpdateAssetStatusInput{
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
		"not-a-uuid",            // invalid format
	}

	result, err := svc.BulkUpdateAssetStatus(context.Background(), tenantID, assetapp.BulkUpdateAssetStatusInput{
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

	result, err := svc.BulkUpdateAssetStatus(context.Background(), tenantID, assetapp.BulkUpdateAssetStatusInput{
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

	_, err := svc.BulkUpdateAssetStatus(context.Background(), tenantID, assetapp.BulkUpdateAssetStatusInput{
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

	_, err := svc.BulkUpdateAssetStatus(context.Background(), "bad-uuid", assetapp.BulkUpdateAssetStatusInput{
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

			result, err := svc.BulkUpdateAssetStatus(context.Background(), tenantID, assetapp.BulkUpdateAssetStatusInput{
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

	input := assetapp.CreateAssetInput{
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

	_, err := svc.UpdateAsset(context.Background(), created.ID().String(), tenantID, assetapp.UpdateAssetInput{
		Name: strPtr("new name"),
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

	err := svc.DeleteAsset(context.Background(), created.ID().String(), tenantID, "")
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

	a, err := svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
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

	a, err := svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
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

	input := assetapp.CreateAssetInput{
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
	updated, err := svc.UpdateAsset(context.Background(), created.ID().String(), tenantID, assetapp.UpdateAssetInput{
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

	input := assetapp.CreateAssetInput{
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
	updated, err := svc.UpdateAsset(context.Background(), created.ID().String(), tenantID, assetapp.UpdateAssetInput{
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

	a, err := svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
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

	a, err := svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
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

// =============================================================================
// GetAssetDisplayInfo Tests (batched findings-list labeling)
// =============================================================================

func TestAssetService_GetAssetDisplayInfo_BatchesAndIsTenantScoped(t *testing.T) {
	svc, repo, repoExtRepo := newTestServiceWithRepoExt()
	tenantID := serviceTenantID

	repoAsset, err := asset.NewAssetWithTenant(tenantID, "my-repo", asset.AssetTypeRepository, asset.CriticalityHigh)
	if err != nil {
		t.Fatalf("new asset: %v", err)
	}
	repo.assets[repoAsset.ID().String()] = repoAsset
	ext, _ := asset.NewRepositoryExtension(repoAsset.ID(), "org/my-repo", asset.VisibilityPublic)
	ext.SetWebURL("https://github.com/org/my-repo")
	repoExtRepo.extensions[repoAsset.ID().String()] = ext

	host := createAssetForTest(t, svc, tenantID.String(), "Host Asset")

	// An asset of ANOTHER tenant must never be labeled, even when its id is
	// passed in (e.g. a stale/forged asset_id on a finding).
	otherTenant := shared.NewID()
	foreign, _ := asset.NewAssetWithTenant(otherTenant, "foreign", asset.AssetTypeRepository, asset.CriticalityLow)
	repo.assets[foreign.ID().String()] = foreign
	foreignExt, _ := asset.NewRepositoryExtension(foreign.ID(), "evil/foreign", asset.VisibilityPublic)
	repoExtRepo.extensions[foreign.ID().String()] = foreignExt

	ids := []string{
		repoAsset.ID().String(), host.ID().String(), repoAsset.ID().String(), // duplicate
		foreign.ID().String(), shared.NewID().String(), "not-a-uuid",
	}
	got, err := svc.GetAssetDisplayInfo(context.Background(), tenantID.String(), ids)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("want exactly the 2 same-tenant assets, got %d: %+v", len(got), got)
	}
	if _, ok := got[foreign.ID().String()]; ok {
		t.Fatal("cross-tenant asset must not be returned")
	}
	r := got[repoAsset.ID().String()]
	if r.Name != "my-repo" || r.Type != string(asset.AssetTypeRepository) || r.WebURL != "https://github.com/org/my-repo" {
		t.Errorf("repo asset label wrong: %+v", r)
	}
	h := got[host.ID().String()]
	if h.Name != host.Name() || h.Type != host.Type().String() || h.WebURL != "" {
		t.Errorf("host asset label wrong: %+v", h)
	}
	if repoExtRepo.getBatchCalls != 1 {
		t.Errorf("repository extensions must be fetched in one batch, got %d calls", repoExtRepo.getBatchCalls)
	}
}

func TestAssetService_GetAssetDisplayInfo_ExtensionErrorKeepsLabels(t *testing.T) {
	svc, repo, repoExtRepo := newTestServiceWithRepoExt()
	repoExtRepo.getByAssetIDsErr = errors.New("batch query failed")

	a, _ := asset.NewAssetWithTenant(serviceTenantID, "my-repo", asset.AssetTypeRepository, asset.CriticalityHigh)
	repo.assets[a.ID().String()] = a

	got, err := svc.GetAssetDisplayInfo(context.Background(), serviceTenantID.String(), []string{a.ID().String()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d, ok := got[a.ID().String()]; !ok || d.Name != "my-repo" || d.WebURL != "" {
		t.Fatalf("expected label without web url, got %+v (present=%v)", d, ok)
	}
}

func TestAssetService_GetAssetDisplayInfo_InvalidTenant(t *testing.T) {
	svc, _, _ := newTestServiceWithRepoExt()
	if _, err := svc.GetAssetDisplayInfo(context.Background(), "bad", []string{shared.NewID().String()}); err == nil {
		t.Fatal("expected validation error for bad tenant id")
	}
}

func (m *MockAssetRepository) PurgeDeleted(_ context.Context, _ time.Time, _ int) (int, error) {
	return 0, nil
}
