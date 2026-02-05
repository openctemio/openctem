package unit

import (
	"context"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// serviceTenantID is a fixed tenant ID used in service tests.
var serviceTenantID = shared.NewID()

// MockAssetRepository implements asset.Repository for testing.
type MockAssetRepository struct {
	assets map[string]*asset.Asset
}

func NewMockAssetRepository() *MockAssetRepository {
	return &MockAssetRepository{
		assets: make(map[string]*asset.Asset),
	}
}

func (m *MockAssetRepository) Create(ctx context.Context, a *asset.Asset) error {
	m.assets[a.ID().String()] = a
	return nil
}

func (m *MockAssetRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*asset.Asset, error) {
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

func (m *MockAssetRepository) Update(ctx context.Context, a *asset.Asset) error {
	if _, ok := m.assets[a.ID().String()]; !ok {
		return shared.ErrNotFound
	}
	m.assets[a.ID().String()] = a
	return nil
}

func (m *MockAssetRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
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
	ctx context.Context,
	filter asset.Filter,
	opts asset.ListOptions,
	page pagination.Pagination,
) (pagination.Result[*asset.Asset], error) {
	var result []*asset.Asset
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

func (m *MockAssetRepository) Count(ctx context.Context, filter asset.Filter) (int64, error) {
	return int64(len(m.assets)), nil
}

func (m *MockAssetRepository) ExistsByName(ctx context.Context, tenantID shared.ID, name string) (bool, error) {
	for _, a := range m.assets {
		if a.TenantID() == tenantID && a.Name() == name {
			return true, nil
		}
	}
	return false, nil
}

func (m *MockAssetRepository) GetByExternalID(ctx context.Context, tenantID shared.ID, provider asset.Provider, externalID string) (*asset.Asset, error) {
	for _, a := range m.assets {
		if a.TenantID() == tenantID && a.Provider() == provider && a.ExternalID() == externalID {
			return a, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *MockAssetRepository) GetByName(ctx context.Context, tenantID shared.ID, name string) (*asset.Asset, error) {
	for _, a := range m.assets {
		if a.TenantID() == tenantID && a.Name() == name {
			return a, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *MockAssetRepository) FindRepositoryByRepoName(ctx context.Context, tenantID shared.ID, repoName string) (*asset.Asset, error) {
	return nil, shared.ErrNotFound
}

func (m *MockAssetRepository) FindRepositoryByFullName(ctx context.Context, tenantID shared.ID, fullName string) (*asset.Asset, error) {
	return nil, shared.ErrNotFound
}

func (m *MockAssetRepository) GetByNames(ctx context.Context, tenantID shared.ID, names []string) (map[string]*asset.Asset, error) {
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

func (m *MockAssetRepository) UpsertBatch(ctx context.Context, assets []*asset.Asset) (created int, updated int, err error) {
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

func (m *MockAssetRepository) UpdateFindingCounts(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) error {
	return nil
}

func newTestService() (*app.AssetService, *MockAssetRepository) {
	repo := NewMockAssetRepository()
	log := logger.NewDevelopment()
	svc := app.NewAssetService(repo, log)
	return svc, repo
}

func TestAssetService_CreateAsset_Success(t *testing.T) {
	svc, _ := newTestService()

	input := app.CreateAssetInput{
		Name:        "Test Server",
		Type:        "server",
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
}

func TestAssetService_CreateAsset_DuplicateName(t *testing.T) {
	svc, _ := newTestService()

	input := app.CreateAssetInput{
		Name:        "Duplicate Asset",
		Type:        "server",
		Criticality: "high",
	}

	// Create first asset
	_, err := svc.CreateAsset(context.Background(), input)
	if err != nil {
		t.Fatalf("failed to create first asset: %v", err)
	}

	// Try to create duplicate
	_, err = svc.CreateAsset(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
}

func TestAssetService_CreateAsset_InvalidType(t *testing.T) {
	svc, _ := newTestService()

	input := app.CreateAssetInput{
		Name:        "Test Asset",
		Type:        "invalid_type",
		Criticality: "high",
	}

	_, err := svc.CreateAsset(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid type")
	}
}

func TestAssetService_CreateAsset_InvalidCriticality(t *testing.T) {
	svc, _ := newTestService()

	input := app.CreateAssetInput{
		Name:        "Test Asset",
		Type:        "server",
		Criticality: "super_critical",
	}

	_, err := svc.CreateAsset(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid criticality")
	}
}

func TestAssetService_GetAsset_Success(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	// Create asset first
	input := app.CreateAssetInput{
		TenantID:    tenantID,
		Name:        "Test Asset",
		Type:        "server",
		Criticality: "high",
	}

	created, err := svc.CreateAsset(context.Background(), input)
	if err != nil {
		t.Fatalf("failed to create asset: %v", err)
	}

	// Get asset
	a, err := svc.GetAsset(context.Background(), tenantID, created.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if a.ID() != created.ID() {
		t.Errorf("expected ID %s, got %s", created.ID(), a.ID())
	}
}

func TestAssetService_GetAsset_NotFound(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	_, err := svc.GetAsset(context.Background(), tenantID, shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for not found")
	}
}

func TestAssetService_GetAsset_InvalidID(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	_, err := svc.GetAsset(context.Background(), tenantID, "invalid-uuid")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
}

func TestAssetService_UpdateAsset_Success(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	// Create asset first
	input := app.CreateAssetInput{
		TenantID:    tenantID,
		Name:        "Original Name",
		Type:        "server",
		Criticality: "high",
	}

	created, err := svc.CreateAsset(context.Background(), input)
	if err != nil {
		t.Fatalf("failed to create asset: %v", err)
	}

	// Update asset
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

	// Create asset
	input := app.CreateAssetInput{
		TenantID:    tenantID,
		Name:        "Original Name",
		Type:        "server",
		Criticality: "high",
		Description: "Original description",
	}

	created, err := svc.CreateAsset(context.Background(), input)
	if err != nil {
		t.Fatalf("failed to create asset: %v", err)
	}

	// Update only name
	newName := "New Name"
	updateInput := app.UpdateAssetInput{
		Name: &newName,
	}

	updated, err := svc.UpdateAsset(context.Background(), created.ID().String(), tenantID, updateInput)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if updated.Name() != newName {
		t.Errorf("expected name %s, got %s", newName, updated.Name())
	}
	// Criticality should remain unchanged
	if updated.Criticality().String() != input.Criticality {
		t.Errorf("expected criticality %s, got %s", input.Criticality, updated.Criticality().String())
	}
}

func TestAssetService_DeleteAsset_Success(t *testing.T) {
	svc, repo := newTestService()
	tenantID := serviceTenantID.String()

	// Create asset
	input := app.CreateAssetInput{
		TenantID:    tenantID,
		Name:        "To Delete",
		Type:        "server",
		Criticality: "low",
	}

	created, err := svc.CreateAsset(context.Background(), input)
	if err != nil {
		t.Fatalf("failed to create asset: %v", err)
	}

	// Delete
	err = svc.DeleteAsset(context.Background(), created.ID().String(), tenantID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify deleted
	if len(repo.assets) != 0 {
		t.Error("expected asset to be deleted")
	}
}

func TestAssetService_ListAssets_WithFilters(t *testing.T) {
	svc, _ := newTestService()

	// Create multiple assets
	assets := []app.CreateAssetInput{
		{Name: "Server 1", Type: "server", Criticality: "high"},
		{Name: "Server 2", Type: "server", Criticality: "medium"},
		{Name: "Database 1", Type: "database", Criticality: "high"},
	}

	for _, input := range assets {
		_, err := svc.CreateAsset(context.Background(), input)
		if err != nil {
			t.Fatalf("failed to create asset: %v", err)
		}
	}

	// List all
	listInput := app.ListAssetsInput{
		Page:    1,
		PerPage: 10,
	}

	result, err := svc.ListAssets(context.Background(), listInput)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(result.Data) != 3 {
		t.Errorf("expected 3 assets, got %d", len(result.Data))
	}
}

func TestAssetService_ListAssets_Pagination(t *testing.T) {
	svc, _ := newTestService()

	// Create multiple assets
	for i := 0; i < 5; i++ {
		input := app.CreateAssetInput{
			Name:        "Asset " + string(rune('A'+i)),
			Type:        "server",
			Criticality: "medium",
		}
		_, err := svc.CreateAsset(context.Background(), input)
		if err != nil {
			t.Fatalf("failed to create asset: %v", err)
		}
	}

	// List with pagination
	listInput := app.ListAssetsInput{
		Page:    1,
		PerPage: 2,
	}

	result, err := svc.ListAssets(context.Background(), listInput)
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

func TestAssetService_ActivateAsset(t *testing.T) {
	svc, _ := newTestService()
	tenantID := serviceTenantID.String()

	// Create and deactivate asset
	input := app.CreateAssetInput{
		TenantID:    tenantID,
		Name:        "Test Asset",
		Type:        "server",
		Criticality: "high",
	}

	created, _ := svc.CreateAsset(context.Background(), input)
	_, _ = svc.DeactivateAsset(context.Background(), tenantID, created.ID().String())

	// Activate
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

	input := app.CreateAssetInput{
		TenantID:    tenantID,
		Name:        "Test Asset",
		Type:        "server",
		Criticality: "high",
	}

	created, _ := svc.CreateAsset(context.Background(), input)

	// Deactivate
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

	input := app.CreateAssetInput{
		TenantID:    tenantID,
		Name:        "Test Asset",
		Type:        "server",
		Criticality: "high",
	}

	created, _ := svc.CreateAsset(context.Background(), input)

	// Archive
	archived, err := svc.ArchiveAsset(context.Background(), tenantID, created.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if archived.Status().String() != "archived" {
		t.Errorf("expected status archived, got %s", archived.Status().String())
	}
}
