package integration

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// MockAssetRepository is a mock implementation of asset.Repository for testing.
type MockAssetRepository struct {
	assets map[string]*asset.Asset
}

// NewMockAssetRepository creates a new MockAssetRepository.
func NewMockAssetRepository() *MockAssetRepository {
	return &MockAssetRepository{
		assets: make(map[string]*asset.Asset),
	}
}

func (m *MockAssetRepository) Create(ctx context.Context, a *asset.Asset) error {
	if _, exists := m.assets[a.ID().String()]; exists {
		return asset.AlreadyExistsError(a.Name())
	}
	m.assets[a.ID().String()] = a
	return nil
}

func (m *MockAssetRepository) GetByID(ctx context.Context, assetID shared.ID) (*asset.Asset, error) {
	a, exists := m.assets[assetID.String()]
	if !exists {
		return nil, asset.NotFoundError(assetID)
	}
	return a, nil
}

func (m *MockAssetRepository) Update(ctx context.Context, a *asset.Asset) error {
	if _, exists := m.assets[a.ID().String()]; !exists {
		return asset.NotFoundError(a.ID())
	}
	m.assets[a.ID().String()] = a
	return nil
}

func (m *MockAssetRepository) Delete(ctx context.Context, assetID shared.ID) error {
	if _, exists := m.assets[assetID.String()]; !exists {
		return asset.NotFoundError(assetID)
	}
	delete(m.assets, assetID.String())
	return nil
}

func (m *MockAssetRepository) List(ctx context.Context, filter asset.Filter, page pagination.Pagination) (pagination.Result[*asset.Asset], error) {
	var assets []*asset.Asset
	for _, a := range m.assets {
		assets = append(assets, a)
	}
	return pagination.NewResult(assets, int64(len(assets)), page), nil
}

func (m *MockAssetRepository) Count(ctx context.Context, filter asset.Filter) (int64, error) {
	return int64(len(m.assets)), nil
}

func (m *MockAssetRepository) ExistsByName(ctx context.Context, name string) (bool, error) {
	for _, a := range m.assets {
		if a.Name() == name {
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

// Tests

func TestAssetEntity_NewAsset(t *testing.T) {
	tests := []struct {
		name        string
		assetName   string
		assetType   asset.AssetType
		criticality asset.Criticality
		wantErr     bool
	}{
		{
			name:        "valid asset",
			assetName:   "test-server",
			assetType:   asset.AssetTypeServer,
			criticality: asset.CriticalityHigh,
			wantErr:     false,
		},
		{
			name:        "empty name",
			assetName:   "",
			assetType:   asset.AssetTypeServer,
			criticality: asset.CriticalityHigh,
			wantErr:     true,
		},
		{
			name:        "invalid asset type",
			assetName:   "test-server",
			assetType:   asset.AssetType("invalid"),
			criticality: asset.CriticalityHigh,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := asset.NewAsset(tt.assetName, tt.assetType, tt.criticality)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if a.Name() != tt.assetName {
				t.Errorf("expected name %s, got %s", tt.assetName, a.Name())
			}

			if a.Type() != tt.assetType {
				t.Errorf("expected type %s, got %s", tt.assetType, a.Type())
			}

			if a.Criticality() != tt.criticality {
				t.Errorf("expected criticality %s, got %s", tt.criticality, a.Criticality())
			}

			if a.Status() != asset.StatusActive {
				t.Errorf("expected status active, got %s", a.Status())
			}

			if a.ID().IsZero() {
				t.Error("expected non-zero ID")
			}
		})
	}
}

func TestAssetEntity_UpdateName(t *testing.T) {
	a, _ := asset.NewAsset("original", asset.AssetTypeServer, asset.CriticalityHigh)
	originalUpdatedAt := a.UpdatedAt()

	time.Sleep(time.Millisecond)

	err := a.UpdateName("updated")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if a.Name() != "updated" {
		t.Errorf("expected name 'updated', got %s", a.Name())
	}

	if !a.UpdatedAt().After(originalUpdatedAt) {
		t.Error("expected updated_at to be updated")
	}
}

func TestAssetEntity_Tags(t *testing.T) {
	a, _ := asset.NewAsset("test", asset.AssetTypeServer, asset.CriticalityHigh)

	a.AddTag("production")
	a.AddTag("web")

	tags := a.Tags()
	if len(tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(tags))
	}

	a.AddTag("production")
	tags = a.Tags()
	if len(tags) != 2 {
		t.Errorf("expected 2 tags after adding duplicate, got %d", len(tags))
	}

	a.RemoveTag("production")
	tags = a.Tags()
	if len(tags) != 1 {
		t.Errorf("expected 1 tag after removal, got %d", len(tags))
	}
}

func TestAssetEntity_StatusTransitions(t *testing.T) {
	a, _ := asset.NewAsset("test", asset.AssetTypeServer, asset.CriticalityHigh)

	if !a.IsActive() {
		t.Error("expected asset to be active by default")
	}

	a.Deactivate()
	if a.Status() != asset.StatusInactive {
		t.Errorf("expected status inactive, got %s", a.Status())
	}

	a.Activate()
	if a.Status() != asset.StatusActive {
		t.Errorf("expected status active, got %s", a.Status())
	}

	a.Archive()
	if a.Status() != asset.StatusArchived {
		t.Errorf("expected status archived, got %s", a.Status())
	}
}

func TestMockRepository_CRUD(t *testing.T) {
	ctx := context.Background()
	repo := NewMockAssetRepository()

	a, _ := asset.NewAsset("test-server", asset.AssetTypeServer, asset.CriticalityHigh)
	err := repo.Create(ctx, a)
	if err != nil {
		t.Fatalf("failed to create asset: %v", err)
	}

	retrieved, err := repo.GetByID(ctx, a.ID())
	if err != nil {
		t.Fatalf("failed to get asset: %v", err)
	}
	if retrieved.Name() != a.Name() {
		t.Errorf("expected name %s, got %s", a.Name(), retrieved.Name())
	}

	_ = a.UpdateName("updated-server")
	err = repo.Update(ctx, a)
	if err != nil {
		t.Fatalf("failed to update asset: %v", err)
	}

	retrieved, _ = repo.GetByID(ctx, a.ID())
	if retrieved.Name() != "updated-server" {
		t.Errorf("expected updated name, got %s", retrieved.Name())
	}

	result, err := repo.List(ctx, asset.NewFilter(), pagination.New(1, 20))
	if err != nil {
		t.Fatalf("failed to list assets: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected 1 asset, got %d", result.Total)
	}

	err = repo.Delete(ctx, a.ID())
	if err != nil {
		t.Fatalf("failed to delete asset: %v", err)
	}

	_, err = repo.GetByID(ctx, a.ID())
	if err == nil {
		t.Error("expected error when getting deleted asset")
	}
}

func TestValueObjects_AssetType(t *testing.T) {
	tests := []struct {
		input  string
		valid  bool
		asType asset.AssetType
	}{
		{"server", true, asset.AssetTypeServer},
		{"container", true, asset.AssetTypeContainer},
		{"database", true, asset.AssetTypeDatabase},
		{"invalid", false, ""},
		{"", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			parsed, err := asset.ParseAssetType(tt.input)

			if tt.valid {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if parsed != tt.asType {
					t.Errorf("expected %s, got %s", tt.asType, parsed)
				}
			} else {
				if err == nil {
					t.Error("expected error but got nil")
				}
			}
		})
	}
}

func TestValueObjects_Criticality(t *testing.T) {
	tests := []struct {
		input string
		score int
		valid bool
	}{
		{"critical", 100, true},
		{"high", 75, true},
		{"medium", 50, true},
		{"low", 25, true},
		{"none", 0, true},
		{"invalid", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			parsed, err := asset.ParseCriticality(tt.input)

			if tt.valid {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if parsed.Score() != tt.score {
					t.Errorf("expected score %d, got %d", tt.score, parsed.Score())
				}
			} else {
				if err == nil {
					t.Error("expected error but got nil")
				}
			}
		})
	}
}

func TestPagination(t *testing.T) {
	tests := []struct {
		page    int
		perPage int
		offset  int
		limit   int
	}{
		{1, 20, 0, 20},
		{2, 20, 20, 20},
		{3, 10, 20, 10},
		{0, 0, 0, 20},
		{-1, 200, 0, 100},
	}

	for _, tt := range tests {
		p := pagination.New(tt.page, tt.perPage)

		if p.Offset() != tt.offset {
			t.Errorf("page=%d, perPage=%d: expected offset %d, got %d", tt.page, tt.perPage, tt.offset, p.Offset())
		}
		if p.Limit() != tt.limit {
			t.Errorf("page=%d, perPage=%d: expected limit %d, got %d", tt.page, tt.perPage, tt.limit, p.Limit())
		}
	}
}

func TestID(t *testing.T) {
	newID := shared.NewID()
	if newID.IsZero() {
		t.Error("expected non-zero ID")
	}

	str := newID.String()
	parsed, err := shared.IDFromString(str)
	if err != nil {
		t.Errorf("failed to parse ID: %v", err)
	}
	if !newID.Equals(parsed) {
		t.Error("parsed ID should equal original")
	}

	_, err = shared.IDFromString("invalid")
	if err == nil {
		t.Error("expected error for invalid ID string")
	}
}
