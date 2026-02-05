package unit

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
	"github.com/openctemio/api/pkg/validator"
)

// testTenantID is a fixed tenant ID used in handler tests.
var testTenantID = shared.NewID()

// withTenantContext adds a tenant context to the request for testing.
// Uses "tenant_id" key to match middleware.GetTenantID() which extracts from JWT claims.
func withTenantContext(req *http.Request) *http.Request {
	ctx := context.WithValue(req.Context(), logger.ContextKey("tenant_id"), testTenantID.String())
	return req.WithContext(ctx)
}

// HandlerMockRepository is a mock for handler tests.
type HandlerMockRepository struct {
	assets map[string]*asset.Asset
}

func NewHandlerMockRepository() *HandlerMockRepository {
	return &HandlerMockRepository{
		assets: make(map[string]*asset.Asset),
	}
}

func (m *HandlerMockRepository) Create(ctx context.Context, a *asset.Asset) error {
	m.assets[a.ID().String()] = a
	return nil
}

func (m *HandlerMockRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*asset.Asset, error) {
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

func (m *HandlerMockRepository) Update(ctx context.Context, a *asset.Asset) error {
	if _, ok := m.assets[a.ID().String()]; !ok {
		return shared.ErrNotFound
	}
	m.assets[a.ID().String()] = a
	return nil
}

func (m *HandlerMockRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
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

func (m *HandlerMockRepository) List(
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

func (m *HandlerMockRepository) Count(ctx context.Context, filter asset.Filter) (int64, error) {
	return int64(len(m.assets)), nil
}

func (m *HandlerMockRepository) ExistsByName(ctx context.Context, tenantID shared.ID, name string) (bool, error) {
	for _, a := range m.assets {
		if a.TenantID() == tenantID && a.Name() == name {
			return true, nil
		}
	}
	return false, nil
}

func (m *HandlerMockRepository) GetByExternalID(ctx context.Context, tenantID shared.ID, provider asset.Provider, externalID string) (*asset.Asset, error) {
	for _, a := range m.assets {
		if a.TenantID() == tenantID && a.Provider() == provider && a.ExternalID() == externalID {
			return a, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *HandlerMockRepository) GetByName(ctx context.Context, tenantID shared.ID, name string) (*asset.Asset, error) {
	for _, a := range m.assets {
		if a.TenantID() == tenantID && a.Name() == name {
			return a, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *HandlerMockRepository) FindRepositoryByRepoName(ctx context.Context, tenantID shared.ID, repoName string) (*asset.Asset, error) {
	return nil, shared.ErrNotFound
}

func (m *HandlerMockRepository) FindRepositoryByFullName(ctx context.Context, tenantID shared.ID, fullName string) (*asset.Asset, error) {
	return nil, shared.ErrNotFound
}

func (m *HandlerMockRepository) GetByNames(ctx context.Context, tenantID shared.ID, names []string) (map[string]*asset.Asset, error) {
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

func (m *HandlerMockRepository) UpsertBatch(ctx context.Context, assets []*asset.Asset) (created int, updated int, err error) {
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

func (m *HandlerMockRepository) UpdateFindingCounts(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) error {
	return nil
}

func newTestHandler() *handler.AssetHandler {
	repo := NewHandlerMockRepository()
	log := logger.NewDevelopment()
	v := validator.New()
	svc := app.NewAssetService(repo, log)
	return handler.NewAssetHandler(svc, v, log)
}

func TestAssetHandler_Create_Success(t *testing.T) {
	h := newTestHandler()

	body := map[string]any{
		"name":        "Test Asset",
		"type":        "server",
		"criticality": "high",
		"description": "Test description",
		"tags":        []string{"production"},
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/test-team/assets", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req = withTenantContext(req)
	rec := httptest.NewRecorder()

	h.Create(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var response map[string]any
	json.Unmarshal(rec.Body.Bytes(), &response)

	if response["name"] != "Test Asset" {
		t.Errorf("expected name 'Test Asset', got %v", response["name"])
	}
}

func TestAssetHandler_Create_InvalidJSON(t *testing.T) {
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/test-team/assets", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	req = withTenantContext(req)
	rec := httptest.NewRecorder()

	h.Create(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}
}

func TestAssetHandler_Create_ValidationError(t *testing.T) {
	h := newTestHandler()

	tests := []struct {
		name string
		body map[string]any
	}{
		{
			name: "missing name",
			body: map[string]any{"type": "server", "criticality": "high"},
		},
		{
			name: "invalid type",
			body: map[string]any{"name": "Test", "type": "invalid", "criticality": "high"},
		},
		{
			name: "invalid criticality",
			body: map[string]any{"name": "Test", "type": "server", "criticality": "super"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonBody, _ := json.Marshal(tt.body)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/test-team/assets", bytes.NewReader(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			req = withTenantContext(req)
			rec := httptest.NewRecorder()

			h.Create(rec, req)

			if rec.Code != http.StatusUnprocessableEntity {
				t.Errorf("expected status 422, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestAssetHandler_Get_Success(t *testing.T) {
	h := newTestHandler()

	// First create an asset
	createBody := map[string]any{
		"name":        "Test Asset",
		"type":        "server",
		"criticality": "high",
	}
	jsonBody, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/test-team/assets", bytes.NewReader(jsonBody))
	createReq.Header.Set("Content-Type", "application/json")
	createReq = withTenantContext(createReq)
	createRec := httptest.NewRecorder()
	h.Create(createRec, createReq)

	var created map[string]any
	json.Unmarshal(createRec.Body.Bytes(), &created)
	assetID := created["id"].(string)

	// Get the asset
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/test-team/assets/"+assetID, nil)
	req.SetPathValue("id", assetID)
	req = withTenantContext(req)
	rec := httptest.NewRecorder()

	h.Get(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var response map[string]any
	json.Unmarshal(rec.Body.Bytes(), &response)

	if response["id"] != assetID {
		t.Errorf("expected id %s, got %v", assetID, response["id"])
	}
}

func TestAssetHandler_Get_NotFound(t *testing.T) {
	h := newTestHandler()

	notFoundID := shared.NewID().String()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/test-team/assets/"+notFoundID, nil)
	req.SetPathValue("id", notFoundID)
	req = withTenantContext(req)
	rec := httptest.NewRecorder()

	h.Get(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
}

func TestAssetHandler_Get_InvalidID(t *testing.T) {
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/test-team/assets/invalid-uuid", nil)
	req.SetPathValue("id", "invalid-uuid")
	req = withTenantContext(req)
	rec := httptest.NewRecorder()

	h.Get(rec, req)

	// Service returns NotFound for invalid IDs to prevent information disclosure
	// (don't reveal whether ID format is valid or not)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
}

func TestAssetHandler_Update_Success(t *testing.T) {
	h := newTestHandler()

	// Create asset
	createBody := map[string]any{
		"name":        "Original Name",
		"type":        "server",
		"criticality": "high",
	}
	jsonBody, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/test-team/assets", bytes.NewReader(jsonBody))
	createReq.Header.Set("Content-Type", "application/json")
	createReq = withTenantContext(createReq)
	createRec := httptest.NewRecorder()
	h.Create(createRec, createReq)

	var created map[string]any
	json.Unmarshal(createRec.Body.Bytes(), &created)
	assetID := created["id"].(string)

	// Update asset
	updateBody := map[string]any{
		"name":        "Updated Name",
		"criticality": "medium",
	}
	updateJson, _ := json.Marshal(updateBody)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/test-team/assets/"+assetID, bytes.NewReader(updateJson))
	req.SetPathValue("id", assetID)
	req.Header.Set("Content-Type", "application/json")
	req = withTenantContext(req)
	rec := httptest.NewRecorder()

	h.Update(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var response map[string]any
	json.Unmarshal(rec.Body.Bytes(), &response)

	if response["name"] != "Updated Name" {
		t.Errorf("expected name 'Updated Name', got %v", response["name"])
	}
}

func TestAssetHandler_Update_PartialFields(t *testing.T) {
	h := newTestHandler()

	// Create asset
	createBody := map[string]any{
		"name":        "Original Name",
		"type":        "server",
		"criticality": "high",
		"description": "Original description",
	}
	jsonBody, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/test-team/assets", bytes.NewReader(jsonBody))
	createReq.Header.Set("Content-Type", "application/json")
	createReq = withTenantContext(createReq)
	createRec := httptest.NewRecorder()
	h.Create(createRec, createReq)

	var created map[string]any
	json.Unmarshal(createRec.Body.Bytes(), &created)
	assetID := created["id"].(string)

	// Update only criticality
	updateBody := map[string]any{
		"criticality": "low",
	}
	updateJson, _ := json.Marshal(updateBody)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/test-team/assets/"+assetID, bytes.NewReader(updateJson))
	req.SetPathValue("id", assetID)
	req.Header.Set("Content-Type", "application/json")
	req = withTenantContext(req)
	rec := httptest.NewRecorder()

	h.Update(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var response map[string]any
	json.Unmarshal(rec.Body.Bytes(), &response)

	// Name should remain unchanged
	if response["name"] != "Original Name" {
		t.Errorf("expected name to remain 'Original Name', got %v", response["name"])
	}
	if response["criticality"] != "low" {
		t.Errorf("expected criticality 'low', got %v", response["criticality"])
	}
}

func TestAssetHandler_Delete_Success(t *testing.T) {
	h := newTestHandler()

	// Create asset
	createBody := map[string]any{
		"name":        "To Delete",
		"type":        "server",
		"criticality": "low",
	}
	jsonBody, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/test-team/assets", bytes.NewReader(jsonBody))
	createReq.Header.Set("Content-Type", "application/json")
	createReq = withTenantContext(createReq)
	createRec := httptest.NewRecorder()
	h.Create(createRec, createReq)

	var created map[string]any
	json.Unmarshal(createRec.Body.Bytes(), &created)
	assetID := created["id"].(string)

	// Delete asset
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/test-team/assets/"+assetID, nil)
	req.SetPathValue("id", assetID)
	req = withTenantContext(req)
	rec := httptest.NewRecorder()

	h.Delete(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected status 204, got %d", rec.Code)
	}
}

func TestAssetHandler_List_Success(t *testing.T) {
	h := newTestHandler()

	// Create some assets
	for i := 0; i < 3; i++ {
		createBody := map[string]any{
			"name":        "Asset " + string(rune('A'+i)),
			"type":        "server",
			"criticality": "high",
		}
		jsonBody, _ := json.Marshal(createBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/test-team/assets", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		req = withTenantContext(req)
		rec := httptest.NewRecorder()
		h.Create(rec, req)
	}

	// List assets
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/test-team/assets", nil)
	req = withTenantContext(req)
	rec := httptest.NewRecorder()

	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var response map[string]any
	json.Unmarshal(rec.Body.Bytes(), &response)

	data := response["data"].([]any)
	if len(data) != 3 {
		t.Errorf("expected 3 assets, got %d", len(data))
	}
}

func TestAssetHandler_List_WithFilters(t *testing.T) {
	h := newTestHandler()

	// Create assets
	createBody := map[string]any{
		"name":        "Test Server",
		"type":        "server",
		"criticality": "high",
	}
	jsonBody, _ := json.Marshal(createBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/test-team/assets", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req = withTenantContext(req)
	rec := httptest.NewRecorder()
	h.Create(rec, req)

	// List with page parameter
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/test-team/assets?page=1&per_page=10", nil)
	listReq = withTenantContext(listReq)
	listRec := httptest.NewRecorder()

	h.List(listRec, listReq)

	if listRec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", listRec.Code)
	}
}
