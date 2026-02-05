package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/scannertemplate"
	"github.com/openctemio/api/pkg/domain/secretstore"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/templatesource"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
	"github.com/openctemio/api/pkg/validator"
)

// =============================================================================
// Mock Repositories for Template Sync Tests
// =============================================================================

// MockTemplateSourceRepo implements templatesource.Repository
type MockTemplateSourceRepo struct {
	sources map[string]*templatesource.TemplateSource
}

func NewMockTemplateSourceRepo() *MockTemplateSourceRepo {
	return &MockTemplateSourceRepo{
		sources: make(map[string]*templatesource.TemplateSource),
	}
}

func (m *MockTemplateSourceRepo) Create(ctx context.Context, source *templatesource.TemplateSource) error {
	m.sources[source.ID.String()] = source
	return nil
}

func (m *MockTemplateSourceRepo) GetByID(ctx context.Context, id shared.ID) (*templatesource.TemplateSource, error) {
	source, ok := m.sources[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return source, nil
}

func (m *MockTemplateSourceRepo) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*templatesource.TemplateSource, error) {
	source, ok := m.sources[id.String()]
	if !ok || source.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return source, nil
}

func (m *MockTemplateSourceRepo) GetByTenantAndName(ctx context.Context, tenantID shared.ID, name string) (*templatesource.TemplateSource, error) {
	for _, s := range m.sources {
		if s.TenantID == tenantID && s.Name == name {
			return s, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *MockTemplateSourceRepo) List(ctx context.Context, input templatesource.ListInput) (*templatesource.ListOutput, error) {
	var sources []*templatesource.TemplateSource
	for _, s := range m.sources {
		if s.TenantID == input.TenantID {
			sources = append(sources, s)
		}
	}
	return &templatesource.ListOutput{
		Items:      sources,
		TotalCount: len(sources),
	}, nil
}

func (m *MockTemplateSourceRepo) ListByTenantAndTemplateType(ctx context.Context, tenantID shared.ID, templateType scannertemplate.TemplateType) ([]*templatesource.TemplateSource, error) {
	var sources []*templatesource.TemplateSource
	for _, s := range m.sources {
		if s.TenantID == tenantID && s.TemplateType == templateType {
			sources = append(sources, s)
		}
	}
	return sources, nil
}

func (m *MockTemplateSourceRepo) Update(ctx context.Context, source *templatesource.TemplateSource) error {
	m.sources[source.ID.String()] = source
	return nil
}

func (m *MockTemplateSourceRepo) UpdateSyncStatus(ctx context.Context, source *templatesource.TemplateSource) error {
	if existing, ok := m.sources[source.ID.String()]; ok {
		existing.LastSyncAt = source.LastSyncAt
		existing.LastSyncHash = source.LastSyncHash
		existing.LastSyncStatus = source.LastSyncStatus
		existing.LastSyncError = source.LastSyncError
		existing.UpdatedAt = source.UpdatedAt
	}
	return nil
}

func (m *MockTemplateSourceRepo) Delete(ctx context.Context, id shared.ID) error {
	delete(m.sources, id.String())
	return nil
}

func (m *MockTemplateSourceRepo) ListEnabledForSync(ctx context.Context, tenantID shared.ID) ([]*templatesource.TemplateSource, error) {
	var sources []*templatesource.TemplateSource
	for _, s := range m.sources {
		if s.TenantID == tenantID && s.Enabled {
			sources = append(sources, s)
		}
	}
	return sources, nil
}

func (m *MockTemplateSourceRepo) ListAllNeedingSync(ctx context.Context) ([]*templatesource.TemplateSource, error) {
	var sources []*templatesource.TemplateSource
	for _, s := range m.sources {
		if s.Enabled && s.NeedsSync() {
			sources = append(sources, s)
		}
	}
	return sources, nil
}

func (m *MockTemplateSourceRepo) CountByTenant(ctx context.Context, tenantID shared.ID) (int, error) {
	var count int
	for _, s := range m.sources {
		if s.TenantID == tenantID {
			count++
		}
	}
	return count, nil
}

// MockScannerTemplateRepo implements scannertemplate.Repository
type MockScannerTemplateRepo struct {
	templates map[string]*scannertemplate.ScannerTemplate
}

func NewMockScannerTemplateRepo() *MockScannerTemplateRepo {
	return &MockScannerTemplateRepo{
		templates: make(map[string]*scannertemplate.ScannerTemplate),
	}
}

func (m *MockScannerTemplateRepo) Create(ctx context.Context, template *scannertemplate.ScannerTemplate) error {
	m.templates[template.ID.String()] = template
	return nil
}

func (m *MockScannerTemplateRepo) GetByID(ctx context.Context, id shared.ID) (*scannertemplate.ScannerTemplate, error) {
	tpl, ok := m.templates[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return tpl, nil
}

func (m *MockScannerTemplateRepo) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*scannertemplate.ScannerTemplate, error) {
	tpl, ok := m.templates[id.String()]
	if !ok || tpl.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return tpl, nil
}

func (m *MockScannerTemplateRepo) List(ctx context.Context, filter scannertemplate.Filter, page pagination.Pagination) (pagination.Result[*scannertemplate.ScannerTemplate], error) {
	var templates []*scannertemplate.ScannerTemplate
	for _, t := range m.templates {
		// Filter by TenantID if specified
		if filter.TenantID != nil && t.TenantID != *filter.TenantID {
			continue
		}
		templates = append(templates, t)
	}
	return pagination.NewResult(templates, int64(len(templates)), page), nil
}

func (m *MockScannerTemplateRepo) ListByIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]*scannertemplate.ScannerTemplate, error) {
	idSet := make(map[string]bool)
	for _, id := range ids {
		idSet[id.String()] = true
	}

	var templates []*scannertemplate.ScannerTemplate
	for _, t := range m.templates {
		if t.TenantID == tenantID && idSet[t.ID.String()] {
			templates = append(templates, t)
		}
	}
	return templates, nil
}

func (m *MockScannerTemplateRepo) Update(ctx context.Context, template *scannertemplate.ScannerTemplate) error {
	m.templates[template.ID.String()] = template
	return nil
}

func (m *MockScannerTemplateRepo) Delete(ctx context.Context, id shared.ID) error {
	delete(m.templates, id.String())
	return nil
}

func (m *MockScannerTemplateRepo) Exists(ctx context.Context, tenantID shared.ID, templateType scannertemplate.TemplateType, name string) (bool, error) {
	for _, t := range m.templates {
		if t.TenantID == tenantID && t.TemplateType == templateType && t.Name == name {
			return true, nil
		}
	}
	return false, nil
}

func (m *MockScannerTemplateRepo) GetByContentHash(ctx context.Context, tenantID shared.ID, templateType scannertemplate.TemplateType, hash string) (*scannertemplate.ScannerTemplate, error) {
	for _, t := range m.templates {
		if t.TenantID == tenantID && t.TemplateType == templateType && t.ContentHash == hash {
			return t, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *MockScannerTemplateRepo) ListBySourceID(ctx context.Context, sourceID shared.ID) ([]*scannertemplate.ScannerTemplate, error) {
	var templates []*scannertemplate.ScannerTemplate
	for _, t := range m.templates {
		if t.SourceID != nil && *t.SourceID == sourceID {
			templates = append(templates, t)
		}
	}
	return templates, nil
}

func (m *MockScannerTemplateRepo) DeleteBySourceID(ctx context.Context, sourceID shared.ID) error {
	for id, t := range m.templates {
		if t.SourceID != nil && *t.SourceID == sourceID {
			delete(m.templates, id)
		}
	}
	return nil
}

func (m *MockScannerTemplateRepo) CountByTenant(ctx context.Context, tenantID shared.ID) (int64, error) {
	var count int64
	for _, t := range m.templates {
		if t.TenantID == tenantID {
			count++
		}
	}
	return count, nil
}

func (m *MockScannerTemplateRepo) CountByType(ctx context.Context, tenantID shared.ID, templateType scannertemplate.TemplateType) (int64, error) {
	var count int64
	for _, t := range m.templates {
		if t.TenantID == tenantID && t.TemplateType == templateType {
			count++
		}
	}
	return count, nil
}

func (m *MockScannerTemplateRepo) ExistsByName(ctx context.Context, tenantID shared.ID, templateType scannertemplate.TemplateType, name string) (bool, error) {
	for _, t := range m.templates {
		if t.TenantID == tenantID && t.TemplateType == templateType && t.Name == name {
			return true, nil
		}
	}
	return false, nil
}

func (m *MockScannerTemplateRepo) GetByTenantAndName(ctx context.Context, tenantID shared.ID, templateType scannertemplate.TemplateType, name string) (*scannertemplate.ScannerTemplate, error) {
	for _, t := range m.templates {
		if t.TenantID == tenantID && t.TemplateType == templateType && t.Name == name {
			return t, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *MockScannerTemplateRepo) GetUsage(ctx context.Context, tenantID shared.ID) (*scannertemplate.TemplateUsage, error) {
	usage := &scannertemplate.TemplateUsage{}
	for _, t := range m.templates {
		if t.TenantID == tenantID {
			usage.TotalTemplates++
			usage.TotalStorageBytes += int64(len(t.Content))
			switch t.TemplateType {
			case scannertemplate.TemplateTypeNuclei:
				usage.NucleiTemplates++
			case scannertemplate.TemplateTypeSemgrep:
				usage.SemgrepTemplates++
			case scannertemplate.TemplateTypeGitleaks:
				usage.GitleaksTemplates++
			}
		}
	}
	return usage, nil
}

// MockSecretStoreRepo implements secretstore.Repository
type MockSecretStoreRepo struct {
	credentials map[string]*secretstore.Credential
}

func NewMockSecretStoreRepo() *MockSecretStoreRepo {
	return &MockSecretStoreRepo{
		credentials: make(map[string]*secretstore.Credential),
	}
}

func (m *MockSecretStoreRepo) Create(ctx context.Context, cred *secretstore.Credential) error {
	m.credentials[cred.ID.String()] = cred
	return nil
}

func (m *MockSecretStoreRepo) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*secretstore.Credential, error) {
	cred, ok := m.credentials[id.String()]
	if !ok || cred.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return cred, nil
}

func (m *MockSecretStoreRepo) GetByTenantAndName(ctx context.Context, tenantID shared.ID, name string) (*secretstore.Credential, error) {
	for _, c := range m.credentials {
		if c.TenantID == tenantID && c.Name == name {
			return c, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *MockSecretStoreRepo) List(ctx context.Context, input secretstore.ListInput) (*secretstore.ListOutput, error) {
	var creds []*secretstore.Credential
	for _, c := range m.credentials {
		if c.TenantID == input.TenantID {
			creds = append(creds, c)
		}
	}
	return &secretstore.ListOutput{Items: creds, TotalCount: len(creds)}, nil
}

func (m *MockSecretStoreRepo) Update(ctx context.Context, cred *secretstore.Credential) error {
	m.credentials[cred.ID.String()] = cred
	return nil
}

func (m *MockSecretStoreRepo) DeleteByTenantAndID(ctx context.Context, tenantID, id shared.ID) error {
	cred, ok := m.credentials[id.String()]
	if !ok || cred.TenantID != tenantID {
		return shared.ErrNotFound
	}
	delete(m.credentials, id.String())
	return nil
}

func (m *MockSecretStoreRepo) UpdateLastUsedByTenantAndID(ctx context.Context, tenantID, id shared.ID) error {
	cred, ok := m.credentials[id.String()]
	if !ok || cred.TenantID != tenantID {
		return shared.ErrNotFound
	}
	now := time.Now()
	cred.LastUsedAt = &now
	return nil
}

func (m *MockSecretStoreRepo) CountByTenant(ctx context.Context, tenantID shared.ID) (int, error) {
	count := 0
	for _, c := range m.credentials {
		if c.TenantID == tenantID {
			count++
		}
	}
	return count, nil
}

// =============================================================================
// Test Setup
// =============================================================================

type templateTestHandlers struct {
	templateHandler *handler.ScannerTemplateHandler
	sourceHandler   *handler.TemplateSourceHandler
	templateRepo    *MockScannerTemplateRepo
	sourceRepo      *MockTemplateSourceRepo
	secretRepo      *MockSecretStoreRepo
	router          *chi.Mux
	tenantID        shared.ID
}

func setupTemplateTestHandlers(t *testing.T) *templateTestHandlers {
	t.Helper()

	tenantID := shared.NewID()
	templateRepo := NewMockScannerTemplateRepo()
	sourceRepo := NewMockTemplateSourceRepo()
	log := logger.NewNop()
	v := validator.New()

	// Create services with correct signatures
	templateService := app.NewScannerTemplateService(
		templateRepo,
		"test-signing-secret-for-templates",
		log,
	)

	sourceService := app.NewTemplateSourceService(
		sourceRepo,
		log,
	)

	// Create handlers
	templateHandler := handler.NewScannerTemplateHandler(templateService, v, log)
	sourceHandler := handler.NewTemplateSourceHandler(sourceService, v, log)

	// Setup router with tenant context
	router := chi.NewRouter()

	// Middleware to inject tenant context
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// GetTenantID expects string, not shared.ID
			ctx := context.WithValue(r.Context(), middleware.TenantIDKey, tenantID.String())
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	// Template routes
	router.Route("/api/v1/scanner-templates", func(r chi.Router) {
		r.Get("/", templateHandler.List)
		r.Post("/", templateHandler.Create)
		r.Post("/validate", templateHandler.Validate)
		r.Get("/{id}", templateHandler.Get)
		r.Put("/{id}", templateHandler.Update)
		r.Delete("/{id}", templateHandler.Delete)
		r.Get("/{id}/download", templateHandler.Download)
		r.Post("/{id}/deprecate", templateHandler.Deprecate)
	})

	// Template source routes
	router.Route("/api/v1/template-sources", func(r chi.Router) {
		r.Get("/", sourceHandler.List)
		r.Post("/", sourceHandler.Create)
		r.Get("/{id}", sourceHandler.Get)
		r.Put("/{id}", sourceHandler.Update)
		r.Delete("/{id}", sourceHandler.Delete)
		r.Post("/{id}/enable", sourceHandler.Enable)
		r.Post("/{id}/disable", sourceHandler.Disable)
	})

	return &templateTestHandlers{
		templateHandler: templateHandler,
		sourceHandler:   sourceHandler,
		templateRepo:    templateRepo,
		sourceRepo:      sourceRepo,
		secretRepo:      NewMockSecretStoreRepo(),
		router:          router,
		tenantID:        tenantID,
	}
}

// =============================================================================
// Template API Tests
// =============================================================================

func TestScannerTemplate_Create_Nuclei(t *testing.T) {
	th := setupTemplateTestHandlers(t)

	// Valid Nuclei template
	nucleiContent := `id: custom-sqli-test
info:
  name: Custom SQL Injection Test
  severity: high
  author: test
  tags: sqli,owasp

requests:
  - method: GET
    path:
      - "{{BaseURL}}/search?q={{payload}}"
    matchers:
      - type: word
        words:
          - "SQL syntax"
`

	body := map[string]interface{}{
		"name":          "custom-sqli",
		"template_type": "nuclei",
		"description":   "Custom SQL injection template",
		"content":       base64.StdEncoding.EncodeToString([]byte(nucleiContent)),
		"tags":          []string{"sqli", "custom"},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scanner-templates", jsonReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	th.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp["name"] != "custom-sqli" {
		t.Errorf("expected name 'custom-sqli', got %v", resp["name"])
	}
	if resp["template_type"] != "nuclei" {
		t.Errorf("expected template_type 'nuclei', got %v", resp["template_type"])
	}
	if resp["status"] != "active" {
		t.Errorf("expected status 'active', got %v", resp["status"])
	}
	if resp["rule_count"].(float64) != 1 {
		t.Errorf("expected rule_count 1, got %v", resp["rule_count"])
	}
}

func TestScannerTemplate_Create_Semgrep(t *testing.T) {
	th := setupTemplateTestHandlers(t)

	// Valid Semgrep rule
	semgrepContent := `rules:
  - id: custom-hardcoded-password
    pattern: password = "$PASSWORD"
    message: Hardcoded password detected
    severity: ERROR
    languages: [python, javascript]
    metadata:
      cwe: CWE-798
`

	body := map[string]interface{}{
		"name":          "custom-secrets",
		"template_type": "semgrep",
		"description":   "Custom secret detection rules",
		"content":       base64.StdEncoding.EncodeToString([]byte(semgrepContent)),
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scanner-templates", jsonReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	th.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp["template_type"] != "semgrep" {
		t.Errorf("expected template_type 'semgrep', got %v", resp["template_type"])
	}
	if resp["rule_count"].(float64) != 1 {
		t.Errorf("expected rule_count 1, got %v", resp["rule_count"])
	}
}

func TestScannerTemplate_Create_Gitleaks(t *testing.T) {
	th := setupTemplateTestHandlers(t)

	// Valid Gitleaks config
	gitleaksContent := `[[rules]]
id = "custom-api-key"
description = "Custom API Key Pattern"
regex = '''(?i)custom[_-]?api[_-]?key["\s]*[:=]["\s]*([a-z0-9]{32})'''
tags = ["api", "custom"]

[[rules]]
id = "custom-token"
description = "Custom Token Pattern"
regex = '''(?i)custom[_-]?token["\s]*[:=]["\s]*([a-z0-9]{40})'''
tags = ["token", "custom"]
`

	body := map[string]interface{}{
		"name":          "custom-gitleaks",
		"template_type": "gitleaks",
		"description":   "Custom Gitleaks patterns",
		"content":       base64.StdEncoding.EncodeToString([]byte(gitleaksContent)),
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scanner-templates", jsonReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	th.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp["template_type"] != "gitleaks" {
		t.Errorf("expected template_type 'gitleaks', got %v", resp["template_type"])
	}
	if resp["rule_count"].(float64) != 2 {
		t.Errorf("expected rule_count 2, got %v", resp["rule_count"])
	}
}

func TestScannerTemplate_Validate_Invalid(t *testing.T) {
	th := setupTemplateTestHandlers(t)

	// Invalid Nuclei template (missing required fields)
	invalidContent := `id: incomplete-template
# Missing info section
`

	body := map[string]interface{}{
		"template_type": "nuclei",
		"content":       base64.StdEncoding.EncodeToString([]byte(invalidContent)),
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scanner-templates/validate", jsonReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	th.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp["valid"].(bool) {
		t.Error("expected validation to fail for invalid template")
	}
	if errors, ok := resp["errors"].([]interface{}); !ok || len(errors) == 0 {
		t.Error("expected validation errors")
	}
}

func TestScannerTemplate_List(t *testing.T) {
	th := setupTemplateTestHandlers(t)

	// Add some templates directly to the repo
	tpl1 := createTestTemplate(th.tenantID, "template-1", scannertemplate.TemplateTypeNuclei)
	tpl2 := createTestTemplate(th.tenantID, "template-2", scannertemplate.TemplateTypeSemgrep)
	th.templateRepo.templates[tpl1.ID.String()] = tpl1
	th.templateRepo.templates[tpl2.ID.String()] = tpl2

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scanner-templates", nil)
	rr := httptest.NewRecorder()

	th.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	items := resp["items"].([]interface{})
	if len(items) != 2 {
		t.Errorf("expected 2 templates, got %d", len(items))
	}
}

func TestScannerTemplate_Download(t *testing.T) {
	th := setupTemplateTestHandlers(t)

	// Add a template
	content := []byte("test template content")
	tpl := createTestTemplate(th.tenantID, "download-test", scannertemplate.TemplateTypeNuclei)
	tpl.Content = content
	th.templateRepo.templates[tpl.ID.String()] = tpl

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scanner-templates/"+tpl.ID.String()+"/download", nil)
	rr := httptest.NewRecorder()

	th.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	if rr.Header().Get("Content-Type") != "application/octet-stream" {
		t.Errorf("expected Content-Type 'application/octet-stream', got %s", rr.Header().Get("Content-Type"))
	}

	if rr.Body.String() != string(content) {
		t.Errorf("expected content '%s', got '%s'", string(content), rr.Body.String())
	}
}

// =============================================================================
// Template Source API Tests
// =============================================================================

func TestTemplateSource_Create_Git(t *testing.T) {
	th := setupTemplateTestHandlers(t)

	body := map[string]interface{}{
		"name":          "company-templates",
		"source_type":   "git",
		"template_type": "nuclei",
		"git_config": map[string]interface{}{
			"url":    "https://github.com/company/templates",
			"branch": "main",
			"path":   "nuclei/",
		},
		"enabled":           true,
		"auto_sync_on_scan": true,
		"cache_ttl_minutes": 60,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/template-sources", jsonReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	th.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp["name"] != "company-templates" {
		t.Errorf("expected name 'company-templates', got %v", resp["name"])
	}
	if resp["source_type"] != "git" {
		t.Errorf("expected source_type 'git', got %v", resp["source_type"])
	}
}

func TestTemplateSource_Create_S3(t *testing.T) {
	th := setupTemplateTestHandlers(t)

	body := map[string]interface{}{
		"name":          "s3-templates",
		"source_type":   "s3",
		"template_type": "semgrep",
		"s3_config": map[string]interface{}{
			"bucket":    "security-templates",
			"region":    "us-east-1",
			"prefix":    "semgrep/",
			"auth_type": "keys",
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/template-sources", jsonReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	th.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp["source_type"] != "s3" {
		t.Errorf("expected source_type 's3', got %v", resp["source_type"])
	}
}

func TestTemplateSource_EnableDisable(t *testing.T) {
	th := setupTemplateTestHandlers(t)

	// Create a source
	source := &templatesource.TemplateSource{
		ID:           shared.NewID(),
		TenantID:     th.tenantID,
		Name:         "test-source",
		SourceType:   templatesource.SourceTypeGit,
		TemplateType: scannertemplate.TemplateTypeNuclei,
		Enabled:      true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	th.sourceRepo.sources[source.ID.String()] = source

	// Disable the source
	req := httptest.NewRequest(http.MethodPost, "/api/v1/template-sources/"+source.ID.String()+"/disable", nil)
	rr := httptest.NewRecorder()
	th.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 on disable, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify it's disabled
	if th.sourceRepo.sources[source.ID.String()].Enabled {
		t.Error("expected source to be disabled")
	}

	// Enable the source
	req = httptest.NewRequest(http.MethodPost, "/api/v1/template-sources/"+source.ID.String()+"/enable", nil)
	rr = httptest.NewRecorder()
	th.router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 on enable, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify it's enabled
	if !th.sourceRepo.sources[source.ID.String()].Enabled {
		t.Error("expected source to be enabled")
	}
}

// =============================================================================
// E2E Template Sync Flow Test
// =============================================================================

func TestE2E_TemplateSync_ManualUpload(t *testing.T) {
	// This test simulates the full flow:
	// 1. Create a template via API
	// 2. Verify it's stored correctly
	// 3. Verify it can be fetched by ID
	// 4. Verify it can be listed

	th := setupTemplateTestHandlers(t)

	// Step 1: Create template
	nucleiContent := `id: e2e-test-template
info:
  name: E2E Test Template
  severity: medium
  author: test

requests:
  - method: GET
    path:
      - "{{BaseURL}}/test"
`

	createBody := map[string]interface{}{
		"name":          "e2e-test",
		"template_type": "nuclei",
		"description":   "E2E test template",
		"content":       base64.StdEncoding.EncodeToString([]byte(nucleiContent)),
	}
	createBodyBytes, _ := json.Marshal(createBody)

	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/scanner-templates", jsonReader(createBodyBytes))
	createReq.Header.Set("Content-Type", "application/json")
	createRR := httptest.NewRecorder()
	th.router.ServeHTTP(createRR, createReq)

	if createRR.Code != http.StatusCreated {
		t.Fatalf("Step 1 failed: expected status 201, got %d: %s", createRR.Code, createRR.Body.String())
	}

	var createResp map[string]interface{}
	json.Unmarshal(createRR.Body.Bytes(), &createResp)
	templateID := createResp["id"].(string)

	// Step 2: Verify stored correctly
	storedTemplate, exists := th.templateRepo.templates[templateID]
	if !exists {
		t.Fatal("Step 2 failed: template not found in repository")
	}

	if storedTemplate.Name != "e2e-test" {
		t.Errorf("Step 2 failed: expected name 'e2e-test', got '%s'", storedTemplate.Name)
	}

	// Verify content hash
	hash := sha256.Sum256([]byte(nucleiContent))
	expectedHash := hex.EncodeToString(hash[:])
	if storedTemplate.ContentHash != expectedHash {
		t.Errorf("Step 2 failed: content hash mismatch")
	}

	// Verify signature was generated
	if storedTemplate.SignatureHash == "" {
		t.Error("Step 2 failed: signature not generated")
	}

	// Step 3: Fetch by ID
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/scanner-templates/"+templateID, nil)
	getRR := httptest.NewRecorder()
	th.router.ServeHTTP(getRR, getReq)

	if getRR.Code != http.StatusOK {
		t.Fatalf("Step 3 failed: expected status 200, got %d: %s", getRR.Code, getRR.Body.String())
	}

	var getResp map[string]interface{}
	json.Unmarshal(getRR.Body.Bytes(), &getResp)

	if getResp["id"] != templateID {
		t.Errorf("Step 3 failed: expected id '%s', got '%s'", templateID, getResp["id"])
	}

	// Step 4: List templates
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/scanner-templates", nil)
	listRR := httptest.NewRecorder()
	th.router.ServeHTTP(listRR, listReq)

	if listRR.Code != http.StatusOK {
		t.Fatalf("Step 4 failed: expected status 200, got %d: %s", listRR.Code, listRR.Body.String())
	}

	var listResp map[string]interface{}
	json.Unmarshal(listRR.Body.Bytes(), &listResp)

	items := listResp["items"].([]interface{})
	if len(items) != 1 {
		t.Errorf("Step 4 failed: expected 1 template, got %d", len(items))
	}

	t.Log("E2E template sync flow completed successfully")
}

func TestE2E_TemplateSource_CreateAndList(t *testing.T) {
	// This test simulates:
	// 1. Create a Git template source
	// 2. Create an S3 template source
	// 3. List all sources
	// 4. Disable one source
	// 5. Verify only enabled source is returned for sync

	th := setupTemplateTestHandlers(t)

	// Step 1: Create Git source
	gitBody := map[string]interface{}{
		"name":          "git-source",
		"source_type":   "git",
		"template_type": "nuclei",
		"git_config": map[string]interface{}{
			"url":    "https://github.com/test/templates",
			"branch": "main",
		},
		"enabled":           true,
		"auto_sync_on_scan": true,
	}
	gitBodyBytes, _ := json.Marshal(gitBody)

	gitReq := httptest.NewRequest(http.MethodPost, "/api/v1/template-sources", jsonReader(gitBodyBytes))
	gitReq.Header.Set("Content-Type", "application/json")
	gitRR := httptest.NewRecorder()
	th.router.ServeHTTP(gitRR, gitReq)

	if gitRR.Code != http.StatusCreated {
		t.Fatalf("Step 1 failed: expected status 201, got %d: %s", gitRR.Code, gitRR.Body.String())
	}

	var gitResp map[string]interface{}
	json.Unmarshal(gitRR.Body.Bytes(), &gitResp)
	gitSourceID := gitResp["id"].(string)

	// Step 2: Create S3 source
	s3Body := map[string]interface{}{
		"name":          "s3-source",
		"source_type":   "s3",
		"template_type": "semgrep",
		"s3_config": map[string]interface{}{
			"bucket": "test-bucket",
			"region": "us-east-1",
		},
		"enabled": true,
	}
	s3BodyBytes, _ := json.Marshal(s3Body)

	s3Req := httptest.NewRequest(http.MethodPost, "/api/v1/template-sources", jsonReader(s3BodyBytes))
	s3Req.Header.Set("Content-Type", "application/json")
	s3RR := httptest.NewRecorder()
	th.router.ServeHTTP(s3RR, s3Req)

	if s3RR.Code != http.StatusCreated {
		t.Fatalf("Step 2 failed: expected status 201, got %d: %s", s3RR.Code, s3RR.Body.String())
	}

	// Step 3: List all sources
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/template-sources", nil)
	listRR := httptest.NewRecorder()
	th.router.ServeHTTP(listRR, listReq)

	if listRR.Code != http.StatusOK {
		t.Fatalf("Step 3 failed: expected status 200, got %d: %s", listRR.Code, listRR.Body.String())
	}

	var listResp map[string]interface{}
	json.Unmarshal(listRR.Body.Bytes(), &listResp)

	items := listResp["items"].([]interface{})
	if len(items) != 2 {
		t.Errorf("Step 3 failed: expected 2 sources, got %d", len(items))
	}

	// Step 4: Disable Git source
	disableReq := httptest.NewRequest(http.MethodPost, "/api/v1/template-sources/"+gitSourceID+"/disable", nil)
	disableRR := httptest.NewRecorder()
	th.router.ServeHTTP(disableRR, disableReq)

	if disableRR.Code != http.StatusOK {
		t.Fatalf("Step 4 failed: expected status 200, got %d: %s", disableRR.Code, disableRR.Body.String())
	}

	// Step 5: Verify only enabled source for sync
	enabledSources, err := th.sourceRepo.ListEnabledForSync(context.Background(), th.tenantID)
	if err != nil {
		t.Fatalf("Step 5 failed: %v", err)
	}

	if len(enabledSources) != 1 {
		t.Errorf("Step 5 failed: expected 1 enabled source, got %d", len(enabledSources))
	}

	if enabledSources[0].Name != "s3-source" {
		t.Errorf("Step 5 failed: expected 's3-source' to be enabled, got '%s'", enabledSources[0].Name)
	}

	t.Log("E2E template source flow completed successfully")
}

// =============================================================================
// Helper Functions
// =============================================================================

func createTestTemplate(tenantID shared.ID, name string, templateType scannertemplate.TemplateType) *scannertemplate.ScannerTemplate {
	content := []byte("test content")
	hash := sha256.Sum256(content)

	return &scannertemplate.ScannerTemplate{
		ID:            shared.NewID(),
		TenantID:      tenantID,
		Name:          name,
		TemplateType:  templateType,
		Content:       content,
		ContentHash:   hex.EncodeToString(hash[:]),
		SignatureHash: "test-signature",
		RuleCount:     1,
		Status:        scannertemplate.TemplateStatusActive,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
}

func jsonReader(data []byte) *bytes.Reader {
	return bytes.NewReader(data)
}
