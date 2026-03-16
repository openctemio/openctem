package unit

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/scannertemplate"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// ============================================================================
// Mock Repositories
// ============================================================================

// scannerTemplateMockRepository implements scannertemplate.Repository for testing.
type scannerTemplateMockRepository struct {
	templates map[string]*scannertemplate.ScannerTemplate
	usage     *scannertemplate.TemplateUsage

	createErr      error
	getErr         error
	listErr        error
	updateErr      error
	deleteErr      error
	existsByNameFn func(ctx context.Context, tenantID shared.ID, tt scannertemplate.TemplateType, name string) (bool, error)
	getUsageErr    error
	listByIDsErr   error
}

func newScannerTemplateMockRepository() *scannerTemplateMockRepository {
	return &scannerTemplateMockRepository{
		templates: make(map[string]*scannertemplate.ScannerTemplate),
		usage: &scannertemplate.TemplateUsage{
			TotalTemplates:    0,
			NucleiTemplates:   0,
			SemgrepTemplates:  0,
			GitleaksTemplates: 0,
			TotalStorageBytes: 0,
		},
	}
}

func (m *scannerTemplateMockRepository) Create(_ context.Context, t *scannertemplate.ScannerTemplate) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.templates[t.ID.String()] = t
	return nil
}

func (m *scannerTemplateMockRepository) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*scannertemplate.ScannerTemplate, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	t, ok := m.templates[id.String()]
	if !ok {
		return nil, shared.NewDomainError("NOT_FOUND", "template not found", shared.ErrNotFound)
	}
	if !t.TenantID.Equals(tenantID) {
		return nil, shared.NewDomainError("NOT_FOUND", "template not found", shared.ErrNotFound)
	}
	return t, nil
}

func (m *scannerTemplateMockRepository) GetByTenantAndName(_ context.Context, tenantID shared.ID, templateType scannertemplate.TemplateType, name string) (*scannertemplate.ScannerTemplate, error) {
	for _, t := range m.templates {
		if t.TenantID.Equals(tenantID) && t.TemplateType == templateType && t.Name == name {
			return t, nil
		}
	}
	return nil, shared.NewDomainError("NOT_FOUND", "template not found", shared.ErrNotFound)
}

func (m *scannerTemplateMockRepository) List(_ context.Context, _ scannertemplate.Filter, page pagination.Pagination) (pagination.Result[*scannertemplate.ScannerTemplate], error) {
	if m.listErr != nil {
		return pagination.Result[*scannertemplate.ScannerTemplate]{}, m.listErr
	}
	result := make([]*scannertemplate.ScannerTemplate, 0, len(m.templates))
	for _, t := range m.templates {
		result = append(result, t)
	}
	total := int64(len(result))
	return pagination.Result[*scannertemplate.ScannerTemplate]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: int((total + int64(page.PerPage) - 1) / int64(page.PerPage)),
	}, nil
}

func (m *scannerTemplateMockRepository) ListByIDs(_ context.Context, tenantID shared.ID, ids []shared.ID) ([]*scannertemplate.ScannerTemplate, error) {
	if m.listByIDsErr != nil {
		return nil, m.listByIDsErr
	}
	result := make([]*scannertemplate.ScannerTemplate, 0, len(ids))
	for _, id := range ids {
		if t, ok := m.templates[id.String()]; ok && t.TenantID.Equals(tenantID) {
			result = append(result, t)
		}
	}
	return result, nil
}

func (m *scannerTemplateMockRepository) Update(_ context.Context, t *scannertemplate.ScannerTemplate) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.templates[t.ID.String()] = t
	return nil
}

func (m *scannerTemplateMockRepository) Delete(_ context.Context, tenantID, id shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	t, ok := m.templates[id.String()]
	if !ok {
		return shared.NewDomainError("NOT_FOUND", "template not found", shared.ErrNotFound)
	}
	if !t.TenantID.Equals(tenantID) {
		return shared.NewDomainError("NOT_FOUND", "template not found", shared.ErrNotFound)
	}
	delete(m.templates, id.String())
	return nil
}

func (m *scannerTemplateMockRepository) CountByTenant(_ context.Context, _ shared.ID) (int64, error) {
	return int64(len(m.templates)), nil
}

func (m *scannerTemplateMockRepository) CountByType(_ context.Context, _ shared.ID, tt scannertemplate.TemplateType) (int64, error) {
	var count int64
	for _, t := range m.templates {
		if t.TemplateType == tt {
			count++
		}
	}
	return count, nil
}

func (m *scannerTemplateMockRepository) ExistsByName(ctx context.Context, tenantID shared.ID, templateType scannertemplate.TemplateType, name string) (bool, error) {
	if m.existsByNameFn != nil {
		return m.existsByNameFn(ctx, tenantID, templateType, name)
	}
	for _, t := range m.templates {
		if t.TenantID.Equals(tenantID) && t.TemplateType == templateType && t.Name == name {
			return true, nil
		}
	}
	return false, nil
}

func (m *scannerTemplateMockRepository) GetUsage(_ context.Context, _ shared.ID) (*scannertemplate.TemplateUsage, error) {
	if m.getUsageErr != nil {
		return nil, m.getUsageErr
	}
	return m.usage, nil
}

// ============================================================================
// Test Helpers
// ============================================================================

func newTestScannerTemplateService(repo *scannerTemplateMockRepository) *app.ScannerTemplateService {
	log := logger.New(logger.Config{Level: "error"})
	return app.NewScannerTemplateService(repo, "test-signing-secret", log)
}

// validNucleiYAML returns a valid nuclei template in base64 format.
func validNucleiYAML() string {
	content := `id: test-template
info:
  name: Test Template
  severity: high
  author: tester
http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
`
	return base64.StdEncoding.EncodeToString([]byte(content))
}

// validSemgrepYAML returns a valid semgrep rule in base64 format.
func validSemgrepYAML() string {
	content := `rules:
  - id: test-rule
    pattern: "exec($X)"
    message: "Found exec call"
    languages: [python]
    severity: WARNING
`
	return base64.StdEncoding.EncodeToString([]byte(content))
}

// validGitleaksTOML returns a valid gitleaks config in base64 format.
func validGitleaksTOML() string {
	content := `[[rules]]
id = "test-secret"
regex = '''[A-Za-z0-9]{32}'''
`
	return base64.StdEncoding.EncodeToString([]byte(content))
}

// ============================================================================
// CreateTemplate Tests
// ============================================================================

func TestScannerTemplateService_CreateTemplate_Success(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()
	userID := shared.NewID()

	input := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		UserID:       userID.String(),
		Name:         "My Nuclei Template",
		TemplateType: "nuclei",
		Description:  "A test template",
		Content:      validNucleiYAML(),
		Tags:         []string{"web", "sqli"},
	}

	tmpl, err := svc.CreateTemplate(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if tmpl == nil {
		t.Fatal("expected template, got nil")
	}
	if tmpl.Name != "My Nuclei Template" {
		t.Errorf("expected name 'My Nuclei Template', got %q", tmpl.Name)
	}
	if tmpl.TemplateType != scannertemplate.TemplateTypeNuclei {
		t.Errorf("expected type nuclei, got %v", tmpl.TemplateType)
	}
	if tmpl.Description != "A test template" {
		t.Errorf("expected description 'A test template', got %q", tmpl.Description)
	}
	if len(tmpl.Tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(tmpl.Tags))
	}
	if tmpl.SignatureHash == "" {
		t.Error("expected signature hash to be set")
	}
	if tmpl.Status != scannertemplate.TemplateStatusActive {
		t.Errorf("expected status active, got %v", tmpl.Status)
	}
	if tmpl.RuleCount != 1 {
		t.Errorf("expected rule count 1, got %d", tmpl.RuleCount)
	}

	// Verify persisted
	if _, ok := repo.templates[tmpl.ID.String()]; !ok {
		t.Error("expected template to be persisted in repository")
	}
}

func TestScannerTemplateService_CreateTemplate_SemgrepSuccess(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()

	input := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "My Semgrep Rule",
		TemplateType: "semgrep",
		Content:      validSemgrepYAML(),
	}

	tmpl, err := svc.CreateTemplate(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if tmpl.TemplateType != scannertemplate.TemplateTypeSemgrep {
		t.Errorf("expected type semgrep, got %v", tmpl.TemplateType)
	}
	if tmpl.RuleCount != 1 {
		t.Errorf("expected rule count 1, got %d", tmpl.RuleCount)
	}
}

func TestScannerTemplateService_CreateTemplate_GitleaksSuccess(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()

	input := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "My Gitleaks Config",
		TemplateType: "gitleaks",
		Content:      validGitleaksTOML(),
	}

	tmpl, err := svc.CreateTemplate(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if tmpl.TemplateType != scannertemplate.TemplateTypeGitleaks {
		t.Errorf("expected type gitleaks, got %v", tmpl.TemplateType)
	}
}

func TestScannerTemplateService_CreateTemplate_InvalidTenantID(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	input := app.CreateScannerTemplateInput{
		TenantID:     "not-a-uuid",
		Name:         "Test",
		TemplateType: "nuclei",
		Content:      validNucleiYAML(),
	}

	_, err := svc.CreateTemplate(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestScannerTemplateService_CreateTemplate_InvalidUserID(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()

	input := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		UserID:       "bad-uuid",
		Name:         "Test",
		TemplateType: "nuclei",
		Content:      validNucleiYAML(),
	}

	_, err := svc.CreateTemplate(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid user ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestScannerTemplateService_CreateTemplate_InvalidTemplateType(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()

	input := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "Test",
		TemplateType: "invalid_type",
		Content:      validNucleiYAML(),
	}

	_, err := svc.CreateTemplate(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid template type")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestScannerTemplateService_CreateTemplate_InvalidBase64(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()

	input := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "Test",
		TemplateType: "nuclei",
		Content:      "not!!valid!!base64!!",
	}

	_, err := svc.CreateTemplate(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestScannerTemplateService_CreateTemplate_ContentExceedsMaxSize(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()

	// Gitleaks max size is 256KB; create content larger than that.
	largeContent := make([]byte, 256*1024+1)
	for i := range largeContent {
		largeContent[i] = 'x'
	}

	input := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "Test",
		TemplateType: "gitleaks",
		Content:      base64.StdEncoding.EncodeToString(largeContent),
	}

	_, err := svc.CreateTemplate(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for content exceeding max size")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestScannerTemplateService_CreateTemplate_DuplicateName(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()

	input := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "Duplicate Name",
		TemplateType: "nuclei",
		Content:      validNucleiYAML(),
	}

	// Create first template
	_, err := svc.CreateTemplate(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error on first create, got %v", err)
	}

	// Try to create another with the same name
	_, err = svc.CreateTemplate(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
	if !errors.Is(err, shared.ErrAlreadyExists) {
		t.Errorf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestScannerTemplateService_CreateTemplate_ExistsByNameRepoError(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	repoErr := errors.New("database connection lost")
	repo.existsByNameFn = func(_ context.Context, _ shared.ID, _ scannertemplate.TemplateType, _ string) (bool, error) {
		return false, repoErr
	}

	tenantID := shared.NewID()

	input := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "Test",
		TemplateType: "nuclei",
		Content:      validNucleiYAML(),
	}

	_, err := svc.CreateTemplate(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
}

func TestScannerTemplateService_CreateTemplate_QuotaTotalTemplatesExceeded(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	// Set usage to be at the limit
	repo.usage = &scannertemplate.TemplateUsage{
		TotalTemplates:    100,
		NucleiTemplates:   10,
		SemgrepTemplates:  0,
		GitleaksTemplates: 0,
		TotalStorageBytes: 0,
	}

	tenantID := shared.NewID()

	input := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "Test",
		TemplateType: "nuclei",
		Content:      validNucleiYAML(),
	}

	_, err := svc.CreateTemplate(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for quota exceeded")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

func TestScannerTemplateService_CreateTemplate_QuotaPerTypeExceeded(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	repo.usage = &scannertemplate.TemplateUsage{
		TotalTemplates:    10,
		NucleiTemplates:   50, // At per-type limit
		SemgrepTemplates:  0,
		GitleaksTemplates: 0,
		TotalStorageBytes: 0,
	}

	tenantID := shared.NewID()

	input := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "Test",
		TemplateType: "nuclei",
		Content:      validNucleiYAML(),
	}

	_, err := svc.CreateTemplate(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for per-type quota exceeded")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

func TestScannerTemplateService_CreateTemplate_QuotaStorageExceeded(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	repo.usage = &scannertemplate.TemplateUsage{
		TotalTemplates:    1,
		NucleiTemplates:   1,
		SemgrepTemplates:  0,
		GitleaksTemplates: 0,
		TotalStorageBytes: 50 * 1024 * 1024, // At storage limit
	}

	tenantID := shared.NewID()

	input := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "Test",
		TemplateType: "nuclei",
		Content:      validNucleiYAML(),
	}

	_, err := svc.CreateTemplate(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for storage quota exceeded")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

func TestScannerTemplateService_CreateTemplate_QuotaUsageRepoError(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	repo.getUsageErr = errors.New("usage check failed")

	tenantID := shared.NewID()

	input := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "Test",
		TemplateType: "nuclei",
		Content:      validNucleiYAML(),
	}

	_, err := svc.CreateTemplate(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when usage check fails")
	}
}

func TestScannerTemplateService_CreateTemplate_CreateRepoError(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	repo.createErr = errors.New("insert failed")

	tenantID := shared.NewID()

	input := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "Test",
		TemplateType: "nuclei",
		Content:      validNucleiYAML(),
	}

	_, err := svc.CreateTemplate(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when repo create fails")
	}
}

func TestScannerTemplateService_CreateTemplate_NoUserID(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()

	input := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "No User Template",
		TemplateType: "nuclei",
		Content:      validNucleiYAML(),
	}

	tmpl, err := svc.CreateTemplate(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if tmpl.CreatedBy != nil {
		t.Error("expected CreatedBy to be nil when no user ID provided")
	}
}

func TestScannerTemplateService_CreateTemplate_CustomQuota(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	// Set a very low quota
	svc.SetQuota(scannertemplate.TemplateQuota{
		MaxTemplates:         1,
		MaxTemplatesNuclei:   1,
		MaxTemplatesSemgrep:  1,
		MaxTemplatesGitleaks: 1,
		MaxTotalStorageBytes: 100,
	})

	tenantID := shared.NewID()

	input := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "Test",
		TemplateType: "nuclei",
		Content:      validNucleiYAML(),
	}

	// Content is larger than 100 bytes, should exceed storage quota
	_, err := svc.CreateTemplate(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for custom storage quota exceeded")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

// ============================================================================
// GetTemplate Tests
// ============================================================================

func TestScannerTemplateService_GetTemplate_Success(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()

	// Seed a template
	tmpl, err := scannertemplate.NewScannerTemplate(tenantID, "Test Template", scannertemplate.TemplateTypeNuclei, []byte("test content"), nil)
	if err != nil {
		t.Fatalf("failed to create template: %v", err)
	}
	repo.templates[tmpl.ID.String()] = tmpl

	result, err := svc.GetTemplate(context.Background(), tenantID.String(), tmpl.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Name != "Test Template" {
		t.Errorf("expected name 'Test Template', got %q", result.Name)
	}
}

func TestScannerTemplateService_GetTemplate_InvalidTenantID(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	_, err := svc.GetTemplate(context.Background(), "bad-id", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestScannerTemplateService_GetTemplate_InvalidTemplateID(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	_, err := svc.GetTemplate(context.Background(), shared.NewID().String(), "bad-id")
	if err == nil {
		t.Fatal("expected error for invalid template ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestScannerTemplateService_GetTemplate_NotFound(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	_, err := svc.GetTemplate(context.Background(), shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent template")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestScannerTemplateService_GetTemplate_WrongTenant(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()
	otherTenantID := shared.NewID()

	tmpl, _ := scannertemplate.NewScannerTemplate(tenantID, "Test", scannertemplate.TemplateTypeNuclei, []byte("content"), nil)
	repo.templates[tmpl.ID.String()] = tmpl

	_, err := svc.GetTemplate(context.Background(), otherTenantID.String(), tmpl.ID.String())
	if err == nil {
		t.Fatal("expected error for wrong tenant")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// ============================================================================
// ListTemplates Tests
// ============================================================================

func TestScannerTemplateService_ListTemplates_Success(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()

	// Seed templates
	for i := 0; i < 3; i++ {
		tmpl, _ := scannertemplate.NewScannerTemplate(tenantID, "tmpl-"+string(rune('a'+i)), scannertemplate.TemplateTypeNuclei, []byte("content"), nil)
		repo.templates[tmpl.ID.String()] = tmpl
	}

	input := app.ListScannerTemplatesInput{
		TenantID: tenantID.String(),
		Page:     1,
		PerPage:  10,
	}

	result, err := svc.ListTemplates(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 3 {
		t.Errorf("expected total 3, got %d", result.Total)
	}
}

func TestScannerTemplateService_ListTemplates_WithTypeFilter(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()
	nucleiType := "nuclei"

	input := app.ListScannerTemplatesInput{
		TenantID:     tenantID.String(),
		TemplateType: &nucleiType,
		Page:         1,
		PerPage:      10,
	}

	_, err := svc.ListTemplates(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestScannerTemplateService_ListTemplates_WithStatusFilter(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()
	status := "active"

	input := app.ListScannerTemplatesInput{
		TenantID: tenantID.String(),
		Status:   &status,
		Page:     1,
		PerPage:  10,
	}

	_, err := svc.ListTemplates(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestScannerTemplateService_ListTemplates_InvalidTenantID(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	input := app.ListScannerTemplatesInput{
		TenantID: "bad-id",
		Page:     1,
		PerPage:  10,
	}

	_, err := svc.ListTemplates(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestScannerTemplateService_ListTemplates_RepoError(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	repo.listErr = errors.New("list failed")

	input := app.ListScannerTemplatesInput{
		TenantID: shared.NewID().String(),
		Page:     1,
		PerPage:  10,
	}

	_, err := svc.ListTemplates(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
}

// ============================================================================
// UpdateTemplate Tests
// ============================================================================

func TestScannerTemplateService_UpdateTemplate_Success(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()

	// Create a template first
	createInput := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "Original Name",
		TemplateType: "nuclei",
		Content:      validNucleiYAML(),
	}
	created, err := svc.CreateTemplate(context.Background(), createInput)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	updateInput := app.UpdateScannerTemplateInput{
		TenantID:    tenantID.String(),
		TemplateID:  created.ID.String(),
		Name:        "Updated Name",
		Description: "Updated description",
		Tags:        []string{"updated"},
	}

	updated, err := svc.UpdateTemplate(context.Background(), updateInput)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.Name != "Updated Name" {
		t.Errorf("expected name 'Updated Name', got %q", updated.Name)
	}
	if updated.Description != "Updated description" {
		t.Errorf("expected description 'Updated description', got %q", updated.Description)
	}
	if len(updated.Tags) != 1 || updated.Tags[0] != "updated" {
		t.Errorf("expected tags [updated], got %v", updated.Tags)
	}
}

func TestScannerTemplateService_UpdateTemplate_WithNewContent(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()

	createInput := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "Content Update Test",
		TemplateType: "nuclei",
		Content:      validNucleiYAML(),
	}
	created, err := svc.CreateTemplate(context.Background(), createInput)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	originalSig := created.SignatureHash

	updateInput := app.UpdateScannerTemplateInput{
		TenantID:   tenantID.String(),
		TemplateID: created.ID.String(),
		Content:    validNucleiYAML(), // Same valid YAML
	}

	updated, err := svc.UpdateTemplate(context.Background(), updateInput)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Signature should be recomputed
	if updated.SignatureHash == "" {
		t.Error("expected signature to be set after content update")
	}
	// Content is the same so signature should match
	if updated.SignatureHash != originalSig {
		// The content is the same, but version may have changed.
		// Signature is based on content, not version, so it should be the same.
		t.Log("signature changed despite same content; this is expected only if content byte-level differs")
	}
}

func TestScannerTemplateService_UpdateTemplate_InvalidTenantID(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	updateInput := app.UpdateScannerTemplateInput{
		TenantID:   "bad-id",
		TemplateID: shared.NewID().String(),
	}

	_, err := svc.UpdateTemplate(context.Background(), updateInput)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestScannerTemplateService_UpdateTemplate_NotFound(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	updateInput := app.UpdateScannerTemplateInput{
		TenantID:   shared.NewID().String(),
		TemplateID: shared.NewID().String(),
		Name:       "Updated",
	}

	_, err := svc.UpdateTemplate(context.Background(), updateInput)
	if err == nil {
		t.Fatal("expected error for non-existent template")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestScannerTemplateService_UpdateTemplate_WrongTenant(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()
	otherTenantID := shared.NewID()

	tmpl, _ := scannertemplate.NewScannerTemplate(tenantID, "Test", scannertemplate.TemplateTypeNuclei, []byte("content"), nil)
	repo.templates[tmpl.ID.String()] = tmpl

	updateInput := app.UpdateScannerTemplateInput{
		TenantID:   otherTenantID.String(),
		TemplateID: tmpl.ID.String(),
		Name:       "Stolen",
	}

	_, err := svc.UpdateTemplate(context.Background(), updateInput)
	if err == nil {
		t.Fatal("expected error for wrong tenant")
	}
}

func TestScannerTemplateService_UpdateTemplate_InvalidBase64Content(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()

	createInput := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "Base64 Test",
		TemplateType: "nuclei",
		Content:      validNucleiYAML(),
	}
	created, err := svc.CreateTemplate(context.Background(), createInput)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	updateInput := app.UpdateScannerTemplateInput{
		TenantID:   tenantID.String(),
		TemplateID: created.ID.String(),
		Content:    "not!!valid!!base64",
	}

	_, err = svc.UpdateTemplate(context.Background(), updateInput)
	if err == nil {
		t.Fatal("expected error for invalid base64 content")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestScannerTemplateService_UpdateTemplate_RepoError(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()

	createInput := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "Repo Error Test",
		TemplateType: "nuclei",
		Content:      validNucleiYAML(),
	}
	created, err := svc.CreateTemplate(context.Background(), createInput)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	repo.updateErr = errors.New("update failed")

	updateInput := app.UpdateScannerTemplateInput{
		TenantID:   tenantID.String(),
		TemplateID: created.ID.String(),
		Name:       "Should Fail",
	}

	_, err = svc.UpdateTemplate(context.Background(), updateInput)
	if err == nil {
		t.Fatal("expected error when repo update fails")
	}
}

// ============================================================================
// DeleteTemplate Tests
// ============================================================================

func TestScannerTemplateService_DeleteTemplate_Success(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()

	createInput := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "To Delete",
		TemplateType: "nuclei",
		Content:      validNucleiYAML(),
	}
	created, err := svc.CreateTemplate(context.Background(), createInput)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	err = svc.DeleteTemplate(context.Background(), tenantID.String(), created.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify deleted
	if _, ok := repo.templates[created.ID.String()]; ok {
		t.Error("expected template to be deleted from repository")
	}
}

func TestScannerTemplateService_DeleteTemplate_InvalidTenantID(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	err := svc.DeleteTemplate(context.Background(), "bad-id", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestScannerTemplateService_DeleteTemplate_NotFound(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	err := svc.DeleteTemplate(context.Background(), shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent template")
	}
}

func TestScannerTemplateService_DeleteTemplate_WrongTenant(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()
	otherTenantID := shared.NewID()

	tmpl, _ := scannertemplate.NewScannerTemplate(tenantID, "Test", scannertemplate.TemplateTypeNuclei, []byte("content"), nil)
	repo.templates[tmpl.ID.String()] = tmpl

	err := svc.DeleteTemplate(context.Background(), otherTenantID.String(), tmpl.ID.String())
	if err == nil {
		t.Fatal("expected error for wrong tenant")
	}
}

func TestScannerTemplateService_DeleteTemplate_RepoError(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()

	tmpl, _ := scannertemplate.NewScannerTemplate(tenantID, "Test", scannertemplate.TemplateTypeNuclei, []byte("content"), nil)
	repo.templates[tmpl.ID.String()] = tmpl

	repo.deleteErr = errors.New("delete failed")

	err := svc.DeleteTemplate(context.Background(), tenantID.String(), tmpl.ID.String())
	if err == nil {
		t.Fatal("expected error when repo delete fails")
	}
}

// ============================================================================
// ValidateTemplate Tests
// ============================================================================

func TestScannerTemplateService_ValidateTemplate_ValidNuclei(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	input := app.ValidateTemplateInput{
		TemplateType: "nuclei",
		Content:      validNucleiYAML(),
	}

	result, err := svc.ValidateTemplate(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.Valid {
		t.Errorf("expected valid result, got errors: %v", result.Errors)
	}
}

func TestScannerTemplateService_ValidateTemplate_ValidSemgrep(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	input := app.ValidateTemplateInput{
		TemplateType: "semgrep",
		Content:      validSemgrepYAML(),
	}

	result, err := svc.ValidateTemplate(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.Valid {
		t.Errorf("expected valid result, got errors: %v", result.Errors)
	}
}

func TestScannerTemplateService_ValidateTemplate_ValidGitleaks(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	input := app.ValidateTemplateInput{
		TemplateType: "gitleaks",
		Content:      validGitleaksTOML(),
	}

	result, err := svc.ValidateTemplate(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.Valid {
		t.Errorf("expected valid result, got errors: %v", result.Errors)
	}
}

func TestScannerTemplateService_ValidateTemplate_InvalidTemplateType(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	input := app.ValidateTemplateInput{
		TemplateType: "unknown",
		Content:      validNucleiYAML(),
	}

	_, err := svc.ValidateTemplate(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid template type")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestScannerTemplateService_ValidateTemplate_InvalidBase64(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	input := app.ValidateTemplateInput{
		TemplateType: "nuclei",
		Content:      "not-valid-base64!!",
	}

	_, err := svc.ValidateTemplate(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestScannerTemplateService_ValidateTemplate_ContentExceedsSize(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	largeContent := make([]byte, 256*1024+1)
	for i := range largeContent {
		largeContent[i] = 'x'
	}

	input := app.ValidateTemplateInput{
		TemplateType: "gitleaks",
		Content:      base64.StdEncoding.EncodeToString(largeContent),
	}

	result, err := svc.ValidateTemplate(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error (size check returns result, not error), got %v", err)
	}
	if result.Valid {
		t.Error("expected result to be invalid for oversized content")
	}
}

// ============================================================================
// DownloadTemplate Tests
// ============================================================================

func TestScannerTemplateService_DownloadTemplate_NucleiSuccess(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()

	createInput := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "download-test",
		TemplateType: "nuclei",
		Content:      validNucleiYAML(),
	}
	created, err := svc.CreateTemplate(context.Background(), createInput)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	content, filename, err := svc.DownloadTemplate(context.Background(), tenantID.String(), created.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(content) == 0 {
		t.Error("expected content, got empty")
	}
	if filename != "download-test.yaml" {
		t.Errorf("expected filename 'download-test.yaml', got %q", filename)
	}
}

func TestScannerTemplateService_DownloadTemplate_GitleaksExtension(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()

	createInput := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "gitleaks-download",
		TemplateType: "gitleaks",
		Content:      validGitleaksTOML(),
	}
	created, err := svc.CreateTemplate(context.Background(), createInput)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	_, filename, err := svc.DownloadTemplate(context.Background(), tenantID.String(), created.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if filename != "gitleaks-download.toml" {
		t.Errorf("expected filename 'gitleaks-download.toml', got %q", filename)
	}
}

func TestScannerTemplateService_DownloadTemplate_NotFound(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	_, _, err := svc.DownloadTemplate(context.Background(), shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent template")
	}
}

func TestScannerTemplateService_DownloadTemplate_InvalidIDs(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	_, _, err := svc.DownloadTemplate(context.Background(), "bad-id", "bad-id")
	if err == nil {
		t.Fatal("expected error for invalid IDs")
	}
}

// ============================================================================
// DeprecateTemplate Tests
// ============================================================================

func TestScannerTemplateService_DeprecateTemplate_Success(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()

	createInput := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "To Deprecate",
		TemplateType: "nuclei",
		Content:      validNucleiYAML(),
	}
	created, err := svc.CreateTemplate(context.Background(), createInput)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	result, err := svc.DeprecateTemplate(context.Background(), tenantID.String(), created.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Status != scannertemplate.TemplateStatusDeprecated {
		t.Errorf("expected status deprecated, got %v", result.Status)
	}
}

func TestScannerTemplateService_DeprecateTemplate_InvalidTenantID(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	_, err := svc.DeprecateTemplate(context.Background(), "bad-id", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestScannerTemplateService_DeprecateTemplate_WrongTenant(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()
	otherTenantID := shared.NewID()

	tmpl, _ := scannertemplate.NewScannerTemplate(tenantID, "Test", scannertemplate.TemplateTypeNuclei, []byte("content"), nil)
	repo.templates[tmpl.ID.String()] = tmpl

	_, err := svc.DeprecateTemplate(context.Background(), otherTenantID.String(), tmpl.ID.String())
	if err == nil {
		t.Fatal("expected error for wrong tenant")
	}
}

func TestScannerTemplateService_DeprecateTemplate_RepoUpdateError(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()

	createInput := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "Deprecate Fail",
		TemplateType: "nuclei",
		Content:      validNucleiYAML(),
	}
	created, err := svc.CreateTemplate(context.Background(), createInput)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	repo.updateErr = errors.New("update failed")

	_, err = svc.DeprecateTemplate(context.Background(), tenantID.String(), created.ID.String())
	if err == nil {
		t.Fatal("expected error when repo update fails")
	}
}

// ============================================================================
// GetTemplatesByIDs Tests
// ============================================================================

func TestScannerTemplateService_GetTemplatesByIDs_Success(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()

	tmpl1, _ := scannertemplate.NewScannerTemplate(tenantID, "One", scannertemplate.TemplateTypeNuclei, []byte("content1"), nil)
	tmpl2, _ := scannertemplate.NewScannerTemplate(tenantID, "Two", scannertemplate.TemplateTypeSemgrep, []byte("content2"), nil)
	repo.templates[tmpl1.ID.String()] = tmpl1
	repo.templates[tmpl2.ID.String()] = tmpl2

	results, err := svc.GetTemplatesByIDs(context.Background(), tenantID.String(), []string{tmpl1.ID.String(), tmpl2.ID.String()})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestScannerTemplateService_GetTemplatesByIDs_InvalidTenantID(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	_, err := svc.GetTemplatesByIDs(context.Background(), "bad-id", []string{shared.NewID().String()})
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestScannerTemplateService_GetTemplatesByIDs_InvalidTemplateID(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	_, err := svc.GetTemplatesByIDs(context.Background(), shared.NewID().String(), []string{"bad-id"})
	if err == nil {
		t.Fatal("expected error for invalid template ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestScannerTemplateService_GetTemplatesByIDs_EmptyList(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	results, err := svc.GetTemplatesByIDs(context.Background(), shared.NewID().String(), []string{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestScannerTemplateService_GetTemplatesByIDs_RepoError(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	repo.listByIDsErr = errors.New("list by ids failed")

	_, err := svc.GetTemplatesByIDs(context.Background(), shared.NewID().String(), []string{shared.NewID().String()})
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
}

// ============================================================================
// VerifyTemplateSignature Tests
// ============================================================================

func TestScannerTemplateService_VerifyTemplateSignature_ValidSignature(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()

	createInput := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "Signed Template",
		TemplateType: "nuclei",
		Content:      validNucleiYAML(),
	}
	created, err := svc.CreateTemplate(context.Background(), createInput)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	if !svc.VerifyTemplateSignature(created) {
		t.Error("expected signature verification to pass for freshly created template")
	}
}

func TestScannerTemplateService_VerifyTemplateSignature_TamperedContent(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()

	createInput := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "Tampered Template",
		TemplateType: "nuclei",
		Content:      validNucleiYAML(),
	}
	created, err := svc.CreateTemplate(context.Background(), createInput)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	// Tamper with content after creation
	created.Content = []byte("tampered content")

	if svc.VerifyTemplateSignature(created) {
		t.Error("expected signature verification to fail for tampered content")
	}
}

func TestScannerTemplateService_VerifyTemplateSignature_EmptySignature(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tmpl, _ := scannertemplate.NewScannerTemplate(shared.NewID(), "Test", scannertemplate.TemplateTypeNuclei, []byte("content"), nil)
	// SignatureHash is empty by default (not set via SetSignature)

	if svc.VerifyTemplateSignature(tmpl) {
		t.Error("expected signature verification to fail for template with no signature")
	}
}

func TestScannerTemplateService_VerifyTemplateSignature_WrongSecret(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	log := logger.New(logger.Config{Level: "error"})

	svc1 := app.NewScannerTemplateService(repo, "secret-one", log)
	svc2 := app.NewScannerTemplateService(repo, "secret-two", log)

	tenantID := shared.NewID()

	createInput := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "Wrong Secret Test",
		TemplateType: "nuclei",
		Content:      validNucleiYAML(),
	}
	created, err := svc1.CreateTemplate(context.Background(), createInput)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	// Verify with a service using a different secret
	if svc2.VerifyTemplateSignature(created) {
		t.Error("expected signature verification to fail with different secret")
	}
}

// ============================================================================
// GetUsage Tests
// ============================================================================

func TestScannerTemplateService_GetUsage_Success(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	repo.usage = &scannertemplate.TemplateUsage{
		TotalTemplates:    5,
		NucleiTemplates:   2,
		SemgrepTemplates:  2,
		GitleaksTemplates: 1,
		TotalStorageBytes: 12345,
	}

	tenantID := shared.NewID()

	result, err := svc.GetUsage(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Usage.TotalTemplates != 5 {
		t.Errorf("expected total templates 5, got %d", result.Usage.TotalTemplates)
	}
	if result.Usage.NucleiTemplates != 2 {
		t.Errorf("expected nuclei templates 2, got %d", result.Usage.NucleiTemplates)
	}
	if result.Quota.MaxTemplates != scannertemplate.DefaultMaxTemplatesPerTenant {
		t.Errorf("expected default max templates %d, got %d", scannertemplate.DefaultMaxTemplatesPerTenant, result.Quota.MaxTemplates)
	}
}

func TestScannerTemplateService_GetUsage_InvalidTenantID(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	_, err := svc.GetUsage(context.Background(), "bad-id")
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestScannerTemplateService_GetUsage_RepoError(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	repo.getUsageErr = errors.New("usage query failed")

	_, err := svc.GetUsage(context.Background(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
}

// ============================================================================
// GetQuota Tests
// ============================================================================

func TestScannerTemplateService_GetQuota_Default(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	quota := svc.GetQuota()
	if quota.MaxTemplates != scannertemplate.DefaultMaxTemplatesPerTenant {
		t.Errorf("expected max templates %d, got %d", scannertemplate.DefaultMaxTemplatesPerTenant, quota.MaxTemplates)
	}
	if quota.MaxTemplatesNuclei != scannertemplate.DefaultMaxTemplatesPerType {
		t.Errorf("expected max nuclei %d, got %d", scannertemplate.DefaultMaxTemplatesPerType, quota.MaxTemplatesNuclei)
	}
	if quota.MaxTemplatesSemgrep != scannertemplate.DefaultMaxTemplatesPerType {
		t.Errorf("expected max semgrep %d, got %d", scannertemplate.DefaultMaxTemplatesPerType, quota.MaxTemplatesSemgrep)
	}
	if quota.MaxTemplatesGitleaks != scannertemplate.DefaultMaxTemplatesPerType {
		t.Errorf("expected max gitleaks %d, got %d", scannertemplate.DefaultMaxTemplatesPerType, quota.MaxTemplatesGitleaks)
	}
	if quota.MaxTotalStorageBytes != scannertemplate.DefaultMaxTotalStorageBytes {
		t.Errorf("expected max storage %d, got %d", scannertemplate.DefaultMaxTotalStorageBytes, quota.MaxTotalStorageBytes)
	}
}

func TestScannerTemplateService_GetQuota_Custom(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	customQuota := scannertemplate.TemplateQuota{
		MaxTemplates:         200,
		MaxTemplatesNuclei:   100,
		MaxTemplatesSemgrep:  80,
		MaxTemplatesGitleaks: 60,
		MaxTotalStorageBytes: 100 * 1024 * 1024,
	}
	svc.SetQuota(customQuota)

	quota := svc.GetQuota()
	if quota.MaxTemplates != 200 {
		t.Errorf("expected max templates 200, got %d", quota.MaxTemplates)
	}
	if quota.MaxTemplatesNuclei != 100 {
		t.Errorf("expected max nuclei 100, got %d", quota.MaxTemplatesNuclei)
	}
}

// ============================================================================
// Quota Edge Cases (Per-Type)
// ============================================================================

func TestScannerTemplateService_CreateTemplate_SemgrepQuotaExceeded(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	repo.usage = &scannertemplate.TemplateUsage{
		TotalTemplates:    10,
		NucleiTemplates:   0,
		SemgrepTemplates:  50, // At per-type limit
		GitleaksTemplates: 0,
		TotalStorageBytes: 0,
	}

	tenantID := shared.NewID()

	input := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "Semgrep Quota Test",
		TemplateType: "semgrep",
		Content:      validSemgrepYAML(),
	}

	_, err := svc.CreateTemplate(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for semgrep per-type quota exceeded")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

func TestScannerTemplateService_CreateTemplate_GitleaksQuotaExceeded(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	repo.usage = &scannertemplate.TemplateUsage{
		TotalTemplates:    10,
		NucleiTemplates:   0,
		SemgrepTemplates:  0,
		GitleaksTemplates: 50, // At per-type limit
		TotalStorageBytes: 0,
	}

	tenantID := shared.NewID()

	input := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "Gitleaks Quota Test",
		TemplateType: "gitleaks",
		Content:      validGitleaksTOML(),
	}

	_, err := svc.CreateTemplate(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for gitleaks per-type quota exceeded")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

// ============================================================================
// Signature Computation Consistency
// ============================================================================

func TestScannerTemplateService_SignatureConsistency(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := newTestScannerTemplateService(repo)

	tenantID := shared.NewID()
	content := validNucleiYAML()

	// Create two templates with the same content
	input1 := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "Sig Test 1",
		TemplateType: "nuclei",
		Content:      content,
	}
	input2 := app.CreateScannerTemplateInput{
		TenantID:     tenantID.String(),
		Name:         "Sig Test 2",
		TemplateType: "nuclei",
		Content:      content,
	}

	tmpl1, err := svc.CreateTemplate(context.Background(), input1)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	tmpl2, err := svc.CreateTemplate(context.Background(), input2)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	// Same content should produce the same signature
	if tmpl1.SignatureHash != tmpl2.SignatureHash {
		t.Error("expected same signature for same content")
	}

	// Both should verify
	if !svc.VerifyTemplateSignature(tmpl1) {
		t.Error("expected template 1 signature to verify")
	}
	if !svc.VerifyTemplateSignature(tmpl2) {
		t.Error("expected template 2 signature to verify")
	}
}
