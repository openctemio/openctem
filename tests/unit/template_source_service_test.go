package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/scannertemplate"
	"github.com/openctemio/api/pkg/domain/shared"
	ts "github.com/openctemio/api/pkg/domain/templatesource"
	"github.com/openctemio/api/pkg/logger"
)

// ============================================================================
// Mock Repository
// ============================================================================

type tmplSrcMockRepo struct {
	sources          map[string]*ts.TemplateSource
	createErr        error
	updateErr        error
	deleteErr        error
	countByTenantVal int
	countByTenantErr error
	listOutput       *ts.ListOutput
	listErr          error
	listByTypeSrcs   []*ts.TemplateSource
	listByTypeErr    error
	listEnabledSrcs  []*ts.TemplateSource
	listEnabledErr   error
	updateSyncErr    error
}

func newTmplSrcMockRepo() *tmplSrcMockRepo {
	return &tmplSrcMockRepo{
		sources: make(map[string]*ts.TemplateSource),
	}
}

func (m *tmplSrcMockRepo) Create(_ context.Context, source *ts.TemplateSource) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.sources[source.ID.String()] = source
	return nil
}

func (m *tmplSrcMockRepo) GetByID(_ context.Context, id shared.ID) (*ts.TemplateSource, error) {
	s, ok := m.sources[id.String()]
	if !ok {
		return nil, shared.NewDomainError("NOT_FOUND", "source not found", shared.ErrNotFound)
	}
	return s, nil
}

func (m *tmplSrcMockRepo) GetByTenantAndID(_ context.Context, tenantID, sourceID shared.ID) (*ts.TemplateSource, error) {
	s, ok := m.sources[sourceID.String()]
	if !ok {
		return nil, shared.NewDomainError("NOT_FOUND", "source not found", shared.ErrNotFound)
	}
	if !s.BelongsToTenant(tenantID) {
		return nil, shared.NewDomainError("FORBIDDEN", "source belongs to another tenant", shared.ErrForbidden)
	}
	return s, nil
}

func (m *tmplSrcMockRepo) GetByTenantAndName(_ context.Context, tenantID shared.ID, name string) (*ts.TemplateSource, error) {
	for _, s := range m.sources {
		if s.BelongsToTenant(tenantID) && s.Name == name {
			return s, nil
		}
	}
	return nil, shared.NewDomainError("NOT_FOUND", "source not found", shared.ErrNotFound)
}

func (m *tmplSrcMockRepo) List(_ context.Context, _ ts.ListInput) (*ts.ListOutput, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	if m.listOutput != nil {
		return m.listOutput, nil
	}
	items := make([]*ts.TemplateSource, 0, len(m.sources))
	for _, s := range m.sources {
		items = append(items, s)
	}
	return &ts.ListOutput{Items: items, TotalCount: len(items)}, nil
}

func (m *tmplSrcMockRepo) ListByTenantAndTemplateType(_ context.Context, _ shared.ID, _ scannertemplate.TemplateType) ([]*ts.TemplateSource, error) {
	if m.listByTypeErr != nil {
		return nil, m.listByTypeErr
	}
	return m.listByTypeSrcs, nil
}

func (m *tmplSrcMockRepo) ListEnabledForSync(_ context.Context, _ shared.ID) ([]*ts.TemplateSource, error) {
	if m.listEnabledErr != nil {
		return nil, m.listEnabledErr
	}
	return m.listEnabledSrcs, nil
}

func (m *tmplSrcMockRepo) ListAllNeedingSync(_ context.Context) ([]*ts.TemplateSource, error) {
	return nil, nil
}

func (m *tmplSrcMockRepo) Update(_ context.Context, source *ts.TemplateSource) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.sources[source.ID.String()] = source
	return nil
}

func (m *tmplSrcMockRepo) Delete(_ context.Context, id shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.sources, id.String())
	return nil
}

func (m *tmplSrcMockRepo) UpdateSyncStatus(_ context.Context, source *ts.TemplateSource) error {
	if m.updateSyncErr != nil {
		return m.updateSyncErr
	}
	m.sources[source.ID.String()] = source
	return nil
}

func (m *tmplSrcMockRepo) CountByTenant(_ context.Context, _ shared.ID) (int, error) {
	if m.countByTenantErr != nil {
		return 0, m.countByTenantErr
	}
	return m.countByTenantVal, nil
}

// ============================================================================
// Helpers
// ============================================================================

func newTmplSrcService(repo ts.Repository) *app.TemplateSourceService {
	log := logger.NewNop()
	return app.NewTemplateSourceService(repo, log)
}

func tmplSrcValidGitInput(tenantID string) app.CreateTemplateSourceInput {
	return app.CreateTemplateSourceInput{
		TenantID:     tenantID,
		Name:         "My Git Templates",
		SourceType:   "git",
		TemplateType: "nuclei",
		Description:  "Nuclei templates from GitHub",
		Enabled:      true,
		GitConfig: &ts.GitSourceConfig{
			URL:    "https://github.com/org/templates",
			Branch: "main",
		},
	}
}

func tmplSrcAddSource(repo *tmplSrcMockRepo, tenantID shared.ID, name string) *ts.TemplateSource {
	uid := shared.NewID()
	src, _ := ts.NewTemplateSource(tenantID, name, ts.SourceTypeGit, scannertemplate.TemplateTypeNuclei, &uid)
	_ = src.SetGitConfig(&ts.GitSourceConfig{URL: "https://github.com/org/repo", Branch: "main"})
	repo.sources[src.ID.String()] = src
	return src
}

// ============================================================================
// Tests: CreateSource
// ============================================================================

func TestTemplateSourceService_CreateSource_Success(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	input := tmplSrcValidGitInput(tenantID.String())

	source, err := svc.CreateSource(ctx, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if source == nil {
		t.Fatal("expected source to be created")
	}
	if source.Name != "My Git Templates" {
		t.Errorf("expected name 'My Git Templates', got %q", source.Name)
	}
	if source.SourceType != ts.SourceTypeGit {
		t.Errorf("expected source type git, got %v", source.SourceType)
	}
	if source.TemplateType != scannertemplate.TemplateTypeNuclei {
		t.Errorf("expected template type nuclei, got %v", source.TemplateType)
	}
	if !source.Enabled {
		t.Error("expected source to be enabled")
	}
	if source.GitConfig == nil {
		t.Fatal("expected git config to be set")
	}
	if source.GitConfig.URL != "https://github.com/org/templates" {
		t.Errorf("expected git url, got %q", source.GitConfig.URL)
	}
}

func TestTemplateSourceService_CreateSource_S3(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	input := app.CreateTemplateSourceInput{
		TenantID:     tenantID.String(),
		Name:         "S3 Templates",
		SourceType:   "s3",
		TemplateType: "semgrep",
		Enabled:      true,
		S3Config: &ts.S3SourceConfig{
			Bucket: "my-bucket",
			Region: "us-east-1",
		},
	}

	source, err := svc.CreateSource(ctx, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if source.SourceType != ts.SourceTypeS3 {
		t.Errorf("expected source type s3, got %v", source.SourceType)
	}
	if source.S3Config == nil || source.S3Config.Bucket != "my-bucket" {
		t.Error("expected s3 config to be set")
	}
}

func TestTemplateSourceService_CreateSource_HTTP(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	input := app.CreateTemplateSourceInput{
		TenantID:     tenantID.String(),
		Name:         "HTTP Templates",
		SourceType:   "http",
		TemplateType: "gitleaks",
		Enabled:      true,
		HTTPConfig: &ts.HTTPSourceConfig{
			URL: "https://templates.example.com/gitleaks.zip",
		},
	}

	source, err := svc.CreateSource(ctx, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if source.SourceType != ts.SourceTypeHTTP {
		t.Errorf("expected source type http, got %v", source.SourceType)
	}
	if source.HTTPConfig == nil || source.HTTPConfig.URL != "https://templates.example.com/gitleaks.zip" {
		t.Error("expected http config to be set")
	}
}

func TestTemplateSourceService_CreateSource_InvalidTenantID(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()

	input := tmplSrcValidGitInput("not-a-uuid")

	_, err := svc.CreateSource(ctx, input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestTemplateSourceService_CreateSource_InvalidUserID(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	input := tmplSrcValidGitInput(tenantID.String())
	input.UserID = "invalid-uuid"

	_, err := svc.CreateSource(ctx, input)
	if err == nil {
		t.Fatal("expected error for invalid user ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestTemplateSourceService_CreateSource_InvalidSourceType(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	input := tmplSrcValidGitInput(tenantID.String())
	input.SourceType = "ftp"

	_, err := svc.CreateSource(ctx, input)
	if err == nil {
		t.Fatal("expected error for invalid source type")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestTemplateSourceService_CreateSource_InvalidTemplateType(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	input := tmplSrcValidGitInput(tenantID.String())
	input.TemplateType = "snyk"

	_, err := svc.CreateSource(ctx, input)
	if err == nil {
		t.Fatal("expected error for invalid template type")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestTemplateSourceService_CreateSource_TenantLimitExceeded(t *testing.T) {
	repo := newTmplSrcMockRepo()
	repo.countByTenantVal = 50
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	input := tmplSrcValidGitInput(tenantID.String())

	_, err := svc.CreateSource(ctx, input)
	if err == nil {
		t.Fatal("expected error for limit exceeded")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

func TestTemplateSourceService_CreateSource_DuplicateName(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	tmplSrcAddSource(repo, tenantID, "My Git Templates")

	input := tmplSrcValidGitInput(tenantID.String())

	_, err := svc.CreateSource(ctx, input)
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
	if !errors.Is(err, shared.ErrAlreadyExists) {
		t.Errorf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestTemplateSourceService_CreateSource_GitMissingConfig(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	input := tmplSrcValidGitInput(tenantID.String())
	input.GitConfig = nil

	_, err := svc.CreateSource(ctx, input)
	if err == nil {
		t.Fatal("expected error for missing git config")
	}
}

func TestTemplateSourceService_CreateSource_S3MissingConfig(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	input := app.CreateTemplateSourceInput{
		TenantID:     tenantID.String(),
		Name:         "S3 Source",
		SourceType:   "s3",
		TemplateType: "nuclei",
		S3Config:     nil,
	}

	_, err := svc.CreateSource(ctx, input)
	if err == nil {
		t.Fatal("expected error for missing s3 config")
	}
}

func TestTemplateSourceService_CreateSource_HTTPMissingConfig(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	input := app.CreateTemplateSourceInput{
		TenantID:     tenantID.String(),
		Name:         "HTTP Source",
		SourceType:   "http",
		TemplateType: "nuclei",
		HTTPConfig:   nil,
	}

	_, err := svc.CreateSource(ctx, input)
	if err == nil {
		t.Fatal("expected error for missing http config")
	}
}

func TestTemplateSourceService_CreateSource_WithCredential(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()
	credID := shared.NewID()

	input := tmplSrcValidGitInput(tenantID.String())
	input.CredentialID = credID.String()

	source, err := svc.CreateSource(ctx, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if source.CredentialID == nil {
		t.Fatal("expected credential to be set")
	}
	if !source.CredentialID.Equals(credID) {
		t.Error("credential ID mismatch")
	}
}

func TestTemplateSourceService_CreateSource_InvalidCredentialID(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	input := tmplSrcValidGitInput(tenantID.String())
	input.CredentialID = "not-a-uuid"

	_, err := svc.CreateSource(ctx, input)
	if err == nil {
		t.Fatal("expected error for invalid credential ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestTemplateSourceService_CreateSource_WithCacheTTL(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	input := tmplSrcValidGitInput(tenantID.String())
	input.CacheTTLMinutes = 120

	source, err := svc.CreateSource(ctx, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if source.CacheTTLMinutes != 120 {
		t.Errorf("expected cache TTL 120, got %d", source.CacheTTLMinutes)
	}
}

func TestTemplateSourceService_CreateSource_CountByTenantError(t *testing.T) {
	repo := newTmplSrcMockRepo()
	repo.countByTenantErr = errors.New("db error")
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	input := tmplSrcValidGitInput(tenantID.String())

	_, err := svc.CreateSource(ctx, input)
	if err == nil {
		t.Fatal("expected error when CountByTenant fails")
	}
}

func TestTemplateSourceService_CreateSource_RepoCreateError(t *testing.T) {
	repo := newTmplSrcMockRepo()
	repo.createErr = errors.New("db create error")
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	input := tmplSrcValidGitInput(tenantID.String())

	_, err := svc.CreateSource(ctx, input)
	if err == nil {
		t.Fatal("expected error when repo.Create fails")
	}
}

func TestTemplateSourceService_CreateSource_WithUserID(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()

	input := tmplSrcValidGitInput(tenantID.String())
	input.UserID = userID.String()

	source, err := svc.CreateSource(ctx, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if source.CreatedBy == nil {
		t.Fatal("expected CreatedBy to be set")
	}
}

// ============================================================================
// Tests: GetSource
// ============================================================================

func TestTemplateSourceService_GetSource_Success(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	src := tmplSrcAddSource(repo, tenantID, "Test Source")

	result, err := svc.GetSource(ctx, tenantID.String(), src.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Name != "Test Source" {
		t.Errorf("expected name 'Test Source', got %q", result.Name)
	}
}

func TestTemplateSourceService_GetSource_InvalidTenantID(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()

	_, err := svc.GetSource(ctx, "bad", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestTemplateSourceService_GetSource_InvalidSourceID(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()

	_, err := svc.GetSource(ctx, shared.NewID().String(), "bad")
	if err == nil {
		t.Fatal("expected error for invalid source ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestTemplateSourceService_GetSource_NotFound(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()

	_, err := svc.GetSource(ctx, shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for missing source")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestTemplateSourceService_GetSource_WrongTenant(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()
	otherTenantID := shared.NewID()

	src := tmplSrcAddSource(repo, tenantID, "Source A")

	_, err := svc.GetSource(ctx, otherTenantID.String(), src.ID.String())
	if err == nil {
		t.Fatal("expected error when tenant does not match")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

// ============================================================================
// Tests: ListSources
// ============================================================================

func TestTemplateSourceService_ListSources_Success(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	tmplSrcAddSource(repo, tenantID, "Source A")
	tmplSrcAddSource(repo, tenantID, "Source B")

	input := app.ListTemplateSourcesInput{
		TenantID: tenantID.String(),
		Page:     1,
		PageSize: 20,
	}

	result, err := svc.ListSources(ctx, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.TotalCount != 2 {
		t.Errorf("expected 2 sources, got %d", result.TotalCount)
	}
}

func TestTemplateSourceService_ListSources_InvalidTenantID(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()

	input := app.ListTemplateSourcesInput{TenantID: "bad-uuid"}

	_, err := svc.ListSources(ctx, input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestTemplateSourceService_ListSources_WithFilters(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	sourceType := "git"
	templateType := "nuclei"
	enabled := true

	input := app.ListTemplateSourcesInput{
		TenantID:     tenantID.String(),
		SourceType:   &sourceType,
		TemplateType: &templateType,
		Enabled:      &enabled,
	}

	_, err := svc.ListSources(ctx, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestTemplateSourceService_ListSources_RepoError(t *testing.T) {
	repo := newTmplSrcMockRepo()
	repo.listErr = errors.New("db error")
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	input := app.ListTemplateSourcesInput{TenantID: tenantID.String()}

	_, err := svc.ListSources(ctx, input)
	if err == nil {
		t.Fatal("expected error when repo.List fails")
	}
}

// ============================================================================
// Tests: UpdateSource
// ============================================================================

func TestTemplateSourceService_UpdateSource_Success(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	src := tmplSrcAddSource(repo, tenantID, "Original Name")

	newName := "Updated Name"
	enabled := false
	cacheTTL := 240
	autoSync := false

	input := app.UpdateTemplateSourceInput{
		TenantID:        tenantID.String(),
		SourceID:        src.ID.String(),
		Name:            newName,
		Description:     "Updated description",
		Enabled:         &enabled,
		CacheTTLMinutes: &cacheTTL,
		AutoSyncOnScan:  &autoSync,
	}

	result, err := svc.UpdateSource(ctx, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Name != "Updated Name" {
		t.Errorf("expected name 'Updated Name', got %q", result.Name)
	}
	if result.Enabled {
		t.Error("expected source to be disabled")
	}
	if result.CacheTTLMinutes != 240 {
		t.Errorf("expected cache TTL 240, got %d", result.CacheTTLMinutes)
	}
	if result.AutoSyncOnScan {
		t.Error("expected auto sync to be disabled")
	}
}

func TestTemplateSourceService_UpdateSource_InvalidTenantID(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()

	input := app.UpdateTemplateSourceInput{
		TenantID: "bad",
		SourceID: shared.NewID().String(),
	}

	_, err := svc.UpdateSource(ctx, input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

func TestTemplateSourceService_UpdateSource_NotFound(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	input := app.UpdateTemplateSourceInput{
		TenantID: tenantID.String(),
		SourceID: shared.NewID().String(),
	}

	_, err := svc.UpdateSource(ctx, input)
	if err == nil {
		t.Fatal("expected error for missing source")
	}
}

func TestTemplateSourceService_UpdateSource_WrongTenant(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()
	otherTenant := shared.NewID()

	src := tmplSrcAddSource(repo, tenantID, "Source")

	input := app.UpdateTemplateSourceInput{
		TenantID: otherTenant.String(),
		SourceID: src.ID.String(),
	}

	_, err := svc.UpdateSource(ctx, input)
	if err == nil {
		t.Fatal("expected error for wrong tenant")
	}
}

func TestTemplateSourceService_UpdateSource_WithGitConfig(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	src := tmplSrcAddSource(repo, tenantID, "Git Source")

	input := app.UpdateTemplateSourceInput{
		TenantID: tenantID.String(),
		SourceID: src.ID.String(),
		GitConfig: &ts.GitSourceConfig{
			URL:    "https://github.com/org/new-repo",
			Branch: "develop",
		},
	}

	result, err := svc.UpdateSource(ctx, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.GitConfig.URL != "https://github.com/org/new-repo" {
		t.Errorf("expected updated git URL, got %q", result.GitConfig.URL)
	}
}

func TestTemplateSourceService_UpdateSource_SetCredential(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	src := tmplSrcAddSource(repo, tenantID, "Source")
	credID := shared.NewID().String()

	input := app.UpdateTemplateSourceInput{
		TenantID:     tenantID.String(),
		SourceID:     src.ID.String(),
		CredentialID: &credID,
	}

	result, err := svc.UpdateSource(ctx, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.CredentialID == nil {
		t.Fatal("expected credential to be set")
	}
}

func TestTemplateSourceService_UpdateSource_ClearCredential(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	src := tmplSrcAddSource(repo, tenantID, "Source")
	credID := shared.NewID()
	src.SetCredential(credID)
	repo.sources[src.ID.String()] = src

	emptyStr := ""
	input := app.UpdateTemplateSourceInput{
		TenantID:     tenantID.String(),
		SourceID:     src.ID.String(),
		CredentialID: &emptyStr,
	}

	result, err := svc.UpdateSource(ctx, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.CredentialID != nil {
		t.Error("expected credential to be cleared")
	}
}

func TestTemplateSourceService_UpdateSource_InvalidCredentialID(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	src := tmplSrcAddSource(repo, tenantID, "Source")
	badCred := "not-a-uuid"

	input := app.UpdateTemplateSourceInput{
		TenantID:     tenantID.String(),
		SourceID:     src.ID.String(),
		CredentialID: &badCred,
	}

	_, err := svc.UpdateSource(ctx, input)
	if err == nil {
		t.Fatal("expected error for invalid credential ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestTemplateSourceService_UpdateSource_RepoUpdateError(t *testing.T) {
	repo := newTmplSrcMockRepo()
	repo.updateErr = errors.New("db update error")
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	src := tmplSrcAddSource(repo, tenantID, "Source")

	input := app.UpdateTemplateSourceInput{
		TenantID: tenantID.String(),
		SourceID: src.ID.String(),
		Name:     "New Name",
	}

	_, err := svc.UpdateSource(ctx, input)
	if err == nil {
		t.Fatal("expected error when repo.Update fails")
	}
}

// ============================================================================
// Tests: DeleteSource
// ============================================================================

func TestTemplateSourceService_DeleteSource_Success(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	src := tmplSrcAddSource(repo, tenantID, "To Delete")

	err := svc.DeleteSource(ctx, tenantID.String(), src.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if _, ok := repo.sources[src.ID.String()]; ok {
		t.Error("expected source to be deleted from repo")
	}
}

func TestTemplateSourceService_DeleteSource_InvalidTenantID(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()

	err := svc.DeleteSource(ctx, "bad", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

func TestTemplateSourceService_DeleteSource_NotFound(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	err := svc.DeleteSource(ctx, tenantID.String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for missing source")
	}
}

func TestTemplateSourceService_DeleteSource_WrongTenant(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()
	otherTenant := shared.NewID()

	src := tmplSrcAddSource(repo, tenantID, "Source")

	err := svc.DeleteSource(ctx, otherTenant.String(), src.ID.String())
	if err == nil {
		t.Fatal("expected error for wrong tenant")
	}
}

func TestTemplateSourceService_DeleteSource_RepoDeleteError(t *testing.T) {
	repo := newTmplSrcMockRepo()
	repo.deleteErr = errors.New("db delete error")
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	src := tmplSrcAddSource(repo, tenantID, "Source")

	err := svc.DeleteSource(ctx, tenantID.String(), src.ID.String())
	if err == nil {
		t.Fatal("expected error when repo.Delete fails")
	}
}

// ============================================================================
// Tests: EnableSource / DisableSource
// ============================================================================

func TestTemplateSourceService_EnableSource_Success(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	src := tmplSrcAddSource(repo, tenantID, "Source")
	src.Disable()
	repo.sources[src.ID.String()] = src

	result, err := svc.EnableSource(ctx, tenantID.String(), src.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.Enabled {
		t.Error("expected source to be enabled")
	}
}

func TestTemplateSourceService_EnableSource_WrongTenant(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	src := tmplSrcAddSource(repo, tenantID, "Source")

	_, err := svc.EnableSource(ctx, shared.NewID().String(), src.ID.String())
	if err == nil {
		t.Fatal("expected error for wrong tenant")
	}
}

func TestTemplateSourceService_DisableSource_Success(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	src := tmplSrcAddSource(repo, tenantID, "Source")

	result, err := svc.DisableSource(ctx, tenantID.String(), src.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Enabled {
		t.Error("expected source to be disabled")
	}
}

func TestTemplateSourceService_DisableSource_WrongTenant(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	src := tmplSrcAddSource(repo, tenantID, "Source")

	_, err := svc.DisableSource(ctx, shared.NewID().String(), src.ID.String())
	if err == nil {
		t.Fatal("expected error for wrong tenant")
	}
}

func TestTemplateSourceService_EnableSource_UpdateError(t *testing.T) {
	repo := newTmplSrcMockRepo()
	repo.updateErr = errors.New("db error")
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	src := tmplSrcAddSource(repo, tenantID, "Source")

	_, err := svc.EnableSource(ctx, tenantID.String(), src.ID.String())
	if err == nil {
		t.Fatal("expected error when repo.Update fails")
	}
}

// ============================================================================
// Tests: GetSourcesForScan
// ============================================================================

func TestTemplateSourceService_GetSourcesForScan_Success(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	src1, _ := ts.NewTemplateSource(tenantID, "Src1", ts.SourceTypeGit, scannertemplate.TemplateTypeNuclei, nil)
	src2, _ := ts.NewTemplateSource(tenantID, "Src2", ts.SourceTypeGit, scannertemplate.TemplateTypeSemgrep, nil)
	repo.listByTypeSrcs = []*ts.TemplateSource{src1, src2}

	result, err := svc.GetSourcesForScan(ctx, tenantID.String(), []scannertemplate.TemplateType{
		scannertemplate.TemplateTypeNuclei,
		scannertemplate.TemplateTypeSemgrep,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Each template type returns the full list from mock, so 2 types x 2 sources = 4
	if len(result) != 4 {
		t.Errorf("expected 4 sources, got %d", len(result))
	}
}

func TestTemplateSourceService_GetSourcesForScan_InvalidTenantID(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()

	_, err := svc.GetSourcesForScan(ctx, "bad", []scannertemplate.TemplateType{scannertemplate.TemplateTypeNuclei})
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

func TestTemplateSourceService_GetSourcesForScan_RepoError(t *testing.T) {
	repo := newTmplSrcMockRepo()
	repo.listByTypeErr = errors.New("db error")
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	_, err := svc.GetSourcesForScan(ctx, tenantID.String(), []scannertemplate.TemplateType{scannertemplate.TemplateTypeNuclei})
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
}

// ============================================================================
// Tests: GetSourcesNeedingSync
// ============================================================================

func TestTemplateSourceService_GetSourcesNeedingSync_Success(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	// Source that needs sync (never synced, enabled, auto sync on)
	src1, _ := ts.NewTemplateSource(tenantID, "NeedsSync", ts.SourceTypeGit, scannertemplate.TemplateTypeNuclei, nil)

	// Source that does NOT need sync (recently synced)
	src2, _ := ts.NewTemplateSource(tenantID, "Fresh", ts.SourceTypeGit, scannertemplate.TemplateTypeNuclei, nil)
	src2.CompleteSyncSuccess("abc123", 10)

	repo.listEnabledSrcs = []*ts.TemplateSource{src1, src2}

	result, err := svc.GetSourcesNeedingSync(ctx, tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 source needing sync, got %d", len(result))
	}
	if len(result) > 0 && result[0].Name != "NeedsSync" {
		t.Errorf("expected source 'NeedsSync', got %q", result[0].Name)
	}
}

func TestTemplateSourceService_GetSourcesNeedingSync_InvalidTenantID(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()

	_, err := svc.GetSourcesNeedingSync(ctx, "bad")
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

func TestTemplateSourceService_GetSourcesNeedingSync_RepoError(t *testing.T) {
	repo := newTmplSrcMockRepo()
	repo.listEnabledErr = errors.New("db error")
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	_, err := svc.GetSourcesNeedingSync(ctx, tenantID.String())
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
}

func TestTemplateSourceService_GetSourcesNeedingSync_ExpiredCache(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	src, _ := ts.NewTemplateSource(tenantID, "Expired", ts.SourceTypeGit, scannertemplate.TemplateTypeNuclei, nil)
	src.CacheTTLMinutes = 1
	pastTime := time.Now().Add(-2 * time.Minute)
	src.LastSyncAt = &pastTime
	src.LastSyncStatus = ts.SyncStatusSuccess

	repo.listEnabledSrcs = []*ts.TemplateSource{src}

	result, err := svc.GetSourcesNeedingSync(ctx, tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 source needing sync (expired cache), got %d", len(result))
	}
}

// ============================================================================
// Tests: UpdateSyncStatus
// ============================================================================

func TestTemplateSourceService_UpdateSyncStatus_Success(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	src := tmplSrcAddSource(repo, tenantID, "Source")
	src.StartSync()

	err := svc.UpdateSyncStatus(ctx, src)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestTemplateSourceService_UpdateSyncStatus_RepoError(t *testing.T) {
	repo := newTmplSrcMockRepo()
	repo.updateSyncErr = errors.New("db error")
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	src := tmplSrcAddSource(repo, tenantID, "Source")

	err := svc.UpdateSyncStatus(ctx, src)
	if err == nil {
		t.Fatal("expected error when repo.UpdateSyncStatus fails")
	}
}

// ============================================================================
// Tests: ForceSync
// ============================================================================

func TestTemplateSourceService_ForceSync_NoSyncer(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()
	tenantID := shared.NewID()

	_, err := svc.ForceSync(ctx, tenantID.String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error when syncer is not configured")
	}
}

func TestTemplateSourceService_ForceSync_InvalidTenantID(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	// Even without syncer, invalid tenant ID should fail first if syncer were set
	// But syncer check comes first, so this test confirms the order
	ctx := context.Background()

	_, err := svc.ForceSync(ctx, "bad", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTemplateSourceService_ForceSync_InvalidSourceID(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)
	ctx := context.Background()

	_, err := svc.ForceSync(ctx, shared.NewID().String(), "bad")
	if err == nil {
		t.Fatal("expected error")
	}
}

// ============================================================================
// Tests: SetTemplateSyncer
// ============================================================================

func TestTemplateSourceService_SetTemplateSyncer(t *testing.T) {
	repo := newTmplSrcMockRepo()
	svc := newTmplSrcService(repo)

	// Just verify it doesn't panic
	svc.SetTemplateSyncer(nil)
}

// ============================================================================
// Tests: MaxSourcesPerTenant constant
// ============================================================================

func TestTemplateSourceService_MaxSourcesPerTenant(t *testing.T) {
	if app.MaxSourcesPerTenant != 50 {
		t.Errorf("expected MaxSourcesPerTenant to be 50, got %d", app.MaxSourcesPerTenant)
	}
}
