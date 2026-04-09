package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/scanprofile"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// ============================================================================
// Mock Repository
// ============================================================================

type scanProfileMockRepository struct {
	profiles              map[string]*scanprofile.ScanProfile
	createErr             error
	updateErr             error
	deleteErr             error
	clearDefaultErr       error
	listErr               error
	listWithSystemErr     error
	getByTenantAndIDErr   error
	getDefaultByTenantErr error
	getWithFallbackErr    error
}

func newScanProfileMockRepository() *scanProfileMockRepository {
	return &scanProfileMockRepository{
		profiles: make(map[string]*scanprofile.ScanProfile),
	}
}

func (m *scanProfileMockRepository) Create(_ context.Context, profile *scanprofile.ScanProfile) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.profiles[profile.ID.String()] = profile
	return nil
}

func (m *scanProfileMockRepository) GetByID(_ context.Context, id shared.ID) (*scanprofile.ScanProfile, error) {
	p, ok := m.profiles[id.String()]
	if !ok {
		return nil, shared.NewDomainError("NOT_FOUND", "scan profile not found", shared.ErrNotFound)
	}
	return p, nil
}

func (m *scanProfileMockRepository) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*scanprofile.ScanProfile, error) {
	if m.getByTenantAndIDErr != nil {
		return nil, m.getByTenantAndIDErr
	}
	p, ok := m.profiles[id.String()]
	if !ok {
		return nil, shared.NewDomainError("NOT_FOUND", "scan profile not found", shared.ErrNotFound)
	}
	if !p.TenantID.Equals(tenantID) {
		return nil, shared.NewDomainError("NOT_FOUND", "scan profile not found", shared.ErrNotFound)
	}
	return p, nil
}

func (m *scanProfileMockRepository) GetAccessibleByID(_ context.Context, tenantID, id shared.ID) (*scanprofile.ScanProfile, error) {
	p, ok := m.profiles[id.String()]
	if !ok {
		return nil, shared.NewDomainError("NOT_FOUND", "scan profile not found", shared.ErrNotFound)
	}
	// Accessible: own tenant OR system profile (tenant is zero)
	if !p.TenantID.IsZero() && !p.TenantID.Equals(tenantID) {
		return nil, shared.NewDomainError("NOT_FOUND", "scan profile not found", shared.ErrNotFound)
	}
	return p, nil
}

func (m *scanProfileMockRepository) GetByTenantAndName(_ context.Context, tenantID shared.ID, name string) (*scanprofile.ScanProfile, error) {
	for _, p := range m.profiles {
		if p.TenantID.Equals(tenantID) && p.Name == name {
			return p, nil
		}
	}
	return nil, shared.NewDomainError("NOT_FOUND", "scan profile not found", shared.ErrNotFound)
}

func (m *scanProfileMockRepository) GetDefaultByTenant(_ context.Context, tenantID shared.ID) (*scanprofile.ScanProfile, error) {
	if m.getDefaultByTenantErr != nil {
		return nil, m.getDefaultByTenantErr
	}
	for _, p := range m.profiles {
		if p.TenantID.Equals(tenantID) && p.IsDefault {
			return p, nil
		}
	}
	return nil, shared.NewDomainError("NOT_FOUND", "no default scan profile found", shared.ErrNotFound)
}

func (m *scanProfileMockRepository) List(_ context.Context, filter scanprofile.Filter, page pagination.Pagination) (pagination.Result[*scanprofile.ScanProfile], error) {
	if m.listErr != nil {
		return pagination.Result[*scanprofile.ScanProfile]{}, m.listErr
	}
	result := make([]*scanprofile.ScanProfile, 0, len(m.profiles))
	for _, p := range m.profiles {
		if filter.TenantID != nil && !p.TenantID.Equals(*filter.TenantID) {
			continue
		}
		result = append(result, p)
	}
	total := int64(len(result))
	return pagination.Result[*scanprofile.ScanProfile]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: int((total + int64(page.PerPage) - 1) / int64(page.PerPage)),
	}, nil
}

func (m *scanProfileMockRepository) ListWithSystemProfiles(_ context.Context, tenantID shared.ID, _ scanprofile.Filter, page pagination.Pagination) (pagination.Result[*scanprofile.ScanProfile], error) {
	if m.listWithSystemErr != nil {
		return pagination.Result[*scanprofile.ScanProfile]{}, m.listWithSystemErr
	}
	result := make([]*scanprofile.ScanProfile, 0, len(m.profiles))
	for _, p := range m.profiles {
		if p.TenantID.Equals(tenantID) || p.IsSystem {
			result = append(result, p)
		}
	}
	total := int64(len(result))
	return pagination.Result[*scanprofile.ScanProfile]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: int((total + int64(page.PerPage) - 1) / int64(page.PerPage)),
	}, nil
}

func (m *scanProfileMockRepository) GetByIDWithSystemFallback(_ context.Context, tenantID, id shared.ID) (*scanprofile.ScanProfile, error) {
	if m.getWithFallbackErr != nil {
		return nil, m.getWithFallbackErr
	}
	p, ok := m.profiles[id.String()]
	if !ok {
		return nil, shared.NewDomainError("NOT_FOUND", "scan profile not found", shared.ErrNotFound)
	}
	if p.TenantID.Equals(tenantID) || p.IsSystem {
		return p, nil
	}
	return nil, shared.NewDomainError("NOT_FOUND", "scan profile not found", shared.ErrNotFound)
}

func (m *scanProfileMockRepository) Update(_ context.Context, profile *scanprofile.ScanProfile) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.profiles[profile.ID.String()] = profile
	return nil
}

func (m *scanProfileMockRepository) Delete(_ context.Context, id shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.profiles, id.String())
	return nil
}

func (m *scanProfileMockRepository) ClearDefaultForTenant(_ context.Context, tenantID shared.ID) error {
	if m.clearDefaultErr != nil {
		return m.clearDefaultErr
	}
	for _, p := range m.profiles {
		if p.TenantID.Equals(tenantID) {
			p.IsDefault = false
		}
	}
	return nil
}

func (m *scanProfileMockRepository) CountByTenant(_ context.Context, tenantID shared.ID) (int64, error) {
	var count int64
	for _, p := range m.profiles {
		if p.TenantID.Equals(tenantID) {
			count++
		}
	}
	return count, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

func newTestScanProfileService() (*app.ScanProfileService, *scanProfileMockRepository) {
	repo := newScanProfileMockRepository()
	log := logger.NewNop()
	svc := app.NewScanProfileService(repo, log)
	return svc, repo
}

func makeScanProfileInRepo(repo *scanProfileMockRepository, tenantID shared.ID, name string) *scanprofile.ScanProfile {
	p, _ := scanprofile.NewScanProfile(tenantID, name, "test description", nil, scanprofile.IntensityMedium, nil)
	repo.profiles[p.ID.String()] = p
	return p
}

func makeSystemScanProfileInRepo(repo *scanProfileMockRepository, name string) *scanprofile.ScanProfile {
	systemTenantID := shared.NewID()
	p, _ := scanprofile.NewScanProfile(systemTenantID, name, "system profile", nil, scanprofile.IntensityMedium, nil)
	p.IsSystem = true
	repo.profiles[p.ID.String()] = p
	return p
}

// ============================================================================
// CreateScanProfile Tests
// ============================================================================

func TestCreateScanProfile_Success(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()

	input := app.CreateScanProfileInput{
		TenantID:    tenantID.String(),
		Name:        "My Profile",
		Description: "A test profile",
		Intensity:   "high",
		Tags:        []string{"web", "api"},
	}

	result, err := svc.CreateScanProfile(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Name != "My Profile" {
		t.Errorf("expected name 'My Profile', got %q", result.Name)
	}
	if result.Intensity != scanprofile.IntensityHigh {
		t.Errorf("expected intensity high, got %q", result.Intensity)
	}
	if len(result.Tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(result.Tags))
	}
	if len(repo.profiles) != 1 {
		t.Errorf("expected 1 profile in repo, got %d", len(repo.profiles))
	}
}

func TestCreateScanProfile_DefaultIntensity(t *testing.T) {
	svc, _ := newTestScanProfileService()
	tenantID := shared.NewID()

	input := app.CreateScanProfileInput{
		TenantID: tenantID.String(),
		Name:     "Default Intensity Profile",
		// Intensity left empty - should default to medium
	}

	result, err := svc.CreateScanProfile(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Intensity != scanprofile.IntensityMedium {
		t.Errorf("expected default intensity medium, got %q", result.Intensity)
	}
}

func TestCreateScanProfile_InvalidIntensity_DefaultsToMedium(t *testing.T) {
	svc, _ := newTestScanProfileService()
	tenantID := shared.NewID()

	input := app.CreateScanProfileInput{
		TenantID:  tenantID.String(),
		Name:      "Bad Intensity",
		Intensity: "extreme",
	}

	result, err := svc.CreateScanProfile(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Intensity != scanprofile.IntensityMedium {
		t.Errorf("expected fallback to medium, got %q", result.Intensity)
	}
}

func TestCreateScanProfile_InvalidTenantID(t *testing.T) {
	svc, _ := newTestScanProfileService()

	input := app.CreateScanProfileInput{
		TenantID: "not-a-uuid",
		Name:     "Bad Tenant",
	}

	_, err := svc.CreateScanProfile(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCreateScanProfile_InvalidUserID(t *testing.T) {
	svc, _ := newTestScanProfileService()
	tenantID := shared.NewID()

	input := app.CreateScanProfileInput{
		TenantID: tenantID.String(),
		UserID:   "bad-uuid",
		Name:     "Bad User",
	}

	_, err := svc.CreateScanProfile(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid user ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCreateScanProfile_WithUserID(t *testing.T) {
	svc, _ := newTestScanProfileService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	input := app.CreateScanProfileInput{
		TenantID: tenantID.String(),
		UserID:   userID.String(),
		Name:     "User Profile",
	}

	result, err := svc.CreateScanProfile(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.CreatedBy == nil {
		t.Fatal("expected CreatedBy to be set")
	}
	if !result.CreatedBy.Equals(userID) {
		t.Errorf("expected CreatedBy %s, got %s", userID, result.CreatedBy)
	}
}

func TestCreateScanProfile_WithOptionalSettings(t *testing.T) {
	svc, _ := newTestScanProfileService()
	tenantID := shared.NewID()

	input := app.CreateScanProfileInput{
		TenantID:           tenantID.String(),
		Name:               "Full Profile",
		MaxConcurrentScans: 10,
		TimeoutSeconds:     7200,
		Tags:               []string{"tag1"},
	}

	result, err := svc.CreateScanProfile(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.MaxConcurrentScans != 10 {
		t.Errorf("expected MaxConcurrentScans 10, got %d", result.MaxConcurrentScans)
	}
	if result.TimeoutSeconds != 7200 {
		t.Errorf("expected TimeoutSeconds 7200, got %d", result.TimeoutSeconds)
	}
}

func TestCreateScanProfile_WithQualityGate(t *testing.T) {
	svc, _ := newTestScanProfileService()
	tenantID := shared.NewID()

	qg := &scanprofile.QualityGate{
		Enabled:        true,
		FailOnCritical: true,
		MaxHigh:        5,
		MaxTotal:       100,
	}

	input := app.CreateScanProfileInput{
		TenantID:    tenantID.String(),
		Name:        "QG Profile",
		QualityGate: qg,
	}

	result, err := svc.CreateScanProfile(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.QualityGate.Enabled {
		t.Error("expected quality gate to be enabled")
	}
	if !result.QualityGate.FailOnCritical {
		t.Error("expected FailOnCritical to be true")
	}
	if result.QualityGate.MaxHigh != 5 {
		t.Errorf("expected MaxHigh 5, got %d", result.QualityGate.MaxHigh)
	}
}

func TestCreateScanProfile_IsDefault(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()

	// Create a first default profile
	existing := makeScanProfileInRepo(repo, tenantID, "Old Default")
	existing.SetAsDefault()

	input := app.CreateScanProfileInput{
		TenantID:  tenantID.String(),
		Name:      "New Default",
		IsDefault: true,
	}

	result, err := svc.CreateScanProfile(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.IsDefault {
		t.Error("expected new profile to be default")
	}
	// Old default should have been cleared
	if existing.IsDefault {
		t.Error("expected old default to be cleared")
	}
}

func TestCreateScanProfile_IsDefault_ClearError(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	repo.clearDefaultErr = errors.New("db error")

	input := app.CreateScanProfileInput{
		TenantID:  tenantID.String(),
		Name:      "Default",
		IsDefault: true,
	}

	_, err := svc.CreateScanProfile(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when clearing default fails")
	}
}

func TestCreateScanProfile_RepoCreateError(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	repo.createErr = errors.New("db error")

	input := app.CreateScanProfileInput{
		TenantID: tenantID.String(),
		Name:     "Will Fail",
	}

	_, err := svc.CreateScanProfile(context.Background(), input)
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

func TestCreateScanProfile_WithToolsConfig(t *testing.T) {
	svc, _ := newTestScanProfileService()
	tenantID := shared.NewID()

	tools := map[string]scanprofile.ToolConfig{
		"nuclei": {Enabled: true, Severity: "high", Timeout: 300},
		"nmap":   {Enabled: false},
	}

	input := app.CreateScanProfileInput{
		TenantID:    tenantID.String(),
		Name:        "Tools Profile",
		ToolsConfig: tools,
	}

	result, err := svc.CreateScanProfile(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result.ToolsConfig) != 2 {
		t.Errorf("expected 2 tools, got %d", len(result.ToolsConfig))
	}
	nucleiCfg, ok := result.ToolsConfig["nuclei"]
	if !ok {
		t.Fatal("expected nuclei tool config")
	}
	if !nucleiCfg.Enabled {
		t.Error("expected nuclei to be enabled")
	}
}

// ============================================================================
// GetScanProfile Tests
// ============================================================================

func TestGetScanProfile_Success(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantID, "Test")

	result, err := svc.GetScanProfile(context.Background(), tenantID.String(), profile.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Name != "Test" {
		t.Errorf("expected name 'Test', got %q", result.Name)
	}
}

func TestGetScanProfile_InvalidTenantID(t *testing.T) {
	svc, _ := newTestScanProfileService()

	_, err := svc.GetScanProfile(context.Background(), "bad", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestGetScanProfile_InvalidProfileID(t *testing.T) {
	svc, _ := newTestScanProfileService()

	_, err := svc.GetScanProfile(context.Background(), shared.NewID().String(), "bad")
	if err == nil {
		t.Fatal("expected error for invalid profile ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestGetScanProfile_NotFound(t *testing.T) {
	svc, _ := newTestScanProfileService()

	_, err := svc.GetScanProfile(context.Background(), shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected not found error")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected not found error, got %v", err)
	}
}

// ============================================================================
// GetDefaultScanProfile Tests
// ============================================================================

func TestGetDefaultScanProfile_Success(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantID, "Default Profile")
	profile.SetAsDefault()

	result, err := svc.GetDefaultScanProfile(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.IsDefault {
		t.Error("expected profile to be default")
	}
}

func TestGetDefaultScanProfile_InvalidTenantID(t *testing.T) {
	svc, _ := newTestScanProfileService()

	_, err := svc.GetDefaultScanProfile(context.Background(), "bad-uuid")
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestGetDefaultScanProfile_NotFound(t *testing.T) {
	svc, _ := newTestScanProfileService()

	_, err := svc.GetDefaultScanProfile(context.Background(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected not found error")
	}
}

// ============================================================================
// GetScanProfileForUse Tests
// ============================================================================

func TestGetScanProfileForUse_TenantProfile(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantID, "Tenant Profile")

	result, err := svc.GetScanProfileForUse(context.Background(), tenantID.String(), profile.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ID != profile.ID {
		t.Error("expected same profile")
	}
}

func TestGetScanProfileForUse_SystemProfile(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	sysProfile := makeSystemScanProfileInRepo(repo, "System Default")

	result, err := svc.GetScanProfileForUse(context.Background(), tenantID.String(), sysProfile.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.IsSystem {
		t.Error("expected system profile")
	}
}

func TestGetScanProfileForUse_InvalidTenantID(t *testing.T) {
	svc, _ := newTestScanProfileService()

	_, err := svc.GetScanProfileForUse(context.Background(), "bad", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestGetScanProfileForUse_InvalidProfileID(t *testing.T) {
	svc, _ := newTestScanProfileService()

	_, err := svc.GetScanProfileForUse(context.Background(), shared.NewID().String(), "bad")
	if err == nil {
		t.Fatal("expected error for invalid profile ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestGetScanProfileForUse_NotFound(t *testing.T) {
	svc, _ := newTestScanProfileService()

	_, err := svc.GetScanProfileForUse(context.Background(), shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected not found error")
	}
}

// ============================================================================
// ListScanProfiles Tests
// ============================================================================

func TestListScanProfiles_Success(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	makeScanProfileInRepo(repo, tenantID, "Profile 1")
	makeScanProfileInRepo(repo, tenantID, "Profile 2")

	input := app.ListScanProfilesInput{
		TenantID: tenantID.String(),
		Page:     1,
		PerPage:  10,
	}

	result, err := svc.ListScanProfiles(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 2 {
		t.Errorf("expected 2 profiles, got %d", result.Total)
	}
}

func TestListScanProfiles_InvalidTenantID(t *testing.T) {
	svc, _ := newTestScanProfileService()

	input := app.ListScanProfilesInput{
		TenantID: "bad",
	}

	_, err := svc.ListScanProfiles(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestListScanProfiles_IncludeSystem(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	makeScanProfileInRepo(repo, tenantID, "Tenant Profile")
	makeSystemScanProfileInRepo(repo, "System Profile")

	input := app.ListScanProfilesInput{
		TenantID:      tenantID.String(),
		IncludeSystem: true,
		Page:          1,
		PerPage:       10,
	}

	result, err := svc.ListScanProfiles(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 2 {
		t.Errorf("expected 2 profiles (tenant + system), got %d", result.Total)
	}
}

func TestListScanProfiles_ExcludeSystem(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	makeScanProfileInRepo(repo, tenantID, "Tenant Profile")
	makeSystemScanProfileInRepo(repo, "System Profile")

	input := app.ListScanProfilesInput{
		TenantID:      tenantID.String(),
		IncludeSystem: false,
		Page:          1,
		PerPage:       10,
	}

	result, err := svc.ListScanProfiles(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected 1 tenant profile only, got %d", result.Total)
	}
}

func TestListScanProfiles_RepoError(t *testing.T) {
	svc, repo := newTestScanProfileService()
	repo.listErr = errors.New("db error")

	input := app.ListScanProfilesInput{
		TenantID: shared.NewID().String(),
		Page:     1,
		PerPage:  10,
	}

	_, err := svc.ListScanProfiles(context.Background(), input)
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

func TestListScanProfiles_IncludeSystem_RepoError(t *testing.T) {
	svc, repo := newTestScanProfileService()
	repo.listWithSystemErr = errors.New("db error")

	input := app.ListScanProfilesInput{
		TenantID:      shared.NewID().String(),
		IncludeSystem: true,
		Page:          1,
		PerPage:       10,
	}

	_, err := svc.ListScanProfiles(context.Background(), input)
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

// ============================================================================
// UpdateScanProfile Tests
// ============================================================================

func TestUpdateScanProfile_Success(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantID, "Original")

	input := app.UpdateScanProfileInput{
		TenantID:  tenantID.String(),
		ProfileID: profile.ID.String(),
		Name:      "Updated",
		Intensity: "high",
	}

	result, err := svc.UpdateScanProfile(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Name != "Updated" {
		t.Errorf("expected name 'Updated', got %q", result.Name)
	}
	if result.Intensity != scanprofile.IntensityHigh {
		t.Errorf("expected intensity high, got %q", result.Intensity)
	}
}

func TestUpdateScanProfile_InvalidTenantID(t *testing.T) {
	svc, _ := newTestScanProfileService()

	input := app.UpdateScanProfileInput{
		TenantID:  "bad",
		ProfileID: shared.NewID().String(),
		Name:      "Updated",
	}

	_, err := svc.UpdateScanProfile(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestUpdateScanProfile_NotFound(t *testing.T) {
	svc, _ := newTestScanProfileService()

	input := app.UpdateScanProfileInput{
		TenantID:  shared.NewID().String(),
		ProfileID: shared.NewID().String(),
		Name:      "Updated",
	}

	_, err := svc.UpdateScanProfile(context.Background(), input)
	if err == nil {
		t.Fatal("expected not found error")
	}
}

func TestUpdateScanProfile_SystemProfile_Forbidden(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	sysProfile := makeSystemScanProfileInRepo(repo, "System")
	// Override tenant ID so GetByTenantAndID succeeds
	sysProfile.TenantID = tenantID

	input := app.UpdateScanProfileInput{
		TenantID:  tenantID.String(),
		ProfileID: sysProfile.ID.String(),
		Name:      "Hacked",
	}

	_, err := svc.UpdateScanProfile(context.Background(), input)
	if err == nil {
		t.Fatal("expected forbidden error for system profile")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("expected forbidden error, got %v", err)
	}
}

func TestUpdateScanProfile_WrongTenant_Forbidden(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantA := shared.NewID()
	tenantB := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantA, "Tenant A Profile")

	input := app.UpdateScanProfileInput{
		TenantID:  tenantB.String(),
		ProfileID: profile.ID.String(),
		Name:      "Stolen",
	}

	// This should fail at GetByTenantAndID because tenant doesn't match
	_, err := svc.UpdateScanProfile(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for wrong tenant")
	}
}

func TestUpdateScanProfile_WithQualityGate(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantID, "Profile")

	qg := &scanprofile.QualityGate{
		Enabled:    true,
		MaxTotal:   50,
		MaxCritical: 0,
	}

	input := app.UpdateScanProfileInput{
		TenantID:    tenantID.String(),
		ProfileID:   profile.ID.String(),
		QualityGate: qg,
	}

	result, err := svc.UpdateScanProfile(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.QualityGate.Enabled {
		t.Error("expected quality gate to be enabled")
	}
	if result.QualityGate.MaxTotal != 50 {
		t.Errorf("expected MaxTotal 50, got %d", result.QualityGate.MaxTotal)
	}
}

func TestUpdateScanProfile_RepoUpdateError(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	makeScanProfileInRepo(repo, tenantID, "Profile")
	repo.updateErr = errors.New("db error")

	// Get the profile ID from what was stored
	var profileID string
	for id := range repo.profiles {
		profileID = id
	}

	input := app.UpdateScanProfileInput{
		TenantID:  tenantID.String(),
		ProfileID: profileID,
		Name:      "Updated",
	}

	_, err := svc.UpdateScanProfile(context.Background(), input)
	if err == nil {
		t.Fatal("expected error from repo update")
	}
}

// ============================================================================
// DeleteScanProfile Tests
// ============================================================================

func TestDeleteScanProfile_Success(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantID, "To Delete")

	err := svc.DeleteScanProfile(context.Background(), tenantID.String(), profile.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(repo.profiles) != 0 {
		t.Errorf("expected 0 profiles after delete, got %d", len(repo.profiles))
	}
}

func TestDeleteScanProfile_InvalidTenantID(t *testing.T) {
	svc, _ := newTestScanProfileService()

	err := svc.DeleteScanProfile(context.Background(), "bad", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestDeleteScanProfile_NotFound(t *testing.T) {
	svc, _ := newTestScanProfileService()

	err := svc.DeleteScanProfile(context.Background(), shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected not found error")
	}
}

func TestDeleteScanProfile_SystemProfile_Forbidden(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	sysProfile := makeSystemScanProfileInRepo(repo, "System")
	sysProfile.TenantID = tenantID

	err := svc.DeleteScanProfile(context.Background(), tenantID.String(), sysProfile.ID.String())
	if err == nil {
		t.Fatal("expected forbidden error for system profile")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("expected forbidden error, got %v", err)
	}
}

func TestDeleteScanProfile_WrongTenant_Forbidden(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantA := shared.NewID()
	tenantB := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantA, "Tenant A Profile")

	err := svc.DeleteScanProfile(context.Background(), tenantB.String(), profile.ID.String())
	if err == nil {
		t.Fatal("expected error for wrong tenant")
	}
}

func TestDeleteScanProfile_RepoDeleteError(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantID, "To Delete")
	repo.deleteErr = errors.New("db error")

	err := svc.DeleteScanProfile(context.Background(), tenantID.String(), profile.ID.String())
	if err == nil {
		t.Fatal("expected error from repo delete")
	}
}

// ============================================================================
// SetDefaultScanProfile Tests
// ============================================================================

func TestSetDefaultScanProfile_Success(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantID, "New Default")

	result, err := svc.SetDefaultScanProfile(context.Background(), tenantID.String(), profile.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.IsDefault {
		t.Error("expected profile to be set as default")
	}
}

func TestSetDefaultScanProfile_ClearsExisting(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	oldDefault := makeScanProfileInRepo(repo, tenantID, "Old Default")
	oldDefault.SetAsDefault()
	newDefault := makeScanProfileInRepo(repo, tenantID, "New Default")

	result, err := svc.SetDefaultScanProfile(context.Background(), tenantID.String(), newDefault.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.IsDefault {
		t.Error("expected new profile to be default")
	}
	if oldDefault.IsDefault {
		t.Error("expected old default to be cleared")
	}
}

func TestSetDefaultScanProfile_InvalidTenantID(t *testing.T) {
	svc, _ := newTestScanProfileService()

	_, err := svc.SetDefaultScanProfile(context.Background(), "bad", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestSetDefaultScanProfile_NotFound(t *testing.T) {
	svc, _ := newTestScanProfileService()

	_, err := svc.SetDefaultScanProfile(context.Background(), shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected not found error")
	}
}

func TestSetDefaultScanProfile_ClearDefaultError(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	makeScanProfileInRepo(repo, tenantID, "Profile")
	repo.clearDefaultErr = errors.New("db error")

	var profileID string
	for id := range repo.profiles {
		profileID = id
	}

	_, err := svc.SetDefaultScanProfile(context.Background(), tenantID.String(), profileID)
	if err == nil {
		t.Fatal("expected error when clearing default fails")
	}
}

func TestSetDefaultScanProfile_UpdateError(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantID, "Profile")
	repo.updateErr = errors.New("db error")

	_, err := svc.SetDefaultScanProfile(context.Background(), tenantID.String(), profile.ID.String())
	if err == nil {
		t.Fatal("expected error from repo update")
	}
}

// ============================================================================
// CloneScanProfile Tests
// ============================================================================

func TestCloneScanProfile_Success(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	original := makeScanProfileInRepo(repo, tenantID, "Original")
	original.Intensity = scanprofile.IntensityHigh
	original.Tags = []string{"web", "api"}
	original.ToolsConfig = map[string]scanprofile.ToolConfig{
		"nuclei": {Enabled: true, Severity: "high"},
	}

	input := app.CloneScanProfileInput{
		TenantID:  tenantID.String(),
		ProfileID: original.ID.String(),
		NewName:   "Cloned",
	}

	result, err := svc.CloneScanProfile(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Name != "Cloned" {
		t.Errorf("expected name 'Cloned', got %q", result.Name)
	}
	if result.ID == original.ID {
		t.Error("expected different ID for clone")
	}
	if result.Intensity != scanprofile.IntensityHigh {
		t.Errorf("expected cloned intensity high, got %q", result.Intensity)
	}
	if !result.TenantID.Equals(tenantID) {
		t.Error("expected clone to belong to same tenant")
	}
	if result.IsDefault {
		t.Error("expected clone not to be default")
	}
}

func TestCloneScanProfile_WithUserID(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	userID := shared.NewID()
	makeScanProfileInRepo(repo, tenantID, "Original")

	var profileID string
	for id := range repo.profiles {
		profileID = id
	}

	input := app.CloneScanProfileInput{
		TenantID:  tenantID.String(),
		ProfileID: profileID,
		NewName:   "User Clone",
		UserID:    userID.String(),
	}

	result, err := svc.CloneScanProfile(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.CreatedBy == nil {
		t.Fatal("expected CreatedBy to be set")
	}
	if !result.CreatedBy.Equals(userID) {
		t.Errorf("expected CreatedBy %s, got %s", userID, result.CreatedBy)
	}
}

func TestCloneScanProfile_InvalidUserID(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantID, "Original")

	input := app.CloneScanProfileInput{
		TenantID:  tenantID.String(),
		ProfileID: profile.ID.String(),
		NewName:   "Clone",
		UserID:    "bad-uuid",
	}

	_, err := svc.CloneScanProfile(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid user ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCloneScanProfile_SourceNotFound(t *testing.T) {
	svc, _ := newTestScanProfileService()

	input := app.CloneScanProfileInput{
		TenantID:  shared.NewID().String(),
		ProfileID: shared.NewID().String(),
		NewName:   "Clone",
	}

	_, err := svc.CloneScanProfile(context.Background(), input)
	if err == nil {
		t.Fatal("expected not found error")
	}
}

func TestCloneScanProfile_EmptyName(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantID, "Original")

	input := app.CloneScanProfileInput{
		TenantID:  tenantID.String(),
		ProfileID: profile.ID.String(),
		NewName:   "",
	}

	_, err := svc.CloneScanProfile(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for empty clone name")
	}
}

func TestCloneScanProfile_RepoCreateError(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantID, "Original")
	repo.createErr = errors.New("db error")

	input := app.CloneScanProfileInput{
		TenantID:  tenantID.String(),
		ProfileID: profile.ID.String(),
		NewName:   "Clone",
	}

	_, err := svc.CloneScanProfile(context.Background(), input)
	if err == nil {
		t.Fatal("expected error from repo create")
	}
}

// ============================================================================
// UpdateQualityGate Tests
// ============================================================================

func TestUpdateQualityGate_Success(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantID, "Profile")

	input := app.UpdateQualityGateInput{
		TenantID:  tenantID.String(),
		ProfileID: profile.ID.String(),
		QualityGate: scanprofile.QualityGate{
			Enabled:        true,
			FailOnCritical: true,
			MaxHigh:        3,
			MaxTotal:       50,
		},
	}

	result, err := svc.UpdateQualityGate(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.QualityGate.Enabled {
		t.Error("expected quality gate to be enabled")
	}
	if !result.QualityGate.FailOnCritical {
		t.Error("expected FailOnCritical to be true")
	}
	if result.QualityGate.MaxHigh != 3 {
		t.Errorf("expected MaxHigh 3, got %d", result.QualityGate.MaxHigh)
	}
}

func TestUpdateQualityGate_InvalidTenantID(t *testing.T) {
	svc, _ := newTestScanProfileService()

	input := app.UpdateQualityGateInput{
		TenantID:  "bad",
		ProfileID: shared.NewID().String(),
	}

	_, err := svc.UpdateQualityGate(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestUpdateQualityGate_NotFound(t *testing.T) {
	svc, _ := newTestScanProfileService()

	input := app.UpdateQualityGateInput{
		TenantID:  shared.NewID().String(),
		ProfileID: shared.NewID().String(),
	}

	_, err := svc.UpdateQualityGate(context.Background(), input)
	if err == nil {
		t.Fatal("expected not found error")
	}
}

func TestUpdateQualityGate_SystemProfile_Forbidden(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	sysProfile := makeSystemScanProfileInRepo(repo, "System")
	sysProfile.TenantID = tenantID

	input := app.UpdateQualityGateInput{
		TenantID:  tenantID.String(),
		ProfileID: sysProfile.ID.String(),
		QualityGate: scanprofile.QualityGate{
			Enabled: true,
		},
	}

	_, err := svc.UpdateQualityGate(context.Background(), input)
	if err == nil {
		t.Fatal("expected forbidden error for system profile")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("expected forbidden error, got %v", err)
	}
}

func TestUpdateQualityGate_WrongTenant_Forbidden(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantA := shared.NewID()
	tenantB := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantA, "Tenant A Profile")

	input := app.UpdateQualityGateInput{
		TenantID:  tenantB.String(),
		ProfileID: profile.ID.String(),
	}

	_, err := svc.UpdateQualityGate(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for wrong tenant")
	}
}

func TestUpdateQualityGate_RepoUpdateError(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantID, "Profile")
	repo.updateErr = errors.New("db error")

	input := app.UpdateQualityGateInput{
		TenantID:  tenantID.String(),
		ProfileID: profile.ID.String(),
		QualityGate: scanprofile.QualityGate{
			Enabled: true,
		},
	}

	_, err := svc.UpdateQualityGate(context.Background(), input)
	if err == nil {
		t.Fatal("expected error from repo update")
	}
}

// ============================================================================
// EvaluateQualityGate Tests
// ============================================================================

func TestEvaluateQualityGate_Passes(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantID, "Profile")
	profile.QualityGate = scanprofile.QualityGate{
		Enabled:    true,
		MaxTotal:   100,
		MaxCritical: 5,
		MaxHigh:    10,
		MaxMedium:  -1,
	}

	input := app.EvaluateQualityGateInput{
		TenantID:  tenantID.String(),
		ProfileID: profile.ID.String(),
		Counts: scanprofile.FindingCounts{
			Critical: 2,
			High:     5,
			Medium:   10,
			Total:    17,
		},
	}

	result, err := svc.EvaluateQualityGate(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.Passed {
		t.Errorf("expected quality gate to pass, got breaches: %v", result.Breaches)
	}
}

func TestEvaluateQualityGate_Fails(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantID, "Profile")
	profile.QualityGate = scanprofile.QualityGate{
		Enabled:        true,
		FailOnCritical: true,
		MaxTotal:       10,
		MaxCritical:    -1,
		MaxHigh:        -1,
		MaxMedium:      -1,
	}

	input := app.EvaluateQualityGateInput{
		TenantID:  tenantID.String(),
		ProfileID: profile.ID.String(),
		Counts: scanprofile.FindingCounts{
			Critical: 3,
			High:     5,
			Total:    20,
		},
	}

	result, err := svc.EvaluateQualityGate(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Passed {
		t.Error("expected quality gate to fail")
	}
	if len(result.Breaches) == 0 {
		t.Error("expected at least one breach")
	}
	if result.Reason == "" {
		t.Error("expected reason to be set")
	}
}

func TestEvaluateQualityGate_Disabled_AlwaysPasses(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantID, "Profile")
	profile.QualityGate = scanprofile.QualityGate{
		Enabled: false,
	}

	input := app.EvaluateQualityGateInput{
		TenantID:  tenantID.String(),
		ProfileID: profile.ID.String(),
		Counts: scanprofile.FindingCounts{
			Critical: 999,
			Total:    9999,
		},
	}

	result, err := svc.EvaluateQualityGate(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.Passed {
		t.Error("expected disabled quality gate to always pass")
	}
}

func TestEvaluateQualityGate_ProfileNotFound(t *testing.T) {
	svc, _ := newTestScanProfileService()

	input := app.EvaluateQualityGateInput{
		TenantID:  shared.NewID().String(),
		ProfileID: shared.NewID().String(),
		Counts:    scanprofile.FindingCounts{},
	}

	_, err := svc.EvaluateQualityGate(context.Background(), input)
	if err == nil {
		t.Fatal("expected not found error")
	}
}

func TestEvaluateQualityGate_FailOnHigh(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantID, "Profile")
	profile.QualityGate = scanprofile.QualityGate{
		Enabled:    true,
		FailOnHigh: true,
		MaxCritical: -1,
		MaxHigh:    -1,
		MaxMedium:  -1,
		MaxTotal:   -1,
	}

	input := app.EvaluateQualityGateInput{
		TenantID:  tenantID.String(),
		ProfileID: profile.ID.String(),
		Counts: scanprofile.FindingCounts{
			High:  1,
			Total: 1,
		},
	}

	result, err := svc.EvaluateQualityGate(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Passed {
		t.Error("expected quality gate to fail on high finding")
	}
}

func TestEvaluateQualityGate_MaxMediumExceeded(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantID, "Profile")
	profile.QualityGate = scanprofile.QualityGate{
		Enabled:    true,
		MaxCritical: -1,
		MaxHigh:    -1,
		MaxMedium:  5,
		MaxTotal:   -1,
	}

	input := app.EvaluateQualityGateInput{
		TenantID:  tenantID.String(),
		ProfileID: profile.ID.String(),
		Counts: scanprofile.FindingCounts{
			Medium: 10,
			Total:  10,
		},
	}

	result, err := svc.EvaluateQualityGate(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Passed {
		t.Error("expected quality gate to fail on medium count")
	}
	foundMediumBreach := false
	for _, b := range result.Breaches {
		if b.Metric == "medium" {
			foundMediumBreach = true
			if b.Limit != 5 {
				t.Errorf("expected medium limit 5, got %d", b.Limit)
			}
			if b.Actual != 10 {
				t.Errorf("expected medium actual 10, got %d", b.Actual)
			}
		}
	}
	if !foundMediumBreach {
		t.Error("expected medium breach in results")
	}
}

// ============================================================================
// EvaluateQualityGateByProfile Tests
// ============================================================================

func TestEvaluateQualityGateByProfile_Passes(t *testing.T) {
	svc, _ := newTestScanProfileService()
	tenantID := shared.NewID()
	profile, _ := scanprofile.NewScanProfile(tenantID, "Test", "", nil, scanprofile.IntensityMedium, nil)
	profile.QualityGate = scanprofile.QualityGate{
		Enabled:    true,
		MaxTotal:   100,
		MaxCritical: -1,
		MaxHigh:    -1,
		MaxMedium:  -1,
	}

	counts := scanprofile.FindingCounts{
		Critical: 0,
		High:     2,
		Total:    10,
	}

	result := svc.EvaluateQualityGateByProfile(profile, counts)
	if !result.Passed {
		t.Error("expected quality gate to pass")
	}
}

func TestEvaluateQualityGateByProfile_Fails(t *testing.T) {
	svc, _ := newTestScanProfileService()
	tenantID := shared.NewID()
	profile, _ := scanprofile.NewScanProfile(tenantID, "Test", "", nil, scanprofile.IntensityMedium, nil)
	profile.QualityGate = scanprofile.QualityGate{
		Enabled:        true,
		FailOnCritical: true,
		MaxCritical:    -1,
		MaxHigh:        -1,
		MaxMedium:      -1,
		MaxTotal:       -1,
	}

	counts := scanprofile.FindingCounts{
		Critical: 1,
		Total:    1,
	}

	result := svc.EvaluateQualityGateByProfile(profile, counts)
	if result.Passed {
		t.Error("expected quality gate to fail")
	}
}

func TestEvaluateQualityGateByProfile_Disabled(t *testing.T) {
	svc, _ := newTestScanProfileService()
	tenantID := shared.NewID()
	profile, _ := scanprofile.NewScanProfile(tenantID, "Test", "", nil, scanprofile.IntensityMedium, nil)
	profile.QualityGate = scanprofile.QualityGate{Enabled: false}

	counts := scanprofile.FindingCounts{Critical: 999, Total: 999}

	result := svc.EvaluateQualityGateByProfile(profile, counts)
	if !result.Passed {
		t.Error("expected disabled quality gate to pass")
	}
}

// ============================================================================
// Edge Cases and Combined Scenarios
// ============================================================================

func TestCreateScanProfile_EmptyName(t *testing.T) {
	svc, _ := newTestScanProfileService()
	tenantID := shared.NewID()

	input := app.CreateScanProfileInput{
		TenantID: tenantID.String(),
		Name:     "",
	}

	_, err := svc.CreateScanProfile(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestCreateScanProfile_AllIntensityLevels(t *testing.T) {
	tests := []struct {
		input    string
		expected scanprofile.Intensity
	}{
		{"low", scanprofile.IntensityLow},
		{"medium", scanprofile.IntensityMedium},
		{"high", scanprofile.IntensityHigh},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			svc, _ := newTestScanProfileService()
			tenantID := shared.NewID()

			input := app.CreateScanProfileInput{
				TenantID:  tenantID.String(),
				Name:      "Profile " + tc.input,
				Intensity: tc.input,
			}

			result, err := svc.CreateScanProfile(context.Background(), input)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if result.Intensity != tc.expected {
				t.Errorf("expected intensity %q, got %q", tc.expected, result.Intensity)
			}
		})
	}
}

func TestEvaluateQualityGate_MultipleBreaches(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantID, "Strict Profile")
	profile.QualityGate = scanprofile.QualityGate{
		Enabled:        true,
		FailOnCritical: true,
		FailOnHigh:     true,
		MaxCritical:    0,
		MaxHigh:        0,
		MaxMedium:      0,
		MaxTotal:       0,
	}

	input := app.EvaluateQualityGateInput{
		TenantID:  tenantID.String(),
		ProfileID: profile.ID.String(),
		Counts: scanprofile.FindingCounts{
			Critical: 2,
			High:     3,
			Medium:   5,
			Total:    10,
		},
	}

	result, err := svc.EvaluateQualityGate(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Passed {
		t.Error("expected quality gate to fail with multiple breaches")
	}
	// FailOnCritical, MaxCritical, FailOnHigh, MaxHigh, MaxMedium, MaxTotal = at least 6 breaches
	if len(result.Breaches) < 4 {
		t.Errorf("expected at least 4 breaches, got %d", len(result.Breaches))
	}
}

func TestEvaluateQualityGate_ZeroCounts_Passes(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantID, "Profile")
	profile.QualityGate = scanprofile.QualityGate{
		Enabled:        true,
		FailOnCritical: true,
		FailOnHigh:     true,
		MaxCritical:    0,
		MaxHigh:        0,
		MaxMedium:      0,
		MaxTotal:       0,
	}

	input := app.EvaluateQualityGateInput{
		TenantID:  tenantID.String(),
		ProfileID: profile.ID.String(),
		Counts:    scanprofile.FindingCounts{},
	}

	result, err := svc.EvaluateQualityGate(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.Passed {
		t.Error("expected quality gate to pass with zero counts")
	}
}

func TestCloneScanProfile_SystemProfile(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	sysProfile := makeSystemScanProfileInRepo(repo, "System Template")
	// Make GetByTenantAndID work by setting tenant ID
	sysProfile.TenantID = tenantID

	input := app.CloneScanProfileInput{
		TenantID:  tenantID.String(),
		ProfileID: sysProfile.ID.String(),
		NewName:   "My Clone of System",
	}

	result, err := svc.CloneScanProfile(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.IsSystem {
		t.Error("expected clone to not be a system profile")
	}
	if result.Name != "My Clone of System" {
		t.Errorf("expected clone name 'My Clone of System', got %q", result.Name)
	}
}

func TestUpdateScanProfile_WithToolsConfig(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantID, "Profile")

	tools := map[string]scanprofile.ToolConfig{
		"nmap":   {Enabled: true, Timeout: 600},
		"nuclei": {Enabled: true, Severity: "medium"},
	}

	input := app.UpdateScanProfileInput{
		TenantID:    tenantID.String(),
		ProfileID:   profile.ID.String(),
		ToolsConfig: tools,
	}

	result, err := svc.UpdateScanProfile(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result.ToolsConfig) != 2 {
		t.Errorf("expected 2 tools, got %d", len(result.ToolsConfig))
	}
}

func TestListScanProfiles_EmptyResult(t *testing.T) {
	svc, _ := newTestScanProfileService()

	input := app.ListScanProfilesInput{
		TenantID: shared.NewID().String(),
		Page:     1,
		PerPage:  10,
	}

	result, err := svc.ListScanProfiles(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 0 {
		t.Errorf("expected 0 profiles, got %d", result.Total)
	}
	if len(result.Data) != 0 {
		t.Errorf("expected empty data, got %d items", len(result.Data))
	}
}

func TestCreateScanProfile_NoUserID(t *testing.T) {
	svc, _ := newTestScanProfileService()
	tenantID := shared.NewID()

	input := app.CreateScanProfileInput{
		TenantID: tenantID.String(),
		Name:     "No User",
	}

	result, err := svc.CreateScanProfile(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.CreatedBy != nil {
		t.Error("expected CreatedBy to be nil when no user ID provided")
	}
}

func TestEvaluateQualityGate_CountsReflectedInResult(t *testing.T) {
	svc, repo := newTestScanProfileService()
	tenantID := shared.NewID()
	profile := makeScanProfileInRepo(repo, tenantID, "Profile")
	profile.QualityGate = scanprofile.QualityGate{Enabled: true, MaxCritical: -1, MaxHigh: -1, MaxMedium: -1, MaxTotal: -1}

	counts := scanprofile.FindingCounts{
		Critical: 1,
		High:     2,
		Medium:   3,
		Low:      4,
		Info:     5,
		Total:    15,
	}

	input := app.EvaluateQualityGateInput{
		TenantID:  tenantID.String(),
		ProfileID: profile.ID.String(),
		Counts:    counts,
	}

	result, err := svc.EvaluateQualityGate(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Counts.Critical != 1 {
		t.Errorf("expected Critical 1, got %d", result.Counts.Critical)
	}
	if result.Counts.High != 2 {
		t.Errorf("expected High 2, got %d", result.Counts.High)
	}
	if result.Counts.Medium != 3 {
		t.Errorf("expected Medium 3, got %d", result.Counts.Medium)
	}
	if result.Counts.Low != 4 {
		t.Errorf("expected Low 4, got %d", result.Counts.Low)
	}
	if result.Counts.Info != 5 {
		t.Errorf("expected Info 5, got %d", result.Counts.Info)
	}
	if result.Counts.Total != 15 {
		t.Errorf("expected Total 15, got %d", result.Counts.Total)
	}
}
