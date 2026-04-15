package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/component"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock Component Repository
// =============================================================================

type mockComponentRepo struct {
	// Storage
	components   map[string]*component.Component
	dependencies map[string]*component.AssetDependency

	// Configurable return values
	upsertID  shared.ID
	upsertErr error

	getByPURLResult *component.Component
	getByPURLErr    error

	getByIDResult *component.Component
	getByIDErr    error

	linkLicensesLinked int
	linkLicensesErr    error

	linkAssetErr error

	getDependencyResult *component.AssetDependency
	getDependencyErr    error

	updateDependencyErr error

	deleteDependencyErr error

	deleteByAssetIDErr error

	getExistingDepByPURLResult *component.AssetDependency
	getExistingDepByPURLErr    error

	getExistingDepByCompIDResult *component.AssetDependency
	getExistingDepByCompIDErr    error

	updateAssetDepParentErr error

	listComponentsResult pagination.Result[*component.Component]
	listComponentsErr    error

	listDependenciesResult pagination.Result[*component.AssetDependency]
	listDependenciesErr    error

	getStatsResult *component.ComponentStats
	getStatsErr    error

	getEcosystemStatsResult []component.EcosystemStats
	getEcosystemStatsErr    error

	getVulnerableResult []component.VulnerableComponent
	getVulnerableErr    error

	getLicenseStatsResult []component.LicenseStats
	getLicenseStatsErr    error

	// Call tracking
	upsertCalls          int
	linkAssetCalls       int
	getDependencyCalls   int
	updateDependCalls    int
	deleteDependCalls    int
	deleteByAssetIDCalls int
	listComponentsCalls  int
	listDependCalls      int
	getStatsCalls        int
}

func newMockComponentRepo() *mockComponentRepo {
	return &mockComponentRepo{
		components:   make(map[string]*component.Component),
		dependencies: make(map[string]*component.AssetDependency),
	}
}

func (m *mockComponentRepo) Upsert(_ context.Context, comp *component.Component) (shared.ID, error) {
	m.upsertCalls++
	if m.upsertErr != nil {
		return shared.ID{}, m.upsertErr
	}
	if !m.upsertID.IsZero() {
		return m.upsertID, nil
	}
	m.components[comp.ID().String()] = comp
	return comp.ID(), nil
}

func (m *mockComponentRepo) GetByPURL(_ context.Context, _ string) (*component.Component, error) {
	if m.getByPURLErr != nil {
		return nil, m.getByPURLErr
	}
	return m.getByPURLResult, nil
}

func (m *mockComponentRepo) GetByID(_ context.Context, id shared.ID) (*component.Component, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	if m.getByIDResult != nil {
		return m.getByIDResult, nil
	}
	c, ok := m.components[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return c, nil
}

func (m *mockComponentRepo) LinkLicenses(_ context.Context, _ shared.ID, _ []string) (int, error) {
	if m.linkLicensesErr != nil {
		return 0, m.linkLicensesErr
	}
	return m.linkLicensesLinked, nil
}

func (m *mockComponentRepo) LinkAsset(_ context.Context, dep *component.AssetDependency) error {
	m.linkAssetCalls++
	if m.linkAssetErr != nil {
		return m.linkAssetErr
	}
	m.dependencies[dep.ID().String()] = dep
	return nil
}

func (m *mockComponentRepo) GetDependency(_ context.Context, id shared.ID) (*component.AssetDependency, error) {
	m.getDependencyCalls++
	if m.getDependencyErr != nil {
		return nil, m.getDependencyErr
	}
	if m.getDependencyResult != nil {
		return m.getDependencyResult, nil
	}
	d, ok := m.dependencies[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return d, nil
}

func (m *mockComponentRepo) UpdateDependency(_ context.Context, _ *component.AssetDependency) error {
	m.updateDependCalls++
	return m.updateDependencyErr
}

func (m *mockComponentRepo) DeleteDependency(_ context.Context, _ shared.ID) error {
	m.deleteDependCalls++
	return m.deleteDependencyErr
}

func (m *mockComponentRepo) DeleteByAssetID(_ context.Context, _ shared.ID) error {
	m.deleteByAssetIDCalls++
	return m.deleteByAssetIDErr
}

func (m *mockComponentRepo) GetExistingDependencyByPURL(_ context.Context, _ shared.ID, _ string) (*component.AssetDependency, error) {
	return m.getExistingDepByPURLResult, m.getExistingDepByPURLErr
}

func (m *mockComponentRepo) GetExistingDependencyByComponentID(_ context.Context, _ shared.ID, _ shared.ID, _ string) (*component.AssetDependency, error) {
	return m.getExistingDepByCompIDResult, m.getExistingDepByCompIDErr
}

func (m *mockComponentRepo) UpdateAssetDependencyParent(_ context.Context, _ shared.ID, _ shared.ID, _ int) error {
	return m.updateAssetDepParentErr
}

func (m *mockComponentRepo) ListComponents(_ context.Context, _ component.Filter, _ pagination.Pagination) (pagination.Result[*component.Component], error) {
	m.listComponentsCalls++
	return m.listComponentsResult, m.listComponentsErr
}

func (m *mockComponentRepo) ListDependencies(_ context.Context, _ shared.ID, _ pagination.Pagination) (pagination.Result[*component.AssetDependency], error) {
	m.listDependCalls++
	return m.listDependenciesResult, m.listDependenciesErr
}

func (m *mockComponentRepo) GetStats(_ context.Context, _ shared.ID) (*component.ComponentStats, error) {
	m.getStatsCalls++
	return m.getStatsResult, m.getStatsErr
}

func (m *mockComponentRepo) GetEcosystemStats(_ context.Context, _ shared.ID) ([]component.EcosystemStats, error) {
	return m.getEcosystemStatsResult, m.getEcosystemStatsErr
}

func (m *mockComponentRepo) GetVulnerableComponents(_ context.Context, _ shared.ID, page pagination.Pagination) (pagination.Result[component.VulnerableComponent], error) {
	if m.getVulnerableErr != nil {
		return pagination.Result[component.VulnerableComponent]{}, m.getVulnerableErr
	}
	return pagination.NewResult(m.getVulnerableResult, int64(len(m.getVulnerableResult)), page), nil
}

func (m *mockComponentRepo) GetLicenseStats(_ context.Context, _ shared.ID) ([]component.LicenseStats, error) {
	return m.getLicenseStatsResult, m.getLicenseStatsErr
}

// =============================================================================
// Helper functions
// =============================================================================

func newComponentService(repo *mockComponentRepo) *app.ComponentService {
	return app.NewComponentService(repo, logger.NewNop())
}

func validCreateComponentInput() app.CreateComponentInput {
	return app.CreateComponentInput{
		TenantID:  shared.NewID().String(),
		AssetID:   shared.NewID().String(),
		Name:      "lodash",
		Version:   "4.17.21",
		Ecosystem: "npm",
	}
}

// =============================================================================
// CreateComponent Tests
// =============================================================================

func TestCreateComponent_Success(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	input := validCreateComponentInput()
	result, err := svc.CreateComponent(context.Background(), input)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected component, got nil")
	}
	if result.Name() != "lodash" {
		t.Errorf("expected name lodash, got %s", result.Name())
	}
	if result.Version() != "4.17.21" {
		t.Errorf("expected version 4.17.21, got %s", result.Version())
	}
	if result.Ecosystem() != component.EcosystemNPM {
		t.Errorf("expected ecosystem npm, got %s", result.Ecosystem())
	}
	if repo.upsertCalls != 1 {
		t.Errorf("expected 1 upsert call, got %d", repo.upsertCalls)
	}
	if repo.linkAssetCalls != 1 {
		t.Errorf("expected 1 linkAsset call, got %d", repo.linkAssetCalls)
	}
}

func TestCreateComponent_InvalidTenantID(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	input := validCreateComponentInput()
	input.TenantID = "not-a-uuid"

	_, err := svc.CreateComponent(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestCreateComponent_InvalidAssetID(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	input := validCreateComponentInput()
	input.AssetID = "bad-id"

	_, err := svc.CreateComponent(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid asset ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestCreateComponent_UnknownEcosystemDefaultsToOther(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	input := validCreateComponentInput()
	input.Ecosystem = "unknown_ecosystem"

	result, err := svc.CreateComponent(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestCreateComponent_UpsertError(t *testing.T) {
	repo := newMockComponentRepo()
	repo.upsertErr = errors.New("db connection failed")
	svc := newComponentService(repo)

	input := validCreateComponentInput()

	_, err := svc.CreateComponent(context.Background(), input)
	if err == nil {
		t.Fatal("expected error from upsert failure")
	}
	if repo.upsertCalls != 1 {
		t.Errorf("expected 1 upsert call, got %d", repo.upsertCalls)
	}
	if repo.linkAssetCalls != 0 {
		t.Errorf("expected 0 linkAsset calls after upsert failure, got %d", repo.linkAssetCalls)
	}
}

func TestCreateComponent_LinkAssetError(t *testing.T) {
	repo := newMockComponentRepo()
	repo.linkAssetErr = errors.New("link failed")
	svc := newComponentService(repo)

	input := validCreateComponentInput()

	_, err := svc.CreateComponent(context.Background(), input)
	if err == nil {
		t.Fatal("expected error from link asset failure")
	}
	if repo.upsertCalls != 1 {
		t.Errorf("expected 1 upsert call, got %d", repo.upsertCalls)
	}
	if repo.linkAssetCalls != 1 {
		t.Errorf("expected 1 linkAsset call, got %d", repo.linkAssetCalls)
	}
}

func TestCreateComponent_WithPackageManager(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	input := validCreateComponentInput()
	input.PackageManager = "yarn"

	result, err := svc.CreateComponent(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	meta := result.Metadata()
	if meta["package_manager"] != "yarn" {
		t.Errorf("expected package_manager=yarn, got %v", meta["package_manager"])
	}
}

func TestCreateComponent_WithNamespace(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	input := validCreateComponentInput()
	input.Namespace = "@types"

	result, err := svc.CreateComponent(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	meta := result.Metadata()
	if meta["namespace"] != "@types" {
		t.Errorf("expected namespace=@types, got %v", meta["namespace"])
	}
}

func TestCreateComponent_WithLicense(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	input := validCreateComponentInput()
	input.License = "MIT"

	result, err := svc.CreateComponent(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.License() != "MIT" {
		t.Errorf("expected license MIT, got %s", result.License())
	}
}

func TestCreateComponent_WithDependencyType(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	input := validCreateComponentInput()
	input.DependencyType = "dev"

	_, err := svc.CreateComponent(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if repo.linkAssetCalls != 1 {
		t.Errorf("expected 1 linkAsset call, got %d", repo.linkAssetCalls)
	}
}

// =============================================================================
// GetComponent Tests
// =============================================================================

func TestGetComponent_Success(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	comp, _ := component.NewComponent("express", "4.18.0", component.EcosystemNPM)
	repo.components[comp.ID().String()] = comp

	result, err := svc.GetComponent(context.Background(), comp.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Name() != "express" {
		t.Errorf("expected name express, got %s", result.Name())
	}
}

func TestGetComponent_InvalidID(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	_, err := svc.GetComponent(context.Background(), "not-valid")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestGetComponent_NotFound(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	_, err := svc.GetComponent(context.Background(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for not found")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// =============================================================================
// GetComponentByPURL Tests
// =============================================================================

func TestGetComponentByPURL_Success(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	comp, _ := component.NewComponent("react", "18.2.0", component.EcosystemNPM)
	repo.getByPURLResult = comp

	result, err := svc.GetComponentByPURL(context.Background(), shared.NewID().String(), "pkg:npm/react@18.2.0")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Name() != "react" {
		t.Errorf("expected name react, got %s", result.Name())
	}
}

func TestGetComponentByPURL_InvalidTenantID(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	_, err := svc.GetComponentByPURL(context.Background(), "bad-tenant", "pkg:npm/react@18.2.0")
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestGetComponentByPURL_NotFound(t *testing.T) {
	repo := newMockComponentRepo()
	repo.getByPURLErr = shared.ErrNotFound
	svc := newComponentService(repo)

	_, err := svc.GetComponentByPURL(context.Background(), shared.NewID().String(), "pkg:npm/nonexistent@1.0.0")
	if err == nil {
		t.Fatal("expected error for not found")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// =============================================================================
// UpdateComponent Tests
// =============================================================================

func TestUpdateComponent_Success(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	tenantID := shared.NewID()
	assetID := shared.NewID()
	compID := shared.NewID()

	dep, _ := component.NewAssetDependency(tenantID, assetID, compID, "/app", component.DependencyTypeDirect)
	comp, _ := component.NewComponent("lodash", "4.17.21", component.EcosystemNPM)
	dep.SetComponent(comp)
	repo.getDependencyResult = dep

	input := app.UpdateComponentInput{}

	result, err := svc.UpdateComponent(context.Background(), dep.ID().String(), tenantID.String(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected dependency result, got nil")
	}
	if repo.updateDependCalls != 1 {
		t.Errorf("expected 1 updateDependency call, got %d", repo.updateDependCalls)
	}
}

func TestUpdateComponent_InvalidID(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	_, err := svc.UpdateComponent(context.Background(), "bad-id", shared.NewID().String(), app.UpdateComponentInput{})
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestUpdateComponent_NotFound(t *testing.T) {
	repo := newMockComponentRepo()
	repo.getDependencyErr = shared.ErrNotFound
	svc := newComponentService(repo)

	_, err := svc.UpdateComponent(context.Background(), shared.NewID().String(), shared.NewID().String(), app.UpdateComponentInput{})
	if err == nil {
		t.Fatal("expected error for not found")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestUpdateComponent_IDORCheck_WrongTenant(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	realTenantID := shared.NewID()
	attackerTenantID := shared.NewID()
	assetID := shared.NewID()
	compID := shared.NewID()

	dep, _ := component.NewAssetDependency(realTenantID, assetID, compID, "/app", component.DependencyTypeDirect)
	comp, _ := component.NewComponent("lodash", "4.17.21", component.EcosystemNPM)
	dep.SetComponent(comp)
	repo.getDependencyResult = dep

	_, err := svc.UpdateComponent(context.Background(), dep.ID().String(), attackerTenantID.String(), app.UpdateComponentInput{})
	if err == nil {
		t.Fatal("expected error for IDOR (wrong tenant)")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound for IDOR check, got %v", err)
	}
}

func TestUpdateComponent_RepoError(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	tenantID := shared.NewID()
	assetID := shared.NewID()
	compID := shared.NewID()

	dep, _ := component.NewAssetDependency(tenantID, assetID, compID, "/app", component.DependencyTypeDirect)
	comp, _ := component.NewComponent("lodash", "4.17.21", component.EcosystemNPM)
	dep.SetComponent(comp)
	repo.getDependencyResult = dep
	repo.updateDependencyErr = errors.New("db write failed")

	_, err := svc.UpdateComponent(context.Background(), dep.ID().String(), tenantID.String(), app.UpdateComponentInput{})
	if err == nil {
		t.Fatal("expected error from repo update failure")
	}
}

// =============================================================================
// DeleteComponent Tests
// =============================================================================

func TestDeleteComponent_Success(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	tenantID := shared.NewID()
	assetID := shared.NewID()
	compID := shared.NewID()

	dep, _ := component.NewAssetDependency(tenantID, assetID, compID, "/app", component.DependencyTypeDirect)
	repo.getDependencyResult = dep

	err := svc.DeleteComponent(context.Background(), dep.ID().String(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if repo.deleteDependCalls != 1 {
		t.Errorf("expected 1 deleteDependency call, got %d", repo.deleteDependCalls)
	}
}

func TestDeleteComponent_InvalidID(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	err := svc.DeleteComponent(context.Background(), "bad-id", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestDeleteComponent_NotFound(t *testing.T) {
	repo := newMockComponentRepo()
	repo.getDependencyErr = shared.ErrNotFound
	svc := newComponentService(repo)

	err := svc.DeleteComponent(context.Background(), shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for not found")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestDeleteComponent_IDORCheck_WrongTenant(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	realTenantID := shared.NewID()
	attackerTenantID := shared.NewID()
	assetID := shared.NewID()
	compID := shared.NewID()

	dep, _ := component.NewAssetDependency(realTenantID, assetID, compID, "/app", component.DependencyTypeDirect)
	repo.getDependencyResult = dep

	err := svc.DeleteComponent(context.Background(), dep.ID().String(), attackerTenantID.String())
	if err == nil {
		t.Fatal("expected error for IDOR (wrong tenant)")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound for IDOR check, got %v", err)
	}
}

func TestDeleteComponent_RepoError(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	tenantID := shared.NewID()
	assetID := shared.NewID()
	compID := shared.NewID()

	dep, _ := component.NewAssetDependency(tenantID, assetID, compID, "/app", component.DependencyTypeDirect)
	repo.getDependencyResult = dep
	repo.deleteDependencyErr = errors.New("db error")

	err := svc.DeleteComponent(context.Background(), dep.ID().String(), tenantID.String())
	if err == nil {
		t.Fatal("expected error from repo delete failure")
	}
}

// =============================================================================
// ListComponents Tests
// =============================================================================

func TestListComponents_Success(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	comp, _ := component.NewComponent("axios", "1.6.0", component.EcosystemNPM)
	repo.listComponentsResult = pagination.Result[*component.Component]{
		Data:       []*component.Component{comp},
		Total:      1,
		Page:       1,
		PerPage:    20,
		TotalPages: 1,
	}

	input := app.ListComponentsInput{
		TenantID: shared.NewID().String(),
		Page:     1,
		PerPage:  20,
	}

	result, err := svc.ListComponents(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result.Data) != 1 {
		t.Errorf("expected 1 component, got %d", len(result.Data))
	}
	if result.Total != 1 {
		t.Errorf("expected total 1, got %d", result.Total)
	}
	if repo.listComponentsCalls != 1 {
		t.Errorf("expected 1 listComponents call, got %d", repo.listComponentsCalls)
	}
}

func TestListComponents_InvalidTenantID(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	input := app.ListComponentsInput{
		TenantID: "not-a-uuid",
	}

	_, err := svc.ListComponents(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestListComponents_WithAssetIDFilter(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	repo.listComponentsResult = pagination.Result[*component.Component]{
		Data:       []*component.Component{},
		Total:      0,
		Page:       1,
		PerPage:    20,
		TotalPages: 0,
	}

	input := app.ListComponentsInput{
		TenantID: shared.NewID().String(),
		AssetID:  shared.NewID().String(),
		Page:     1,
		PerPage:  20,
	}

	_, err := svc.ListComponents(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if repo.listComponentsCalls != 1 {
		t.Errorf("expected 1 listComponents call, got %d", repo.listComponentsCalls)
	}
}

func TestListComponents_WithNameFilter(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	repo.listComponentsResult = pagination.Result[*component.Component]{
		Data: []*component.Component{},
	}

	input := app.ListComponentsInput{
		TenantID: shared.NewID().String(),
		Name:     "lodash",
	}

	_, err := svc.ListComponents(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestListComponents_WithEcosystemsFilter(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	repo.listComponentsResult = pagination.Result[*component.Component]{
		Data: []*component.Component{},
	}

	input := app.ListComponentsInput{
		TenantID:   shared.NewID().String(),
		Ecosystems: []string{"npm", "pypi"},
	}

	_, err := svc.ListComponents(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestListComponents_RepoError(t *testing.T) {
	repo := newMockComponentRepo()
	repo.listComponentsErr = errors.New("db read failure")
	svc := newComponentService(repo)

	input := app.ListComponentsInput{
		TenantID: shared.NewID().String(),
	}

	_, err := svc.ListComponents(context.Background(), input)
	if err == nil {
		t.Fatal("expected error from repo failure")
	}
}

// =============================================================================
// ListAssetComponents Tests
// =============================================================================

func TestListAssetComponents_Success(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	tenantID := shared.NewID()
	assetID := shared.NewID()
	compID := shared.NewID()

	dep, _ := component.NewAssetDependency(tenantID, assetID, compID, "/app", component.DependencyTypeDirect)
	repo.listDependenciesResult = pagination.Result[*component.AssetDependency]{
		Data:       []*component.AssetDependency{dep},
		Total:      1,
		Page:       1,
		PerPage:    20,
		TotalPages: 1,
	}

	result, err := svc.ListAssetComponents(context.Background(), assetID.String(), 1, 20)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result.Data) != 1 {
		t.Errorf("expected 1 dependency, got %d", len(result.Data))
	}
	if repo.listDependCalls != 1 {
		t.Errorf("expected 1 listDependencies call, got %d", repo.listDependCalls)
	}
}

func TestListAssetComponents_InvalidAssetID(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	_, err := svc.ListAssetComponents(context.Background(), "bad-id", 1, 20)
	if err == nil {
		t.Fatal("expected error for invalid asset ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestListAssetComponents_RepoError(t *testing.T) {
	repo := newMockComponentRepo()
	repo.listDependenciesErr = errors.New("db error")
	svc := newComponentService(repo)

	_, err := svc.ListAssetComponents(context.Background(), shared.NewID().String(), 1, 20)
	if err == nil {
		t.Fatal("expected error from repo failure")
	}
}

// =============================================================================
// GetComponentStats Tests
// =============================================================================

func TestGetComponentStats_Success(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	repo.getStatsResult = &component.ComponentStats{
		TotalComponents:        150,
		DirectDependencies:     80,
		TransitiveDependencies: 70,
		VulnerableComponents:   12,
	}

	result, err := svc.GetComponentStats(context.Background(), shared.NewID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.TotalComponents != 150 {
		t.Errorf("expected 150 total components, got %d", result.TotalComponents)
	}
	if result.DirectDependencies != 80 {
		t.Errorf("expected 80 direct deps, got %d", result.DirectDependencies)
	}
	if result.VulnerableComponents != 12 {
		t.Errorf("expected 12 vulnerable, got %d", result.VulnerableComponents)
	}
}

func TestGetComponentStats_InvalidTenantID(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	_, err := svc.GetComponentStats(context.Background(), "not-uuid")
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestGetComponentStats_RepoError(t *testing.T) {
	repo := newMockComponentRepo()
	repo.getStatsErr = errors.New("stats query failed")
	svc := newComponentService(repo)

	_, err := svc.GetComponentStats(context.Background(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error from repo failure")
	}
}

// =============================================================================
// GetEcosystemStats Tests
// =============================================================================

func TestGetEcosystemStats_Success(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	repo.getEcosystemStatsResult = []component.EcosystemStats{
		{Ecosystem: "npm", Total: 80, Vulnerable: 5},
		{Ecosystem: "pypi", Total: 40, Vulnerable: 2},
	}

	result, err := svc.GetEcosystemStats(context.Background(), shared.NewID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 ecosystem stats, got %d", len(result))
	}
	if result[0].Ecosystem != "npm" {
		t.Errorf("expected first ecosystem npm, got %s", result[0].Ecosystem)
	}
}

func TestGetEcosystemStats_InvalidTenantID(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	_, err := svc.GetEcosystemStats(context.Background(), "bad")
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// =============================================================================
// GetVulnerableComponents Tests
// =============================================================================

func TestGetVulnerableComponents_Success(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	repo.getVulnerableResult = []component.VulnerableComponent{
		{
			ID:            shared.NewID().String(),
			Name:          "log4j",
			Version:       "2.14.0",
			Ecosystem:     "maven",
			CriticalCount: 1,
			TotalCount:    3,
			InCisaKev:     true,
		},
	}

	result, err := svc.GetVulnerableComponents(context.Background(), shared.NewID().String(), pagination.New(1, 20))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result.Data) != 1 {
		t.Errorf("expected 1 vulnerable component, got %d", len(result.Data))
	}
	if result.Data[0].Name != "log4j" {
		t.Errorf("expected name log4j, got %s", result.Data[0].Name)
	}
	if !result.Data[0].InCisaKev {
		t.Error("expected InCisaKev to be true")
	}
}

func TestGetVulnerableComponents_InvalidTenantID(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	_, err := svc.GetVulnerableComponents(context.Background(), "invalid", pagination.New(1, 20))
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// =============================================================================
// DeleteAssetComponents Tests
// =============================================================================

func TestDeleteAssetComponents_Success(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	err := svc.DeleteAssetComponents(context.Background(), shared.NewID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if repo.deleteByAssetIDCalls != 1 {
		t.Errorf("expected 1 deleteByAssetID call, got %d", repo.deleteByAssetIDCalls)
	}
}

func TestDeleteAssetComponents_InvalidAssetID(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	err := svc.DeleteAssetComponents(context.Background(), "not-uuid")
	if err == nil {
		t.Fatal("expected error for invalid asset ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestDeleteAssetComponents_RepoError(t *testing.T) {
	repo := newMockComponentRepo()
	repo.deleteByAssetIDErr = errors.New("delete failed")
	svc := newComponentService(repo)

	err := svc.DeleteAssetComponents(context.Background(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error from repo failure")
	}
}

// =============================================================================
// GetLicenseStats Tests
// =============================================================================

func TestGetLicenseStats_Success(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	repo.getLicenseStatsResult = []component.LicenseStats{
		{LicenseID: "MIT", Name: "MIT License", Category: "permissive", Risk: "low", Count: 45},
		{LicenseID: "GPL-3.0", Name: "GNU GPLv3", Category: "copyleft", Risk: "high", Count: 10},
	}

	result, err := svc.GetLicenseStats(context.Background(), shared.NewID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 license stats, got %d", len(result))
	}
	if result[0].LicenseID != "MIT" {
		t.Errorf("expected first license MIT, got %s", result[0].LicenseID)
	}
	if result[0].Count != 45 {
		t.Errorf("expected MIT count 45, got %d", result[0].Count)
	}
	if result[1].Risk != "high" {
		t.Errorf("expected GPL risk high, got %s", result[1].Risk)
	}
}

func TestGetLicenseStats_InvalidTenantID(t *testing.T) {
	repo := newMockComponentRepo()
	svc := newComponentService(repo)

	_, err := svc.GetLicenseStats(context.Background(), "xyz")
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}
