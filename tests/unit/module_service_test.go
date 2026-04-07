package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/module"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock Module Repository
// =============================================================================

type moduleMockRepo struct {
	modules      []*module.Module
	modulesByID  map[string]*module.Module
	subModules   map[string][]*module.Module
	allSubMods   map[string][]*module.Module

	listAllErr       error
	listActiveErr    error
	getByIDErr       error
	getSubModulesErr error
	listAllSubErr    error

	listAllCalls    int
	listActiveCalls int
	getByIDCalls    int
	getSubCalls     int
	listAllSubCalls int
}

func newModuleMockRepo() *moduleMockRepo {
	return &moduleMockRepo{
		modules:     make([]*module.Module, 0),
		modulesByID: make(map[string]*module.Module),
		subModules:  make(map[string][]*module.Module),
		allSubMods:  make(map[string][]*module.Module),
	}
}

func (m *moduleMockRepo) ListAllModules(_ context.Context) ([]*module.Module, error) {
	m.listAllCalls++
	if m.listAllErr != nil {
		return nil, m.listAllErr
	}
	return m.modules, nil
}

func (m *moduleMockRepo) ListActiveModules(_ context.Context) ([]*module.Module, error) {
	m.listActiveCalls++
	if m.listActiveErr != nil {
		return nil, m.listActiveErr
	}
	// Return only active modules
	active := make([]*module.Module, 0, len(m.modules))
	for _, mod := range m.modules {
		if mod.IsActive() {
			active = append(active, mod)
		}
	}
	return active, nil
}

func (m *moduleMockRepo) GetModuleByID(_ context.Context, id string) (*module.Module, error) {
	m.getByIDCalls++
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	mod, ok := m.modulesByID[id]
	if !ok {
		return nil, module.ErrModuleNotFound
	}
	return mod, nil
}

func (m *moduleMockRepo) GetSubModules(_ context.Context, parentModuleID string) ([]*module.Module, error) {
	m.getSubCalls++
	if m.getSubModulesErr != nil {
		return nil, m.getSubModulesErr
	}
	return m.subModules[parentModuleID], nil
}

func (m *moduleMockRepo) ListAllSubModules(_ context.Context) (map[string][]*module.Module, error) {
	m.listAllSubCalls++
	if m.listAllSubErr != nil {
		return nil, m.listAllSubErr
	}
	return m.allSubMods, nil
}

func (m *moduleMockRepo) addModule(mod *module.Module) {
	m.modules = append(m.modules, mod)
	m.modulesByID[mod.ID()] = mod
}

// =============================================================================
// Mock Tenant Module Repository
// =============================================================================

type moduleTenanMockRepo struct {
	overrides map[string][]*module.TenantModuleOverride // keyed by tenantID string

	listByTenantErr   error
	upsertBatchErr    error
	deleteByTenantErr error

	listByTenantCalls   int
	upsertBatchCalls    int
	deleteByTenantCalls int

	lastUpsertTenantID shared.ID
	lastUpsertUpdates  []module.TenantModuleUpdate
	lastUpsertUpdatedBy *shared.ID

	lastDeleteTenantID shared.ID
}

func newModuleTenantMockRepo() *moduleTenanMockRepo {
	return &moduleTenanMockRepo{
		overrides: make(map[string][]*module.TenantModuleOverride),
	}
}

func (m *moduleTenanMockRepo) ListByTenant(_ context.Context, tenantID shared.ID) ([]*module.TenantModuleOverride, error) {
	m.listByTenantCalls++
	if m.listByTenantErr != nil {
		return nil, m.listByTenantErr
	}
	return m.overrides[tenantID.String()], nil
}

func (m *moduleTenanMockRepo) UpsertBatch(_ context.Context, tenantID shared.ID, updates []module.TenantModuleUpdate, updatedBy *shared.ID) error {
	m.upsertBatchCalls++
	m.lastUpsertTenantID = tenantID
	m.lastUpsertUpdates = updates
	m.lastUpsertUpdatedBy = updatedBy
	if m.upsertBatchErr != nil {
		return m.upsertBatchErr
	}
	return nil
}

func (m *moduleTenanMockRepo) DeleteByTenant(_ context.Context, tenantID shared.ID) error {
	m.deleteByTenantCalls++
	m.lastDeleteTenantID = tenantID
	if m.deleteByTenantErr != nil {
		return m.deleteByTenantErr
	}
	// Clear overrides for tenant
	delete(m.overrides, tenantID.String())
	return nil
}

func (m *moduleTenanMockRepo) addOverride(tenantID shared.ID, moduleID string, isEnabled bool) {
	key := tenantID.String()
	now := time.Now()
	override := &module.TenantModuleOverride{
		TenantID:  tenantID,
		ModuleID:  moduleID,
		IsEnabled: isEnabled,
		UpdatedAt: now,
	}
	m.overrides[key] = append(m.overrides[key], override)
}

// =============================================================================
// Mock Audit Repository (for AuditService)
// =============================================================================

type moduleAuditMockRepo struct {
	logs      []*audit.AuditLog
	createErr error
}

func newModuleAuditMockRepo() *moduleAuditMockRepo {
	return &moduleAuditMockRepo{
		logs: make([]*audit.AuditLog, 0),
	}
}

func (m *moduleAuditMockRepo) Create(_ context.Context, log *audit.AuditLog) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.logs = append(m.logs, log)
	return nil
}

func (m *moduleAuditMockRepo) CreateBatch(_ context.Context, logs []*audit.AuditLog) error {
	m.logs = append(m.logs, logs...)
	return nil
}

func (m *moduleAuditMockRepo) GetByID(_ context.Context, _ shared.ID) (*audit.AuditLog, error) {
	return nil, nil
}

func (m *moduleAuditMockRepo) GetByTenantAndID(_ context.Context, _, _ shared.ID) (*audit.AuditLog, error) {
	return nil, nil
}

func (m *moduleAuditMockRepo) List(_ context.Context, _ audit.Filter, _ pagination.Pagination) (pagination.Result[*audit.AuditLog], error) {
	return pagination.Result[*audit.AuditLog]{}, nil
}

func (m *moduleAuditMockRepo) Count(_ context.Context, _ audit.Filter) (int64, error) {
	return 0, nil
}

func (m *moduleAuditMockRepo) DeleteOlderThan(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (m *moduleAuditMockRepo) GetLatestByResource(_ context.Context, _ audit.ResourceType, _ string) (*audit.AuditLog, error) {
	return nil, nil
}

func (m *moduleAuditMockRepo) ListByActor(_ context.Context, _ shared.ID, _ pagination.Pagination) (pagination.Result[*audit.AuditLog], error) {
	return pagination.Result[*audit.AuditLog]{}, nil
}

func (m *moduleAuditMockRepo) ListByResource(_ context.Context, _ audit.ResourceType, _ string, _ pagination.Pagination) (pagination.Result[*audit.AuditLog], error) {
	return pagination.Result[*audit.AuditLog]{}, nil
}

func (m *moduleAuditMockRepo) CountByAction(_ context.Context, _ *shared.ID, _ audit.Action, _ time.Time) (int64, error) {
	return 0, nil
}

// =============================================================================
// Test Helpers
// =============================================================================

func newTestModuleService(repo *moduleMockRepo) *app.ModuleService {
	log := logger.NewNop()
	return app.NewModuleService(repo, log)
}

func newTestModuleServiceWithTenant(repo *moduleMockRepo, tenantRepo *moduleTenanMockRepo) *app.ModuleService {
	log := logger.NewNop()
	svc := app.NewModuleService(repo, log)
	svc.SetTenantModuleRepo(tenantRepo)
	return svc
}

func newTestModuleServiceWithAudit(repo *moduleMockRepo, tenantRepo *moduleTenanMockRepo, auditRepo *moduleAuditMockRepo) *app.ModuleService {
	log := logger.NewNop()
	svc := app.NewModuleService(repo, log)
	svc.SetTenantModuleRepo(tenantRepo)
	auditSvc := app.NewAuditService(auditRepo, log)
	svc.SetAuditService(auditSvc)
	return svc
}

func makeModule(id, name string, isActive, isCore bool) *module.Module {
	return module.ReconstructModule(
		id, id, name, "Description for "+name, "icon-"+id, module.ModuleCategoryCore,
		0, isActive, isCore, string(module.ReleaseStatusReleased), nil, nil,
	)
}

func makeSubModule(id, name, parentID string, isActive bool) *module.Module {
	parent := parentID
	return module.ReconstructModule(
		id, id, name, "Sub-module "+name, "icon-"+id, module.ModuleCategoryCore,
		0, isActive, false, string(module.ReleaseStatusReleased), &parent, nil,
	)
}

func makeInactiveModule(id, name string) *module.Module {
	return module.ReconstructModule(
		id, id, name, "Description for "+name, "icon-"+id, module.ModuleCategoryCore,
		0, false, false, string(module.ReleaseStatusReleased), nil, nil,
	)
}

func validTenantID() string {
	return shared.NewID().String()
}

func validActorID() string {
	return shared.NewID().String()
}

// =============================================================================
// Tests: ListActiveModules
// =============================================================================

func TestModuleService_ListActiveModules_Success(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("dashboard", "Dashboard", true, true))
	repo.addModule(makeModule("assets", "Assets", true, true))
	repo.addModule(makeInactiveModule("deprecated", "Deprecated"))

	svc := newTestModuleService(repo)
	result, err := svc.ListActiveModules(context.Background())

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 active modules, got %d", len(result))
	}
	if repo.listActiveCalls != 1 {
		t.Errorf("expected 1 ListActiveModules call, got %d", repo.listActiveCalls)
	}
}

func TestModuleService_ListActiveModules_Empty(t *testing.T) {
	repo := newModuleMockRepo()
	svc := newTestModuleService(repo)

	result, err := svc.ListActiveModules(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 modules, got %d", len(result))
	}
}

func TestModuleService_ListActiveModules_RepoError(t *testing.T) {
	repo := newModuleMockRepo()
	repo.listActiveErr = errors.New("db connection failed")
	svc := newTestModuleService(repo)

	_, err := svc.ListActiveModules(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "db connection failed" {
		t.Errorf("expected db connection failed, got: %v", err)
	}
}

// =============================================================================
// Tests: GetModule
// =============================================================================

func TestModuleService_GetModule_Success(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("assets", "Assets", true, true))
	svc := newTestModuleService(repo)

	result, err := svc.GetModule(context.Background(), "assets")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result.ID() != "assets" {
		t.Errorf("expected module ID 'assets', got '%s'", result.ID())
	}
	if result.Name() != "Assets" {
		t.Errorf("expected module name 'Assets', got '%s'", result.Name())
	}
}

func TestModuleService_GetModule_NotFound(t *testing.T) {
	repo := newModuleMockRepo()
	svc := newTestModuleService(repo)

	_, err := svc.GetModule(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestModuleService_GetModule_RepoError(t *testing.T) {
	repo := newModuleMockRepo()
	repo.getByIDErr = errors.New("db error")
	svc := newTestModuleService(repo)

	_, err := svc.GetModule(context.Background(), "assets")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// =============================================================================
// Tests: GetTenantEnabledModules
// =============================================================================

func TestModuleService_GetTenantEnabledModules_AllEnabled(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("dashboard", "Dashboard", true, true))
	repo.addModule(makeModule("assets", "Assets", true, true))
	repo.addModule(makeModule("reports", "Reports", true, false))

	svc := newTestModuleServiceWithTenant(repo, newModuleTenantMockRepo())
	tenantID := validTenantID()

	result, err := svc.GetTenantEnabledModules(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(result.Modules) != 3 {
		t.Fatalf("expected 3 modules, got %d", len(result.Modules))
	}
	if len(result.ModuleIDs) != 3 {
		t.Fatalf("expected 3 module IDs, got %d", len(result.ModuleIDs))
	}
}

func TestModuleService_GetTenantEnabledModules_WithDisabledModule(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("dashboard", "Dashboard", true, true))
	repo.addModule(makeModule("reports", "Reports", true, false))
	repo.addModule(makeModule("credentials", "Credentials", true, false))

	tenantRepo := newModuleTenantMockRepo()
	tenantID, _ := shared.IDFromString(validTenantID())
	tenantRepo.addOverride(tenantID, "reports", false) // disable reports

	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	result, err := svc.GetTenantEnabledModules(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	// dashboard (core) + credentials = 2 enabled; reports disabled
	if len(result.Modules) != 2 {
		t.Fatalf("expected 2 enabled modules, got %d", len(result.Modules))
	}

	// Verify reports is not in module IDs
	for _, id := range result.ModuleIDs {
		if id == "reports" {
			t.Error("reports should be disabled but was found in module IDs")
		}
	}
}

func TestModuleService_GetTenantEnabledModules_CoreCannotBeDisabled(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("dashboard", "Dashboard", true, true))

	tenantRepo := newModuleTenantMockRepo()
	tenantID, _ := shared.IDFromString(validTenantID())
	// Attempt to disable core module via override
	tenantRepo.addOverride(tenantID, "dashboard", false)

	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	result, err := svc.GetTenantEnabledModules(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	// Core module should still be present
	if len(result.Modules) != 1 {
		t.Fatalf("expected 1 module (core stays enabled), got %d", len(result.Modules))
	}
	if result.Modules[0].ID() != "dashboard" {
		t.Errorf("expected dashboard module, got %s", result.Modules[0].ID())
	}
}

func TestModuleService_GetTenantEnabledModules_NoTenantRepo(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("dashboard", "Dashboard", true, true))
	repo.addModule(makeModule("reports", "Reports", true, false))

	// No tenant repo set
	svc := newTestModuleService(repo)

	result, err := svc.GetTenantEnabledModules(context.Background(), validTenantID())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	// Without tenant repo, all modules are enabled
	if len(result.Modules) != 2 {
		t.Fatalf("expected 2 modules, got %d", len(result.Modules))
	}
}

func TestModuleService_GetTenantEnabledModules_RepoError(t *testing.T) {
	repo := newModuleMockRepo()
	repo.listActiveErr = errors.New("db down")

	svc := newTestModuleService(repo)

	_, err := svc.GetTenantEnabledModules(context.Background(), validTenantID())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestModuleService_GetTenantEnabledModules_WithSubModules(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("integrations", "Integrations", true, false))
	repo.addModule(makeSubModule("integrations.scm", "SCM", "integrations", true))
	repo.addModule(makeSubModule("integrations.notifications", "Notifications", "integrations", true))

	svc := newTestModuleServiceWithTenant(repo, newModuleTenantMockRepo())

	result, err := svc.GetTenantEnabledModules(context.Background(), validTenantID())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	// 1 top-level module
	if len(result.Modules) != 1 {
		t.Fatalf("expected 1 top-level module, got %d", len(result.Modules))
	}
	// 2 sub-modules under integrations
	subs, ok := result.SubModules["integrations"]
	if !ok {
		t.Fatal("expected sub-modules for integrations")
	}
	if len(subs) != 2 {
		t.Fatalf("expected 2 sub-modules, got %d", len(subs))
	}
	// 3 total module IDs (1 parent + 2 subs)
	if len(result.ModuleIDs) != 3 {
		t.Fatalf("expected 3 module IDs, got %d", len(result.ModuleIDs))
	}
}

func TestModuleService_GetTenantEnabledModules_DisabledParentExcludesSubModules(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("integrations", "Integrations", true, false))
	repo.addModule(makeSubModule("integrations.scm", "SCM", "integrations", true))

	tenantRepo := newModuleTenantMockRepo()
	tenantID, _ := shared.IDFromString(validTenantID())
	tenantRepo.addOverride(tenantID, "integrations", false)

	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	result, err := svc.GetTenantEnabledModules(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(result.Modules) != 0 {
		t.Fatalf("expected 0 top-level modules, got %d", len(result.Modules))
	}
	if len(result.SubModules) != 0 {
		t.Fatalf("expected 0 sub-module groups, got %d", len(result.SubModules))
	}
}

func TestModuleService_GetTenantEnabledModules_DisabledSubModuleOnly(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("integrations", "Integrations", true, false))
	repo.addModule(makeSubModule("integrations.scm", "SCM", "integrations", true))
	repo.addModule(makeSubModule("integrations.notifications", "Notifications", "integrations", true))

	tenantRepo := newModuleTenantMockRepo()
	tenantID, _ := shared.IDFromString(validTenantID())
	tenantRepo.addOverride(tenantID, "integrations.scm", false) // disable only SCM sub-module

	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	result, err := svc.GetTenantEnabledModules(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(result.Modules) != 1 {
		t.Fatalf("expected 1 top-level module, got %d", len(result.Modules))
	}
	subs := result.SubModules["integrations"]
	if len(subs) != 1 {
		t.Fatalf("expected 1 sub-module (notifications only), got %d", len(subs))
	}
	if subs[0].ID() != "integrations.notifications" {
		t.Errorf("expected notifications sub-module, got %s", subs[0].ID())
	}
}

func TestModuleService_GetTenantEnabledModules_InvalidTenantID(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("dashboard", "Dashboard", true, true))
	repo.addModule(makeModule("reports", "Reports", true, false))

	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	// Invalid tenant ID should be handled gracefully (no overrides applied)
	result, err := svc.GetTenantEnabledModules(context.Background(), "not-a-uuid")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	// All modules should be enabled when tenant ID is invalid (no overrides)
	if len(result.Modules) != 2 {
		t.Fatalf("expected 2 modules, got %d", len(result.Modules))
	}
}

func TestModuleService_GetTenantEnabledModules_TenantRepoError(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("dashboard", "Dashboard", true, true))

	tenantRepo := newModuleTenantMockRepo()
	tenantRepo.listByTenantErr = errors.New("tenant db error")

	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	// Should degrade gracefully: return all modules when tenant overrides fail
	result, err := svc.GetTenantEnabledModules(context.Background(), validTenantID())
	if err != nil {
		t.Fatalf("expected no error (graceful degradation), got: %v", err)
	}
	if len(result.Modules) != 1 {
		t.Fatalf("expected 1 module, got %d", len(result.Modules))
	}
}

// =============================================================================
// Tests: GetTenantModuleConfig
// =============================================================================

func TestModuleService_GetTenantModuleConfig_Success(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("dashboard", "Dashboard", true, true))
	repo.addModule(makeModule("assets", "Assets", true, true))
	repo.addModule(makeModule("reports", "Reports", true, false))
	repo.addModule(makeModule("integrations", "Integrations", true, false))

	tenantRepo := newModuleTenantMockRepo()
	tenantID, _ := shared.IDFromString(validTenantID())
	tenantRepo.addOverride(tenantID, "reports", false)

	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	result, err := svc.GetTenantModuleConfig(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Only user-facing modules are included
	for _, info := range result.Modules {
		if !module.IsUserFacing(info.Module.ID()) {
			t.Errorf("non-user-facing module %s should not be in config", info.Module.ID())
		}
	}

	// Check summary
	if result.Summary.Enabled+result.Summary.Disabled != result.Summary.Total {
		t.Errorf("enabled (%d) + disabled (%d) should equal total (%d)",
			result.Summary.Enabled, result.Summary.Disabled, result.Summary.Total)
	}
}

func TestModuleService_GetTenantModuleConfig_CoreAlwaysEnabled(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("dashboard", "Dashboard", true, true))

	tenantRepo := newModuleTenantMockRepo()
	tenantID, _ := shared.IDFromString(validTenantID())
	tenantRepo.addOverride(tenantID, "dashboard", false) // try to disable core

	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	result, err := svc.GetTenantModuleConfig(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	for _, info := range result.Modules {
		if info.Module.ID() == "dashboard" && !info.IsEnabled {
			t.Error("core module dashboard should always be enabled in config")
		}
	}
}

func TestModuleService_GetTenantModuleConfig_ExcludesNonUserFacing(t *testing.T) {
	repo := newModuleMockRepo()
	// "tools" is not in UserFacingModuleIDs
	repo.addModule(makeModule("tools", "Tools", true, false))
	repo.addModule(makeModule("dashboard", "Dashboard", true, true))

	svc := newTestModuleServiceWithTenant(repo, newModuleTenantMockRepo())

	result, err := svc.GetTenantModuleConfig(context.Background(), validTenantID())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	for _, info := range result.Modules {
		if info.Module.ID() == "tools" {
			t.Error("non-user-facing module 'tools' should not appear in config")
		}
	}
}

func TestModuleService_GetTenantModuleConfig_WithSubModules(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("integrations", "Integrations", true, false))
	repo.addModule(makeSubModule("integrations.scm", "SCM", "integrations", true))
	repo.addModule(makeSubModule("integrations.notifications", "Notifications", "integrations", true))

	tenantRepo := newModuleTenantMockRepo()
	tenantID, _ := shared.IDFromString(validTenantID())
	tenantRepo.addOverride(tenantID, "integrations.scm", false)

	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	result, err := svc.GetTenantModuleConfig(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Find integrations module info
	for _, info := range result.Modules {
		if info.Module.ID() == "integrations" {
			if len(info.SubModules) != 2 {
				t.Fatalf("expected 2 sub-modules, got %d", len(info.SubModules))
			}
			for _, sub := range info.SubModules {
				if sub.Module.ID() == "integrations.scm" && sub.IsEnabled {
					t.Error("integrations.scm should be disabled")
				}
				if sub.Module.ID() == "integrations.notifications" && !sub.IsEnabled {
					t.Error("integrations.notifications should be enabled")
				}
			}
			return
		}
	}
	t.Error("integrations module not found in config")
}

func TestModuleService_GetTenantModuleConfig_RepoError(t *testing.T) {
	repo := newModuleMockRepo()
	repo.listActiveErr = errors.New("db error")

	svc := newTestModuleServiceWithTenant(repo, newModuleTenantMockRepo())

	_, err := svc.GetTenantModuleConfig(context.Background(), validTenantID())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestModuleService_GetTenantModuleConfig_SummaryCoreCounting(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("dashboard", "Dashboard", true, true))
	repo.addModule(makeModule("assets", "Assets", true, true))
	repo.addModule(makeModule("findings", "Findings", true, true))
	repo.addModule(makeModule("scans", "Scans", true, true))
	repo.addModule(makeModule("reports", "Reports", true, false))

	svc := newTestModuleServiceWithTenant(repo, newModuleTenantMockRepo())

	result, err := svc.GetTenantModuleConfig(context.Background(), validTenantID())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if result.Summary.Core < 4 {
		t.Errorf("expected at least 4 core modules, got %d", result.Summary.Core)
	}
}

// =============================================================================
// Tests: UpdateTenantModules
// =============================================================================

func TestModuleService_UpdateTenantModules_Success(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("dashboard", "Dashboard", true, true))
	repo.addModule(makeModule("reports", "Reports", true, false))

	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	tenantID := validTenantID()
	actorID := validActorID()
	updates := []module.TenantModuleUpdate{
		{ModuleID: "reports", IsEnabled: false},
	}
	actx := app.AuditContext{ActorID: actorID}

	result, err := svc.UpdateTenantModules(context.Background(), tenantID, updates, actx)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if tenantRepo.upsertBatchCalls != 1 {
		t.Errorf("expected 1 upsert call, got %d", tenantRepo.upsertBatchCalls)
	}
}

func TestModuleService_UpdateTenantModules_NoTenantRepo(t *testing.T) {
	repo := newModuleMockRepo()
	svc := newTestModuleService(repo) // no tenant repo set

	updates := []module.TenantModuleUpdate{
		{ModuleID: "reports", IsEnabled: false},
	}

	_, err := svc.UpdateTenantModules(context.Background(), validTenantID(), updates, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, shared.ErrInternal) {
		t.Errorf("expected ErrInternal, got: %v", err)
	}
}

func TestModuleService_UpdateTenantModules_TooManyUpdates(t *testing.T) {
	repo := newModuleMockRepo()
	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	// Create 51 updates (exceeds max of 50)
	updates := make([]module.TenantModuleUpdate, 51)
	for i := range updates {
		updates[i] = module.TenantModuleUpdate{ModuleID: "mod", IsEnabled: true}
	}

	_, err := svc.UpdateTenantModules(context.Background(), validTenantID(), updates, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got: %v", err)
	}
}

func TestModuleService_UpdateTenantModules_ExactlyMaxUpdates(t *testing.T) {
	repo := newModuleMockRepo()
	// Add 50 non-core active modules
	for i := range 50 {
		id := "mod" + string(rune('a'+i%26)) + string(rune('0'+i/26))
		repo.addModule(makeModule(id, "Module "+id, true, false))
	}

	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	updates := make([]module.TenantModuleUpdate, 50)
	for i, mod := range repo.modules[:50] {
		updates[i] = module.TenantModuleUpdate{ModuleID: mod.ID(), IsEnabled: false}
	}

	_, err := svc.UpdateTenantModules(context.Background(), validTenantID(), updates, app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error with exactly 50 updates, got: %v", err)
	}
}

func TestModuleService_UpdateTenantModules_InvalidTenantID(t *testing.T) {
	repo := newModuleMockRepo()
	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	updates := []module.TenantModuleUpdate{
		{ModuleID: "reports", IsEnabled: false},
	}

	_, err := svc.UpdateTenantModules(context.Background(), "not-valid-uuid", updates, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got: %v", err)
	}
}

func TestModuleService_UpdateTenantModules_UnknownModule(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("dashboard", "Dashboard", true, true))

	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	updates := []module.TenantModuleUpdate{
		{ModuleID: "nonexistent_module", IsEnabled: false},
	}

	_, err := svc.UpdateTenantModules(context.Background(), validTenantID(), updates, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got: %v", err)
	}
}

func TestModuleService_UpdateTenantModules_DisableCoreModule(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("dashboard", "Dashboard", true, true))

	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	updates := []module.TenantModuleUpdate{
		{ModuleID: "dashboard", IsEnabled: false},
	}

	_, err := svc.UpdateTenantModules(context.Background(), validTenantID(), updates, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, module.ErrCoreModuleCannotBeDisabled) {
		t.Errorf("expected ErrCoreModuleCannotBeDisabled, got: %v", err)
	}
}

func TestModuleService_UpdateTenantModules_EnableCoreModuleAllowed(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("dashboard", "Dashboard", true, true))

	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	// Enabling a core module should be fine
	updates := []module.TenantModuleUpdate{
		{ModuleID: "dashboard", IsEnabled: true},
	}

	_, err := svc.UpdateTenantModules(context.Background(), validTenantID(), updates, app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error when enabling core module, got: %v", err)
	}
}

func TestModuleService_UpdateTenantModules_InactiveModule(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeInactiveModule("deprecated", "Deprecated"))

	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	updates := []module.TenantModuleUpdate{
		{ModuleID: "deprecated", IsEnabled: true},
	}

	// Inactive modules are not returned by ListActiveModules, so should be "unknown"
	_, err := svc.UpdateTenantModules(context.Background(), validTenantID(), updates, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got: %v", err)
	}
}

func TestModuleService_UpdateTenantModules_UpsertBatchError(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("reports", "Reports", true, false))

	tenantRepo := newModuleTenantMockRepo()
	tenantRepo.upsertBatchErr = errors.New("upsert failed")
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	updates := []module.TenantModuleUpdate{
		{ModuleID: "reports", IsEnabled: false},
	}

	_, err := svc.UpdateTenantModules(context.Background(), validTenantID(), updates, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestModuleService_UpdateTenantModules_ListActiveError(t *testing.T) {
	repo := newModuleMockRepo()
	repo.listActiveErr = errors.New("list active failed")

	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	updates := []module.TenantModuleUpdate{
		{ModuleID: "reports", IsEnabled: false},
	}

	_, err := svc.UpdateTenantModules(context.Background(), validTenantID(), updates, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestModuleService_UpdateTenantModules_WithAuditLog(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("reports", "Reports", true, false))
	repo.addModule(makeModule("credentials", "Credentials", true, false))

	tenantRepo := newModuleTenantMockRepo()
	auditRepo := newModuleAuditMockRepo()
	svc := newTestModuleServiceWithAudit(repo, tenantRepo, auditRepo)

	tenantID := validTenantID()
	actorID := validActorID()
	updates := []module.TenantModuleUpdate{
		{ModuleID: "reports", IsEnabled: false},
		{ModuleID: "credentials", IsEnabled: true},
	}
	actx := app.AuditContext{ActorID: actorID}

	_, err := svc.UpdateTenantModules(context.Background(), tenantID, updates, actx)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Audit log should have been created
	if len(auditRepo.logs) != 1 {
		t.Fatalf("expected 1 audit log, got %d", len(auditRepo.logs))
	}
}

func TestModuleService_UpdateTenantModules_ParsesActorID(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("reports", "Reports", true, false))

	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	actorID := validActorID()
	updates := []module.TenantModuleUpdate{
		{ModuleID: "reports", IsEnabled: false},
	}
	actx := app.AuditContext{ActorID: actorID}

	_, err := svc.UpdateTenantModules(context.Background(), validTenantID(), updates, actx)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify updatedBy was set
	if tenantRepo.lastUpsertUpdatedBy == nil {
		t.Fatal("expected updatedBy to be set")
	}
	if tenantRepo.lastUpsertUpdatedBy.String() != actorID {
		t.Errorf("expected actor ID %s, got %s", actorID, tenantRepo.lastUpsertUpdatedBy.String())
	}
}

func TestModuleService_UpdateTenantModules_EmptyActorID(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("reports", "Reports", true, false))

	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	updates := []module.TenantModuleUpdate{
		{ModuleID: "reports", IsEnabled: false},
	}
	actx := app.AuditContext{} // empty actor

	_, err := svc.UpdateTenantModules(context.Background(), validTenantID(), updates, actx)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if tenantRepo.lastUpsertUpdatedBy != nil {
		t.Error("expected updatedBy to be nil with empty actor ID")
	}
}

func TestModuleService_UpdateTenantModules_InvalidActorID(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("reports", "Reports", true, false))

	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	updates := []module.TenantModuleUpdate{
		{ModuleID: "reports", IsEnabled: false},
	}
	actx := app.AuditContext{ActorID: "not-a-uuid"}

	_, err := svc.UpdateTenantModules(context.Background(), validTenantID(), updates, actx)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Invalid actor ID should result in nil updatedBy (not an error)
	if tenantRepo.lastUpsertUpdatedBy != nil {
		t.Error("expected updatedBy to be nil with invalid actor ID")
	}
}

func TestModuleService_UpdateTenantModules_MixedEnableDisable(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("reports", "Reports", true, false))
	repo.addModule(makeModule("credentials", "Credentials", true, false))
	repo.addModule(makeModule("exposures", "Exposures", true, false))

	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	updates := []module.TenantModuleUpdate{
		{ModuleID: "reports", IsEnabled: false},
		{ModuleID: "credentials", IsEnabled: true},
		{ModuleID: "exposures", IsEnabled: false},
	}

	result, err := svc.UpdateTenantModules(context.Background(), validTenantID(), updates, app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if tenantRepo.upsertBatchCalls != 1 {
		t.Errorf("expected 1 upsert call, got %d", tenantRepo.upsertBatchCalls)
	}
	if len(tenantRepo.lastUpsertUpdates) != 3 {
		t.Errorf("expected 3 updates passed, got %d", len(tenantRepo.lastUpsertUpdates))
	}
}

func TestModuleService_UpdateTenantModules_EmptyUpdates(t *testing.T) {
	repo := newModuleMockRepo()
	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	// Empty updates should not fail (0 <= 50)
	updates := []module.TenantModuleUpdate{}

	_, err := svc.UpdateTenantModules(context.Background(), validTenantID(), updates, app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error with empty updates, got: %v", err)
	}
}

// =============================================================================
// Tests: ResetTenantModules
// =============================================================================

func TestModuleService_ResetTenantModules_Success(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("dashboard", "Dashboard", true, true))
	repo.addModule(makeModule("reports", "Reports", true, false))

	tenantRepo := newModuleTenantMockRepo()
	tenantID, _ := shared.IDFromString(validTenantID())
	tenantRepo.addOverride(tenantID, "reports", false)

	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	result, err := svc.ResetTenantModules(context.Background(), tenantID.String(), app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if tenantRepo.deleteByTenantCalls != 1 {
		t.Errorf("expected 1 delete call, got %d", tenantRepo.deleteByTenantCalls)
	}
}

func TestModuleService_ResetTenantModules_NoTenantRepo(t *testing.T) {
	repo := newModuleMockRepo()
	svc := newTestModuleService(repo) // no tenant repo

	_, err := svc.ResetTenantModules(context.Background(), validTenantID(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, shared.ErrInternal) {
		t.Errorf("expected ErrInternal, got: %v", err)
	}
}

func TestModuleService_ResetTenantModules_InvalidTenantID(t *testing.T) {
	repo := newModuleMockRepo()
	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	_, err := svc.ResetTenantModules(context.Background(), "bad-uuid", app.AuditContext{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got: %v", err)
	}
}

func TestModuleService_ResetTenantModules_DeleteError(t *testing.T) {
	repo := newModuleMockRepo()
	tenantRepo := newModuleTenantMockRepo()
	tenantRepo.deleteByTenantErr = errors.New("delete failed")

	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	_, err := svc.ResetTenantModules(context.Background(), validTenantID(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestModuleService_ResetTenantModules_WithAuditLog(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("dashboard", "Dashboard", true, true))

	tenantRepo := newModuleTenantMockRepo()
	auditRepo := newModuleAuditMockRepo()
	svc := newTestModuleServiceWithAudit(repo, tenantRepo, auditRepo)

	_, err := svc.ResetTenantModules(context.Background(), validTenantID(), app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Audit should have been called with "reset" message
	if len(auditRepo.logs) != 1 {
		t.Fatalf("expected 1 audit log, got %d", len(auditRepo.logs))
	}
}

func TestModuleService_ResetTenantModules_ReturnsFullConfig(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("dashboard", "Dashboard", true, true))
	repo.addModule(makeModule("reports", "Reports", true, false))

	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	result, err := svc.ResetTenantModules(context.Background(), validTenantID(), app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// After reset, all user-facing modules should be enabled
	for _, info := range result.Modules {
		if !info.IsEnabled {
			t.Errorf("after reset, module %s should be enabled", info.Module.ID())
		}
	}
}

// =============================================================================
// Tests: Edge Cases
// =============================================================================

func TestModuleService_GetTenantEnabledModules_AllSubModulesDisabled(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("integrations", "Integrations", true, false))
	repo.addModule(makeSubModule("integrations.scm", "SCM", "integrations", true))
	repo.addModule(makeSubModule("integrations.notifications", "Notifications", "integrations", true))

	tenantRepo := newModuleTenantMockRepo()
	tenantID, _ := shared.IDFromString(validTenantID())
	tenantRepo.addOverride(tenantID, "integrations.scm", false)
	tenantRepo.addOverride(tenantID, "integrations.notifications", false)

	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	result, err := svc.GetTenantEnabledModules(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	// Parent still enabled, but no sub-modules
	if len(result.Modules) != 1 {
		t.Fatalf("expected 1 top-level module, got %d", len(result.Modules))
	}
	if len(result.SubModules) != 0 {
		t.Fatalf("expected 0 sub-module groups (all disabled), got %d", len(result.SubModules))
	}
}

func TestModuleService_UpdateTenantModules_MultipleCoreModuleDisableAttempts(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("dashboard", "Dashboard", true, true))
	repo.addModule(makeModule("assets", "Assets", true, true))

	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	// Try to disable first core module - should fail at first validation
	updates := []module.TenantModuleUpdate{
		{ModuleID: "dashboard", IsEnabled: false},
		{ModuleID: "assets", IsEnabled: false},
	}

	_, err := svc.UpdateTenantModules(context.Background(), validTenantID(), updates, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, module.ErrCoreModuleCannotBeDisabled) {
		t.Errorf("expected ErrCoreModuleCannotBeDisabled, got: %v", err)
	}

	// Upsert should not have been called
	if tenantRepo.upsertBatchCalls != 0 {
		t.Errorf("expected 0 upsert calls, got %d", tenantRepo.upsertBatchCalls)
	}
}

func TestModuleService_GetTenantEnabledModules_EnabledOverrideDoesNothing(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("reports", "Reports", true, false))

	tenantRepo := newModuleTenantMockRepo()
	tenantID, _ := shared.IDFromString(validTenantID())
	// Override with enabled=true (same as default)
	tenantRepo.addOverride(tenantID, "reports", true)

	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	result, err := svc.GetTenantEnabledModules(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(result.Modules) != 1 {
		t.Fatalf("expected 1 module, got %d", len(result.Modules))
	}
}

func TestModuleService_SetTenantModuleRepo(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("reports", "Reports", true, false))

	svc := newTestModuleService(repo)

	// Without tenant repo, update should fail
	_, err := svc.UpdateTenantModules(context.Background(), validTenantID(), nil, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error without tenant repo")
	}

	// Set tenant repo
	tenantRepo := newModuleTenantMockRepo()
	svc.SetTenantModuleRepo(tenantRepo)

	// Now it should work
	updates := []module.TenantModuleUpdate{
		{ModuleID: "reports", IsEnabled: false},
	}
	_, err = svc.UpdateTenantModules(context.Background(), validTenantID(), updates, app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error after setting tenant repo, got: %v", err)
	}
}

func TestModuleService_SetAuditService(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("reports", "Reports", true, false))

	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	// Without audit service, should still work (no audit logged)
	updates := []module.TenantModuleUpdate{
		{ModuleID: "reports", IsEnabled: false},
	}

	_, err := svc.UpdateTenantModules(context.Background(), validTenantID(), updates, app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Now set audit service and verify it logs
	auditRepo := newModuleAuditMockRepo()
	log := logger.NewNop()
	auditSvc := app.NewAuditService(auditRepo, log)
	svc.SetAuditService(auditSvc)

	_, err = svc.UpdateTenantModules(context.Background(), validTenantID(), updates, app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(auditRepo.logs) != 1 {
		t.Errorf("expected 1 audit log after setting audit service, got %d", len(auditRepo.logs))
	}
}

func TestModuleService_UpdateTenantModules_AuditFailureDoesNotBreakUpdate(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("reports", "Reports", true, false))

	tenantRepo := newModuleTenantMockRepo()
	auditRepo := newModuleAuditMockRepo()
	auditRepo.createErr = errors.New("audit db error")

	svc := newTestModuleServiceWithAudit(repo, tenantRepo, auditRepo)

	updates := []module.TenantModuleUpdate{
		{ModuleID: "reports", IsEnabled: false},
	}

	// Update should succeed even if audit logging fails
	result, err := svc.UpdateTenantModules(context.Background(), validTenantID(), updates, app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error (audit failure should not propagate), got: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
}

func TestModuleService_GetTenantEnabledModules_OnlyActiveModulesReturned(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("dashboard", "Dashboard", true, true))
	repo.addModule(makeInactiveModule("deprecated_mod", "Deprecated"))

	svc := newTestModuleServiceWithTenant(repo, newModuleTenantMockRepo())

	result, err := svc.GetTenantEnabledModules(context.Background(), validTenantID())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	// Inactive module should not appear
	for _, mod := range result.Modules {
		if mod.ID() == "deprecated_mod" {
			t.Error("inactive module should not be in enabled modules")
		}
	}
}

func TestModuleService_UpdateTenantModules_ReturnsUpdatedConfig(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("dashboard", "Dashboard", true, true))
	repo.addModule(makeModule("reports", "Reports", true, false))

	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	updates := []module.TenantModuleUpdate{
		{ModuleID: "reports", IsEnabled: true},
	}

	result, err := svc.UpdateTenantModules(context.Background(), validTenantID(), updates, app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Result should contain a valid config with summary
	if result.Summary.Total == 0 {
		t.Error("expected non-zero total in summary")
	}
}
