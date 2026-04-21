package module

import (
	auditapp "github.com/openctemio/api/internal/app/audit"
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/api/pkg/domain/audit"
	moduledom "github.com/openctemio/api/pkg/domain/module"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// ModuleRepository interface for module operations.
type ModuleRepository interface {
	ListAllModules(ctx context.Context) ([]*moduledom.Module, error)
	ListActiveModules(ctx context.Context) ([]*moduledom.Module, error)
	GetModuleByID(ctx context.Context, id string) (*moduledom.Module, error)
	GetSubModules(ctx context.Context, parentModuleID string) ([]*moduledom.Module, error)
	ListAllSubModules(ctx context.Context) (map[string][]*moduledom.Module, error)
}

// TenantModuleRepository interface for per-tenant module configuration.
type TenantModuleRepository interface {
	ListByTenant(ctx context.Context, tenantID shared.ID) ([]*moduledom.TenantModuleOverride, error)
	UpsertBatch(ctx context.Context, tenantID shared.ID, updates []moduledom.TenantModuleUpdate, updatedBy *shared.ID) error
	DeleteByTenant(ctx context.Context, tenantID shared.ID) error
}

// ModuleService handles module-related business operations.
type ModuleService struct {
	moduleRepo       ModuleRepository
	tenantModuleRepo TenantModuleRepository
	auditService     *auditapp.AuditService
	logger           *logger.Logger
}

// NewModuleService creates a new ModuleService.
func NewModuleService(moduleRepo ModuleRepository, log *logger.Logger) *ModuleService {
	return &ModuleService{
		moduleRepo: moduleRepo,
		logger:     log.With("service", "module"),
	}
}

// SetTenantModuleRepo sets the tenant module repository.
func (s *ModuleService) SetTenantModuleRepo(repo TenantModuleRepository) {
	s.tenantModuleRepo = repo
}

// SetAuditService sets the audit service for logging module changes.
func (s *ModuleService) SetAuditService(svc *auditapp.AuditService) {
	s.auditService = svc
}

// GetTenantEnabledModulesOutput represents the output for GetTenantEnabledModules.
type GetTenantEnabledModulesOutput struct {
	ModuleIDs  []string
	Modules    []*moduledom.Module
	SubModules map[string][]*moduledom.Module
}

// GetTenantEnabledModules returns all enabled modules for a tenant.
// Filters by tenant module overrides if configured.
// Optimized: 2 queries (modules + tenant_modules) instead of 3.
// Sub-modules are extracted from the same ListActiveModules result.
func (s *ModuleService) GetTenantEnabledModules(ctx context.Context, tenantID string) (*GetTenantEnabledModulesOutput, error) {
	allModules, err := s.moduleRepo.ListActiveModules(ctx)
	if err != nil {
		return nil, err
	}

	// Split into top-level and sub-modules from the same query result
	topLevel, subModulesByParent := splitModules(allModules)

	// Get tenant-specific overrides
	disabledModules := s.getTenantDisabledModules(ctx, tenantID)

	// Filter modules: exclude disabled (non-core) top-level modules
	enabledModules := make([]*moduledom.Module, 0, len(topLevel))
	for _, m := range topLevel {
		if disabledModules[m.ID()] && !m.IsCore() {
			continue
		}
		enabledModules = append(enabledModules, m)
	}

	moduleIDs := make([]string, 0, len(enabledModules))
	enabledSet := make(map[string]bool, len(enabledModules))
	for _, m := range enabledModules {
		moduleIDs = append(moduleIDs, m.ID())
		enabledSet[m.ID()] = true
	}

	// Include sub-modules for enabled parents, excluding individually disabled sub-modules
	subModules := make(map[string][]*moduledom.Module, len(subModulesByParent))
	for parentID, subs := range subModulesByParent {
		if enabledSet[parentID] {
			enabledSubs := make([]*moduledom.Module, 0, len(subs))
			for _, sub := range subs {
				if !disabledModules[sub.ID()] {
					enabledSubs = append(enabledSubs, sub)
					moduleIDs = append(moduleIDs, sub.ID())
				}
			}
			if len(enabledSubs) > 0 {
				subModules[parentID] = enabledSubs
			}
		}
	}

	return &GetTenantEnabledModulesOutput{
		ModuleIDs:  moduleIDs,
		Modules:    enabledModules,
		SubModules: subModules,
	}, nil
}

// TenantModuleConfigOutput represents the full module configuration for a tenant.
type TenantModuleConfigOutput struct {
	Modules []*TenantModuleInfo
	Summary TenantModuleSummary
}

// TenantModuleInfo combines module metadata with tenant-specific enabled state.
type TenantModuleInfo struct {
	Module     *moduledom.Module
	IsEnabled  bool
	SubModules []*SubModuleInfo
}

// SubModuleInfo combines sub-module metadata with tenant-specific enabled state.
type SubModuleInfo struct {
	Module    *moduledom.Module
	IsEnabled bool
}

// TenantModuleSummary provides counts of module states.
type TenantModuleSummary struct {
	Total    int
	Enabled  int
	Disabled int
	Core     int
}

// GetTenantModuleConfig returns the full module configuration for a tenant admin.
// Optimized: 2 queries (modules + tenant_modules) instead of 3.
func (s *ModuleService) GetTenantModuleConfig(ctx context.Context, tenantID string) (*TenantModuleConfigOutput, error) {
	allModules, err := s.moduleRepo.ListActiveModules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list modules: %w", err)
	}

	return s.buildTenantModuleConfig(ctx, tenantID, allModules)
}

// buildTenantModuleConfig builds the tenant module config from pre-loaded modules.
// Separated to allow reuse in UpdateTenantModules (avoids redundant ListActiveModules query).
func (s *ModuleService) buildTenantModuleConfig(ctx context.Context, tenantID string, allModules []*moduledom.Module) (*TenantModuleConfigOutput, error) {
	// Split into top-level and sub-modules from the same query result
	topLevel, subModulesByParent := splitModules(allModules)

	// Get tenant overrides
	disabledModules := s.getTenantDisabledModules(ctx, tenantID)

	// Build output: only top-level, user-facing modules
	var summary TenantModuleSummary
	modules := make([]*TenantModuleInfo, 0, len(topLevel))

	for _, m := range topLevel {
		// Skip internal/infrastructure modules not shown in sidebar
		if !moduledom.IsUserFacing(m.ID()) {
			continue
		}

		isEnabled := !disabledModules[m.ID()] || m.IsCore()

		// Build sub-module info with INDEPENDENT enabled states.
		// The admin UI needs the sub-module's OWN state (not combined with parent)
		// so that when parent is re-enabled, sub-module states are correctly preserved.
		// The frontend handles parent-off visual override via opacity + pointer-events-none.
		var subInfos []*SubModuleInfo
		if subs, ok := subModulesByParent[m.ID()]; ok {
			subInfos = make([]*SubModuleInfo, 0, len(subs))
			for _, sub := range subs {
				subEnabled := !disabledModules[sub.ID()]
				subInfos = append(subInfos, &SubModuleInfo{
					Module:    sub,
					IsEnabled: subEnabled,
				})
			}
		}

		modules = append(modules, &TenantModuleInfo{
			Module:     m,
			IsEnabled:  isEnabled,
			SubModules: subInfos,
		})

		summary.Total++
		if isEnabled {
			summary.Enabled++
		} else {
			summary.Disabled++
		}
		if m.IsCore() {
			summary.Core++
		}
	}

	return &TenantModuleConfigOutput{
		Modules: modules,
		Summary: summary,
	}, nil
}

// maxModuleUpdatesPerRequest limits batch size to prevent abuse.
const maxModuleUpdatesPerRequest = 50

// UpdateTenantModules toggles modules for a tenant.
func (s *ModuleService) UpdateTenantModules(ctx context.Context, tenantID string, updates []moduledom.TenantModuleUpdate, actx auditapp.AuditContext) (*TenantModuleConfigOutput, error) {
	if s.tenantModuleRepo == nil {
		return nil, fmt.Errorf("%w: tenant module management not configured", shared.ErrInternal)
	}

	if len(updates) > maxModuleUpdatesPerRequest {
		return nil, fmt.Errorf("%w: too many module updates (max %d)", shared.ErrValidation, maxModuleUpdatesPerRequest)
	}

	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	// Pre-load all active modules into a map to avoid N individual GetModuleByID queries
	allModules, loadErr := s.moduleRepo.ListActiveModules(ctx)
	if loadErr != nil {
		return nil, fmt.Errorf("failed to load modules for validation: %w", loadErr)
	}
	moduleMap := make(map[string]*moduledom.Module, len(allModules))
	for _, m := range allModules {
		moduleMap[m.ID()] = m
	}

	// Validate all module IDs against pre-loaded map (0 additional queries)
	var disabledNames, enabledNames []string
	for _, u := range updates {
		m, exists := moduleMap[u.ModuleID]
		if !exists {
			return nil, fmt.Errorf("%w: unknown module: %s", shared.ErrValidation, u.ModuleID)
		}

		if !m.IsActive() {
			return nil, fmt.Errorf("%w: module '%s' is not available", moduledom.ErrModuleNotAvailable, u.ModuleID)
		}

		if !u.IsEnabled && m.IsCore() {
			return nil, fmt.Errorf("%w: '%s' is a core module and cannot be disabled", moduledom.ErrCoreModuleCannotBeDisabled, m.Name())
		}

		if u.IsEnabled {
			enabledNames = append(enabledNames, m.Name())
		} else {
			disabledNames = append(disabledNames, m.Name())
		}
	}

	// Parse updatedBy from audit context
	var updatedBy *shared.ID
	if actx.ActorID != "" {
		uid, uidErr := shared.IDFromString(actx.ActorID)
		if uidErr == nil {
			updatedBy = &uid
		}
	}

	// Upsert
	if err := s.tenantModuleRepo.UpsertBatch(ctx, parsedTenantID, updates, updatedBy); err != nil {
		return nil, fmt.Errorf("failed to update tenant modules: %w", err)
	}

	// Audit log
	s.logModuleAudit(ctx, actx, tenantID, enabledNames, disabledNames)

	// Reuse pre-loaded modules to avoid redundant ListActiveModules query
	return s.buildTenantModuleConfig(ctx, tenantID, allModules)
}

// ResetTenantModules resets all module overrides for a tenant (all modules enabled).
func (s *ModuleService) ResetTenantModules(ctx context.Context, tenantID string, actx auditapp.AuditContext) (*TenantModuleConfigOutput, error) {
	if s.tenantModuleRepo == nil {
		return nil, fmt.Errorf("%w: tenant module management not configured", shared.ErrInternal)
	}

	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	if err := s.tenantModuleRepo.DeleteByTenant(ctx, parsedTenantID); err != nil {
		return nil, fmt.Errorf("failed to reset tenant modules: %w", err)
	}

	// Audit log
	s.logModuleAudit(ctx, actx, tenantID, nil, nil)

	return s.GetTenantModuleConfig(ctx, tenantID)
}

func (s *ModuleService) logModuleAudit(ctx context.Context, actx auditapp.AuditContext, tenantID string, enabled, disabled []string) {
	if s.auditService == nil {
		return
	}

	actx.TenantID = tenantID

	var msgParts []string
	if len(enabled) > 0 {
		msgParts = append(msgParts, "enabled "+strings.Join(enabled, ", "))
	}
	if len(disabled) > 0 {
		msgParts = append(msgParts, "disabled "+strings.Join(disabled, ", "))
	}

	var msg string
	if len(msgParts) > 0 {
		msg = "Modules updated: " + strings.Join(msgParts, "; ")
	} else {
		msg = "Modules reset to defaults"
	}

	event := auditapp.NewSuccessEvent(audit.ActionTenantModulesUpdated, audit.ResourceTypeTenant, tenantID).
		WithMessage(msg).
		WithSeverity(audit.SeverityMedium)

	if len(enabled) > 0 {
		event = event.WithMetadata("enabled", strings.Join(enabled, ", "))
	}
	if len(disabled) > 0 {
		event = event.WithMetadata("disabled", strings.Join(disabled, ", "))
	}

	if err := s.auditService.LogEvent(ctx, actx, event); err != nil {
		s.logger.Error("failed to log module audit event", "error", err)
	}
}

// splitModules separates a flat list of modules into top-level modules
// and sub-modules grouped by parent ID. This avoids a separate DB query
// since ListActiveModules already returns both.
func splitModules(allModules []*moduledom.Module) ([]*moduledom.Module, map[string][]*moduledom.Module) {
	topLevel := make([]*moduledom.Module, 0, len(allModules))
	subByParent := make(map[string][]*moduledom.Module)

	for _, m := range allModules {
		if m.IsSubModule() {
			parentID := *m.ParentModuleID()
			subByParent[parentID] = append(subByParent[parentID], m)
		} else {
			topLevel = append(topLevel, m)
		}
	}

	return topLevel, subByParent
}

// getTenantDisabledModules returns a set of module IDs disabled by the tenant.
func (s *ModuleService) getTenantDisabledModules(ctx context.Context, tenantID string) map[string]bool {
	disabled := make(map[string]bool)
	if s.tenantModuleRepo == nil {
		return disabled
	}

	parsedID, parseErr := shared.IDFromString(tenantID)
	if parseErr != nil {
		return disabled
	}

	overrides, err := s.tenantModuleRepo.ListByTenant(ctx, parsedID)
	if err != nil {
		s.logger.Warn("failed to get tenant module overrides", "tenant_id", tenantID, "error", err)
		return disabled
	}

	for _, o := range overrides {
		if !o.IsEnabled {
			disabled[o.ModuleID] = true
		}
	}
	return disabled
}

// ListActiveModules returns all active modules.
func (s *ModuleService) ListActiveModules(ctx context.Context) ([]*moduledom.Module, error) {
	return s.moduleRepo.ListActiveModules(ctx)
}

// GetModule retrieves a module by ID.
func (s *ModuleService) GetModule(ctx context.Context, moduleID string) (*moduledom.Module, error) {
	return s.moduleRepo.GetModuleByID(ctx, moduleID)
}
