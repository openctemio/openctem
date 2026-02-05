package app

import (
	"context"

	"github.com/openctemio/api/pkg/domain/module"
	"github.com/openctemio/api/pkg/logger"
)

// ModuleRepository interface for module operations.
type ModuleRepository interface {
	ListAllModules(ctx context.Context) ([]*module.Module, error)
	ListActiveModules(ctx context.Context) ([]*module.Module, error)
	GetModuleByID(ctx context.Context, id string) (*module.Module, error)
	GetSubModules(ctx context.Context, parentModuleID string) ([]*module.Module, error)
}

// ModuleService handles module-related business operations.
// OSS Edition: All modules are always enabled, no subscription/licensing checks.
type ModuleService struct {
	moduleRepo ModuleRepository
	logger     *logger.Logger
}

// NewModuleService creates a new ModuleService.
func NewModuleService(moduleRepo ModuleRepository, log *logger.Logger) *ModuleService {
	return &ModuleService{
		moduleRepo: moduleRepo,
		logger:     log.With("service", "module"),
	}
}

// TenantHasModule checks if a tenant has access to a specific module.
// OSS Edition: Always returns true (all modules enabled).
func (s *ModuleService) TenantHasModule(ctx context.Context, tenantID, moduleID string) (bool, error) {
	return true, nil
}

// TenantHasSubModule checks if a tenant has access to a specific sub-module.
// OSS Edition: Always returns true (all modules enabled).
func (s *ModuleService) TenantHasSubModule(ctx context.Context, tenantID, parentModuleID, subModuleID string) (bool, error) {
	return true, nil
}

// GetModuleLimitOutput represents the output for GetTenantModuleLimit.
type GetModuleLimitOutput struct {
	Limit     int64
	Unlimited bool
}

// GetTenantModuleLimit returns the limit for a specific module metric.
// OSS Edition: Always returns unlimited.
func (s *ModuleService) GetTenantModuleLimit(ctx context.Context, tenantID, moduleID, metric string) (*GetModuleLimitOutput, error) {
	return &GetModuleLimitOutput{
		Limit:     -1,
		Unlimited: true,
	}, nil
}

// GetTenantEnabledModulesOutput represents the output for GetTenantEnabledModules.
type GetTenantEnabledModulesOutput struct {
	ModuleIDs  []string
	Modules    []*module.Module
	SubModules map[string][]*module.Module
}

// GetTenantEnabledModules returns all enabled modules for a tenant.
// OSS Edition: Returns all active modules from the database.
func (s *ModuleService) GetTenantEnabledModules(ctx context.Context, tenantID string) (*GetTenantEnabledModulesOutput, error) {
	modules, err := s.moduleRepo.ListActiveModules(ctx)
	if err != nil {
		return nil, err
	}

	moduleIDs := make([]string, len(modules))
	for i, m := range modules {
		moduleIDs[i] = m.ID()
	}

	// Get sub-modules for each parent module
	subModules := make(map[string][]*module.Module)
	for _, m := range modules {
		subs, err := s.moduleRepo.GetSubModules(ctx, m.ID())
		if err != nil {
			s.logger.Warn("failed to get sub-modules", "module_id", m.ID(), "error", err)
			continue
		}
		if len(subs) > 0 {
			subModules[m.ID()] = subs
		}
	}

	return &GetTenantEnabledModulesOutput{
		ModuleIDs:  moduleIDs,
		Modules:    modules,
		SubModules: subModules,
	}, nil
}

// ListActiveModules returns all active modules.
func (s *ModuleService) ListActiveModules(ctx context.Context) ([]*module.Module, error) {
	return s.moduleRepo.ListActiveModules(ctx)
}

// GetModule retrieves a module by ID.
func (s *ModuleService) GetModule(ctx context.Context, moduleID string) (*module.Module, error) {
	return s.moduleRepo.GetModuleByID(ctx, moduleID)
}
