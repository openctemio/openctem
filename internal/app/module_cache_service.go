package app

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/openctemio/api/internal/infra/redis"
	"github.com/openctemio/api/pkg/domain/module"
	"github.com/openctemio/api/pkg/logger"
)

// ModuleCacheRepository defines the repository methods needed by ModuleCacheService.
type ModuleCacheRepository interface {
	GetPlanModulesByTenantID(ctx context.Context, tenantID uuid.UUID) ([]string, error)
	GetModulesByIDs(ctx context.Context, ids []string) ([]*module.Module, error)
	GetEventTypesForModulesBatch(ctx context.Context, moduleIDs []string) (map[string][]string, error)
	GetSubModulesForParents(ctx context.Context, parentModuleIDs []string) (map[string][]*module.Module, error)
}

// ModuleCacheService provides cached access to tenant modules.
// Modules are cached in Redis with a short TTL for performance.
// On cache miss, modules are fetched from the database.
//
// Key format: tenant_modules:{tenant_id} → JSON array of module data
// Cache is invalidated when tenant's module configuration changes.
type ModuleCacheService struct {
	cache  *redis.Cache[CachedTenantModules]
	repo   ModuleCacheRepository
	logger *logger.Logger
}

const (
	moduleCachePrefix = "tenant_modules"
	moduleCacheTTL    = 5 * time.Minute
)

// CachedTenantModules represents the cached module data for a tenant.
type CachedTenantModules struct {
	ModuleIDs  []string                   `json:"module_ids"`
	Modules    []*CachedModule            `json:"modules"`
	SubModules map[string][]*CachedModule `json:"sub_modules,omitempty"`
	EventTypes map[string][]string        `json:"event_types,omitempty"` // module_id -> event_types
	CachedAt   time.Time                  `json:"cached_at"`
}

// CachedModule represents a module in the cache.
type CachedModule struct {
	ID             string   `json:"id"`
	Slug           string   `json:"slug"`
	Name           string   `json:"name"`
	Description    string   `json:"description,omitempty"`
	Icon           string   `json:"icon,omitempty"`
	Category       string   `json:"category"`
	DisplayOrder   int      `json:"display_order"`
	IsActive       bool     `json:"is_active"`
	ReleaseStatus  string   `json:"release_status"`
	ParentModuleID *string  `json:"parent_module_id,omitempty"`
	EventTypes     []string `json:"event_types,omitempty"`
}

// NewModuleCacheService creates a new module cache service.
func NewModuleCacheService(
	redisClient *redis.Client,
	repo ModuleCacheRepository,
	log *logger.Logger,
) (*ModuleCacheService, error) {
	cache, err := redis.NewCache[CachedTenantModules](redisClient, moduleCachePrefix, moduleCacheTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to create module cache: %w", err)
	}

	return &ModuleCacheService{
		cache:  cache,
		repo:   repo,
		logger: log.With("service", "module_cache"),
	}, nil
}

// GetTenantModules returns the cached modules for a tenant.
// Uses TTL-based caching (5 min) + explicit invalidation on plan changes.
// No extra DB queries on cache hit - relies on:
// 1. TTL expiration for natural refresh
// 2. Explicit Invalidate() call when module configuration changes (see ModuleService.UpdateTenantModules)
func (s *ModuleCacheService) GetTenantModules(ctx context.Context, tenantID string) (*CachedTenantModules, error) {
	if tenantID == "" {
		return &CachedTenantModules{
			ModuleIDs:  []string{},
			Modules:    []*CachedModule{},
			SubModules: make(map[string][]*CachedModule),
		}, nil
	}

	// Try cache first - no version check needed, rely on TTL + explicit invalidation
	cached, cacheErr := s.cache.Get(ctx, tenantID)
	if cacheErr == nil && cached != nil {
		s.logger.Debug("module cache hit",
			"tenant_id", tenantID,
			"cached_at", cached.CachedAt,
		)
		return cached, nil
	}

	// Cache miss - load from database
	result, err := s.loadFromDatabase(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant modules: %w", err)
	}

	// Store in cache (ignore errors - degraded mode is acceptable)
	if cacheSetErr := s.cache.Set(ctx, tenantID, *result); cacheSetErr != nil {
		s.logger.Warn("failed to cache tenant modules",
			"tenant_id", tenantID,
			"error", cacheSetErr,
		)
	}

	return result, nil
}

// loadFromDatabase fetches tenant modules from the database.
func (s *ModuleCacheService) loadFromDatabase(ctx context.Context, tenantID string) (*CachedTenantModules, error) {
	tid, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant id: %w", err)
	}

	// Get module IDs from tenant's plan
	moduleIDs, err := s.repo.GetPlanModulesByTenantID(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("failed to get plan modules: %w", err)
	}

	if len(moduleIDs) == 0 {
		return &CachedTenantModules{
			ModuleIDs:  []string{},
			Modules:    []*CachedModule{},
			SubModules: make(map[string][]*CachedModule),
			CachedAt:   time.Now(),
		}, nil
	}

	// Batch fetch top-level modules
	modules, err := s.repo.GetModulesByIDs(ctx, moduleIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to get modules: %w", err)
	}

	// Fetch sub-modules for all parent modules (only active sub-modules)
	subModulesFromDB, err := s.repo.GetSubModulesForParents(ctx, moduleIDs)
	if err != nil {
		s.logger.Warn("failed to get sub-modules", "error", err)
		subModulesFromDB = make(map[string][]*module.Module)
	}

	// Collect all module IDs for batch event types fetch
	allModuleIDs := make([]string, 0, len(moduleIDs))
	allModuleIDs = append(allModuleIDs, moduleIDs...)
	for _, subs := range subModulesFromDB {
		for _, sm := range subs {
			allModuleIDs = append(allModuleIDs, sm.ID())
		}
	}

	// Batch fetch event types for all modules
	eventTypesMap, err := s.repo.GetEventTypesForModulesBatch(ctx, allModuleIDs)
	if err != nil {
		s.logger.Warn("failed to get event types", "error", err)
		eventTypesMap = make(map[string][]string)
	}

	// Build top-level modules list (only active top-level modules)
	topLevelModules := make([]*CachedModule, 0)
	activeModuleIDs := make([]string, 0, len(modules))
	for _, m := range modules {
		if !m.IsActive() {
			continue
		}
		activeModuleIDs = append(activeModuleIDs, m.ID())
		topLevelModules = append(topLevelModules, &CachedModule{
			ID:             m.ID(),
			Slug:           m.Slug(),
			Name:           m.Name(),
			Description:    m.Description(),
			Icon:           m.Icon(),
			Category:       m.Category(),
			DisplayOrder:   m.DisplayOrder(),
			IsActive:       m.IsActive(),
			ReleaseStatus:  string(m.ReleaseStatus()),
			ParentModuleID: m.ParentModuleID(),
			EventTypes:     eventTypesMap[m.ID()],
		})
	}

	// Build sub-modules map (sub-modules already filtered by is_active=true in DB query)
	subModulesMap := make(map[string][]*CachedModule)
	for parentID, subs := range subModulesFromDB {
		subModulesMap[parentID] = make([]*CachedModule, 0, len(subs))
		for _, sm := range subs {
			activeModuleIDs = append(activeModuleIDs, sm.ID())
			subModulesMap[parentID] = append(subModulesMap[parentID], &CachedModule{
				ID:             sm.ID(),
				Slug:           sm.Slug(),
				Name:           sm.Name(),
				Description:    sm.Description(),
				Icon:           sm.Icon(),
				Category:       sm.Category(),
				DisplayOrder:   sm.DisplayOrder(),
				IsActive:       sm.IsActive(),
				ReleaseStatus:  string(sm.ReleaseStatus()),
				ParentModuleID: sm.ParentModuleID(),
				EventTypes:     eventTypesMap[sm.ID()],
			})
		}
	}

	return &CachedTenantModules{
		ModuleIDs:  activeModuleIDs,
		Modules:    topLevelModules,
		SubModules: subModulesMap,
		EventTypes: eventTypesMap,
		CachedAt:   time.Now(),
	}, nil
}

// Invalidate removes the cached modules for a tenant.
// Called when tenant's module configuration changes.
// Returns error if cache invalidation fails after retries.
// Callers should log errors but typically should not fail the operation
// since DB transaction has already committed.
func (s *ModuleCacheService) Invalidate(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return nil
	}

	// Simple retry logic: try up to 3 times with small delays
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if err := s.cache.Delete(ctx, tenantID); err != nil {
			lastErr = err
			s.logger.Warn("failed to invalidate module cache",
				"tenant_id", tenantID,
				"attempt", attempt,
				"error", err,
			)
			// Short delay before retry (only if not last attempt)
			if attempt < 3 {
				time.Sleep(time.Duration(attempt*50) * time.Millisecond)
			}
			continue
		}
		// Success
		s.logger.Debug("module cache invalidated",
			"tenant_id", tenantID,
			"attempt", attempt,
		)
		return nil
	}

	return fmt.Errorf("failed to invalidate module cache after 3 attempts: %w", lastErr)
}

// InvalidateAll removes cached modules for all tenants.
// Called when global module configuration changes.
func (s *ModuleCacheService) InvalidateAll(ctx context.Context) {
	pattern := "*"
	if err := s.cache.DeletePattern(ctx, pattern); err != nil {
		s.logger.Warn("failed to invalidate all module caches",
			"error", err,
		)
	} else {
		s.logger.Info("all module caches invalidated")
	}
}

// HasModule checks if a tenant has access to a specific module (using cache).
func (s *ModuleCacheService) HasModule(ctx context.Context, tenantID, moduleID string) (bool, error) {
	cached, err := s.GetTenantModules(ctx, tenantID)
	if err != nil {
		return false, err
	}

	for _, id := range cached.ModuleIDs {
		if id == moduleID {
			return true, nil
		}
	}

	return false, nil
}

// HasSubModule checks if a tenant has access to a specific sub-module (using cache).
func (s *ModuleCacheService) HasSubModule(ctx context.Context, tenantID, parentModuleID, fullSubModuleID string) (bool, error) {
	cached, err := s.GetTenantModules(ctx, tenantID)
	if err != nil {
		return false, err
	}

	// Check if parent module is enabled
	parentFound := false
	for _, id := range cached.ModuleIDs {
		if id == parentModuleID {
			parentFound = true
			break
		}
	}
	if !parentFound {
		return false, nil
	}

	// Check if sub-module is enabled
	subModules, ok := cached.SubModules[parentModuleID]
	if !ok {
		return false, nil
	}

	for _, sm := range subModules {
		if sm.ID == fullSubModuleID {
			// Check release status - only released and beta are accessible
			return sm.ReleaseStatus == "released" || sm.ReleaseStatus == "beta", nil
		}
	}

	return false, nil
}

// Refresh refreshes the cached modules for a tenant.
// Forces a database fetch and updates the cache.
func (s *ModuleCacheService) Refresh(ctx context.Context, tenantID string) (*CachedTenantModules, error) {
	// Invalidate first - log error but continue (we'll overwrite cache anyway)
	if err := s.Invalidate(ctx, tenantID); err != nil {
		s.logger.Warn("refresh: invalidate failed, continuing",
			"tenant_id", tenantID,
			"error", err,
		)
	}

	// Then fetch fresh
	return s.GetTenantModules(ctx, tenantID)
}

// ToModules converts cached modules to domain modules.
func (c *CachedTenantModules) ToModules() []*module.Module {
	modules := make([]*module.Module, 0, len(c.Modules))
	for _, m := range c.Modules {
		modules = append(modules, module.ReconstructModule(
			m.ID,
			m.Slug,
			m.Name,
			m.Description,
			m.Icon,
			m.Category,
			m.DisplayOrder,
			m.IsActive,
			m.ReleaseStatus,
			m.ParentModuleID,
			m.EventTypes,
		))
	}
	return modules
}

// ToSubModules converts cached sub-modules to domain modules map.
func (c *CachedTenantModules) ToSubModulesMap() map[string][]*module.Module {
	subModulesMap := make(map[string][]*module.Module)
	for parentID, subs := range c.SubModules {
		subModulesMap[parentID] = make([]*module.Module, 0, len(subs))
		for _, m := range subs {
			subModulesMap[parentID] = append(subModulesMap[parentID], module.ReconstructModule(
				m.ID,
				m.Slug,
				m.Name,
				m.Description,
				m.Icon,
				m.Category,
				m.DisplayOrder,
				m.IsActive,
				m.ReleaseStatus,
				m.ParentModuleID,
				m.EventTypes,
			))
		}
	}
	return subModulesMap
}
