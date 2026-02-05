package app

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/internal/infra/redis"
	"github.com/openctemio/api/pkg/domain/findingsource"
	"github.com/openctemio/api/pkg/logger"
)

// FindingSourceCacheService provides cached access to finding sources.
// Finding sources are system-level configuration that rarely changes,
// making them ideal candidates for aggressive caching.
//
// Cache structure:
// - Key: "finding_sources:all" → CachedFindingSources (all sources with categories)
// - Key: "finding_sources:code:{code}" → single source (optional, for high-frequency lookups)
//
// Cache invalidation:
// - Manual via InvalidateAll() when sources are modified (rare)
// - TTL-based expiration (24 hours)
//
// This cache is GLOBAL (not per-tenant) because finding sources are system configuration.
type FindingSourceCacheService struct {
	cache  *redis.Cache[CachedFindingSources]
	repo   findingsource.Repository
	logger *logger.Logger
}

const (
	findingSourceCachePrefix = "finding_sources"
	findingSourceCacheTTL    = 24 * time.Hour
	findingSourceAllKey      = "all" // Cache key for all active sources
)

// CachedFindingSources represents the cached finding source data.
type CachedFindingSources struct {
	Sources    []*CachedFindingSource `json:"sources"`
	Categories []*CachedCategory      `json:"categories"`
	ByCode     map[string]int         `json:"by_code"`     // code -> index in Sources for O(1) lookup
	ByCategory map[string][]int       `json:"by_category"` // category_code -> indices in Sources
	CachedAt   time.Time              `json:"cached_at"`
}

// CachedFindingSource represents a finding source in the cache.
type CachedFindingSource struct {
	ID           string `json:"id"`
	Code         string `json:"code"`
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"`
	CategoryID   string `json:"category_id,omitempty"`
	CategoryCode string `json:"category_code,omitempty"`
	CategoryName string `json:"category_name,omitempty"`
	Icon         string `json:"icon,omitempty"`
	Color        string `json:"color,omitempty"`
	DisplayOrder int    `json:"display_order"`
	IsSystem     bool   `json:"is_system"`
}

// CachedCategory represents a category in the cache.
type CachedCategory struct {
	ID           string `json:"id"`
	Code         string `json:"code"`
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"`
	Icon         string `json:"icon,omitempty"`
	DisplayOrder int    `json:"display_order"`
}

// NewFindingSourceCacheService creates a new finding source cache service.
func NewFindingSourceCacheService(
	redisClient *redis.Client,
	repo findingsource.Repository,
	log *logger.Logger,
) (*FindingSourceCacheService, error) {
	if redisClient == nil {
		// Return a service that works without cache (graceful degradation)
		return &FindingSourceCacheService{
			cache:  nil,
			repo:   repo,
			logger: log.With("service", "finding_source_cache"),
		}, nil
	}

	cache, err := redis.NewCache[CachedFindingSources](redisClient, findingSourceCachePrefix, findingSourceCacheTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to create finding source cache: %w", err)
	}

	return &FindingSourceCacheService{
		cache:  cache,
		repo:   repo,
		logger: log.With("service", "finding_source_cache"),
	}, nil
}

// GetAll returns all active finding sources with their categories (cached).
// This is the primary method for UI dropdowns and validation.
func (s *FindingSourceCacheService) GetAll(ctx context.Context) (*CachedFindingSources, error) {
	// If cache is disabled, fetch directly from database
	if s.cache == nil {
		return s.loadFromDatabase(ctx)
	}

	// Try cache first
	cached, err := s.cache.Get(ctx, findingSourceAllKey)
	if err == nil && cached != nil {
		s.logger.Debug("finding source cache hit",
			"sources_count", len(cached.Sources),
			"cached_at", cached.CachedAt,
		)
		return cached, nil
	}

	// Cache miss - load from database
	s.logger.Debug("finding source cache miss, loading from database")
	result, err := s.loadFromDatabase(ctx)
	if err != nil {
		return nil, err
	}

	// Store in cache (ignore errors - graceful degradation)
	if cacheErr := s.cache.Set(ctx, findingSourceAllKey, *result); cacheErr != nil {
		s.logger.Warn("failed to cache finding sources", "error", cacheErr)
	}

	return result, nil
}

// GetByCode returns a finding source by code (from cache).
// Returns nil if not found.
func (s *FindingSourceCacheService) GetByCode(ctx context.Context, code string) (*CachedFindingSource, error) {
	all, err := s.GetAll(ctx)
	if err != nil {
		return nil, err
	}

	idx, ok := all.ByCode[code]
	if !ok {
		return nil, nil
	}

	return all.Sources[idx], nil
}

// IsValidCode checks if a code is a valid active finding source (from cache).
func (s *FindingSourceCacheService) IsValidCode(ctx context.Context, code string) (bool, error) {
	all, err := s.GetAll(ctx)
	if err != nil {
		return false, err
	}

	_, ok := all.ByCode[code]
	return ok, nil
}

// GetByCategory returns finding sources filtered by category code (from cache).
func (s *FindingSourceCacheService) GetByCategory(ctx context.Context, categoryCode string) ([]*CachedFindingSource, error) {
	all, err := s.GetAll(ctx)
	if err != nil {
		return nil, err
	}

	indices, ok := all.ByCategory[categoryCode]
	if !ok {
		return []*CachedFindingSource{}, nil
	}

	sources := make([]*CachedFindingSource, len(indices))
	for i, idx := range indices {
		sources[i] = all.Sources[idx]
	}
	return sources, nil
}

// GetCategories returns all active categories (from cache).
func (s *FindingSourceCacheService) GetCategories(ctx context.Context) ([]*CachedCategory, error) {
	all, err := s.GetAll(ctx)
	if err != nil {
		return nil, err
	}
	return all.Categories, nil
}

// InvalidateAll removes all cached finding source data.
// Call this when finding sources are modified (rare operation).
func (s *FindingSourceCacheService) InvalidateAll(ctx context.Context) error {
	if s.cache == nil {
		return nil
	}

	if err := s.cache.Delete(ctx, findingSourceAllKey); err != nil {
		s.logger.Warn("failed to invalidate finding source cache", "error", err)
		return err
	}

	s.logger.Info("finding source cache invalidated")
	return nil
}

// Refresh forces a cache refresh by invalidating and reloading.
func (s *FindingSourceCacheService) Refresh(ctx context.Context) (*CachedFindingSources, error) {
	if err := s.InvalidateAll(ctx); err != nil {
		s.logger.Warn("refresh: invalidate failed, continuing", "error", err)
	}
	return s.GetAll(ctx)
}

// loadFromDatabase fetches all active finding sources with categories from the database.
func (s *FindingSourceCacheService) loadFromDatabase(ctx context.Context) (*CachedFindingSources, error) {
	sourcesWithCategory, err := s.repo.ListActiveWithCategory(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load finding sources: %w", err)
	}

	// Build cached data structure
	sources := make([]*CachedFindingSource, 0, len(sourcesWithCategory))
	byCode := make(map[string]int)
	byCategory := make(map[string][]int)
	categoriesMap := make(map[string]*CachedCategory)

	for i, fsc := range sourcesWithCategory {
		fs := fsc.FindingSource
		cat := fsc.Category

		cachedSource := &CachedFindingSource{
			ID:           fs.ID().String(),
			Code:         fs.Code(),
			Name:         fs.Name(),
			Description:  fs.Description(),
			Icon:         fs.Icon(),
			Color:        fs.Color(),
			DisplayOrder: fs.DisplayOrder(),
			IsSystem:     fs.IsSystem(),
		}

		if fs.CategoryID() != nil {
			cachedSource.CategoryID = fs.CategoryID().String()
		}

		categoryCode := "other"
		if cat != nil {
			cachedSource.CategoryCode = cat.Code()
			cachedSource.CategoryName = cat.Name()
			categoryCode = cat.Code()

			// Track unique categories
			if _, exists := categoriesMap[cat.Code()]; !exists {
				categoriesMap[cat.Code()] = &CachedCategory{
					ID:           cat.ID().String(),
					Code:         cat.Code(),
					Name:         cat.Name(),
					Description:  cat.Description(),
					Icon:         cat.Icon(),
					DisplayOrder: cat.DisplayOrder(),
				}
			}
		}

		sources = append(sources, cachedSource)
		byCode[fs.Code()] = i
		byCategory[categoryCode] = append(byCategory[categoryCode], i)
	}

	// Convert categories map to slice
	categories := make([]*CachedCategory, 0, len(categoriesMap))
	for _, cat := range categoriesMap {
		categories = append(categories, cat)
	}

	return &CachedFindingSources{
		Sources:    sources,
		Categories: categories,
		ByCode:     byCode,
		ByCategory: byCategory,
		CachedAt:   time.Now(),
	}, nil
}

// WarmCache preloads the cache on startup.
// Call this during application initialization.
func (s *FindingSourceCacheService) WarmCache(ctx context.Context) error {
	_, err := s.GetAll(ctx)
	if err != nil {
		return fmt.Errorf("failed to warm finding source cache: %w", err)
	}
	s.logger.Info("finding source cache warmed")
	return nil
}
