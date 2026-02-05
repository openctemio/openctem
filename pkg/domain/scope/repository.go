package scope

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Target Repository
// =============================================================================

// TargetRepository defines the interface for scope target persistence.
type TargetRepository interface {
	// Create persists a new scope target.
	Create(ctx context.Context, target *Target) error

	// GetByID retrieves a scope target by its ID.
	GetByID(ctx context.Context, id shared.ID) (*Target, error)

	// Update updates an existing scope target.
	Update(ctx context.Context, target *Target) error

	// Delete removes a scope target by its ID.
	Delete(ctx context.Context, id shared.ID) error

	// List retrieves scope targets with filtering and pagination.
	List(ctx context.Context, filter TargetFilter, page pagination.Pagination) (pagination.Result[*Target], error)

	// ListActive retrieves all active scope targets for a tenant.
	ListActive(ctx context.Context, tenantID shared.ID) ([]*Target, error)

	// Count returns the total number of scope targets matching the filter.
	Count(ctx context.Context, filter TargetFilter) (int64, error)

	// ExistsByPattern checks if a target with the given pattern exists.
	ExistsByPattern(ctx context.Context, tenantID shared.ID, targetType TargetType, pattern string) (bool, error)
}

// TargetFilter defines the filtering options for listing targets.
type TargetFilter struct {
	TenantID    *string
	TargetTypes []TargetType
	Statuses    []Status
	Tags        []string
	Search      *string
}

// =============================================================================
// Exclusion Repository
// =============================================================================

// ExclusionRepository defines the interface for scope exclusion persistence.
type ExclusionRepository interface {
	// Create persists a new scope exclusion.
	Create(ctx context.Context, exclusion *Exclusion) error

	// GetByID retrieves a scope exclusion by its ID.
	GetByID(ctx context.Context, id shared.ID) (*Exclusion, error)

	// Update updates an existing scope exclusion.
	Update(ctx context.Context, exclusion *Exclusion) error

	// Delete removes a scope exclusion by its ID.
	Delete(ctx context.Context, id shared.ID) error

	// List retrieves scope exclusions with filtering and pagination.
	List(ctx context.Context, filter ExclusionFilter, page pagination.Pagination) (pagination.Result[*Exclusion], error)

	// ListActive retrieves all active scope exclusions for a tenant.
	ListActive(ctx context.Context, tenantID shared.ID) ([]*Exclusion, error)

	// Count returns the total number of scope exclusions matching the filter.
	Count(ctx context.Context, filter ExclusionFilter) (int64, error)

	// ExpireOld marks expired exclusions as expired.
	ExpireOld(ctx context.Context) error
}

// ExclusionFilter defines the filtering options for listing exclusions.
type ExclusionFilter struct {
	TenantID       *string
	ExclusionTypes []ExclusionType
	Statuses       []Status
	IsApproved     *bool
	Search         *string
}

// =============================================================================
// Schedule Repository
// =============================================================================

// ScheduleRepository defines the interface for scan schedule persistence.
type ScheduleRepository interface {
	// Create persists a new scan schedule.
	Create(ctx context.Context, schedule *Schedule) error

	// GetByID retrieves a scan schedule by its ID.
	GetByID(ctx context.Context, id shared.ID) (*Schedule, error)

	// Update updates an existing scan schedule.
	Update(ctx context.Context, schedule *Schedule) error

	// Delete removes a scan schedule by its ID.
	Delete(ctx context.Context, id shared.ID) error

	// List retrieves scan schedules with filtering and pagination.
	List(ctx context.Context, filter ScheduleFilter, page pagination.Pagination) (pagination.Result[*Schedule], error)

	// ListDue retrieves all enabled schedules that are due to run.
	ListDue(ctx context.Context) ([]*Schedule, error)

	// Count returns the total number of scan schedules matching the filter.
	Count(ctx context.Context, filter ScheduleFilter) (int64, error)
}

// ScheduleFilter defines the filtering options for listing schedules.
type ScheduleFilter struct {
	TenantID      *string
	ScanTypes     []ScanType
	ScheduleTypes []ScheduleType
	Enabled       *bool
	Search        *string
}

// =============================================================================
// List Options
// =============================================================================

// ListOptions contains common options for listing (sorting).
type ListOptions struct {
	Sort *pagination.SortOption
}

// NewListOptions creates empty list options.
func NewListOptions() ListOptions {
	return ListOptions{}
}

// WithSort adds sorting options.
func (o ListOptions) WithSort(sort *pagination.SortOption) ListOptions {
	o.Sort = sort
	return o
}

// =============================================================================
// Stats Types
// =============================================================================

// Stats represents scope configuration statistics.
type Stats struct {
	TotalTargets     int64   `json:"total_targets"`
	ActiveTargets    int64   `json:"active_targets"`
	TotalExclusions  int64   `json:"total_exclusions"`
	ActiveExclusions int64   `json:"active_exclusions"`
	TotalSchedules   int64   `json:"total_schedules"`
	EnabledSchedules int64   `json:"enabled_schedules"`
	Coverage         float64 `json:"coverage"`
}

// Coverage represents scope coverage breakdown.
type Coverage struct {
	TotalAssets    int64                   `json:"total_assets"`
	InScopeAssets  int64                   `json:"in_scope_assets"`
	ExcludedAssets int64                   `json:"excluded_assets"`
	Percentage     float64                 `json:"percentage"`
	ByType         map[string]TypeCoverage `json:"by_type"`
}

// TypeCoverage represents coverage for a specific asset type.
type TypeCoverage struct {
	Total    int64   `json:"total"`
	InScope  int64   `json:"in_scope"`
	Excluded int64   `json:"excluded"`
	Percent  float64 `json:"percent"`
}

// MatchResult represents the result of matching an asset against scope.
type MatchResult struct {
	InScope             bool        `json:"in_scope"`
	Excluded            bool        `json:"excluded"`
	MatchedTargetIDs    []shared.ID `json:"matched_target_ids,omitempty"`
	MatchedExclusionIDs []shared.ID `json:"matched_exclusion_ids,omitempty"`
}
