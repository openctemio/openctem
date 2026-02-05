package rule

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// SourceFilter represents filter options for listing sources.
type SourceFilter struct {
	TenantID          *shared.ID
	ToolID            *shared.ID
	SourceType        *SourceType
	Enabled           *bool
	IsPlatformDefault *bool
	SyncStatus        *SyncStatus
	Search            string
}

// SourceRepository defines the interface for rule source persistence.
type SourceRepository interface {
	// Create creates a new rule source.
	Create(ctx context.Context, source *Source) error

	// GetByID retrieves a source by ID.
	GetByID(ctx context.Context, id shared.ID) (*Source, error)

	// GetByTenantAndID retrieves a source by tenant and ID.
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*Source, error)

	// List lists sources with filters and pagination.
	List(ctx context.Context, filter SourceFilter, page pagination.Pagination) (pagination.Result[*Source], error)

	// ListByTenantAndTool lists all sources for a tenant and tool.
	ListByTenantAndTool(ctx context.Context, tenantID shared.ID, toolID *shared.ID) ([]*Source, error)

	// ListNeedingSync lists sources that need synchronization.
	ListNeedingSync(ctx context.Context, limit int) ([]*Source, error)

	// Update updates a source.
	Update(ctx context.Context, source *Source) error

	// Delete deletes a source.
	Delete(ctx context.Context, id shared.ID) error
}

// RuleFilter represents filter options for listing rules.
type RuleFilter struct {
	TenantID *shared.ID
	ToolID   *shared.ID
	SourceID *shared.ID
	Severity *Severity
	Category string
	Tags     []string
	RuleIDs  []string // Filter by specific rule IDs
	Search   string
}

// RuleRepository defines the interface for rule persistence.
type RuleRepository interface {
	// Create creates a new rule.
	Create(ctx context.Context, rule *Rule) error

	// CreateBatch creates multiple rules in batch.
	CreateBatch(ctx context.Context, rules []*Rule) error

	// GetByID retrieves a rule by ID.
	GetByID(ctx context.Context, id shared.ID) (*Rule, error)

	// GetBySourceAndRuleID retrieves a rule by source and rule ID.
	GetBySourceAndRuleID(ctx context.Context, sourceID shared.ID, ruleID string) (*Rule, error)

	// List lists rules with filters and pagination.
	List(ctx context.Context, filter RuleFilter, page pagination.Pagination) (pagination.Result[*Rule], error)

	// ListBySource lists all rules for a source.
	ListBySource(ctx context.Context, sourceID shared.ID) ([]*Rule, error)

	// Update updates a rule.
	Update(ctx context.Context, rule *Rule) error

	// UpsertBatch upserts multiple rules (insert or update).
	UpsertBatch(ctx context.Context, rules []*Rule) error

	// Delete deletes a rule.
	Delete(ctx context.Context, id shared.ID) error

	// DeleteBySource deletes all rules for a source.
	DeleteBySource(ctx context.Context, sourceID shared.ID) error

	// CountBySource counts rules for a source.
	CountBySource(ctx context.Context, sourceID shared.ID) (int, error)

	// CountByTenantAndTool counts rules for a tenant and tool.
	CountByTenantAndTool(ctx context.Context, tenantID shared.ID, toolID *shared.ID) (int, error)
}

// BundleFilter represents filter options for listing bundles.
type BundleFilter struct {
	TenantID *shared.ID
	ToolID   *shared.ID
	Status   *BundleStatus
}

// BundleRepository defines the interface for rule bundle persistence.
type BundleRepository interface {
	// Create creates a new bundle.
	Create(ctx context.Context, bundle *Bundle) error

	// GetByID retrieves a bundle by ID.
	GetByID(ctx context.Context, id shared.ID) (*Bundle, error)

	// GetLatest retrieves the latest ready bundle for a tenant and tool.
	GetLatest(ctx context.Context, tenantID, toolID shared.ID) (*Bundle, error)

	// GetByContentHash retrieves a bundle by content hash.
	GetByContentHash(ctx context.Context, hash string) (*Bundle, error)

	// List lists bundles with filters.
	List(ctx context.Context, filter BundleFilter) ([]*Bundle, error)

	// Update updates a bundle.
	Update(ctx context.Context, bundle *Bundle) error

	// Delete deletes a bundle.
	Delete(ctx context.Context, id shared.ID) error

	// DeleteExpired deletes all expired bundles.
	DeleteExpired(ctx context.Context) (int64, error)
}

// OverrideFilter represents filter options for listing overrides.
type OverrideFilter struct {
	TenantID      *shared.ID
	ToolID        *shared.ID
	AssetGroupID  *shared.ID
	ScanProfileID *shared.ID
	Enabled       *bool
}

// OverrideRepository defines the interface for rule override persistence.
type OverrideRepository interface {
	// Create creates a new override.
	Create(ctx context.Context, override *Override) error

	// GetByID retrieves an override by ID.
	GetByID(ctx context.Context, id shared.ID) (*Override, error)

	// GetByTenantAndID retrieves an override by tenant and ID.
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*Override, error)

	// List lists overrides with filters and pagination.
	List(ctx context.Context, filter OverrideFilter, page pagination.Pagination) (pagination.Result[*Override], error)

	// ListByTenantAndTool lists all overrides for a tenant and tool.
	ListByTenantAndTool(ctx context.Context, tenantID shared.ID, toolID *shared.ID) ([]*Override, error)

	// Update updates an override.
	Update(ctx context.Context, override *Override) error

	// Delete deletes an override.
	Delete(ctx context.Context, id shared.ID) error

	// DeleteExpired deletes all expired overrides.
	DeleteExpired(ctx context.Context) (int64, error)
}

// SyncHistory represents a record of a rule source sync.
type SyncHistory struct {
	ID           shared.ID
	SourceID     shared.ID
	Status       SyncStatus
	RulesAdded   int
	RulesUpdated int
	RulesRemoved int
	Duration     time.Duration
	ErrorMessage string
	ErrorDetails map[string]any
	PreviousHash string
	NewHash      string
	CreatedAt    time.Time
}

// SyncHistoryRepository defines the interface for sync history persistence.
type SyncHistoryRepository interface {
	// Create creates a new sync history record.
	Create(ctx context.Context, history *SyncHistory) error

	// ListBySource lists sync history for a source.
	ListBySource(ctx context.Context, sourceID shared.ID, limit int) ([]*SyncHistory, error)
}
