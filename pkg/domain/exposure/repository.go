package exposure

import (
	"context"
	"database/sql"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// Repository defines the interface for exposure event persistence.
type Repository interface {
	// Create persists a new exposure event.
	Create(ctx context.Context, event *ExposureEvent) error

	// CreateInTx persists a new exposure event within an existing transaction.
	// This is used for the transactional outbox pattern.
	CreateInTx(ctx context.Context, tx *sql.Tx, event *ExposureEvent) error

	// GetByID retrieves an exposure event by its ID.
	GetByID(ctx context.Context, id shared.ID) (*ExposureEvent, error)

	// GetByFingerprint retrieves an exposure event by fingerprint within a tenant.
	GetByFingerprint(ctx context.Context, tenantID shared.ID, fingerprint string) (*ExposureEvent, error)

	// Update updates an existing exposure event.
	Update(ctx context.Context, event *ExposureEvent) error

	// Delete removes an exposure event by its ID.
	Delete(ctx context.Context, id shared.ID) error

	// List retrieves exposure events with filtering, sorting, and pagination.
	List(ctx context.Context, filter Filter, opts ListOptions, page pagination.Pagination) (pagination.Result[*ExposureEvent], error)

	// Count returns the total number of exposure events matching the filter.
	Count(ctx context.Context, filter Filter) (int64, error)

	// ListByAsset retrieves all exposure events for an asset.
	ListByAsset(ctx context.Context, assetID shared.ID, page pagination.Pagination) (pagination.Result[*ExposureEvent], error)

	// ExistsByFingerprint checks if an exposure event with the given fingerprint exists.
	ExistsByFingerprint(ctx context.Context, tenantID shared.ID, fingerprint string) (bool, error)

	// Upsert creates or updates an exposure event based on fingerprint.
	// If the fingerprint exists, updates last_seen_at. Otherwise creates a new event.
	Upsert(ctx context.Context, event *ExposureEvent) error

	// BulkUpsert creates or updates multiple exposure events based on fingerprint.
	// Uses batch INSERT with ON CONFLICT for better performance.
	BulkUpsert(ctx context.Context, events []*ExposureEvent) error

	// CountByState returns counts grouped by state for a tenant.
	CountByState(ctx context.Context, tenantID shared.ID) (map[State]int64, error)

	// CountBySeverity returns counts grouped by severity for a tenant.
	CountBySeverity(ctx context.Context, tenantID shared.ID) (map[Severity]int64, error)
}

// StateHistoryRepository defines the interface for state history persistence.
type StateHistoryRepository interface {
	// Create persists a new state history entry.
	Create(ctx context.Context, history *StateHistory) error

	// ListByExposureEvent retrieves all state history for an exposure event.
	ListByExposureEvent(ctx context.Context, exposureEventID shared.ID) ([]*StateHistory, error)

	// GetLatest retrieves the most recent state change for an exposure event.
	GetLatest(ctx context.Context, exposureEventID shared.ID) (*StateHistory, error)
}

// Filter defines the filtering options for listing exposure events.
type Filter struct {
	TenantID        *string     // Filter by tenant ID
	AssetID         *string     // Filter by asset ID
	EventTypes      []EventType // Filter by event types
	Severities      []Severity  // Filter by severities
	States          []State     // Filter by states
	Sources         []string    // Filter by sources
	Search          *string     // Full-text search across title and description
	FirstSeenAfter  *int64      // Filter by first seen after (unix timestamp)
	FirstSeenBefore *int64      // Filter by first seen before (unix timestamp)
	LastSeenAfter   *int64      // Filter by last seen after (unix timestamp)
	LastSeenBefore  *int64      // Filter by last seen before (unix timestamp)
}

// NewFilter creates an empty filter.
func NewFilter() Filter {
	return Filter{}
}

// WithTenantID adds a tenant ID filter.
func (f Filter) WithTenantID(tenantID string) Filter {
	f.TenantID = &tenantID
	return f
}

// WithAssetID adds an asset ID filter.
func (f Filter) WithAssetID(id string) Filter {
	f.AssetID = &id
	return f
}

// WithEventTypes adds an event types filter.
func (f Filter) WithEventTypes(types ...EventType) Filter {
	f.EventTypes = types
	return f
}

// WithSeverities adds a severities filter.
func (f Filter) WithSeverities(severities ...Severity) Filter {
	f.Severities = severities
	return f
}

// WithStates adds a states filter.
func (f Filter) WithStates(states ...State) Filter {
	f.States = states
	return f
}

// WithSources adds a sources filter.
func (f Filter) WithSources(sources ...string) Filter {
	f.Sources = sources
	return f
}

// WithSearch adds a full-text search filter.
func (f Filter) WithSearch(search string) Filter {
	f.Search = &search
	return f
}

// WithFirstSeenAfter adds a first seen after filter.
func (f Filter) WithFirstSeenAfter(timestamp int64) Filter {
	f.FirstSeenAfter = &timestamp
	return f
}

// WithFirstSeenBefore adds a first seen before filter.
func (f Filter) WithFirstSeenBefore(timestamp int64) Filter {
	f.FirstSeenBefore = &timestamp
	return f
}

// WithLastSeenAfter adds a last seen after filter.
func (f Filter) WithLastSeenAfter(timestamp int64) Filter {
	f.LastSeenAfter = &timestamp
	return f
}

// WithLastSeenBefore adds a last seen before filter.
func (f Filter) WithLastSeenBefore(timestamp int64) Filter {
	f.LastSeenBefore = &timestamp
	return f
}

// IsEmpty returns true if no filters are set.
func (f Filter) IsEmpty() bool {
	return f.TenantID == nil &&
		f.AssetID == nil &&
		len(f.EventTypes) == 0 &&
		len(f.Severities) == 0 &&
		len(f.States) == 0 &&
		len(f.Sources) == 0 &&
		f.Search == nil &&
		f.FirstSeenAfter == nil &&
		f.FirstSeenBefore == nil &&
		f.LastSeenAfter == nil &&
		f.LastSeenBefore == nil
}

// ListOptions contains options for listing (sorting).
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

// AllowedSortFields returns the allowed sort fields for exposure events.
func AllowedSortFields() map[string]string {
	return map[string]string{
		"title":         "title",
		"created_at":    "created_at",
		"updated_at":    "updated_at",
		"first_seen_at": "first_seen_at",
		"last_seen_at":  "last_seen_at",
		"severity":      "severity",
		"state":         "state",
		"event_type":    "event_type",
		"source":        "source",
	}
}
