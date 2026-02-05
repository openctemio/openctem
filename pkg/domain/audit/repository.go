package audit

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// Repository defines the interface for audit log persistence.
type Repository interface {
	// Create persists a new audit log entry.
	Create(ctx context.Context, log *AuditLog) error

	// CreateBatch persists multiple audit log entries.
	CreateBatch(ctx context.Context, logs []*AuditLog) error

	// GetByID retrieves an audit log by ID.
	GetByID(ctx context.Context, id shared.ID) (*AuditLog, error)

	// List retrieves audit logs matching the filter with pagination.
	List(ctx context.Context, filter Filter, page pagination.Pagination) (pagination.Result[*AuditLog], error)

	// Count returns the count of audit logs matching the filter.
	Count(ctx context.Context, filter Filter) (int64, error)

	// DeleteOlderThan deletes audit logs older than the specified time.
	// Used for retention policy enforcement.
	DeleteOlderThan(ctx context.Context, before time.Time) (int64, error)

	// GetLatestByResource retrieves the latest audit log for a resource.
	GetLatestByResource(ctx context.Context, resourceType ResourceType, resourceID string) (*AuditLog, error)

	// ListByActor retrieves audit logs for a specific actor.
	ListByActor(ctx context.Context, actorID shared.ID, page pagination.Pagination) (pagination.Result[*AuditLog], error)

	// ListByResource retrieves audit logs for a specific resource.
	ListByResource(ctx context.Context, resourceType ResourceType, resourceID string, page pagination.Pagination) (pagination.Result[*AuditLog], error)

	// CountByAction counts occurrences of an action within a time range.
	CountByAction(ctx context.Context, tenantID *shared.ID, action Action, since time.Time) (int64, error)
}

// Filter defines criteria for filtering audit logs.
type Filter struct {
	TenantID      *shared.ID
	ActorID       *shared.ID
	Actions       []Action
	ResourceTypes []ResourceType
	ResourceID    *string
	Results       []Result
	Severities    []Severity
	Categories    []string
	RequestID     *string
	SessionID     *string
	Since         *time.Time
	Until         *time.Time
	SearchTerm    *string // Search in message, resource name, actor email
	SortBy        string
	SortOrder     string // "asc" or "desc"
	ExcludeSystem bool   // Exclude system events
}

// NewFilter creates a new empty filter.
func NewFilter() Filter {
	return Filter{}
}

// WithTenantID sets the tenant ID filter.
func (f Filter) WithTenantID(tenantID shared.ID) Filter {
	f.TenantID = &tenantID
	return f
}

// WithActorID sets the actor ID filter.
func (f Filter) WithActorID(actorID shared.ID) Filter {
	f.ActorID = &actorID
	return f
}

// WithActions sets the actions filter.
func (f Filter) WithActions(actions ...Action) Filter {
	f.Actions = actions
	return f
}

// WithResourceTypes sets the resource types filter.
func (f Filter) WithResourceTypes(types ...ResourceType) Filter {
	f.ResourceTypes = types
	return f
}

// WithResourceID sets the resource ID filter.
func (f Filter) WithResourceID(resourceID string) Filter {
	f.ResourceID = &resourceID
	return f
}

// WithResults sets the results filter.
func (f Filter) WithResults(results ...Result) Filter {
	f.Results = results
	return f
}

// WithSeverities sets the severities filter.
func (f Filter) WithSeverities(severities ...Severity) Filter {
	f.Severities = severities
	return f
}

// WithCategories sets the categories filter.
func (f Filter) WithCategories(categories ...string) Filter {
	f.Categories = categories
	return f
}

// WithRequestID sets the request ID filter.
func (f Filter) WithRequestID(requestID string) Filter {
	f.RequestID = &requestID
	return f
}

// WithSessionID sets the session ID filter.
func (f Filter) WithSessionID(sessionID string) Filter {
	f.SessionID = &sessionID
	return f
}

// WithSince sets the since time filter.
func (f Filter) WithSince(since time.Time) Filter {
	f.Since = &since
	return f
}

// WithUntil sets the until time filter.
func (f Filter) WithUntil(until time.Time) Filter {
	f.Until = &until
	return f
}

// WithTimeRange sets both since and until time filters.
func (f Filter) WithTimeRange(since, until time.Time) Filter {
	f.Since = &since
	f.Until = &until
	return f
}

// WithSearchTerm sets the search term filter.
func (f Filter) WithSearchTerm(term string) Filter {
	f.SearchTerm = &term
	return f
}

// WithSort sets the sort order.
func (f Filter) WithSort(sortBy, sortOrder string) Filter {
	f.SortBy = sortBy
	f.SortOrder = sortOrder
	return f
}

// WithExcludeSystem sets the exclude system filter.
func (f Filter) WithExcludeSystem(exclude bool) Filter {
	f.ExcludeSystem = exclude
	return f
}

// IsEmpty checks if no filters are applied.
func (f Filter) IsEmpty() bool {
	return f.TenantID == nil &&
		f.ActorID == nil &&
		len(f.Actions) == 0 &&
		len(f.ResourceTypes) == 0 &&
		f.ResourceID == nil &&
		len(f.Results) == 0 &&
		len(f.Severities) == 0 &&
		len(f.Categories) == 0 &&
		f.RequestID == nil &&
		f.SessionID == nil &&
		f.Since == nil &&
		f.Until == nil &&
		f.SearchTerm == nil &&
		f.SortBy == "" &&
		!f.ExcludeSystem
}
