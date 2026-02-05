package notification

import (
	"context"
	"database/sql"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// OutboxRepository defines the interface for outbox persistence.
type OutboxRepository interface {
	// ==========================================================================
	// Basic CRUD
	// ==========================================================================

	// Create inserts a new outbox entry.
	Create(ctx context.Context, outbox *Outbox) error

	// CreateInTx inserts a new outbox entry within an existing transaction.
	// This is the key method for the transactional outbox pattern.
	// The tx parameter should be a *sql.Tx from the same database connection.
	CreateInTx(ctx context.Context, tx *sql.Tx, outbox *Outbox) error

	// GetByID retrieves an outbox entry by ID.
	GetByID(ctx context.Context, id ID) (*Outbox, error)

	// Update updates an outbox entry.
	Update(ctx context.Context, outbox *Outbox) error

	// Delete removes an outbox entry.
	Delete(ctx context.Context, id ID) error

	// ==========================================================================
	// Worker Operations
	// ==========================================================================

	// FetchPendingBatch retrieves and locks a batch of pending outbox entries.
	// Uses FOR UPDATE SKIP LOCKED for concurrent worker safety.
	// Returns entries where scheduled_at <= now and status = 'pending'.
	FetchPendingBatch(ctx context.Context, workerID string, batchSize int) ([]*Outbox, error)

	// UnlockStale releases locks on entries that have been processing for too long.
	// This handles worker crashes or timeouts.
	UnlockStale(ctx context.Context, olderThanMinutes int) (int64, error)

	// ==========================================================================
	// Cleanup Operations
	// ==========================================================================

	// DeleteOldCompleted removes completed entries older than the specified days.
	DeleteOldCompleted(ctx context.Context, olderThanDays int) (int64, error)

	// DeleteOldFailed removes failed/dead entries older than the specified days.
	DeleteOldFailed(ctx context.Context, olderThanDays int) (int64, error)

	// ==========================================================================
	// Query Operations
	// ==========================================================================

	// List retrieves outbox entries with filtering and pagination.
	List(ctx context.Context, filter OutboxFilter, page pagination.Pagination) (pagination.Result[*Outbox], error)

	// GetStats returns aggregated statistics for outbox entries.
	GetStats(ctx context.Context, tenantID *shared.ID) (*OutboxStats, error)

	// ListByTenant retrieves outbox entries for a tenant with pagination.
	ListByTenant(ctx context.Context, tenantID shared.ID, filter OutboxFilter) ([]*Outbox, int64, error)

	// CountByStatus returns counts grouped by status for a tenant.
	CountByStatus(ctx context.Context, tenantID shared.ID) (map[OutboxStatus]int64, error)

	// GetByAggregateID retrieves outbox entries for a specific aggregate.
	GetByAggregateID(ctx context.Context, aggregateType string, aggregateID string) ([]*Outbox, error)
}

// OutboxFilter contains filter options for listing outbox entries.
type OutboxFilter struct {
	TenantID      *shared.ID
	Status        *OutboxStatus
	EventType     string
	AggregateType string
	Limit         int
	Offset        int
}

// OutboxStats contains aggregated statistics for outbox entries.
type OutboxStats struct {
	Pending    int64
	Processing int64
	Completed  int64
	Failed     int64
	Dead       int64
	Total      int64
}

// =============================================================================
// Event Repository
// =============================================================================

// EventRepository defines the interface for notification event persistence.
type EventRepository interface {
	// ==========================================================================
	// Basic CRUD
	// ==========================================================================

	// Create inserts a new event.
	Create(ctx context.Context, event *Event) error

	// GetByID retrieves an event by ID.
	GetByID(ctx context.Context, id ID) (*Event, error)

	// Delete removes an event.
	Delete(ctx context.Context, id ID) error

	// ==========================================================================
	// Query Operations
	// ==========================================================================

	// ListByTenant retrieves events for a tenant with pagination.
	ListByTenant(ctx context.Context, tenantID shared.ID, filter EventFilter) ([]*Event, int64, error)

	// GetStats returns aggregated statistics for events.
	GetStats(ctx context.Context, tenantID *shared.ID) (*EventStats, error)

	// ListByIntegration retrieves events that were sent to a specific integration.
	// Uses JSONB query on send_results array.
	ListByIntegration(ctx context.Context, integrationID string, limit, offset int) ([]*Event, int64, error)

	// ==========================================================================
	// Cleanup Operations
	// ==========================================================================

	// DeleteOldEvents removes events older than the specified days.
	// If retentionDays <= 0, no deletion is performed (unlimited retention).
	DeleteOldEvents(ctx context.Context, retentionDays int) (int64, error)
}
