package aitriage

import (
	"context"
	"errors"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Repository errors
var (
	// ErrTokenLimitExceeded is returned when the monthly token limit is exceeded.
	ErrTokenLimitExceeded = errors.New("monthly token limit exceeded")

	// ErrAlreadyProcessing is returned when the triage job is already being processed.
	ErrAlreadyProcessing = errors.New("triage job is already being processed")

	// ErrSlotNotAvailable is returned when unable to acquire a processing slot.
	ErrSlotNotAvailable = errors.New("unable to acquire processing slot")

	// ErrDuplicateRequest is returned when a triage request already exists for the finding.
	ErrDuplicateRequest = errors.New("triage request already in progress for this finding")
)

// Repository defines the interface for triage result persistence.
type Repository interface {
	// Create creates a new triage result.
	Create(ctx context.Context, result *TriageResult) error

	// Update updates an existing triage result.
	Update(ctx context.Context, result *TriageResult) error

	// GetByID retrieves a triage result by ID.
	GetByID(ctx context.Context, tenantID, id shared.ID) (*TriageResult, error)

	// GetByFindingID retrieves the latest triage result for a finding.
	GetByFindingID(ctx context.Context, tenantID, findingID shared.ID) (*TriageResult, error)

	// ListByFindingID retrieves all triage results for a finding (history).
	ListByFindingID(ctx context.Context, tenantID, findingID shared.ID, limit, offset int) ([]*TriageResult, int, error)

	// GetPendingJobs retrieves pending triage jobs for processing.
	// SECURITY NOTE: Results are ordered by tenant_id for proper isolation.
	// Consider using GetPendingJobsByTenant for better tenant isolation.
	GetPendingJobs(ctx context.Context, limit int) ([]*TriageResult, error)

	// GetPendingJobsByTenant retrieves pending jobs for a specific tenant.
	// SECURITY: This is the preferred method for workers - ensures tenant isolation.
	GetPendingJobsByTenant(ctx context.Context, tenantID shared.ID, limit int) ([]*TriageResult, error)

	// GetTenantsWithPendingJobs returns tenant IDs that have pending jobs.
	// SECURITY: Use with GetPendingJobsByTenant for proper tenant isolation.
	GetTenantsWithPendingJobs(ctx context.Context, limit int) ([]shared.ID, error)

	// CountByTenantThisMonth counts triage jobs for token usage tracking.
	CountByTenantThisMonth(ctx context.Context, tenantID shared.ID) (int, error)

	// SumTokensByTenantThisMonth sums tokens used this month.
	SumTokensByTenantThisMonth(ctx context.Context, tenantID shared.ID) (int, error)

	// GetTriageContext retrieves triage result with tenant settings and token usage in one call.
	// This optimizes the ProcessTriage flow by reducing multiple queries to one.
	GetTriageContext(ctx context.Context, tenantID, resultID shared.ID) (*TriageContext, error)

	// AcquireTriageSlot atomically checks token limit and reserves a slot for processing.
	// Uses SELECT FOR UPDATE to prevent race conditions when multiple workers process concurrently.
	// Returns:
	// - (context, nil) if slot acquired successfully
	// - (nil, ErrTokenLimitExceeded) if token limit exceeded
	// - (nil, ErrAlreadyProcessing) if result is already being processed
	// - (nil, err) for other errors
	AcquireTriageSlot(ctx context.Context, tenantID, resultID shared.ID) (*TriageContext, error)

	// HasPendingOrProcessing checks if a finding has a pending or processing triage job.
	// Used for deduplication to prevent multiple concurrent triage requests for the same finding.
	HasPendingOrProcessing(ctx context.Context, tenantID, findingID shared.ID) (bool, error)

	// FindStuckJobs finds triage jobs that have been in pending/processing state for too long.
	// Used by recovery job to mark them as failed.
	// stuckDuration: how long a job must be stuck before being considered for recovery
	FindStuckJobs(ctx context.Context, stuckDuration time.Duration, limit int) ([]*TriageResult, error)

	// MarkStuckAsFailed marks a stuck triage job as failed.
	// Returns true if the job was updated, false if it was already in a terminal state.
	MarkStuckAsFailed(ctx context.Context, id shared.ID, errorMessage string) (bool, error)
}

// TriageContext contains all data needed to process a triage job.
// Used to reduce N+1 queries during triage processing.
type TriageContext struct {
	Result            *TriageResult
	TenantSettings    map[string]any // Raw tenant settings JSON
	TokensUsedMonth   int            // Tokens used this month
	MonthlyTokenLimit int            // Monthly limit (0 = unlimited)
}

// Filters for listing triage results.
type ListFilters struct {
	TenantID  shared.ID
	FindingID *shared.ID
	Status    *TriageStatus
	Type      *TriageType
	Limit     int
	Offset    int
}

// FindingExistsChecker is an interface for checking if findings exist.
// This allows batch validation without N+1 queries.
type FindingExistsChecker interface {
	// ExistsByIDs returns a map of finding ID -> exists (true/false).
	ExistsByIDs(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID) (map[shared.ID]bool, error)
}
