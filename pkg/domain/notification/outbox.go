// Package notification provides domain entities for the notification system.
package notification

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/openctemio/api/pkg/domain/shared"
)

// =============================================================================
// ID Type
// =============================================================================

// ID represents a notification outbox ID.
type ID = shared.ID

// ParseID parses a string into a notification ID.
func ParseID(s string) (ID, error) {
	return shared.IDFromString(s)
}

// NewID generates a new notification ID.
func NewID() ID {
	return shared.NewID()
}

// =============================================================================
// Status Type
// =============================================================================

// OutboxStatus represents the processing status of an outbox entry.
type OutboxStatus string

const (
	// OutboxStatusPending - Task is waiting to be processed.
	OutboxStatusPending OutboxStatus = "pending"

	// OutboxStatusProcessing - Task is currently being processed by a worker.
	OutboxStatusProcessing OutboxStatus = "processing"

	// OutboxStatusCompleted - Task was processed successfully.
	OutboxStatusCompleted OutboxStatus = "completed"

	// OutboxStatusFailed - Task failed but may be retried.
	OutboxStatusFailed OutboxStatus = "failed"

	// OutboxStatusDead - Task failed permanently, requires manual intervention.
	OutboxStatusDead OutboxStatus = "dead"
)

// String returns the string representation of the status.
func (s OutboxStatus) String() string {
	return string(s)
}

// IsTerminal returns true if the status is a terminal state (no more processing).
func (s OutboxStatus) IsTerminal() bool {
	return s == OutboxStatusCompleted || s == OutboxStatusDead
}

// =============================================================================
// Severity Type
// =============================================================================

// Severity represents the severity level of a notification.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
	SeverityNone     Severity = "none"
)

// String returns the string representation of the severity.
func (s Severity) String() string {
	return string(s)
}

// =============================================================================
// Outbox Entity
// =============================================================================

// Outbox represents a notification task in the outbox queue.
// It follows the Transactional Outbox Pattern for reliable message delivery.
type Outbox struct {
	id       ID
	tenantID shared.ID

	// Event source
	eventType     string     // e.g., "new_finding", "scan_completed"
	aggregateType string     // e.g., "finding", "scan", "asset"
	aggregateID   *uuid.UUID // ID of the source entity (nil for system events)

	// Notification payload
	title    string
	body     string
	severity Severity
	url      string
	metadata map[string]any

	// Processing state
	status     OutboxStatus
	retryCount int
	maxRetries int
	lastError  string

	// Scheduling
	scheduledAt time.Time
	lockedAt    *time.Time
	lockedBy    string

	// Timestamps
	createdAt   time.Time
	updatedAt   time.Time
	processedAt *time.Time
}

// =============================================================================
// Constructor
// =============================================================================

// OutboxParams contains parameters for creating a new outbox entry.
type OutboxParams struct {
	TenantID      shared.ID
	EventType     string
	AggregateType string
	AggregateID   *uuid.UUID
	Title         string
	Body          string
	Severity      Severity
	URL           string
	Metadata      map[string]any
	MaxRetries    int        // Optional, defaults to 3
	ScheduledAt   *time.Time // Optional, defaults to now
}

// NewOutbox creates a new outbox entry.
func NewOutbox(params OutboxParams) *Outbox {
	now := time.Now()

	maxRetries := params.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 3
	}

	scheduledAt := now
	if params.ScheduledAt != nil {
		scheduledAt = *params.ScheduledAt
	}

	metadata := params.Metadata
	if metadata == nil {
		metadata = make(map[string]any)
	}

	severity := params.Severity
	if severity == "" {
		severity = SeverityInfo
	}

	return &Outbox{
		id:            NewID(),
		tenantID:      params.TenantID,
		eventType:     params.EventType,
		aggregateType: params.AggregateType,
		aggregateID:   params.AggregateID,
		title:         params.Title,
		body:          params.Body,
		severity:      severity,
		url:           params.URL,
		metadata:      metadata,
		status:        OutboxStatusPending,
		retryCount:    0,
		maxRetries:    maxRetries,
		scheduledAt:   scheduledAt,
		createdAt:     now,
		updatedAt:     now,
	}
}

// Reconstitute recreates an outbox entry from persistence.
func Reconstitute(
	id ID,
	tenantID shared.ID,
	eventType string,
	aggregateType string,
	aggregateID *uuid.UUID,
	title string,
	body string,
	severity Severity,
	url string,
	metadata map[string]any,
	status OutboxStatus,
	retryCount int,
	maxRetries int,
	lastError string,
	scheduledAt time.Time,
	lockedAt *time.Time,
	lockedBy string,
	createdAt time.Time,
	updatedAt time.Time,
	processedAt *time.Time,
) *Outbox {
	if metadata == nil {
		metadata = make(map[string]any)
	}
	return &Outbox{
		id:            id,
		tenantID:      tenantID,
		eventType:     eventType,
		aggregateType: aggregateType,
		aggregateID:   aggregateID,
		title:         title,
		body:          body,
		severity:      severity,
		url:           url,
		metadata:      metadata,
		status:        status,
		retryCount:    retryCount,
		maxRetries:    maxRetries,
		lastError:     lastError,
		scheduledAt:   scheduledAt,
		lockedAt:      lockedAt,
		lockedBy:      lockedBy,
		createdAt:     createdAt,
		updatedAt:     updatedAt,
		processedAt:   processedAt,
	}
}

// =============================================================================
// Getters
// =============================================================================

func (o *Outbox) ID() ID                   { return o.id }
func (o *Outbox) TenantID() shared.ID      { return o.tenantID }
func (o *Outbox) EventType() string        { return o.eventType }
func (o *Outbox) AggregateType() string    { return o.aggregateType }
func (o *Outbox) AggregateID() *uuid.UUID  { return o.aggregateID }
func (o *Outbox) Title() string            { return o.title }
func (o *Outbox) Body() string             { return o.body }
func (o *Outbox) Severity() Severity       { return o.severity }
func (o *Outbox) URL() string              { return o.url }
func (o *Outbox) Metadata() map[string]any { return o.metadata }
func (o *Outbox) Status() OutboxStatus     { return o.status }
func (o *Outbox) RetryCount() int          { return o.retryCount }
func (o *Outbox) MaxRetries() int          { return o.maxRetries }
func (o *Outbox) LastError() string        { return o.lastError }
func (o *Outbox) ScheduledAt() time.Time   { return o.scheduledAt }
func (o *Outbox) LockedAt() *time.Time     { return o.lockedAt }
func (o *Outbox) LockedBy() string         { return o.lockedBy }
func (o *Outbox) CreatedAt() time.Time     { return o.createdAt }
func (o *Outbox) UpdatedAt() time.Time     { return o.updatedAt }
func (o *Outbox) ProcessedAt() *time.Time  { return o.processedAt }

// CanRetry returns true if the task can be retried.
func (o *Outbox) CanRetry() bool {
	return o.retryCount < o.maxRetries
}

// =============================================================================
// State Transitions
// =============================================================================

// Lock marks the outbox entry as being processed by a worker.
func (o *Outbox) Lock(workerID string) error {
	if o.status != OutboxStatusPending {
		return fmt.Errorf("cannot lock outbox with status %s", o.status)
	}
	now := time.Now()
	o.status = OutboxStatusProcessing
	o.lockedAt = &now
	o.lockedBy = workerID
	o.updatedAt = now
	return nil
}

// MarkCompleted marks the outbox entry as successfully processed.
func (o *Outbox) MarkCompleted() {
	now := time.Now()
	o.status = OutboxStatusCompleted
	o.processedAt = &now
	o.updatedAt = now
}

// MarkFailed marks the outbox entry as failed and schedules a retry if possible.
func (o *Outbox) MarkFailed(errorMessage string) {
	now := time.Now()
	o.lastError = errorMessage
	o.retryCount++
	o.updatedAt = now

	if o.CanRetry() {
		// Schedule retry with exponential backoff: 1min, 2min, 4min, ...
		backoff := time.Duration(1<<o.retryCount) * time.Minute
		o.status = OutboxStatusPending
		o.scheduledAt = now.Add(backoff)
		o.lockedAt = nil
		o.lockedBy = ""
	} else {
		// No more retries, mark as failed
		o.status = OutboxStatusFailed
		o.processedAt = &now
	}
}

// MarkDead marks the outbox entry as dead (requires manual intervention).
func (o *Outbox) MarkDead(reason string) {
	now := time.Now()
	o.status = OutboxStatusDead
	o.lastError = reason
	o.processedAt = &now
	o.updatedAt = now
}

// Unlock releases the lock on the outbox entry (for cleanup of stuck tasks).
func (o *Outbox) Unlock() {
	o.status = OutboxStatusPending
	o.lockedAt = nil
	o.lockedBy = ""
	o.updatedAt = time.Now()
}

// ResetForRetry resets a failed/dead entry to pending for manual retry.
// This resets the retry count and schedules immediate processing.
func (o *Outbox) ResetForRetry() {
	now := time.Now()
	o.status = OutboxStatusPending
	o.retryCount = 0
	o.scheduledAt = now
	o.lockedAt = nil
	o.lockedBy = ""
	o.processedAt = nil
	o.updatedAt = now
}

// =============================================================================
// Metadata Helpers
// =============================================================================

// SetMetadata sets a metadata key-value pair.
func (o *Outbox) SetMetadata(key string, value any) {
	o.metadata[key] = value
}

// GetMetadata gets a metadata value by key.
func (o *Outbox) GetMetadata(key string) (any, bool) {
	v, ok := o.metadata[key]
	return v, ok
}
