package notification

import (
	"time"

	"github.com/google/uuid"
	"github.com/openctemio/api/pkg/domain/shared"
)

// =============================================================================
// Event Status Type
// =============================================================================

// EventStatus represents the final processing status of a notification event.
type EventStatus string

const (
	// EventStatusCompleted - At least one integration succeeded.
	EventStatusCompleted EventStatus = "completed"

	// EventStatusFailed - All integrations failed after retries.
	EventStatusFailed EventStatus = "failed"

	// EventStatusSkipped - No integrations matched the event filters.
	EventStatusSkipped EventStatus = "skipped"
)

// String returns the string representation of the status.
func (s EventStatus) String() string {
	return string(s)
}

// =============================================================================
// Send Result Type
// =============================================================================

// SendResult represents the result of sending to a single integration.
type SendResult struct {
	IntegrationID   string    `json:"integration_id"`
	IntegrationName string    `json:"name"`
	Provider        string    `json:"provider"`
	Status          string    `json:"status"` // success, failed
	MessageID       string    `json:"message_id,omitempty"`
	Error           string    `json:"error,omitempty"`
	SentAt          time.Time `json:"sent_at"`
}

// =============================================================================
// Event Entity
// =============================================================================

// Event represents an archived notification event after processing.
// This is the permanent audit trail of all notifications.
type Event struct {
	id       ID
	tenantID shared.ID

	// Event source (copied from outbox)
	eventType     string
	aggregateType string
	aggregateID   *uuid.UUID

	// Notification payload (copied from outbox)
	title    string
	body     string
	severity Severity
	url      string
	metadata map[string]any

	// Processing results
	status                EventStatus
	integrationsTotal     int
	integrationsMatched   int
	integrationsSucceeded int
	integrationsFailed    int
	sendResults           []SendResult
	lastError             string
	retryCount            int

	// Timestamps
	createdAt   time.Time // When the original event was created
	processedAt time.Time // When processing completed
}

// =============================================================================
// Constructor
// =============================================================================

// EventParams contains parameters for creating a new event.
type EventParams struct {
	ID                    ID
	TenantID              shared.ID
	EventType             string
	AggregateType         string
	AggregateID           *uuid.UUID
	Title                 string
	Body                  string
	Severity              Severity
	URL                   string
	Metadata              map[string]any
	Status                EventStatus
	IntegrationsTotal     int
	IntegrationsMatched   int
	IntegrationsSucceeded int
	IntegrationsFailed    int
	SendResults           []SendResult
	LastError             string
	RetryCount            int
	CreatedAt             time.Time
	ProcessedAt           time.Time
}

// NewEvent creates a new event.
func NewEvent(params EventParams) *Event {
	if params.Metadata == nil {
		params.Metadata = make(map[string]any)
	}
	if params.SendResults == nil {
		params.SendResults = make([]SendResult, 0)
	}

	return &Event{
		id:                    params.ID,
		tenantID:              params.TenantID,
		eventType:             params.EventType,
		aggregateType:         params.AggregateType,
		aggregateID:           params.AggregateID,
		title:                 params.Title,
		body:                  params.Body,
		severity:              params.Severity,
		url:                   params.URL,
		metadata:              params.Metadata,
		status:                params.Status,
		integrationsTotal:     params.IntegrationsTotal,
		integrationsMatched:   params.IntegrationsMatched,
		integrationsSucceeded: params.IntegrationsSucceeded,
		integrationsFailed:    params.IntegrationsFailed,
		sendResults:           params.SendResults,
		lastError:             params.LastError,
		retryCount:            params.RetryCount,
		createdAt:             params.CreatedAt,
		processedAt:           params.ProcessedAt,
	}
}

// NewEventFromOutbox creates an event from a processed outbox entry.
func NewEventFromOutbox(outbox *Outbox, results ProcessingResults) *Event {
	status := EventStatusCompleted
	if results.IntegrationsSucceeded == 0 && results.IntegrationsFailed > 0 {
		status = EventStatusFailed
	} else if results.IntegrationsMatched == 0 {
		status = EventStatusSkipped
	}

	processedAt := time.Now()
	if outbox.ProcessedAt() != nil {
		processedAt = *outbox.ProcessedAt()
	}

	return &Event{
		id:                    outbox.ID(),
		tenantID:              outbox.TenantID(),
		eventType:             outbox.EventType(),
		aggregateType:         outbox.AggregateType(),
		aggregateID:           outbox.AggregateID(),
		title:                 outbox.Title(),
		body:                  outbox.Body(),
		severity:              outbox.Severity(),
		url:                   outbox.URL(),
		metadata:              outbox.Metadata(),
		status:                status,
		integrationsTotal:     results.IntegrationsTotal,
		integrationsMatched:   results.IntegrationsMatched,
		integrationsSucceeded: results.IntegrationsSucceeded,
		integrationsFailed:    results.IntegrationsFailed,
		sendResults:           results.SendResults,
		lastError:             outbox.LastError(),
		retryCount:            outbox.RetryCount(),
		createdAt:             outbox.CreatedAt(),
		processedAt:           processedAt,
	}
}

// ProcessingResults contains the results of processing an outbox entry.
type ProcessingResults struct {
	IntegrationsTotal     int
	IntegrationsMatched   int
	IntegrationsSucceeded int
	IntegrationsFailed    int
	SendResults           []SendResult
}

// ReconstituteEvent recreates an event from persistence.
func ReconstituteEvent(
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
	status EventStatus,
	integrationsTotal int,
	integrationsMatched int,
	integrationsSucceeded int,
	integrationsFailed int,
	sendResults []SendResult,
	lastError string,
	retryCount int,
	createdAt time.Time,
	processedAt time.Time,
) *Event {
	if metadata == nil {
		metadata = make(map[string]any)
	}
	if sendResults == nil {
		sendResults = make([]SendResult, 0)
	}

	return &Event{
		id:                    id,
		tenantID:              tenantID,
		eventType:             eventType,
		aggregateType:         aggregateType,
		aggregateID:           aggregateID,
		title:                 title,
		body:                  body,
		severity:              severity,
		url:                   url,
		metadata:              metadata,
		status:                status,
		integrationsTotal:     integrationsTotal,
		integrationsMatched:   integrationsMatched,
		integrationsSucceeded: integrationsSucceeded,
		integrationsFailed:    integrationsFailed,
		sendResults:           sendResults,
		lastError:             lastError,
		retryCount:            retryCount,
		createdAt:             createdAt,
		processedAt:           processedAt,
	}
}

// =============================================================================
// Getters
// =============================================================================

func (e *Event) ID() ID                     { return e.id }
func (e *Event) TenantID() shared.ID        { return e.tenantID }
func (e *Event) EventType() string          { return e.eventType }
func (e *Event) AggregateType() string      { return e.aggregateType }
func (e *Event) AggregateID() *uuid.UUID    { return e.aggregateID }
func (e *Event) Title() string              { return e.title }
func (e *Event) Body() string               { return e.body }
func (e *Event) Severity() Severity         { return e.severity }
func (e *Event) URL() string                { return e.url }
func (e *Event) Metadata() map[string]any   { return e.metadata }
func (e *Event) Status() EventStatus        { return e.status }
func (e *Event) IntegrationsTotal() int     { return e.integrationsTotal }
func (e *Event) IntegrationsMatched() int   { return e.integrationsMatched }
func (e *Event) IntegrationsSucceeded() int { return e.integrationsSucceeded }
func (e *Event) IntegrationsFailed() int    { return e.integrationsFailed }
func (e *Event) SendResults() []SendResult  { return e.sendResults }
func (e *Event) LastError() string          { return e.lastError }
func (e *Event) RetryCount() int            { return e.retryCount }
func (e *Event) CreatedAt() time.Time       { return e.createdAt }
func (e *Event) ProcessedAt() time.Time     { return e.processedAt }

// =============================================================================
// Event Statistics (for filtering/display)
// =============================================================================

// EventStats represents aggregated statistics for events.
type EventStats struct {
	Completed int64
	Failed    int64
	Skipped   int64
	Total     int64
}

// EventFilter contains filter options for listing events.
type EventFilter struct {
	TenantID      *shared.ID
	Status        *EventStatus
	EventType     string
	AggregateType string
	AggregateID   *uuid.UUID
	Limit         int
	Offset        int
}
