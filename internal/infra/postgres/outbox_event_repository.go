package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/openctemio/api/pkg/domain/outbox"
	"github.com/openctemio/api/pkg/domain/shared"
)

// OutboxEventRepository implements the outbox.EventRepository interface.
type OutboxEventRepository struct {
	db *DB
}

// NewOutboxEventRepository creates a new OutboxEventRepository.
func NewOutboxEventRepository(db *DB) *OutboxEventRepository {
	return &OutboxEventRepository{db: db}
}

// =============================================================================
// Basic CRUD
// =============================================================================

// Create inserts a new event.
func (r *OutboxEventRepository) Create(ctx context.Context, event *outbox.Event) error {
	metadata, err := json.Marshal(event.Metadata())
	if err != nil {
		metadata = []byte("{}")
	}

	sendResults, err := json.Marshal(event.SendResults())
	if err != nil {
		sendResults = []byte("[]")
	}

	var aggregateID *string
	if event.AggregateID() != nil {
		s := event.AggregateID().String()
		aggregateID = &s
	}

	query := `
		INSERT INTO notification_events (
			id, tenant_id, event_type, aggregate_type, aggregate_id,
			title, body, severity, url, metadata,
			status, integrations_total, integrations_matched,
			integrations_succeeded, integrations_failed,
			send_results, last_error, retry_count,
			created_at, processed_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10,
			$11, $12, $13,
			$14, $15,
			$16, $17, $18,
			$19, $20
		)
	`

	_, err = r.db.ExecContext(ctx, query,
		event.ID().String(),
		event.TenantID().String(),
		event.EventType(),
		event.AggregateType(),
		aggregateID,
		event.Title(),
		nullableString(event.Body()),
		event.Severity().String(),
		nullableString(event.URL()),
		metadata,
		event.Status().String(),
		event.IntegrationsTotal(),
		event.IntegrationsMatched(),
		event.IntegrationsSucceeded(),
		event.IntegrationsFailed(),
		sendResults,
		nullableString(event.LastError()),
		event.RetryCount(),
		event.CreatedAt(),
		event.ProcessedAt(),
	)
	if err != nil {
		return fmt.Errorf("insert notification event: %w", err)
	}

	return nil
}

// GetByID retrieves an event by ID.
func (r *OutboxEventRepository) GetByID(ctx context.Context, id outbox.ID) (*outbox.Event, error) {
	query := `
		SELECT id, tenant_id, event_type, aggregate_type, aggregate_id,
			   title, body, severity, url, metadata,
			   status, integrations_total, integrations_matched,
			   integrations_succeeded, integrations_failed,
			   send_results, last_error, retry_count,
			   created_at, processed_at
		FROM notification_events
		WHERE id = $1
	`

	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanEvent(row)
}

// Delete removes an event.
func (r *OutboxEventRepository) Delete(ctx context.Context, id outbox.ID) error {
	query := `DELETE FROM notification_events WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("delete notification event: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rows == 0 {
		return outbox.ErrEventNotFound
	}

	return nil
}

// =============================================================================
// Query Operations
// =============================================================================

// ListByTenant retrieves events for a tenant with pagination.
func (r *OutboxEventRepository) ListByTenant(ctx context.Context, tenantID shared.ID, filter outbox.EventFilter) ([]*outbox.Event, int64, error) {
	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	if filter.Limit > 100 {
		filter.Limit = 100
	}

	// Build WHERE clause
	where := "WHERE tenant_id = $1"
	args := []any{tenantID.String()}
	argNum := 2

	if filter.Status != nil {
		where += fmt.Sprintf(" AND status = $%d", argNum)
		args = append(args, filter.Status.String())
		argNum++
	}
	if filter.EventType != "" {
		where += fmt.Sprintf(" AND event_type = $%d", argNum)
		args = append(args, filter.EventType)
		argNum++
	}
	if filter.AggregateType != "" {
		where += fmt.Sprintf(" AND aggregate_type = $%d", argNum)
		args = append(args, filter.AggregateType)
		argNum++
	}

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM notification_events %s", where)
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count notification events: %w", err)
	}

	// Get paginated results
	query := fmt.Sprintf(`
		SELECT id, tenant_id, event_type, aggregate_type, aggregate_id,
			   title, body, severity, url, metadata,
			   status, integrations_total, integrations_matched,
			   integrations_succeeded, integrations_failed,
			   send_results, last_error, retry_count,
			   created_at, processed_at
		FROM notification_events
		%s
		ORDER BY processed_at DESC
		LIMIT $%d OFFSET $%d
	`, where, argNum, argNum+1)

	args = append(args, filter.Limit, filter.Offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query notification events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	result, err := r.scanEventRows(rows)
	if err != nil {
		return nil, 0, err
	}

	return result, total, nil
}

// GetStats returns aggregated statistics for events.
func (r *OutboxEventRepository) GetStats(ctx context.Context, tenantID *shared.ID) (*outbox.EventStats, error) {
	var query string
	var args []any

	if tenantID != nil {
		query = `
			SELECT
				COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0) as completed,
				COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0) as failed,
				COALESCE(SUM(CASE WHEN status = 'skipped' THEN 1 ELSE 0 END), 0) as skipped,
				COUNT(*) as total
			FROM notification_events
			WHERE tenant_id = $1
		`
		args = []any{tenantID.String()}
	} else {
		query = `
			SELECT
				COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0) as completed,
				COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0) as failed,
				COALESCE(SUM(CASE WHEN status = 'skipped' THEN 1 ELSE 0 END), 0) as skipped,
				COUNT(*) as total
			FROM notification_events
		`
	}

	var stats outbox.EventStats
	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&stats.Completed,
		&stats.Failed,
		&stats.Skipped,
		&stats.Total,
	)
	if err != nil {
		return nil, fmt.Errorf("get event stats: %w", err)
	}

	return &stats, nil
}

// ListByIntegration retrieves events that were sent to a specific integration.
func (r *OutboxEventRepository) ListByIntegration(ctx context.Context, integrationID string, limit, offset int) ([]*outbox.Event, int64, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}

	// Count total using JSONB containment query
	countQuery := `
		SELECT COUNT(*) FROM notification_events
		WHERE send_results @> $1::jsonb
	`
	searchJSON := fmt.Sprintf(`[{"integration_id": %q}]`, integrationID)

	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, searchJSON).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count events by integration: %w", err)
	}

	// Get paginated results
	query := `
		SELECT id, tenant_id, event_type, aggregate_type, aggregate_id,
			   title, body, severity, url, metadata,
			   status, integrations_total, integrations_matched,
			   integrations_succeeded, integrations_failed,
			   send_results, last_error, retry_count,
			   created_at, processed_at
		FROM notification_events
		WHERE send_results @> $1::jsonb
		ORDER BY processed_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.QueryContext(ctx, query, searchJSON, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("query events by integration: %w", err)
	}
	defer func() { _ = rows.Close() }()

	result, err := r.scanEventRows(rows)
	if err != nil {
		return nil, 0, err
	}

	return result, total, nil
}

// =============================================================================
// Cleanup Operations
// =============================================================================

// DeleteOldEvents removes events older than the specified days.
func (r *OutboxEventRepository) DeleteOldEvents(ctx context.Context, retentionDays int) (int64, error) {
	// If retentionDays <= 0, don't delete (unlimited retention)
	if retentionDays <= 0 {
		return 0, nil
	}

	query := `
		DELETE FROM notification_events
		WHERE processed_at < NOW() - INTERVAL '1 day' * $1
	`

	result, err := r.db.ExecContext(ctx, query, retentionDays)
	if err != nil {
		return 0, fmt.Errorf("delete old notification events: %w", err)
	}

	return result.RowsAffected()
}

// =============================================================================
// Scan Helpers
// =============================================================================

func (r *OutboxEventRepository) scanEvent(row *sql.Row) (*outbox.Event, error) {
	var (
		id                    string
		tenantID              string
		eventType             string
		aggregateType         string
		aggregateID           sql.NullString
		title                 string
		body                  sql.NullString
		severity              string
		url                   sql.NullString
		metadata              []byte
		status                string
		integrationsTotal     int
		integrationsMatched   int
		integrationsSucceeded int
		integrationsFailed    int
		sendResults           []byte
		lastError             sql.NullString
		retryCount            int
		createdAt             time.Time
		processedAt           time.Time
	)

	err := row.Scan(
		&id, &tenantID, &eventType, &aggregateType, &aggregateID,
		&title, &body, &severity, &url, &metadata,
		&status, &integrationsTotal, &integrationsMatched,
		&integrationsSucceeded, &integrationsFailed,
		&sendResults, &lastError, &retryCount,
		&createdAt, &processedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, outbox.ErrEventNotFound
		}
		return nil, fmt.Errorf("scan notification event: %w", err)
	}

	return r.mapToEvent(
		id, tenantID, eventType, aggregateType, aggregateID,
		title, body, severity, url, metadata,
		status, integrationsTotal, integrationsMatched,
		integrationsSucceeded, integrationsFailed,
		sendResults, lastError, retryCount,
		createdAt, processedAt,
	)
}

func (r *OutboxEventRepository) scanEventRows(rows *sql.Rows) ([]*outbox.Event, error) {
	result := make([]*outbox.Event, 0)

	for rows.Next() {
		var (
			id                    string
			tenantID              string
			eventType             string
			aggregateType         string
			aggregateID           sql.NullString
			title                 string
			body                  sql.NullString
			severity              string
			url                   sql.NullString
			metadata              []byte
			status                string
			integrationsTotal     int
			integrationsMatched   int
			integrationsSucceeded int
			integrationsFailed    int
			sendResults           []byte
			lastError             sql.NullString
			retryCount            int
			createdAt             time.Time
			processedAt           time.Time
		)

		err := rows.Scan(
			&id, &tenantID, &eventType, &aggregateType, &aggregateID,
			&title, &body, &severity, &url, &metadata,
			&status, &integrationsTotal, &integrationsMatched,
			&integrationsSucceeded, &integrationsFailed,
			&sendResults, &lastError, &retryCount,
			&createdAt, &processedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan notification event row: %w", err)
		}

		event, err := r.mapToEvent(
			id, tenantID, eventType, aggregateType, aggregateID,
			title, body, severity, url, metadata,
			status, integrationsTotal, integrationsMatched,
			integrationsSucceeded, integrationsFailed,
			sendResults, lastError, retryCount,
			createdAt, processedAt,
		)
		if err != nil {
			continue // Skip invalid rows
		}
		result = append(result, event)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate notification event rows: %w", err)
	}

	return result, nil
}

func (r *OutboxEventRepository) mapToEvent(
	idStr, tenantIDStr, eventType, aggregateType string,
	aggregateIDNull sql.NullString,
	title string, body sql.NullString, severity string, url sql.NullString,
	metadataBytes []byte,
	status string,
	integrationsTotal, integrationsMatched, integrationsSucceeded, integrationsFailed int,
	sendResultsBytes []byte, lastError sql.NullString, retryCount int,
	createdAt, processedAt time.Time,
) (*outbox.Event, error) {
	id, err := outbox.ParseID(idStr)
	if err != nil {
		return nil, fmt.Errorf("parse id: %w", err)
	}

	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return nil, fmt.Errorf("parse tenant_id: %w", err)
	}

	var aggregateID *uuid.UUID
	if aggregateIDNull.Valid {
		parsed, err := uuid.Parse(aggregateIDNull.String)
		if err == nil {
			aggregateID = &parsed
		}
	}

	var metadata map[string]any
	if len(metadataBytes) > 0 {
		if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
			metadata = make(map[string]any)
		}
	} else {
		metadata = make(map[string]any)
	}

	var sendResults []outbox.SendResult
	if len(sendResultsBytes) > 0 {
		if err := json.Unmarshal(sendResultsBytes, &sendResults); err != nil {
			sendResults = make([]outbox.SendResult, 0)
		}
	} else {
		sendResults = make([]outbox.SendResult, 0)
	}

	return outbox.ReconstituteEvent(
		id,
		tenantID,
		eventType,
		aggregateType,
		aggregateID,
		title,
		body.String,
		outbox.Severity(severity),
		url.String,
		metadata,
		outbox.EventStatus(status),
		integrationsTotal,
		integrationsMatched,
		integrationsSucceeded,
		integrationsFailed,
		sendResults,
		lastError.String,
		retryCount,
		createdAt,
		processedAt,
	), nil
}
