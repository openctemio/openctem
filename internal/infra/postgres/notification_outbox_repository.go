package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/openctemio/api/pkg/domain/notification"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// NotificationOutboxRepository implements the notification.OutboxRepository interface.
type NotificationOutboxRepository struct {
	db *DB
}

// NewNotificationOutboxRepository creates a new NotificationOutboxRepository.
func NewNotificationOutboxRepository(db *DB) *NotificationOutboxRepository {
	return &NotificationOutboxRepository{db: db}
}

// =============================================================================
// Basic CRUD
// =============================================================================

// Create inserts a new outbox entry.
func (r *NotificationOutboxRepository) Create(ctx context.Context, outbox *notification.Outbox) error {
	return r.createWithExecutor(ctx, r.db, outbox)
}

// CreateInTx inserts a new outbox entry within an existing transaction.
func (r *NotificationOutboxRepository) CreateInTx(ctx context.Context, tx *sql.Tx, outbox *notification.Outbox) error {
	return r.createWithExecutor(ctx, tx, outbox)
}

// executor interface for both *DB and *sql.Tx
type executor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func (r *NotificationOutboxRepository) createWithExecutor(ctx context.Context, exec executor, outbox *notification.Outbox) error {
	metadata, err := json.Marshal(outbox.Metadata())
	if err != nil {
		metadata = []byte("{}")
	}

	var aggregateID *string
	if outbox.AggregateID() != nil {
		s := outbox.AggregateID().String()
		aggregateID = &s
	}

	query := `
		INSERT INTO notification_outbox (
			id, tenant_id, event_type, aggregate_type, aggregate_id,
			title, body, severity, url, metadata,
			status, retry_count, max_retries, last_error,
			scheduled_at, locked_at, locked_by,
			created_at, updated_at, processed_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10,
			$11, $12, $13, $14,
			$15, $16, $17,
			$18, $19, $20
		)
	`

	_, err = exec.ExecContext(ctx, query,
		outbox.ID().String(),
		outbox.TenantID().String(),
		outbox.EventType(),
		outbox.AggregateType(),
		aggregateID,
		outbox.Title(),
		nullableString(outbox.Body()),
		outbox.Severity().String(),
		nullableString(outbox.URL()),
		metadata,
		outbox.Status().String(),
		outbox.RetryCount(),
		outbox.MaxRetries(),
		nullableString(outbox.LastError()),
		outbox.ScheduledAt(),
		outbox.LockedAt(),
		nullableString(outbox.LockedBy()),
		outbox.CreatedAt(),
		outbox.UpdatedAt(),
		outbox.ProcessedAt(),
	)
	if err != nil {
		return fmt.Errorf("insert notification outbox: %w", err)
	}

	return nil
}

// GetByID retrieves an outbox entry by ID.
func (r *NotificationOutboxRepository) GetByID(ctx context.Context, id notification.ID) (*notification.Outbox, error) {
	query := `
		SELECT id, tenant_id, event_type, aggregate_type, aggregate_id,
			   title, body, severity, url, metadata,
			   status, retry_count, max_retries, last_error,
			   scheduled_at, locked_at, locked_by,
			   created_at, updated_at, processed_at
		FROM notification_outbox
		WHERE id = $1
	`

	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanOutbox(row)
}

// Update updates an outbox entry.
func (r *NotificationOutboxRepository) Update(ctx context.Context, outbox *notification.Outbox) error {
	metadata, err := json.Marshal(outbox.Metadata())
	if err != nil {
		metadata = []byte("{}")
	}

	query := `
		UPDATE notification_outbox
		SET status = $2, retry_count = $3, last_error = $4,
			scheduled_at = $5, locked_at = $6, locked_by = $7,
			updated_at = $8, processed_at = $9, metadata = $10
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		outbox.ID().String(),
		outbox.Status().String(),
		outbox.RetryCount(),
		nullableString(outbox.LastError()),
		outbox.ScheduledAt(),
		outbox.LockedAt(),
		nullableString(outbox.LockedBy()),
		outbox.UpdatedAt(),
		outbox.ProcessedAt(),
		metadata,
	)
	if err != nil {
		return fmt.Errorf("update notification outbox: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rows == 0 {
		return notification.ErrOutboxNotFound
	}

	return nil
}

// Delete removes an outbox entry.
func (r *NotificationOutboxRepository) Delete(ctx context.Context, id notification.ID) error {
	query := `DELETE FROM notification_outbox WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("delete notification outbox: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rows == 0 {
		return notification.ErrOutboxNotFound
	}

	return nil
}

// =============================================================================
// Worker Operations
// =============================================================================

// FetchPendingBatch retrieves and locks a batch of pending outbox entries.
// Uses FOR UPDATE SKIP LOCKED for concurrent worker safety.
func (r *NotificationOutboxRepository) FetchPendingBatch(ctx context.Context, workerID string, batchSize int) ([]*notification.Outbox, error) {
	if batchSize <= 0 {
		batchSize = 50
	}
	if batchSize > 100 {
		batchSize = 100
	}

	now := time.Now()

	// Use a transaction to atomically select and lock rows
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Select pending entries that are ready to process
	// FOR UPDATE SKIP LOCKED ensures concurrent workers don't pick the same rows
	selectQuery := `
		SELECT id, tenant_id, event_type, aggregate_type, aggregate_id,
			   title, body, severity, url, metadata,
			   status, retry_count, max_retries, last_error,
			   scheduled_at, locked_at, locked_by,
			   created_at, updated_at, processed_at
		FROM notification_outbox
		WHERE status = 'pending' AND scheduled_at <= $1
		ORDER BY scheduled_at ASC, created_at ASC
		LIMIT $2
		FOR UPDATE SKIP LOCKED
	`

	rows, err := tx.QueryContext(ctx, selectQuery, now, batchSize)
	if err != nil {
		return nil, fmt.Errorf("query pending outbox: %w", err)
	}

	outboxes, err := r.scanOutboxRows(rows)
	if err != nil {
		return nil, err
	}

	if len(outboxes) == 0 {
		return outboxes, nil
	}

	// Collect IDs for batch update
	ids := make([]string, len(outboxes))
	for i, o := range outboxes {
		ids[i] = o.ID().String()
	}

	// Update all selected rows to 'processing' status
	updateQuery := `
		UPDATE notification_outbox
		SET status = 'processing', locked_at = $1, locked_by = $2, updated_at = $1
		WHERE id = ANY($3)
	`

	_, err = tx.ExecContext(ctx, updateQuery, now, workerID, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("lock outbox entries: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	// Update the in-memory objects to reflect the lock
	for _, o := range outboxes {
		_ = o.Lock(workerID)
	}

	return outboxes, nil
}

// UnlockStale releases locks on entries that have been processing for too long.
func (r *NotificationOutboxRepository) UnlockStale(ctx context.Context, olderThanMinutes int) (int64, error) {
	if olderThanMinutes <= 0 {
		olderThanMinutes = 5 // Default 5 minutes
	}

	query := `
		UPDATE notification_outbox
		SET status = 'pending', locked_at = NULL, locked_by = NULL, updated_at = NOW()
		WHERE status = 'processing'
		AND locked_at < NOW() - INTERVAL '1 minute' * $1
	`

	result, err := r.db.ExecContext(ctx, query, olderThanMinutes)
	if err != nil {
		return 0, fmt.Errorf("unlock stale outbox entries: %w", err)
	}

	return result.RowsAffected()
}

// =============================================================================
// Cleanup Operations
// =============================================================================

// DeleteOldCompleted removes completed entries older than the specified days.
func (r *NotificationOutboxRepository) DeleteOldCompleted(ctx context.Context, olderThanDays int) (int64, error) {
	if olderThanDays <= 0 {
		olderThanDays = 7 // Default 7 days
	}

	query := `
		DELETE FROM notification_outbox
		WHERE status = 'completed'
		AND processed_at < NOW() - INTERVAL '1 day' * $1
	`

	result, err := r.db.ExecContext(ctx, query, olderThanDays)
	if err != nil {
		return 0, fmt.Errorf("delete old completed outbox entries: %w", err)
	}

	return result.RowsAffected()
}

// DeleteOldFailed removes failed/dead entries older than the specified days.
func (r *NotificationOutboxRepository) DeleteOldFailed(ctx context.Context, olderThanDays int) (int64, error) {
	if olderThanDays <= 0 {
		olderThanDays = 30 // Default 30 days for failed entries (longer for debugging)
	}

	query := `
		DELETE FROM notification_outbox
		WHERE status IN ('failed', 'dead')
		AND processed_at < NOW() - INTERVAL '1 day' * $1
	`

	result, err := r.db.ExecContext(ctx, query, olderThanDays)
	if err != nil {
		return 0, fmt.Errorf("delete old failed outbox entries: %w", err)
	}

	return result.RowsAffected()
}

// =============================================================================
// Query Operations
// =============================================================================

// List retrieves outbox entries with filtering and pagination.
func (r *NotificationOutboxRepository) List(ctx context.Context, filter notification.OutboxFilter, page pagination.Pagination) (pagination.Result[*notification.Outbox], error) {
	// Build WHERE clause
	where := "WHERE 1=1"
	args := make([]any, 0)
	argNum := 1

	if filter.TenantID != nil {
		where += fmt.Sprintf(" AND tenant_id = $%d", argNum)
		args = append(args, filter.TenantID.String())
		argNum++
	}
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
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM notification_outbox %s", where)
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return pagination.Result[*notification.Outbox]{}, fmt.Errorf("count notification outbox: %w", err)
	}

	// Get paginated results
	query := fmt.Sprintf(`
		SELECT id, tenant_id, event_type, aggregate_type, aggregate_id,
			   title, body, severity, url, metadata,
			   status, retry_count, max_retries, last_error,
			   scheduled_at, locked_at, locked_by,
			   created_at, updated_at, processed_at
		FROM notification_outbox
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, argNum, argNum+1)

	args = append(args, page.Limit(), page.Offset())

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*notification.Outbox]{}, fmt.Errorf("query notification outbox: %w", err)
	}
	defer func() { _ = rows.Close() }()

	data, err := r.scanOutboxRows(rows)
	if err != nil {
		return pagination.Result[*notification.Outbox]{}, err
	}

	return pagination.NewResult(data, total, page), nil
}

// GetStats returns aggregated statistics for outbox entries.
func (r *NotificationOutboxRepository) GetStats(ctx context.Context, tenantID *shared.ID) (*notification.OutboxStats, error) {
	var query string
	var args []any

	if tenantID != nil {
		query = `
			SELECT
				COALESCE(SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END), 0) as pending,
				COALESCE(SUM(CASE WHEN status = 'processing' THEN 1 ELSE 0 END), 0) as processing,
				COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0) as completed,
				COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0) as failed,
				COALESCE(SUM(CASE WHEN status = 'dead' THEN 1 ELSE 0 END), 0) as dead,
				COUNT(*) as total
			FROM notification_outbox
			WHERE tenant_id = $1
		`
		args = []any{tenantID.String()}
	} else {
		query = `
			SELECT
				COALESCE(SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END), 0) as pending,
				COALESCE(SUM(CASE WHEN status = 'processing' THEN 1 ELSE 0 END), 0) as processing,
				COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0) as completed,
				COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0) as failed,
				COALESCE(SUM(CASE WHEN status = 'dead' THEN 1 ELSE 0 END), 0) as dead,
				COUNT(*) as total
			FROM notification_outbox
		`
	}

	var stats notification.OutboxStats
	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&stats.Pending,
		&stats.Processing,
		&stats.Completed,
		&stats.Failed,
		&stats.Dead,
		&stats.Total,
	)
	if err != nil {
		return nil, fmt.Errorf("get outbox stats: %w", err)
	}

	return &stats, nil
}

// ListByTenant retrieves outbox entries for a tenant with pagination.
func (r *NotificationOutboxRepository) ListByTenant(ctx context.Context, tenantID shared.ID, filter notification.OutboxFilter) ([]*notification.Outbox, int64, error) {
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
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM notification_outbox %s", where)
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count notification outbox: %w", err)
	}

	// Get paginated results
	query := fmt.Sprintf(`
		SELECT id, tenant_id, event_type, aggregate_type, aggregate_id,
			   title, body, severity, url, metadata,
			   status, retry_count, max_retries, last_error,
			   scheduled_at, locked_at, locked_by,
			   created_at, updated_at, processed_at
		FROM notification_outbox
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, argNum, argNum+1)

	args = append(args, filter.Limit, filter.Offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query notification outbox: %w", err)
	}
	defer func() { _ = rows.Close() }()

	result, err := r.scanOutboxRows(rows)
	if err != nil {
		return nil, 0, err
	}

	return result, total, nil
}

// CountByStatus returns counts grouped by status for a tenant.
func (r *NotificationOutboxRepository) CountByStatus(ctx context.Context, tenantID shared.ID) (map[notification.OutboxStatus]int64, error) {
	query := `
		SELECT status, COUNT(*) as count
		FROM notification_outbox
		WHERE tenant_id = $1
		GROUP BY status
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("count notification outbox by status: %w", err)
	}
	defer func() { _ = rows.Close() }()

	result := make(map[notification.OutboxStatus]int64)
	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("scan status count: %w", err)
		}
		result[notification.OutboxStatus(status)] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate status counts: %w", err)
	}

	return result, nil
}

// GetByAggregateID retrieves outbox entries for a specific aggregate.
func (r *NotificationOutboxRepository) GetByAggregateID(ctx context.Context, aggregateType string, aggregateID string) ([]*notification.Outbox, error) {
	query := `
		SELECT id, tenant_id, event_type, aggregate_type, aggregate_id,
			   title, body, severity, url, metadata,
			   status, retry_count, max_retries, last_error,
			   scheduled_at, locked_at, locked_by,
			   created_at, updated_at, processed_at
		FROM notification_outbox
		WHERE aggregate_type = $1 AND aggregate_id = $2
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, aggregateType, aggregateID)
	if err != nil {
		return nil, fmt.Errorf("query notification outbox by aggregate: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return r.scanOutboxRows(rows)
}

// =============================================================================
// Scan Helpers
// =============================================================================

func (r *NotificationOutboxRepository) scanOutbox(row *sql.Row) (*notification.Outbox, error) {
	var (
		id            string
		tenantID      string
		eventType     string
		aggregateType string
		aggregateID   sql.NullString
		title         string
		body          sql.NullString
		severity      string
		url           sql.NullString
		metadata      []byte
		status        string
		retryCount    int
		maxRetries    int
		lastError     sql.NullString
		scheduledAt   time.Time
		lockedAt      sql.NullTime
		lockedBy      sql.NullString
		createdAt     time.Time
		updatedAt     time.Time
		processedAt   sql.NullTime
	)

	err := row.Scan(
		&id, &tenantID, &eventType, &aggregateType, &aggregateID,
		&title, &body, &severity, &url, &metadata,
		&status, &retryCount, &maxRetries, &lastError,
		&scheduledAt, &lockedAt, &lockedBy,
		&createdAt, &updatedAt, &processedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, notification.ErrOutboxNotFound
		}
		return nil, fmt.Errorf("scan notification outbox: %w", err)
	}

	return r.mapToOutbox(
		id, tenantID, eventType, aggregateType, aggregateID,
		title, body, severity, url, metadata,
		status, retryCount, maxRetries, lastError,
		scheduledAt, lockedAt, lockedBy,
		createdAt, updatedAt, processedAt,
	)
}

func (r *NotificationOutboxRepository) scanOutboxRows(rows *sql.Rows) ([]*notification.Outbox, error) {
	result := make([]*notification.Outbox, 0)

	for rows.Next() {
		var (
			id            string
			tenantID      string
			eventType     string
			aggregateType string
			aggregateID   sql.NullString
			title         string
			body          sql.NullString
			severity      string
			url           sql.NullString
			metadata      []byte
			status        string
			retryCount    int
			maxRetries    int
			lastError     sql.NullString
			scheduledAt   time.Time
			lockedAt      sql.NullTime
			lockedBy      sql.NullString
			createdAt     time.Time
			updatedAt     time.Time
			processedAt   sql.NullTime
		)

		err := rows.Scan(
			&id, &tenantID, &eventType, &aggregateType, &aggregateID,
			&title, &body, &severity, &url, &metadata,
			&status, &retryCount, &maxRetries, &lastError,
			&scheduledAt, &lockedAt, &lockedBy,
			&createdAt, &updatedAt, &processedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan notification outbox row: %w", err)
		}

		outbox, err := r.mapToOutbox(
			id, tenantID, eventType, aggregateType, aggregateID,
			title, body, severity, url, metadata,
			status, retryCount, maxRetries, lastError,
			scheduledAt, lockedAt, lockedBy,
			createdAt, updatedAt, processedAt,
		)
		if err != nil {
			continue // Skip invalid rows
		}
		result = append(result, outbox)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate notification outbox rows: %w", err)
	}

	return result, nil
}

func (r *NotificationOutboxRepository) mapToOutbox(
	idStr, tenantIDStr, eventType, aggregateType string,
	aggregateIDNull sql.NullString,
	title string, body sql.NullString, severity string, url sql.NullString,
	metadataBytes []byte,
	status string, retryCount, maxRetries int, lastError sql.NullString,
	scheduledAt time.Time, lockedAt sql.NullTime, lockedBy sql.NullString,
	createdAt, updatedAt time.Time, processedAt sql.NullTime,
) (*notification.Outbox, error) {
	id, err := notification.ParseID(idStr)
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

	var lockedAtPtr *time.Time
	if lockedAt.Valid {
		lockedAtPtr = &lockedAt.Time
	}

	var processedAtPtr *time.Time
	if processedAt.Valid {
		processedAtPtr = &processedAt.Time
	}

	return notification.Reconstitute(
		id,
		tenantID,
		eventType,
		aggregateType,
		aggregateID,
		title,
		body.String,
		notification.Severity(severity),
		url.String,
		metadata,
		notification.OutboxStatus(status),
		retryCount,
		maxRetries,
		lastError.String,
		scheduledAt,
		lockedAtPtr,
		lockedBy.String,
		createdAt,
		updatedAt,
		processedAtPtr,
	), nil
}
