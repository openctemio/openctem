package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/webhook"
)

// WebhookRepository is the PostgreSQL implementation of webhook.Repository.
type WebhookRepository struct {
	db *DB
}

// NewWebhookRepository creates a new WebhookRepository.
func NewWebhookRepository(db *DB) *WebhookRepository {
	return &WebhookRepository{db: db}
}

var _ webhook.Repository = (*WebhookRepository)(nil)

// Create inserts a new webhook.
func (r *WebhookRepository) Create(ctx context.Context, w *webhook.Webhook) error {
	query := `
		INSERT INTO webhooks (
			id, tenant_id, name, description, url, secret_encrypted,
			event_types, severity_threshold, asset_group_ids, tags,
			status, max_retries, retry_interval_seconds,
			created_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
		)
	`

	var createdBy *string
	if w.CreatedBy() != nil {
		s := w.CreatedBy().String()
		createdBy = &s
	}

	// Convert asset_group_ids []string to []uuid for postgres
	var assetGroupIDs pq.StringArray = w.AssetGroupIDs()

	_, err := r.db.ExecContext(ctx, query,
		w.ID().String(),
		w.TenantID().String(),
		w.Name(),
		w.Description(),
		w.URL(),
		w.SecretEncrypted(),
		pq.Array(w.EventTypes()),
		w.SeverityThreshold(),
		assetGroupIDs,
		pq.Array(w.Tags()),
		string(w.Status()),
		w.MaxRetries(),
		w.RetryIntervalSeconds(),
		createdBy,
		w.CreatedAt(),
		w.UpdatedAt(),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return webhook.ErrWebhookNameExists
		}
		return fmt.Errorf("create webhook: %w", err)
	}
	return nil
}

// GetByID retrieves a webhook by ID and tenant.
func (r *WebhookRepository) GetByID(ctx context.Context, id, tenantID webhook.ID) (*webhook.Webhook, error) {
	query := `
		SELECT id, tenant_id, name, description, url, secret_encrypted,
			event_types, severity_threshold, asset_group_ids, tags,
			status, max_retries, retry_interval_seconds,
			total_sent, total_failed, last_sent_at, last_error, last_error_at,
			created_by, created_at, updated_at
		FROM webhooks WHERE id = $1 AND tenant_id = $2
	`
	row := r.db.QueryRowContext(ctx, query, id.String(), tenantID.String())
	return r.scanWebhook(row)
}

// List retrieves a paginated list of webhooks.
func (r *WebhookRepository) List(ctx context.Context, filter webhook.Filter) (webhook.ListResult, error) {
	result := webhook.ListResult{
		Data:    make([]*webhook.Webhook, 0),
		Page:    filter.Page,
		PerPage: filter.PerPage,
	}

	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.PerPage < 1 {
		filter.PerPage = 20
	}

	conditions := make([]string, 0)
	args := make([]any, 0)
	argIdx := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIdx))
		args = append(args, filter.TenantID.String())
		argIdx++
	}

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, string(*filter.Status))
		argIdx++
	}

	if filter.EventType != "" {
		conditions = append(conditions, fmt.Sprintf("$%d = ANY(event_types)", argIdx))
		args = append(args, filter.EventType)
		argIdx++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argIdx, argIdx))
		args = append(args, wrapLikePattern(filter.Search))
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count
	countQuery := "SELECT COUNT(*) FROM webhooks " + whereClause
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&result.Total); err != nil {
		return result, fmt.Errorf("count webhooks: %w", err)
	}

	result.TotalPages = int((result.Total + int64(filter.PerPage) - 1) / int64(filter.PerPage))
	result.Page = filter.Page

	// Sort
	orderBy := "created_at DESC"
	if filter.SortBy != "" {
		validFields := map[string]bool{"name": true, "status": true, "created_at": true, "last_sent_at": true}
		if validFields[filter.SortBy] {
			order := "ASC"
			if strings.EqualFold(filter.SortOrder, "desc") {
				order = "DESC"
			}
			orderBy = filter.SortBy + " " + order
		}
	}

	offset := (filter.Page - 1) * filter.PerPage
	args = append(args, filter.PerPage, offset)

	query := fmt.Sprintf(`
		SELECT id, tenant_id, name, description, url, secret_encrypted,
			event_types, severity_threshold, asset_group_ids, tags,
			status, max_retries, retry_interval_seconds,
			total_sent, total_failed, last_sent_at, last_error, last_error_at,
			created_by, created_at, updated_at
		FROM webhooks
		%s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, argIdx, argIdx+1)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return result, fmt.Errorf("list webhooks: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		w, err := r.scanWebhookRow(rows)
		if err != nil {
			return result, err
		}
		result.Data = append(result.Data, w)
	}

	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("iterate webhook rows: %w", err)
	}

	return result, nil
}

// Update updates a webhook.
func (r *WebhookRepository) Update(ctx context.Context, w *webhook.Webhook) error {
	query := `
		UPDATE webhooks SET
			name = $2, description = $3, url = $4, secret_encrypted = $5,
			event_types = $6, severity_threshold = $7,
			status = $8, max_retries = $9, retry_interval_seconds = $10,
			updated_at = $11
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		w.ID().String(),
		w.Name(),
		w.Description(),
		w.URL(),
		w.SecretEncrypted(),
		pq.Array(w.EventTypes()),
		w.SeverityThreshold(),
		string(w.Status()),
		w.MaxRetries(),
		w.RetryIntervalSeconds(),
		w.UpdatedAt(),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return webhook.ErrWebhookNameExists
		}
		return fmt.Errorf("update webhook: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return webhook.ErrWebhookNotFound
	}
	return nil
}

// Delete deletes a webhook by ID and tenant.
func (r *WebhookRepository) Delete(ctx context.Context, id, tenantID webhook.ID) error {
	query := `DELETE FROM webhooks WHERE id = $1 AND tenant_id = $2`
	result, err := r.db.ExecContext(ctx, query, id.String(), tenantID.String())
	if err != nil {
		return fmt.Errorf("delete webhook: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return webhook.ErrWebhookNotFound
	}
	return nil
}

// ListDeliveries retrieves a paginated list of webhook deliveries.
func (r *WebhookRepository) ListDeliveries(ctx context.Context, filter webhook.DeliveryFilter) (webhook.DeliveryListResult, error) {
	result := webhook.DeliveryListResult{
		Data:    make([]*webhook.Delivery, 0),
		Page:    filter.Page,
		PerPage: filter.PerPage,
	}

	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.PerPage < 1 {
		filter.PerPage = 20
	}

	conditions := make([]string, 0)
	args := make([]any, 0)
	argIdx := 1

	if filter.WebhookID != nil {
		conditions = append(conditions, fmt.Sprintf("webhook_id = $%d", argIdx))
		args = append(args, filter.WebhookID.String())
		argIdx++
	}

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, string(*filter.Status))
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := "SELECT COUNT(*) FROM webhook_deliveries " + whereClause
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&result.Total); err != nil {
		return result, fmt.Errorf("count deliveries: %w", err)
	}

	result.TotalPages = int((result.Total + int64(filter.PerPage) - 1) / int64(filter.PerPage))
	result.Page = filter.Page

	offset := (filter.Page - 1) * filter.PerPage
	args = append(args, filter.PerPage, offset)

	query := fmt.Sprintf(`
		SELECT id, webhook_id, event_id, event_type, payload,
			status, response_code, response_body, response_headers,
			attempt, next_retry_at, error_message,
			created_at, delivered_at, duration_ms
		FROM webhook_deliveries
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return result, fmt.Errorf("list deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		d, err := r.scanDeliveryRow(rows)
		if err != nil {
			return result, err
		}
		result.Data = append(result.Data, d)
	}

	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("iterate delivery rows: %w", err)
	}

	return result, nil
}

// --- Scan Helpers ---

func (r *WebhookRepository) scanWebhook(row *sql.Row) (*webhook.Webhook, error) {
	var (
		id, tenantID           string
		name                   string
		description            sql.NullString
		url                    string
		secretEncrypted        []byte
		eventTypes             pq.StringArray
		severityThreshold      string
		assetGroupIDs, tags    pq.StringArray
		status                 string
		maxRetries             int
		retryIntervalSeconds   int
		totalSent, totalFailed int
		lastSentAt             sql.NullTime
		lastError              sql.NullString
		lastErrorAt            sql.NullTime
		createdBy              sql.NullString
		createdAt, updatedAt   time.Time
	)

	err := row.Scan(
		&id, &tenantID, &name, &description, &url, &secretEncrypted,
		&eventTypes, &severityThreshold, &assetGroupIDs, &tags,
		&status, &maxRetries, &retryIntervalSeconds,
		&totalSent, &totalFailed, &lastSentAt, &lastError, &lastErrorAt,
		&createdBy, &createdAt, &updatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, webhook.ErrWebhookNotFound
		}
		return nil, fmt.Errorf("scan webhook: %w", err)
	}

	return r.reconstructWebhook(id, tenantID, name, description.String, url, secretEncrypted,
		[]string(eventTypes), severityThreshold, []string(assetGroupIDs), []string(tags),
		status, maxRetries, retryIntervalSeconds,
		totalSent, totalFailed, lastSentAt, lastError, lastErrorAt,
		createdBy, createdAt, updatedAt)
}

func (r *WebhookRepository) scanWebhookRow(rows *sql.Rows) (*webhook.Webhook, error) {
	var (
		id, tenantID           string
		name                   string
		description            sql.NullString
		url                    string
		secretEncrypted        []byte
		eventTypes             pq.StringArray
		severityThreshold      string
		assetGroupIDs, tags    pq.StringArray
		status                 string
		maxRetries             int
		retryIntervalSeconds   int
		totalSent, totalFailed int
		lastSentAt             sql.NullTime
		lastError              sql.NullString
		lastErrorAt            sql.NullTime
		createdBy              sql.NullString
		createdAt, updatedAt   time.Time
	)

	err := rows.Scan(
		&id, &tenantID, &name, &description, &url, &secretEncrypted,
		&eventTypes, &severityThreshold, &assetGroupIDs, &tags,
		&status, &maxRetries, &retryIntervalSeconds,
		&totalSent, &totalFailed, &lastSentAt, &lastError, &lastErrorAt,
		&createdBy, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan webhook row: %w", err)
	}

	return r.reconstructWebhook(id, tenantID, name, description.String, url, secretEncrypted,
		[]string(eventTypes), severityThreshold, []string(assetGroupIDs), []string(tags),
		status, maxRetries, retryIntervalSeconds,
		totalSent, totalFailed, lastSentAt, lastError, lastErrorAt,
		createdBy, createdAt, updatedAt)
}

func (r *WebhookRepository) reconstructWebhook(
	id, tenantID, name, description, url string,
	secretEncrypted []byte,
	eventTypes []string, severityThreshold string,
	assetGroupIDs, tags []string,
	status string,
	maxRetries, retryIntervalSeconds int,
	totalSent, totalFailed int,
	lastSentAt sql.NullTime,
	lastError sql.NullString,
	lastErrorAt sql.NullTime,
	createdBy sql.NullString,
	createdAt, updatedAt time.Time,
) (*webhook.Webhook, error) {
	wID, _ := shared.IDFromString(id)
	wTenantID, _ := shared.IDFromString(tenantID)

	var lsAt *time.Time
	if lastSentAt.Valid {
		lsAt = &lastSentAt.Time
	}

	var leAt *time.Time
	if lastErrorAt.Valid {
		leAt = &lastErrorAt.Time
	}

	le := ""
	if lastError.Valid {
		le = lastError.String
	}

	var cbID *shared.ID
	if createdBy.Valid {
		c, _ := shared.IDFromString(createdBy.String)
		cbID = &c
	}

	return webhook.Reconstruct(
		wID, wTenantID,
		name, description, url, secretEncrypted,
		eventTypes, severityThreshold, assetGroupIDs, tags,
		webhook.Status(status),
		maxRetries, retryIntervalSeconds,
		totalSent, totalFailed, lsAt, le, leAt,
		cbID, createdAt, updatedAt,
	), nil
}

func (r *WebhookRepository) scanDeliveryRow(rows *sql.Rows) (*webhook.Delivery, error) {
	var (
		id, webhookID   string
		eventID         sql.NullString
		eventType       string
		payloadJSON     []byte
		status          string
		responseCode    sql.NullInt32
		responseBody    sql.NullString
		responseHeaders []byte
		attempt         int
		nextRetryAt     sql.NullTime
		errorMessage    sql.NullString
		createdAt       time.Time
		deliveredAt     sql.NullTime
		durationMs      sql.NullInt32
	)

	err := rows.Scan(
		&id, &webhookID, &eventID, &eventType, &payloadJSON,
		&status, &responseCode, &responseBody, &responseHeaders,
		&attempt, &nextRetryAt, &errorMessage,
		&createdAt, &deliveredAt, &durationMs,
	)
	if err != nil {
		return nil, fmt.Errorf("scan delivery row: %w", err)
	}

	dID, _ := shared.IDFromString(id)
	dWebhookID, _ := shared.IDFromString(webhookID)

	d := &webhook.Delivery{
		ID:        dID,
		WebhookID: dWebhookID,
		EventType: eventType,
		Status:    webhook.DeliveryStatus(status),
		Attempt:   attempt,
		CreatedAt: createdAt,
	}

	if eventID.Valid {
		eid, _ := shared.IDFromString(eventID.String)
		d.EventID = &eid
	}

	if len(payloadJSON) > 0 {
		var payload map[string]any
		if err := json.Unmarshal(payloadJSON, &payload); err == nil {
			d.Payload = payload
		}
	}

	if responseCode.Valid {
		rc := int(responseCode.Int32)
		d.ResponseCode = &rc
	}

	if responseBody.Valid {
		d.ResponseBody = responseBody.String
	}

	if len(responseHeaders) > 0 {
		var headers map[string]any
		if err := json.Unmarshal(responseHeaders, &headers); err == nil {
			d.ResponseHeaders = headers
		}
	}

	if nextRetryAt.Valid {
		d.NextRetryAt = &nextRetryAt.Time
	}

	if errorMessage.Valid {
		d.ErrorMessage = errorMessage.String
	}

	if deliveredAt.Valid {
		d.DeliveredAt = &deliveredAt.Time
	}

	if durationMs.Valid {
		dm := int(durationMs.Int32)
		d.DurationMs = &dm
	}

	return d, nil
}
