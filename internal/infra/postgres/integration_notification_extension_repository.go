package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/shared"
)

// IntegrationNotificationExtensionRepository implements integration.NotificationExtensionRepository using PostgreSQL.
type IntegrationNotificationExtensionRepository struct {
	db              *DB
	integrationRepo *IntegrationRepository
}

// NewIntegrationNotificationExtensionRepository creates a new IntegrationNotificationExtensionRepository.
func NewIntegrationNotificationExtensionRepository(db *DB, integrationRepo *IntegrationRepository) *IntegrationNotificationExtensionRepository {
	return &IntegrationNotificationExtensionRepository{
		db:              db,
		integrationRepo: integrationRepo,
	}
}

// Ensure IntegrationNotificationExtensionRepository implements integration.NotificationExtensionRepository
var _ integration.NotificationExtensionRepository = (*IntegrationNotificationExtensionRepository)(nil)

// Create creates a new notification extension.
func (r *IntegrationNotificationExtensionRepository) Create(ctx context.Context, ext *integration.NotificationExtension) error {
	// Convert severities to JSON
	severitiesJSON, err := json.Marshal(ext.EnabledSeverities())
	if err != nil {
		return fmt.Errorf("marshal severities: %w", err)
	}

	// Convert event types to JSON
	eventTypesJSON, err := json.Marshal(ext.EnabledEventTypes())
	if err != nil {
		return fmt.Errorf("marshal event types: %w", err)
	}

	// Note: channel_id and channel_name are now stored in integrations.metadata
	query := `
		INSERT INTO integration_notification_extensions (
			integration_id,
			enabled_severities, enabled_event_types,
			message_template, include_details, min_interval_minutes
		) VALUES (
			$1, $2, $3, $4, $5, $6
		)
	`

	_, err = r.db.ExecContext(ctx, query,
		ext.IntegrationID().String(),
		severitiesJSON,
		eventTypesJSON,
		ext.MessageTemplate(),
		ext.IncludeDetails(),
		ext.MinIntervalMinutes(),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return shared.ErrAlreadyExists
		}
		return fmt.Errorf("create notification extension: %w", err)
	}

	return nil
}

// GetByIntegrationID retrieves a notification extension by integration ID.
// Note: channel_id and channel_name are now stored in integrations.metadata.
func (r *IntegrationNotificationExtensionRepository) GetByIntegrationID(ctx context.Context, integrationID integration.ID) (*integration.NotificationExtension, error) {
	query := `
		SELECT integration_id,
			   COALESCE(enabled_severities, '["critical", "high"]'::jsonb),
			   COALESCE(enabled_event_types, '["security_alert", "new_finding", "new_exposure"]'::jsonb),
			   message_template, include_details, min_interval_minutes
		FROM integration_notification_extensions
		WHERE integration_id = $1
	`

	row := r.db.QueryRowContext(ctx, query, integrationID.String())
	return r.scanNotificationExtension(row)
}

// Update updates an existing notification extension.
func (r *IntegrationNotificationExtensionRepository) Update(ctx context.Context, ext *integration.NotificationExtension) error {
	// Convert severities to JSON
	severitiesJSON, err := json.Marshal(ext.EnabledSeverities())
	if err != nil {
		return fmt.Errorf("marshal severities: %w", err)
	}

	// Convert event types to JSON
	eventTypesJSON, err := json.Marshal(ext.EnabledEventTypes())
	if err != nil {
		return fmt.Errorf("marshal event types: %w", err)
	}

	// Note: channel_id and channel_name are now stored in integrations.metadata
	query := `
		UPDATE integration_notification_extensions SET
			enabled_severities = $2,
			enabled_event_types = $3,
			message_template = $4,
			include_details = $5,
			min_interval_minutes = $6
		WHERE integration_id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		ext.IntegrationID().String(),
		severitiesJSON,
		eventTypesJSON,
		ext.MessageTemplate(),
		ext.IncludeDetails(),
		ext.MinIntervalMinutes(),
	)
	if err != nil {
		return fmt.Errorf("update notification extension: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return integration.ErrNotificationExtensionNotFound
	}

	return nil
}

// Delete deletes a notification extension by integration ID.
func (r *IntegrationNotificationExtensionRepository) Delete(ctx context.Context, integrationID integration.ID) error {
	query := `DELETE FROM integration_notification_extensions WHERE integration_id = $1`

	result, err := r.db.ExecContext(ctx, query, integrationID.String())
	if err != nil {
		return fmt.Errorf("delete notification extension: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return integration.ErrNotificationExtensionNotFound
	}

	return nil
}

// GetIntegrationWithNotification retrieves an integration with its notification extension.
func (r *IntegrationNotificationExtensionRepository) GetIntegrationWithNotification(ctx context.Context, id integration.ID) (*integration.IntegrationWithNotification, error) {
	// Get the integration
	intg, err := r.integrationRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Check if it's a notification integration
	if intg.Category() != integration.CategoryNotification {
		return nil, fmt.Errorf("%w: integration is not a notification type", shared.ErrValidation)
	}

	// Get the notification extension
	ext, err := r.GetByIntegrationID(ctx, id)
	if err != nil {
		// Extension might not exist, that's okay for backward compatibility
		if errors.Is(err, integration.ErrNotificationExtensionNotFound) {
			return integration.NewIntegrationWithNotification(intg, nil), nil
		}
		return nil, err
	}

	return integration.NewIntegrationWithNotification(intg, ext), nil
}

// ListIntegrationsWithNotification lists all notification integrations with their extensions.
// Note: channel_id and channel_name are now stored in integrations.metadata.
func (r *IntegrationNotificationExtensionRepository) ListIntegrationsWithNotification(ctx context.Context, tenantID integration.ID) ([]*integration.IntegrationWithNotification, error) {
	query := `
		SELECT
			i.id, i.tenant_id, i.name, i.description, i.category, i.provider,
			i.status, i.status_message, i.auth_type, i.base_url, i.credentials_encrypted,
			i.last_sync_at, i.next_sync_at, i.sync_interval_minutes, i.sync_error,
			i.config, i.metadata, i.stats, i.created_at, i.updated_at, i.created_by,
			COALESCE(n.enabled_severities, '["critical", "high"]'::jsonb),
			COALESCE(n.enabled_event_types, '["security_alert", "new_finding", "new_exposure"]'::jsonb),
			n.message_template, n.include_details, n.min_interval_minutes
		FROM integrations i
		LEFT JOIN integration_notification_extensions n ON i.id = n.integration_id
		WHERE i.tenant_id = $1 AND i.category = 'notification'
		ORDER BY i.created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list notification integrations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	result := make([]*integration.IntegrationWithNotification, 0)
	for rows.Next() {
		intgWithNotification, err := r.scanIntegrationWithNotificationRow(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, intgWithNotification)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}

	return result, nil
}

// scanNotificationExtension scans a single row into a NotificationExtension.
// Note: channel_id and channel_name are now stored in integrations.metadata.
func (r *IntegrationNotificationExtensionRepository) scanNotificationExtension(row *sql.Row) (*integration.NotificationExtension, error) {
	var (
		integrationID       string
		enabledSeveritiesDB []byte // JSONB
		enabledEventTypesDB []byte // JSONB
		messageTemplate     sql.NullString
		includeDetails      bool
		minIntervalMinutes  int
	)

	err := row.Scan(
		&integrationID,
		&enabledSeveritiesDB, &enabledEventTypesDB,
		&messageTemplate, &includeDetails, &minIntervalMinutes,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, integration.ErrNotificationExtensionNotFound
		}
		return nil, fmt.Errorf("scan notification extension: %w", err)
	}

	intgID, _ := shared.IDFromString(integrationID)

	// Parse severities from JSONB
	enabledSeverities := parseSeveritiesFromJSON(enabledSeveritiesDB)

	// Parse event types from JSONB
	enabledEventTypes := parseEventTypesFromJSON(enabledEventTypesDB)

	return integration.ReconstructNotificationExtension(
		intgID,
		"", // channelID - deprecated, now in integrations.metadata
		"", // channelName - deprecated, now in integrations.metadata
		enabledSeverities,
		enabledEventTypes,
		messageTemplate.String,
		includeDetails,
		minIntervalMinutes,
	), nil
}

// parseSeveritiesFromJSON parses a JSONB array into []Severity.
func parseSeveritiesFromJSON(data []byte) []integration.Severity {
	if len(data) == 0 {
		return integration.DefaultEnabledSeverities()
	}

	var severities []string
	if err := json.Unmarshal(data, &severities); err != nil {
		return integration.DefaultEnabledSeverities()
	}

	result := make([]integration.Severity, 0, len(severities))
	for _, s := range severities {
		result = append(result, integration.Severity(s))
	}
	return result
}

// parseEventTypesFromJSON parses a JSONB array into []EventType.
func parseEventTypesFromJSON(data []byte) []integration.EventType {
	if len(data) == 0 {
		return integration.DefaultEnabledEventTypes()
	}

	var eventTypes []string
	if err := json.Unmarshal(data, &eventTypes); err != nil {
		return integration.DefaultEnabledEventTypes()
	}

	result := make([]integration.EventType, 0, len(eventTypes))
	for _, et := range eventTypes {
		result = append(result, integration.EventType(et))
	}
	return result
}

// scanIntegrationWithNotificationRow scans a row from sql.Rows into an IntegrationWithNotification.
// Note: channel_id and channel_name are now stored in integrations.metadata.
func (r *IntegrationNotificationExtensionRepository) scanIntegrationWithNotificationRow(rows *sql.Rows) (*integration.IntegrationWithNotification, error) {
	var (
		// Integration fields
		id                   string
		tenantID             string
		name                 string
		description          sql.NullString
		category             string
		provider             string
		status               string
		statusMessage        sql.NullString
		authType             string
		baseURL              sql.NullString
		credentialsEncrypted sql.NullString
		lastSyncAt           sql.NullTime
		nextSyncAt           sql.NullTime
		syncIntervalMinutes  int
		syncError            sql.NullString
		configJSON           []byte
		metadataJSON         []byte
		statsJSON            []byte
		createdAt            time.Time
		updatedAt            time.Time
		createdBy            sql.NullString
		// Notification extension fields (nullable due to LEFT JOIN)
		enabledSeveritiesDB []byte // JSONB
		enabledEventTypesDB []byte // JSONB
		messageTemplate     sql.NullString
		includeDetails      sql.NullBool
		minIntervalMinutes  sql.NullInt32
	)

	err := rows.Scan(
		// Integration
		&id, &tenantID, &name, &description, &category, &provider,
		&status, &statusMessage, &authType, &baseURL, &credentialsEncrypted,
		&lastSyncAt, &nextSyncAt, &syncIntervalMinutes, &syncError,
		&configJSON, &metadataJSON, &statsJSON, &createdAt, &updatedAt, &createdBy,
		// Notification extension
		&enabledSeveritiesDB, &enabledEventTypesDB,
		&messageTemplate, &includeDetails, &minIntervalMinutes,
	)
	if err != nil {
		return nil, fmt.Errorf("scan integration with notification row: %w", err)
	}

	// Reconstruct integration
	intg, err := r.integrationRepo.reconstructIntegration(
		id, tenantID, name, description.String, category, provider,
		status, statusMessage.String, authType, baseURL.String, credentialsEncrypted.String,
		lastSyncAt, nextSyncAt, syncIntervalMinutes, syncError.String,
		configJSON, metadataJSON, statsJSON, createdAt, updatedAt, createdBy,
	)
	if err != nil {
		return nil, err
	}

	// Reconstruct notification extension if it exists
	var notifExt *integration.NotificationExtension
	if len(enabledSeveritiesDB) > 0 {
		intgID, _ := shared.IDFromString(id)
		// Parse severities from JSONB
		enabledSeverities := parseSeveritiesFromJSON(enabledSeveritiesDB)
		// Parse event types from JSONB
		enabledEventTypes := parseEventTypesFromJSON(enabledEventTypesDB)

		notifExt = integration.ReconstructNotificationExtension(
			intgID,
			"", // channelID - deprecated, now in integrations.metadata
			"", // channelName - deprecated, now in integrations.metadata
			enabledSeverities,
			enabledEventTypes,
			messageTemplate.String,
			includeDetails.Bool,
			int(minIntervalMinutes.Int32),
		)
	}

	return integration.NewIntegrationWithNotification(intg, notifExt), nil
}
