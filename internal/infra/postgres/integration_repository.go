package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/shared"
)

// IntegrationRepository implements integration.Repository using PostgreSQL.
type IntegrationRepository struct {
	db *DB
}

// NewIntegrationRepository creates a new IntegrationRepository.
func NewIntegrationRepository(db *DB) *IntegrationRepository {
	return &IntegrationRepository{db: db}
}

// Ensure IntegrationRepository implements integration.Repository
var _ integration.Repository = (*IntegrationRepository)(nil)

// Create creates a new integration.
func (r *IntegrationRepository) Create(ctx context.Context, i *integration.Integration) error {
	config, err := json.Marshal(i.Config())
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	metadata, err := json.Marshal(i.Metadata())
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	stats, err := json.Marshal(i.Stats())
	if err != nil {
		return fmt.Errorf("marshal stats: %w", err)
	}

	query := `
		INSERT INTO integrations (
			id, tenant_id, name, description, category, provider,
			status, status_message, auth_type, base_url, credentials_encrypted,
			last_sync_at, next_sync_at, sync_interval_minutes, sync_error,
			config, metadata, stats, created_at, updated_at, created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
		)
	`

	var createdBy *string
	if i.CreatedBy() != nil {
		s := i.CreatedBy().String()
		createdBy = &s
	}

	_, err = r.db.ExecContext(ctx, query,
		i.ID().String(),
		i.TenantID().String(),
		i.Name(),
		i.Description(),
		i.Category().String(),
		i.Provider().String(),
		i.Status().String(),
		i.StatusMessage(),
		i.AuthType().String(),
		i.BaseURL(),
		i.CredentialsEncrypted(),
		i.LastSyncAt(),
		i.NextSyncAt(),
		i.SyncIntervalMinutes(),
		i.SyncError(),
		config,
		metadata,
		stats,
		i.CreatedAt(),
		i.UpdatedAt(),
		createdBy,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return integration.ErrIntegrationNameExists
		}
		return fmt.Errorf("create integration: %w", err)
	}

	return nil
}

// GetByID retrieves an integration by ID.
func (r *IntegrationRepository) GetByID(ctx context.Context, id integration.ID) (*integration.Integration, error) {
	query := `
		SELECT id, tenant_id, name, description, category, provider,
			   status, status_message, auth_type, base_url, credentials_encrypted,
			   last_sync_at, next_sync_at, sync_interval_minutes, sync_error,
			   config, metadata, stats, created_at, updated_at, created_by
		FROM integrations
		WHERE id = $1
	`

	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanIntegration(row)
}

// GetByTenantAndName retrieves an integration by tenant ID and name.
func (r *IntegrationRepository) GetByTenantAndName(ctx context.Context, tenantID integration.ID, name string) (*integration.Integration, error) {
	query := `
		SELECT id, tenant_id, name, description, category, provider,
			   status, status_message, auth_type, base_url, credentials_encrypted,
			   last_sync_at, next_sync_at, sync_interval_minutes, sync_error,
			   config, metadata, stats, created_at, updated_at, created_by
		FROM integrations
		WHERE tenant_id = $1 AND name = $2
	`

	row := r.db.QueryRowContext(ctx, query, tenantID.String(), name)
	return r.scanIntegration(row)
}

// Update updates an existing integration.
func (r *IntegrationRepository) Update(ctx context.Context, i *integration.Integration) error {
	config, err := json.Marshal(i.Config())
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	metadata, err := json.Marshal(i.Metadata())
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	stats, err := json.Marshal(i.Stats())
	if err != nil {
		return fmt.Errorf("marshal stats: %w", err)
	}

	query := `
		UPDATE integrations SET
			name = $2,
			description = $3,
			status = $4,
			status_message = $5,
			base_url = $6,
			credentials_encrypted = $7,
			last_sync_at = $8,
			next_sync_at = $9,
			sync_interval_minutes = $10,
			sync_error = $11,
			config = $12,
			metadata = $13,
			stats = $14,
			updated_at = $15
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		i.ID().String(),
		i.Name(),
		i.Description(),
		i.Status().String(),
		i.StatusMessage(),
		i.BaseURL(),
		i.CredentialsEncrypted(),
		i.LastSyncAt(),
		i.NextSyncAt(),
		i.SyncIntervalMinutes(),
		i.SyncError(),
		config,
		metadata,
		stats,
		i.UpdatedAt(),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return integration.ErrIntegrationNameExists
		}
		return fmt.Errorf("update integration: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return integration.ErrIntegrationNotFound
	}

	return nil
}

// Delete deletes an integration by ID.
func (r *IntegrationRepository) Delete(ctx context.Context, id integration.ID) error {
	query := `DELETE FROM integrations WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("delete integration: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return integration.ErrIntegrationNotFound
	}

	return nil
}

// List lists integrations with filtering and pagination.
func (r *IntegrationRepository) List(ctx context.Context, filter integration.Filter) (integration.ListResult, error) {
	result := integration.ListResult{
		Data:    make([]*integration.Integration, 0),
		Page:    filter.Page,
		PerPage: filter.PerPage,
	}

	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.PerPage < 1 {
		filter.PerPage = 20
	}

	// Build query
	conditions := make([]string, 0)
	args := make([]any, 0)
	argIdx := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIdx))
		args = append(args, filter.TenantID.String())
		argIdx++
	}

	if filter.Category != nil {
		conditions = append(conditions, fmt.Sprintf("category = $%d", argIdx))
		args = append(args, filter.Category.String())
		argIdx++
	}

	if filter.Provider != nil {
		conditions = append(conditions, fmt.Sprintf("provider = $%d", argIdx))
		args = append(args, filter.Provider.String())
		argIdx++
	}

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, filter.Status.String())
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

	// Get total count
	countQuery := "SELECT COUNT(*) FROM integrations " + whereClause
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&result.Total)
	if err != nil {
		return result, fmt.Errorf("count integrations: %w", err)
	}

	// Calculate pagination
	result.TotalPages = int((result.Total + int64(filter.PerPage) - 1) / int64(filter.PerPage))

	// Build order clause
	orderBy := sortFieldCreatedAt + " " + sortOrderDESC
	if filter.SortBy != "" {
		validSortFields := map[string]bool{
			sortFieldName:      true,
			"category":         true,
			"provider":         true,
			"status":           true,
			sortFieldCreatedAt: true,
			"updated_at":       true,
		}
		if validSortFields[filter.SortBy] {
			order := sortOrderASC
			if filter.SortOrder == sortOrderDescLower {
				order = sortOrderDESC
			}
			orderBy = filter.SortBy + " " + order
		}
	}

	// Get data with pagination
	offset := (filter.Page - 1) * filter.PerPage
	args = append(args, filter.PerPage, offset)

	query := fmt.Sprintf(`
		SELECT id, tenant_id, name, description, category, provider,
			   status, status_message, auth_type, base_url, credentials_encrypted,
			   last_sync_at, next_sync_at, sync_interval_minutes, sync_error,
			   config, metadata, stats, created_at, updated_at, created_by
		FROM integrations
		%s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, argIdx, argIdx+1)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return result, fmt.Errorf("list integrations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		intg, err := r.scanIntegrationRow(rows)
		if err != nil {
			return result, err
		}
		result.Data = append(result.Data, intg)
	}

	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("iterate rows: %w", err)
	}

	return result, nil
}

// Count returns the total number of integrations matching the filter.
func (r *IntegrationRepository) Count(ctx context.Context, filter integration.Filter) (int64, error) {
	conditions := make([]string, 0)
	args := make([]any, 0)
	argIdx := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIdx))
		args = append(args, filter.TenantID.String())
		argIdx++
	}

	if filter.Category != nil {
		conditions = append(conditions, fmt.Sprintf("category = $%d", argIdx))
		args = append(args, filter.Category.String())
		argIdx++
	}

	if filter.Provider != nil {
		conditions = append(conditions, fmt.Sprintf("provider = $%d", argIdx))
		args = append(args, filter.Provider.String())
		argIdx++
	}

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, filter.Status.String())
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := "SELECT COUNT(*) FROM integrations " + whereClause

	var count int64
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count integrations: %w", err)
	}

	return count, nil
}

// ListByTenant lists all integrations for a tenant.
func (r *IntegrationRepository) ListByTenant(ctx context.Context, tenantID integration.ID) ([]*integration.Integration, error) {
	query := `
		SELECT id, tenant_id, name, description, category, provider,
			   status, status_message, auth_type, base_url, credentials_encrypted,
			   last_sync_at, next_sync_at, sync_interval_minutes, sync_error,
			   config, metadata, stats, created_at, updated_at, created_by
		FROM integrations
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list integrations by tenant: %w", err)
	}
	defer func() { _ = rows.Close() }()

	result := make([]*integration.Integration, 0)
	for rows.Next() {
		intg, err := r.scanIntegrationRow(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, intg)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}

	return result, nil
}

// ListByCategory lists integrations by category.
func (r *IntegrationRepository) ListByCategory(ctx context.Context, tenantID integration.ID, category integration.Category) ([]*integration.Integration, error) {
	query := `
		SELECT id, tenant_id, name, description, category, provider,
			   status, status_message, auth_type, base_url, credentials_encrypted,
			   last_sync_at, next_sync_at, sync_interval_minutes, sync_error,
			   config, metadata, stats, created_at, updated_at, created_by
		FROM integrations
		WHERE tenant_id = $1 AND category = $2
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), category.String())
	if err != nil {
		return nil, fmt.Errorf("list integrations by category: %w", err)
	}
	defer func() { _ = rows.Close() }()

	result := make([]*integration.Integration, 0)
	for rows.Next() {
		intg, err := r.scanIntegrationRow(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, intg)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}

	return result, nil
}

// ListByProvider lists integrations by provider.
func (r *IntegrationRepository) ListByProvider(ctx context.Context, tenantID integration.ID, provider integration.Provider) ([]*integration.Integration, error) {
	query := `
		SELECT id, tenant_id, name, description, category, provider,
			   status, status_message, auth_type, base_url, credentials_encrypted,
			   last_sync_at, next_sync_at, sync_interval_minutes, sync_error,
			   config, metadata, stats, created_at, updated_at, created_by
		FROM integrations
		WHERE tenant_id = $1 AND provider = $2
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), provider.String())
	if err != nil {
		return nil, fmt.Errorf("list integrations by provider: %w", err)
	}
	defer func() { _ = rows.Close() }()

	result := make([]*integration.Integration, 0)
	for rows.Next() {
		intg, err := r.scanIntegrationRow(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, intg)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}

	return result, nil
}

// scanIntegration scans a single row into an Integration.
func (r *IntegrationRepository) scanIntegration(row *sql.Row) (*integration.Integration, error) {
	var (
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
	)

	err := row.Scan(
		&id, &tenantID, &name, &description, &category, &provider,
		&status, &statusMessage, &authType, &baseURL, &credentialsEncrypted,
		&lastSyncAt, &nextSyncAt, &syncIntervalMinutes, &syncError,
		&configJSON, &metadataJSON, &statsJSON, &createdAt, &updatedAt, &createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, integration.ErrIntegrationNotFound
		}
		return nil, fmt.Errorf("scan integration: %w", err)
	}

	return r.reconstructIntegration(
		id, tenantID, name, description.String, category, provider,
		status, statusMessage.String, authType, baseURL.String, credentialsEncrypted.String,
		lastSyncAt, nextSyncAt, syncIntervalMinutes, syncError.String,
		configJSON, metadataJSON, statsJSON, createdAt, updatedAt, createdBy,
	)
}

// scanIntegrationRow scans a row from sql.Rows into an Integration.
func (r *IntegrationRepository) scanIntegrationRow(rows *sql.Rows) (*integration.Integration, error) {
	var (
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
	)

	err := rows.Scan(
		&id, &tenantID, &name, &description, &category, &provider,
		&status, &statusMessage, &authType, &baseURL, &credentialsEncrypted,
		&lastSyncAt, &nextSyncAt, &syncIntervalMinutes, &syncError,
		&configJSON, &metadataJSON, &statsJSON, &createdAt, &updatedAt, &createdBy,
	)
	if err != nil {
		return nil, fmt.Errorf("scan integration row: %w", err)
	}

	return r.reconstructIntegration(
		id, tenantID, name, description.String, category, provider,
		status, statusMessage.String, authType, baseURL.String, credentialsEncrypted.String,
		lastSyncAt, nextSyncAt, syncIntervalMinutes, syncError.String,
		configJSON, metadataJSON, statsJSON, createdAt, updatedAt, createdBy,
	)
}

// reconstructIntegration reconstructs an Integration from scanned values.
func (r *IntegrationRepository) reconstructIntegration(
	id, tenantID, name, description, category, provider string,
	status, statusMessage, authType, baseURL, credentialsEncrypted string,
	lastSyncAt, nextSyncAt sql.NullTime, syncIntervalMinutes int, syncError string,
	configJSON, metadataJSON, statsJSON []byte,
	createdAt, updatedAt time.Time, createdBy sql.NullString,
) (*integration.Integration, error) {
	var config map[string]any
	if len(configJSON) > 0 {
		if err := json.Unmarshal(configJSON, &config); err != nil {
			return nil, fmt.Errorf("unmarshal config: %w", err)
		}
	}

	var metadata map[string]any
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}

	var stats integration.Stats
	if len(statsJSON) > 0 {
		if err := json.Unmarshal(statsJSON, &stats); err != nil {
			return nil, fmt.Errorf("unmarshal stats: %w", err)
		}
	}

	var lastSync *time.Time
	if lastSyncAt.Valid {
		lastSync = &lastSyncAt.Time
	}

	var nextSync *time.Time
	if nextSyncAt.Valid {
		nextSync = &nextSyncAt.Time
	}

	var createdByID *shared.ID
	if createdBy.Valid {
		cid, err := shared.IDFromString(createdBy.String)
		if err == nil {
			createdByID = &cid
		}
	}

	intgID, _ := shared.IDFromString(id)
	intgTenantID, _ := shared.IDFromString(tenantID)

	return integration.Reconstruct(
		intgID,
		intgTenantID,
		name,
		description,
		integration.Category(category),
		integration.Provider(provider),
		integration.Status(status),
		statusMessage,
		integration.AuthType(authType),
		baseURL,
		credentialsEncrypted,
		lastSync,
		nextSync,
		syncIntervalMinutes,
		syncError,
		config,
		metadata,
		stats,
		createdAt,
		updatedAt,
		createdByID,
	), nil
}
