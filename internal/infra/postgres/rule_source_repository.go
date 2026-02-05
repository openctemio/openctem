package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/rule"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// RuleSourceRepository implements rule.SourceRepository using PostgreSQL.
type RuleSourceRepository struct {
	db *DB
}

// NewRuleSourceRepository creates a new RuleSourceRepository.
func NewRuleSourceRepository(db *DB) *RuleSourceRepository {
	return &RuleSourceRepository{db: db}
}

// Create persists a new rule source.
func (r *RuleSourceRepository) Create(ctx context.Context, source *rule.Source) error {
	query := `
		INSERT INTO rule_sources (
			id, tenant_id, tool_id, name, description,
			source_type, config, credentials_id,
			sync_enabled, sync_interval_minutes,
			last_sync_status, priority, is_platform_default,
			enabled, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
	`

	var toolID sql.NullString
	if source.ToolID != nil {
		toolID = sql.NullString{String: source.ToolID.String(), Valid: true}
	}

	var credID sql.NullString
	if source.CredentialsID != nil {
		credID = sql.NullString{String: source.CredentialsID.String(), Valid: true}
	}

	_, err := r.db.ExecContext(ctx, query,
		source.ID.String(),
		source.TenantID.String(),
		toolID,
		source.Name,
		source.Description,
		string(source.SourceType),
		source.Config,
		credID,
		source.SyncEnabled,
		source.SyncIntervalMinutes,
		string(source.LastSyncStatus),
		source.Priority,
		source.IsPlatformDefault,
		source.Enabled,
		source.CreatedAt,
		source.UpdatedAt,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "rule source already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to create rule source: %w", err)
	}

	return nil
}

// GetByID retrieves a source by ID.
func (r *RuleSourceRepository) GetByID(ctx context.Context, id shared.ID) (*rule.Source, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanSource(row)
}

// GetByTenantAndID retrieves a source by tenant and ID.
func (r *RuleSourceRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*rule.Source, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanSource(row)
}

// List lists sources with filters and pagination.
func (r *RuleSourceRepository) List(ctx context.Context, filter rule.SourceFilter, page pagination.Pagination) (pagination.Result[*rule.Source], error) {
	var result pagination.Result[*rule.Source]

	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM rule_sources"
	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("failed to count rule sources: %w", err)
	}

	// Apply pagination
	offset := (page.Page - 1) * page.PerPage
	baseQuery += fmt.Sprintf(" ORDER BY priority DESC, name ASC LIMIT %d OFFSET %d", page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list rule sources: %w", err)
	}
	defer rows.Close()

	var sources []*rule.Source
	for rows.Next() {
		source, err := r.scanSourceFromRows(rows)
		if err != nil {
			return result, err
		}
		sources = append(sources, source)
	}

	return pagination.NewResult(sources, total, page), nil
}

// ListByTenantAndTool lists all sources for a tenant and tool.
func (r *RuleSourceRepository) ListByTenantAndTool(ctx context.Context, tenantID shared.ID, toolID *shared.ID) ([]*rule.Source, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND enabled = true"
	args := []any{tenantID.String()}

	if toolID != nil {
		query += " AND (tool_id = $2 OR tool_id IS NULL)"
		args = append(args, toolID.String())
	}

	query += " ORDER BY priority DESC, name ASC"

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list rule sources: %w", err)
	}
	defer rows.Close()

	var sources []*rule.Source
	for rows.Next() {
		source, err := r.scanSourceFromRows(rows)
		if err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}

	return sources, nil
}

// ListNeedingSync lists sources that need synchronization.
func (r *RuleSourceRepository) ListNeedingSync(ctx context.Context, limit int) ([]*rule.Source, error) {
	query := r.selectQuery() + `
		WHERE enabled = true
		  AND sync_enabled = true
		  AND (
			last_sync_at IS NULL
			OR last_sync_at < NOW() - (sync_interval_minutes || ' minutes')::interval
		  )
		ORDER BY last_sync_at ASC NULLS FIRST
		LIMIT $1
	`

	rows, err := r.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list sources needing sync: %w", err)
	}
	defer rows.Close()

	var sources []*rule.Source
	for rows.Next() {
		source, err := r.scanSourceFromRows(rows)
		if err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}

	return sources, nil
}

// Update updates a source.
func (r *RuleSourceRepository) Update(ctx context.Context, source *rule.Source) error {
	query := `
		UPDATE rule_sources
		SET name = $2, description = $3, source_type = $4, config = $5,
		    credentials_id = $6, sync_enabled = $7, sync_interval_minutes = $8,
		    last_sync_at = $9, last_sync_status = $10, last_sync_error = $11,
		    last_sync_duration_ms = $12, content_hash = $13, rule_count = $14,
		    priority = $15, enabled = $16, updated_at = $17
		WHERE id = $1
	`

	var credID sql.NullString
	if source.CredentialsID != nil {
		credID = sql.NullString{String: source.CredentialsID.String(), Valid: true}
	}

	result, err := r.db.ExecContext(ctx, query,
		source.ID.String(),
		source.Name,
		source.Description,
		string(source.SourceType),
		source.Config,
		credID,
		source.SyncEnabled,
		source.SyncIntervalMinutes,
		nullTime(source.LastSyncAt),
		string(source.LastSyncStatus),
		nullString(source.LastSyncError),
		source.LastSyncDuration.Milliseconds(),
		nullString(source.ContentHash),
		source.RuleCount,
		source.Priority,
		source.Enabled,
		source.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update rule source: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// Delete deletes a source.
func (r *RuleSourceRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM rule_sources WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete rule source: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

func (r *RuleSourceRepository) selectQuery() string {
	return `
		SELECT id, tenant_id, tool_id, name, description,
		       source_type, config, credentials_id,
		       sync_enabled, sync_interval_minutes,
		       last_sync_at, last_sync_status, last_sync_error,
		       last_sync_duration_ms, content_hash, rule_count,
		       priority, is_platform_default, enabled,
		       created_at, updated_at
		FROM rule_sources
	`
}

func (r *RuleSourceRepository) buildWhereClause(filter rule.SourceFilter) (string, []any) {
	var conditions []string
	var args []any
	argIndex := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, filter.TenantID.String())
		argIndex++
	}

	if filter.ToolID != nil {
		conditions = append(conditions, fmt.Sprintf("(tool_id = $%d OR tool_id IS NULL)", argIndex))
		args = append(args, filter.ToolID.String())
		argIndex++
	}

	if filter.SourceType != nil {
		conditions = append(conditions, fmt.Sprintf("source_type = $%d", argIndex))
		args = append(args, string(*filter.SourceType))
		argIndex++
	}

	if filter.Enabled != nil {
		conditions = append(conditions, fmt.Sprintf("enabled = $%d", argIndex))
		args = append(args, *filter.Enabled)
		argIndex++
	}

	if filter.IsPlatformDefault != nil {
		conditions = append(conditions, fmt.Sprintf("is_platform_default = $%d", argIndex))
		args = append(args, *filter.IsPlatformDefault)
		argIndex++
	}

	if filter.SyncStatus != nil {
		conditions = append(conditions, fmt.Sprintf("last_sync_status = $%d", argIndex))
		args = append(args, string(*filter.SyncStatus))
		argIndex++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex))
		args = append(args, wrapLikePattern(filter.Search))
		argIndex++
	}

	if len(conditions) == 0 {
		return "", nil
	}

	return strings.Join(conditions, " AND "), args
}

func (r *RuleSourceRepository) scanSource(row *sql.Row) (*rule.Source, error) {
	var (
		s                  rule.Source
		id, tenantID       string
		toolID             sql.NullString
		sourceType         string
		config             []byte
		credID             sql.NullString
		lastSyncAt         sql.NullTime
		lastSyncStatus     string
		lastSyncError      sql.NullString
		lastSyncDurationMs sql.NullInt64
		contentHash        sql.NullString
	)

	err := row.Scan(
		&id, &tenantID, &toolID, &s.Name, &s.Description,
		&sourceType, &config, &credID,
		&s.SyncEnabled, &s.SyncIntervalMinutes,
		&lastSyncAt, &lastSyncStatus, &lastSyncError,
		&lastSyncDurationMs, &contentHash, &s.RuleCount,
		&s.Priority, &s.IsPlatformDefault, &s.Enabled,
		&s.CreatedAt, &s.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan rule source: %w", err)
	}

	s.ID, _ = shared.IDFromString(id)
	s.TenantID, _ = shared.IDFromString(tenantID)
	if toolID.Valid {
		tid, _ := shared.IDFromString(toolID.String)
		s.ToolID = &tid
	}
	s.SourceType = rule.SourceType(sourceType)
	s.Config = config
	if credID.Valid {
		cid, _ := shared.IDFromString(credID.String)
		s.CredentialsID = &cid
	}
	if lastSyncAt.Valid {
		s.LastSyncAt = &lastSyncAt.Time
	}
	s.LastSyncStatus = rule.SyncStatus(lastSyncStatus)
	if lastSyncError.Valid {
		s.LastSyncError = lastSyncError.String
	}
	if lastSyncDurationMs.Valid {
		s.LastSyncDuration = time.Duration(lastSyncDurationMs.Int64) * time.Millisecond
	}
	if contentHash.Valid {
		s.ContentHash = contentHash.String
	}

	return &s, nil
}

func (r *RuleSourceRepository) scanSourceFromRows(rows *sql.Rows) (*rule.Source, error) {
	var (
		s                  rule.Source
		id, tenantID       string
		toolID             sql.NullString
		sourceType         string
		config             []byte
		credID             sql.NullString
		lastSyncAt         sql.NullTime
		lastSyncStatus     string
		lastSyncError      sql.NullString
		lastSyncDurationMs sql.NullInt64
		contentHash        sql.NullString
	)

	err := rows.Scan(
		&id, &tenantID, &toolID, &s.Name, &s.Description,
		&sourceType, &config, &credID,
		&s.SyncEnabled, &s.SyncIntervalMinutes,
		&lastSyncAt, &lastSyncStatus, &lastSyncError,
		&lastSyncDurationMs, &contentHash, &s.RuleCount,
		&s.Priority, &s.IsPlatformDefault, &s.Enabled,
		&s.CreatedAt, &s.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan rule source: %w", err)
	}

	s.ID, _ = shared.IDFromString(id)
	s.TenantID, _ = shared.IDFromString(tenantID)
	if toolID.Valid {
		tid, _ := shared.IDFromString(toolID.String)
		s.ToolID = &tid
	}
	s.SourceType = rule.SourceType(sourceType)
	s.Config = config
	if credID.Valid {
		cid, _ := shared.IDFromString(credID.String)
		s.CredentialsID = &cid
	}
	if lastSyncAt.Valid {
		s.LastSyncAt = &lastSyncAt.Time
	}
	s.LastSyncStatus = rule.SyncStatus(lastSyncStatus)
	if lastSyncError.Valid {
		s.LastSyncError = lastSyncError.String
	}
	if lastSyncDurationMs.Valid {
		s.LastSyncDuration = time.Duration(lastSyncDurationMs.Int64) * time.Millisecond
	}
	if contentHash.Valid {
		s.ContentHash = contentHash.String
	}

	return &s, nil
}

// Ensure interface compliance
var _ rule.SourceRepository = (*RuleSourceRepository)(nil)
