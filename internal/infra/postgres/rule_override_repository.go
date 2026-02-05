package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/api/pkg/domain/rule"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// RuleOverrideRepository implements rule.OverrideRepository using PostgreSQL.
type RuleOverrideRepository struct {
	db *DB
}

// NewRuleOverrideRepository creates a new RuleOverrideRepository.
func NewRuleOverrideRepository(db *DB) *RuleOverrideRepository {
	return &RuleOverrideRepository{db: db}
}

// Create persists a new rule override.
func (r *RuleOverrideRepository) Create(ctx context.Context, override *rule.Override) error {
	query := `
		INSERT INTO rule_overrides (
			id, tenant_id, tool_id,
			rule_pattern, is_pattern,
			enabled, severity_override,
			asset_group_id, scan_profile_id,
			reason, created_by,
			created_at, updated_at, expires_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`

	_, err := r.db.ExecContext(ctx, query,
		override.ID.String(),
		override.TenantID.String(),
		nullID(override.ToolID),
		override.RulePattern,
		override.IsPattern,
		override.Enabled,
		nullSeverity(override.SeverityOverride),
		nullID(override.AssetGroupID),
		nullID(override.ScanProfileID),
		override.Reason,
		nullID(override.CreatedBy),
		override.CreatedAt,
		override.UpdatedAt,
		nullTime(override.ExpiresAt),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "override already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to create override: %w", err)
	}

	return nil
}

// GetByID retrieves an override by ID.
func (r *RuleOverrideRepository) GetByID(ctx context.Context, id shared.ID) (*rule.Override, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanOverride(row)
}

// GetByTenantAndID retrieves an override by tenant and ID.
func (r *RuleOverrideRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*rule.Override, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanOverride(row)
}

// List lists overrides with filters and pagination.
func (r *RuleOverrideRepository) List(ctx context.Context, filter rule.OverrideFilter, page pagination.Pagination) (pagination.Result[*rule.Override], error) {
	var result pagination.Result[*rule.Override]

	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM rule_overrides"
	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("failed to count overrides: %w", err)
	}

	// Apply pagination
	offset := (page.Page - 1) * page.PerPage
	baseQuery += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list overrides: %w", err)
	}
	defer rows.Close()

	var overrides []*rule.Override
	for rows.Next() {
		override, err := r.scanOverrideFromRows(rows)
		if err != nil {
			return result, err
		}
		overrides = append(overrides, override)
	}

	return pagination.NewResult(overrides, total, page), nil
}

// ListByTenantAndTool lists all overrides for a tenant and tool.
func (r *RuleOverrideRepository) ListByTenantAndTool(ctx context.Context, tenantID shared.ID, toolID *shared.ID) ([]*rule.Override, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1"
	args := []any{tenantID.String()}

	// used in ListByTenantAndTool
	const toolIDQueryPart = " AND (tool_id = $2 OR tool_id IS NULL)"

	if toolID != nil {
		query += toolIDQueryPart
		args = append(args, toolID.String())
	}

	// Filter out expired overrides
	query += " AND (expires_at IS NULL OR expires_at > NOW())"
	query += " ORDER BY created_at DESC"

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list overrides: %w", err)
	}
	defer rows.Close()

	var overrides []*rule.Override
	for rows.Next() {
		override, err := r.scanOverrideFromRows(rows)
		if err != nil {
			return nil, err
		}
		overrides = append(overrides, override)
	}

	return overrides, nil
}

// Update updates an override.
func (r *RuleOverrideRepository) Update(ctx context.Context, override *rule.Override) error {
	query := `
		UPDATE rule_overrides
		SET tool_id = $2, rule_pattern = $3, is_pattern = $4,
		    enabled = $5, severity_override = $6,
		    asset_group_id = $7, scan_profile_id = $8,
		    reason = $9, updated_at = $10, expires_at = $11
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		override.ID.String(),
		nullID(override.ToolID),
		override.RulePattern,
		override.IsPattern,
		override.Enabled,
		nullSeverity(override.SeverityOverride),
		nullID(override.AssetGroupID),
		nullID(override.ScanProfileID),
		override.Reason,
		override.UpdatedAt,
		nullTime(override.ExpiresAt),
	)

	if err != nil {
		return fmt.Errorf("failed to update override: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// Delete deletes an override.
func (r *RuleOverrideRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM rule_overrides WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete override: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// DeleteExpired deletes all expired overrides.
func (r *RuleOverrideRepository) DeleteExpired(ctx context.Context) (int64, error) {
	query := "DELETE FROM rule_overrides WHERE expires_at IS NOT NULL AND expires_at < NOW()"
	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired overrides: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	return rowsAffected, nil
}

func (r *RuleOverrideRepository) selectQuery() string {
	return `
		SELECT id, tenant_id, tool_id,
		       rule_pattern, is_pattern,
		       enabled, severity_override,
		       asset_group_id, scan_profile_id,
		       reason, created_by,
		       created_at, updated_at, expires_at
		FROM rule_overrides
	`
}

func (r *RuleOverrideRepository) buildWhereClause(filter rule.OverrideFilter) (string, []any) {
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

	if filter.AssetGroupID != nil {
		conditions = append(conditions, fmt.Sprintf("asset_group_id = $%d", argIndex))
		args = append(args, filter.AssetGroupID.String())
		argIndex++
	}

	if filter.ScanProfileID != nil {
		conditions = append(conditions, fmt.Sprintf("scan_profile_id = $%d", argIndex))
		args = append(args, filter.ScanProfileID.String())
		argIndex++
	}

	if filter.Enabled != nil {
		conditions = append(conditions, fmt.Sprintf("enabled = $%d", argIndex))
		args = append(args, *filter.Enabled)
		argIndex++
	}

	if len(conditions) == 0 {
		return "", nil
	}

	return strings.Join(conditions, " AND "), args
}

func (r *RuleOverrideRepository) scanOverride(row *sql.Row) (*rule.Override, error) {
	var (
		o                rule.Override
		id               string
		tenantID         string
		toolID           sql.NullString
		severityOverride sql.NullString
		assetGroupID     sql.NullString
		scanProfileID    sql.NullString
		createdBy        sql.NullString
		expiresAt        sql.NullTime
	)

	err := row.Scan(
		&id, &tenantID, &toolID,
		&o.RulePattern, &o.IsPattern,
		&o.Enabled, &severityOverride,
		&assetGroupID, &scanProfileID,
		&o.Reason, &createdBy,
		&o.CreatedAt, &o.UpdatedAt, &expiresAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan override: %w", err)
	}

	o.ID, _ = shared.IDFromString(id)
	o.TenantID, _ = shared.IDFromString(tenantID)
	o.ToolID = parseNullID(toolID)
	o.AssetGroupID = parseNullID(assetGroupID)
	o.ScanProfileID = parseNullID(scanProfileID)
	o.CreatedBy = parseNullID(createdBy)

	if severityOverride.Valid {
		o.SeverityOverride = rule.Severity(severityOverride.String)
	}

	if expiresAt.Valid {
		o.ExpiresAt = &expiresAt.Time
	}

	return &o, nil
}

func (r *RuleOverrideRepository) scanOverrideFromRows(rows *sql.Rows) (*rule.Override, error) {
	var (
		o                rule.Override
		id               string
		tenantID         string
		toolID           sql.NullString
		severityOverride sql.NullString
		assetGroupID     sql.NullString
		scanProfileID    sql.NullString
		createdBy        sql.NullString
		expiresAt        sql.NullTime
	)

	err := rows.Scan(
		&id, &tenantID, &toolID,
		&o.RulePattern, &o.IsPattern,
		&o.Enabled, &severityOverride,
		&assetGroupID, &scanProfileID,
		&o.Reason, &createdBy,
		&o.CreatedAt, &o.UpdatedAt, &expiresAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan override: %w", err)
	}

	o.ID, _ = shared.IDFromString(id)
	o.TenantID, _ = shared.IDFromString(tenantID)
	o.ToolID = parseNullID(toolID)
	o.AssetGroupID = parseNullID(assetGroupID)
	o.ScanProfileID = parseNullID(scanProfileID)
	o.CreatedBy = parseNullID(createdBy)

	if severityOverride.Valid {
		o.SeverityOverride = rule.Severity(severityOverride.String)
	}

	if expiresAt.Valid {
		o.ExpiresAt = &expiresAt.Time
	}

	return &o, nil
}

// nullSeverity converts a Severity to sql.NullString.
func nullSeverity(s rule.Severity) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: string(s), Valid: true}
}

// Ensure interface compliance
var _ rule.OverrideRepository = (*RuleOverrideRepository)(nil)
