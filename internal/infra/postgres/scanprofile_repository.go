package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/scanprofile"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// ScanProfileRepository implements scanprofile.Repository using PostgreSQL.
type ScanProfileRepository struct {
	db *DB
}

// NewScanProfileRepository creates a new ScanProfileRepository.
func NewScanProfileRepository(db *DB) *ScanProfileRepository {
	return &ScanProfileRepository{db: db}
}

// Create persists a new scan profile.
func (r *ScanProfileRepository) Create(ctx context.Context, p *scanprofile.ScanProfile) error {
	toolsConfig, err := json.Marshal(p.ToolsConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal tools_config: %w", err)
	}

	metadata, err := json.Marshal(p.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	qualityGate, err := json.Marshal(p.QualityGate)
	if err != nil {
		return fmt.Errorf("failed to marshal quality_gate: %w", err)
	}

	query := `
		INSERT INTO scan_profiles (
			id, tenant_id, name, description,
			is_default, is_system, tools_config,
			intensity, max_concurrent_scans, timeout_seconds,
			tags, metadata, quality_gate, created_by, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
	`

	var createdBy sql.NullString
	if p.CreatedBy != nil {
		createdBy = sql.NullString{String: p.CreatedBy.String(), Valid: true}
	}

	_, err = r.db.ExecContext(ctx, query,
		p.ID.String(),
		p.TenantID.String(),
		p.Name,
		p.Description,
		p.IsDefault,
		p.IsSystem,
		toolsConfig,
		string(p.Intensity),
		p.MaxConcurrentScans,
		p.TimeoutSeconds,
		pq.Array(p.Tags),
		metadata,
		qualityGate,
		createdBy,
		p.CreatedAt,
		p.UpdatedAt,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "scan profile with this name already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to create scan profile: %w", err)
	}

	return nil
}

// GetByID retrieves a scan profile by its ID.
func (r *ScanProfileRepository) GetByID(ctx context.Context, id shared.ID) (*scanprofile.ScanProfile, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanProfile(row)
}

// GetByTenantAndID retrieves a scan profile by tenant and ID.
func (r *ScanProfileRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*scanprofile.ScanProfile, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanProfile(row)
}

// GetByTenantAndName retrieves a scan profile by tenant and name.
func (r *ScanProfileRepository) GetByTenantAndName(ctx context.Context, tenantID shared.ID, name string) (*scanprofile.ScanProfile, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND name = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), name)
	return r.scanProfile(row)
}

// GetDefaultByTenant retrieves the default scan profile for a tenant.
func (r *ScanProfileRepository) GetDefaultByTenant(ctx context.Context, tenantID shared.ID) (*scanprofile.ScanProfile, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND is_default = true"
	row := r.db.QueryRowContext(ctx, query, tenantID.String())
	return r.scanProfile(row)
}

// List lists scan profiles with filters and pagination.
func (r *ScanProfileRepository) List(ctx context.Context, filter scanprofile.Filter, page pagination.Pagination) (pagination.Result[*scanprofile.ScanProfile], error) {
	var result pagination.Result[*scanprofile.ScanProfile]

	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM scan_profiles"
	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("failed to count scan profiles: %w", err)
	}

	// Apply pagination
	offset := (page.Page - 1) * page.PerPage
	baseQuery += fmt.Sprintf(" ORDER BY is_default DESC, created_at DESC LIMIT %d OFFSET %d", page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list scan profiles: %w", err)
	}
	defer rows.Close()

	var profiles []*scanprofile.ScanProfile
	for rows.Next() {
		p, err := r.scanProfileFromRows(rows)
		if err != nil {
			return result, err
		}
		profiles = append(profiles, p)
	}

	return pagination.NewResult(profiles, total, page), nil
}

// Update updates a scan profile.
func (r *ScanProfileRepository) Update(ctx context.Context, p *scanprofile.ScanProfile) error {
	toolsConfig, err := json.Marshal(p.ToolsConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal tools_config: %w", err)
	}

	metadata, err := json.Marshal(p.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	qualityGate, err := json.Marshal(p.QualityGate)
	if err != nil {
		return fmt.Errorf("failed to marshal quality_gate: %w", err)
	}

	query := `
		UPDATE scan_profiles
		SET name = $2, description = $3,
		    is_default = $4, tools_config = $5,
		    intensity = $6, max_concurrent_scans = $7, timeout_seconds = $8,
		    tags = $9, metadata = $10, quality_gate = $11, updated_at = $12
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		p.ID.String(),
		p.Name,
		p.Description,
		p.IsDefault,
		toolsConfig,
		string(p.Intensity),
		p.MaxConcurrentScans,
		p.TimeoutSeconds,
		pq.Array(p.Tags),
		metadata,
		qualityGate,
		p.UpdatedAt,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "scan profile with this name already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to update scan profile: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// Delete deletes a scan profile.
func (r *ScanProfileRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM scan_profiles WHERE id = $1 AND is_system = false"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete scan profile: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// ClearDefaultForTenant clears the default flag for all profiles in a tenant.
func (r *ScanProfileRepository) ClearDefaultForTenant(ctx context.Context, tenantID shared.ID) error {
	query := "UPDATE scan_profiles SET is_default = false, updated_at = NOW() WHERE tenant_id = $1 AND is_default = true"
	_, err := r.db.ExecContext(ctx, query, tenantID.String())
	return err
}

// CountByTenant counts the number of profiles for a tenant.
func (r *ScanProfileRepository) CountByTenant(ctx context.Context, tenantID shared.ID) (int64, error) {
	var count int64
	query := "SELECT COUNT(*) FROM scan_profiles WHERE tenant_id = $1"
	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(&count)
	return count, err
}

// ListWithSystemProfiles lists tenant profiles AND system profiles.
// Returns both tenant-specific profiles and system profiles (marked with is_system=true).
func (r *ScanProfileRepository) ListWithSystemProfiles(ctx context.Context, tenantID shared.ID, filter scanprofile.Filter, page pagination.Pagination) (pagination.Result[*scanprofile.ScanProfile], error) {
	var result pagination.Result[*scanprofile.ScanProfile]

	// Build query that gets both tenant profiles AND system profiles
	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM scan_profiles"

	var conditions []string
	var args []any
	argIndex := 1

	// Core condition: tenant profiles OR system profiles
	conditions = append(conditions, fmt.Sprintf("(tenant_id = $%d OR is_system = true)", argIndex))
	args = append(args, tenantID.String())
	argIndex++

	// Apply additional filters
	if filter.IsDefault != nil {
		conditions = append(conditions, fmt.Sprintf("is_default = $%d", argIndex))
		args = append(args, *filter.IsDefault)
		argIndex++
	}

	if filter.IsSystem != nil {
		conditions = append(conditions, fmt.Sprintf("is_system = $%d", argIndex))
		args = append(args, *filter.IsSystem)
		argIndex++
	}

	if len(filter.Tags) > 0 {
		conditions = append(conditions, fmt.Sprintf("tags && $%d", argIndex))
		args = append(args, pq.Array(filter.Tags))
		argIndex++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex))
		args = append(args, wrapLikePattern(filter.Search))
	}

	whereClause := strings.Join(conditions, " AND ")
	baseQuery += " WHERE " + whereClause
	countQuery += " WHERE " + whereClause

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("failed to count scan profiles: %w", err)
	}

	// Apply pagination - order by is_system DESC (system first), then is_default DESC, then created_at DESC
	offset := (page.Page - 1) * page.PerPage
	baseQuery += fmt.Sprintf(" ORDER BY is_system DESC, is_default DESC, created_at DESC LIMIT %d OFFSET %d", page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list scan profiles: %w", err)
	}
	defer rows.Close()

	var profiles []*scanprofile.ScanProfile
	for rows.Next() {
		p, err := r.scanProfileFromRows(rows)
		if err != nil {
			return result, err
		}
		profiles = append(profiles, p)
	}

	return pagination.NewResult(profiles, total, page), nil
}

// GetByIDWithSystemFallback retrieves a profile by ID, checking both tenant and system profiles.
// This allows tenants to reference system profiles for use in scans.
func (r *ScanProfileRepository) GetByIDWithSystemFallback(ctx context.Context, tenantID, id shared.ID) (*scanprofile.ScanProfile, error) {
	query := r.selectQuery() + " WHERE id = $1 AND (tenant_id = $2 OR is_system = true)"
	row := r.db.QueryRowContext(ctx, query, id.String(), tenantID.String())
	return r.scanProfile(row)
}

// selectQuery returns the base SELECT query.
func (r *ScanProfileRepository) selectQuery() string {
	return `
		SELECT id, tenant_id, name, description,
		       is_default, is_system, tools_config,
		       intensity, max_concurrent_scans, timeout_seconds,
		       tags, metadata, quality_gate, created_by, created_at, updated_at
		FROM scan_profiles
	`
}

// buildWhereClause builds the WHERE clause from filters.
func (r *ScanProfileRepository) buildWhereClause(filter scanprofile.Filter) (string, []any) {
	var conditions []string
	var args []any
	argIndex := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, filter.TenantID.String())
		argIndex++
	}

	if filter.IsDefault != nil {
		conditions = append(conditions, fmt.Sprintf("is_default = $%d", argIndex))
		args = append(args, *filter.IsDefault)
		argIndex++
	}

	if filter.IsSystem != nil {
		conditions = append(conditions, fmt.Sprintf("is_system = $%d", argIndex))
		args = append(args, *filter.IsSystem)
		argIndex++
	}

	if len(filter.Tags) > 0 {
		conditions = append(conditions, fmt.Sprintf("tags && $%d", argIndex))
		args = append(args, pq.Array(filter.Tags))
		argIndex++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex))
		args = append(args, wrapLikePattern(filter.Search))
	}

	if len(conditions) == 0 {
		return "", nil
	}

	return strings.Join(conditions, " AND "), args
}

// scanProfile scans a single row into a ScanProfile.
func (r *ScanProfileRepository) scanProfile(row *sql.Row) (*scanprofile.ScanProfile, error) {
	p := &scanprofile.ScanProfile{}
	var (
		id          string
		tenantID    string
		intensity   string
		tags        pq.StringArray
		toolsConfig []byte
		metadata    []byte
		qualityGate []byte
		createdBy   sql.NullString
	)

	err := row.Scan(
		&id,
		&tenantID,
		&p.Name,
		&p.Description,
		&p.IsDefault,
		&p.IsSystem,
		&toolsConfig,
		&intensity,
		&p.MaxConcurrentScans,
		&p.TimeoutSeconds,
		&tags,
		&metadata,
		&qualityGate,
		&createdBy,
		&p.CreatedAt,
		&p.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan scan profile: %w", err)
	}

	p.ID, _ = shared.IDFromString(id)
	p.TenantID, _ = shared.IDFromString(tenantID)
	p.Intensity = scanprofile.Intensity(intensity)
	p.Tags = tags

	if createdBy.Valid {
		createdByID, _ := shared.IDFromString(createdBy.String)
		p.CreatedBy = &createdByID
	}

	if len(toolsConfig) > 0 {
		_ = json.Unmarshal(toolsConfig, &p.ToolsConfig)
	} else {
		p.ToolsConfig = make(map[string]scanprofile.ToolConfig)
	}

	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &p.Metadata)
	} else {
		p.Metadata = make(map[string]any)
	}

	if len(qualityGate) > 0 {
		_ = json.Unmarshal(qualityGate, &p.QualityGate)
	} else {
		p.QualityGate = scanprofile.NewQualityGate()
	}

	return p, nil
}

// scanProfileFromRows scans a row from Rows into a ScanProfile.
func (r *ScanProfileRepository) scanProfileFromRows(rows *sql.Rows) (*scanprofile.ScanProfile, error) {
	p := &scanprofile.ScanProfile{}
	var (
		id          string
		tenantID    string
		intensity   string
		tags        pq.StringArray
		toolsConfig []byte
		metadata    []byte
		qualityGate []byte
		createdBy   sql.NullString
	)

	err := rows.Scan(
		&id,
		&tenantID,
		&p.Name,
		&p.Description,
		&p.IsDefault,
		&p.IsSystem,
		&toolsConfig,
		&intensity,
		&p.MaxConcurrentScans,
		&p.TimeoutSeconds,
		&tags,
		&metadata,
		&qualityGate,
		&createdBy,
		&p.CreatedAt,
		&p.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan scan profile: %w", err)
	}

	p.ID, _ = shared.IDFromString(id)
	p.TenantID, _ = shared.IDFromString(tenantID)
	p.Intensity = scanprofile.Intensity(intensity)
	p.Tags = tags

	if createdBy.Valid {
		createdByID, _ := shared.IDFromString(createdBy.String)
		p.CreatedBy = &createdByID
	}

	if len(toolsConfig) > 0 {
		_ = json.Unmarshal(toolsConfig, &p.ToolsConfig)
	} else {
		p.ToolsConfig = make(map[string]scanprofile.ToolConfig)
	}

	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &p.Metadata)
	} else {
		p.Metadata = make(map[string]any)
	}

	if len(qualityGate) > 0 {
		_ = json.Unmarshal(qualityGate, &p.QualityGate)
	} else {
		p.QualityGate = scanprofile.NewQualityGate()
	}

	return p, nil
}
