package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/scannertemplate"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// ScannerTemplateRepository implements scannertemplate.Repository using PostgreSQL.
type ScannerTemplateRepository struct {
	db *DB
}

// NewScannerTemplateRepository creates a new ScannerTemplateRepository.
func NewScannerTemplateRepository(db *DB) *ScannerTemplateRepository {
	return &ScannerTemplateRepository{db: db}
}

// Create persists a new scanner template.
func (r *ScannerTemplateRepository) Create(ctx context.Context, t *scannertemplate.ScannerTemplate) error {
	metadata, err := json.Marshal(t.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO scanner_templates (
			id, tenant_id, source_id, name, template_type, version,
			content, content_url, content_hash, signature_hash,
			rule_count, description, tags, metadata,
			status, validation_error, sync_source, source_path, source_commit,
			created_by, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
	`

	var sourceID, contentURL, validationError, sourcePath, sourceCommit, createdBy sql.NullString

	if t.SourceID != nil {
		sourceID = sql.NullString{String: t.SourceID.String(), Valid: true}
	}
	if t.ContentURL != nil {
		contentURL = sql.NullString{String: *t.ContentURL, Valid: true}
	}
	if t.ValidationError != nil {
		validationError = sql.NullString{String: *t.ValidationError, Valid: true}
	}
	if t.SourcePath != nil {
		sourcePath = sql.NullString{String: *t.SourcePath, Valid: true}
	}
	if t.SourceCommit != nil {
		sourceCommit = sql.NullString{String: *t.SourceCommit, Valid: true}
	}
	if t.CreatedBy != nil {
		createdBy = sql.NullString{String: t.CreatedBy.String(), Valid: true}
	}

	_, err = r.db.ExecContext(ctx, query,
		t.ID.String(),
		t.TenantID.String(),
		sourceID,
		t.Name,
		string(t.TemplateType),
		t.Version,
		t.Content,
		contentURL,
		t.ContentHash,
		t.SignatureHash,
		t.RuleCount,
		t.Description,
		pq.Array(t.Tags),
		metadata,
		string(t.Status),
		validationError,
		string(t.SyncSource),
		sourcePath,
		sourceCommit,
		createdBy,
		t.CreatedAt,
		t.UpdatedAt,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "template with this name already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to create scanner template: %w", err)
	}

	return nil
}

// GetByTenantAndID retrieves a scanner template by tenant and ID.
func (r *ScannerTemplateRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*scannertemplate.ScannerTemplate, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanTemplate(row)
}

// GetByTenantAndName retrieves a scanner template by tenant, type, and name.
func (r *ScannerTemplateRepository) GetByTenantAndName(ctx context.Context, tenantID shared.ID, templateType scannertemplate.TemplateType, name string) (*scannertemplate.ScannerTemplate, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND template_type = $2 AND name = $3"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), string(templateType), name)
	return r.scanTemplate(row)
}

// List lists scanner templates with filters and pagination.
func (r *ScannerTemplateRepository) List(ctx context.Context, filter scannertemplate.Filter, page pagination.Pagination) (pagination.Result[*scannertemplate.ScannerTemplate], error) {
	var result pagination.Result[*scannertemplate.ScannerTemplate]

	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM scanner_templates"
	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("failed to count scanner templates: %w", err)
	}

	// Apply pagination
	offset := (page.Page - 1) * page.PerPage
	baseQuery += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list scanner templates: %w", err)
	}
	defer rows.Close()

	var templates []*scannertemplate.ScannerTemplate
	for rows.Next() {
		t, err := r.scanTemplateFromRows(rows)
		if err != nil {
			return result, err
		}
		templates = append(templates, t)
	}

	return pagination.NewResult(templates, total, page), nil
}

// ListByIDs retrieves multiple templates by their IDs.
func (r *ScannerTemplateRepository) ListByIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]*scannertemplate.ScannerTemplate, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	// Build placeholders
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids)+1)
	args[0] = tenantID.String()
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args[i+1] = id.String()
	}

	query := r.selectQuery() + fmt.Sprintf(" WHERE tenant_id = $1 AND id IN (%s)", strings.Join(placeholders, ", "))

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list scanner templates by IDs: %w", err)
	}
	defer rows.Close()

	var templates []*scannertemplate.ScannerTemplate
	for rows.Next() {
		t, err := r.scanTemplateFromRows(rows)
		if err != nil {
			return nil, err
		}
		templates = append(templates, t)
	}

	return templates, nil
}

// Update updates a scanner template.
func (r *ScannerTemplateRepository) Update(ctx context.Context, t *scannertemplate.ScannerTemplate) error {
	metadata, err := json.Marshal(t.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		UPDATE scanner_templates
		SET name = $2, version = $3, content = $4, content_url = $5,
		    content_hash = $6, signature_hash = $7, rule_count = $8,
		    description = $9, tags = $10, metadata = $11,
		    status = $12, validation_error = $13, sync_source = $14,
		    source_path = $15, source_commit = $16, updated_at = $17
		WHERE id = $1
	`

	var contentURL, validationError, sourcePath, sourceCommit sql.NullString

	if t.ContentURL != nil {
		contentURL = sql.NullString{String: *t.ContentURL, Valid: true}
	}
	if t.ValidationError != nil {
		validationError = sql.NullString{String: *t.ValidationError, Valid: true}
	}
	if t.SourcePath != nil {
		sourcePath = sql.NullString{String: *t.SourcePath, Valid: true}
	}
	if t.SourceCommit != nil {
		sourceCommit = sql.NullString{String: *t.SourceCommit, Valid: true}
	}

	result, err := r.db.ExecContext(ctx, query,
		t.ID.String(),
		t.Name,
		t.Version,
		t.Content,
		contentURL,
		t.ContentHash,
		t.SignatureHash,
		t.RuleCount,
		t.Description,
		pq.Array(t.Tags),
		metadata,
		string(t.Status),
		validationError,
		string(t.SyncSource),
		sourcePath,
		sourceCommit,
		t.UpdatedAt,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "template with this name already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to update scanner template: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// Delete deletes a scanner template (tenant-scoped).
func (r *ScannerTemplateRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	query := "DELETE FROM scanner_templates WHERE id = $1 AND tenant_id = $2"
	result, err := r.db.ExecContext(ctx, query, id.String(), tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to delete scanner template: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// CountByTenant counts the number of templates for a tenant.
func (r *ScannerTemplateRepository) CountByTenant(ctx context.Context, tenantID shared.ID) (int64, error) {
	var count int64
	query := "SELECT COUNT(*) FROM scanner_templates WHERE tenant_id = $1"
	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(&count)
	return count, err
}

// CountByType counts the number of templates by type for a tenant.
func (r *ScannerTemplateRepository) CountByType(ctx context.Context, tenantID shared.ID, templateType scannertemplate.TemplateType) (int64, error) {
	var count int64
	query := "SELECT COUNT(*) FROM scanner_templates WHERE tenant_id = $1 AND template_type = $2"
	err := r.db.QueryRowContext(ctx, query, tenantID.String(), string(templateType)).Scan(&count)
	return count, err
}

// ExistsByName checks if a template with the given name exists.
func (r *ScannerTemplateRepository) ExistsByName(ctx context.Context, tenantID shared.ID, templateType scannertemplate.TemplateType, name string) (bool, error) {
	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM scanner_templates WHERE tenant_id = $1 AND template_type = $2 AND name = $3)"
	err := r.db.QueryRowContext(ctx, query, tenantID.String(), string(templateType), name).Scan(&exists)
	return exists, err
}

// GetUsage returns the current template usage for a tenant.
func (r *ScannerTemplateRepository) GetUsage(ctx context.Context, tenantID shared.ID) (*scannertemplate.TemplateUsage, error) {
	query := `
		SELECT
			COUNT(*) as total_templates,
			COUNT(*) FILTER (WHERE template_type = 'nuclei') as nuclei_templates,
			COUNT(*) FILTER (WHERE template_type = 'semgrep') as semgrep_templates,
			COUNT(*) FILTER (WHERE template_type = 'gitleaks') as gitleaks_templates,
			COALESCE(SUM(LENGTH(content)), 0) as total_storage_bytes
		FROM scanner_templates
		WHERE tenant_id = $1
	`

	usage := &scannertemplate.TemplateUsage{}
	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(
		&usage.TotalTemplates,
		&usage.NucleiTemplates,
		&usage.SemgrepTemplates,
		&usage.GitleaksTemplates,
		&usage.TotalStorageBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get template usage: %w", err)
	}

	return usage, nil
}

// selectQuery returns the base SELECT query.
func (r *ScannerTemplateRepository) selectQuery() string {
	return `
		SELECT id, tenant_id, source_id, name, template_type, version,
		       content, content_url, content_hash, signature_hash,
		       rule_count, description, tags, metadata,
		       status, validation_error, sync_source, source_path, source_commit,
		       created_by, created_at, updated_at
		FROM scanner_templates
	`
}

// buildWhereClause builds the WHERE clause from filters.
func (r *ScannerTemplateRepository) buildWhereClause(filter scannertemplate.Filter) (string, []any) {
	var conditions []string
	var args []any
	argIndex := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, filter.TenantID.String())
		argIndex++
	}

	if filter.TemplateType != nil {
		conditions = append(conditions, fmt.Sprintf("template_type = $%d", argIndex))
		args = append(args, string(*filter.TemplateType))
		argIndex++
	}

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, string(*filter.Status))
		argIndex++
	}

	if filter.SourceID != nil {
		conditions = append(conditions, fmt.Sprintf("source_id = $%d", argIndex))
		args = append(args, filter.SourceID.String())
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

// scanTemplate scans a single row into a ScannerTemplate.
func (r *ScannerTemplateRepository) scanTemplate(row *sql.Row) (*scannertemplate.ScannerTemplate, error) {
	t := &scannertemplate.ScannerTemplate{}
	var (
		id              string
		tenantID        string
		sourceID        sql.NullString
		templateType    string
		contentURL      sql.NullString
		status          string
		validationError sql.NullString
		syncSource      string
		sourcePath      sql.NullString
		sourceCommit    sql.NullString
		createdBy       sql.NullString
		tags            pq.StringArray
		metadata        []byte
	)

	err := row.Scan(
		&id,
		&tenantID,
		&sourceID,
		&t.Name,
		&templateType,
		&t.Version,
		&t.Content,
		&contentURL,
		&t.ContentHash,
		&t.SignatureHash,
		&t.RuleCount,
		&t.Description,
		&tags,
		&metadata,
		&status,
		&validationError,
		&syncSource,
		&sourcePath,
		&sourceCommit,
		&createdBy,
		&t.CreatedAt,
		&t.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan scanner template: %w", err)
	}

	t.ID, _ = shared.IDFromString(id)
	t.TenantID, _ = shared.IDFromString(tenantID)
	t.TemplateType = scannertemplate.TemplateType(templateType)
	t.Status = scannertemplate.TemplateStatus(status)
	t.SyncSource = scannertemplate.SyncSource(syncSource)
	t.Tags = tags

	if sourceID.Valid {
		sid, _ := shared.IDFromString(sourceID.String)
		t.SourceID = &sid
	}
	if contentURL.Valid {
		t.ContentURL = &contentURL.String
	}
	if validationError.Valid {
		t.ValidationError = &validationError.String
	}
	if sourcePath.Valid {
		t.SourcePath = &sourcePath.String
	}
	if sourceCommit.Valid {
		t.SourceCommit = &sourceCommit.String
	}
	if createdBy.Valid {
		createdByID, _ := shared.IDFromString(createdBy.String)
		t.CreatedBy = &createdByID
	}

	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &t.Metadata)
	} else {
		t.Metadata = make(map[string]any)
	}

	return t, nil
}

// scanTemplateFromRows scans a row from Rows into a ScannerTemplate.
func (r *ScannerTemplateRepository) scanTemplateFromRows(rows *sql.Rows) (*scannertemplate.ScannerTemplate, error) {
	t := &scannertemplate.ScannerTemplate{}
	var (
		id              string
		tenantID        string
		sourceID        sql.NullString
		templateType    string
		contentURL      sql.NullString
		status          string
		validationError sql.NullString
		syncSource      string
		sourcePath      sql.NullString
		sourceCommit    sql.NullString
		createdBy       sql.NullString
		tags            pq.StringArray
		metadata        []byte
	)

	err := rows.Scan(
		&id,
		&tenantID,
		&sourceID,
		&t.Name,
		&templateType,
		&t.Version,
		&t.Content,
		&contentURL,
		&t.ContentHash,
		&t.SignatureHash,
		&t.RuleCount,
		&t.Description,
		&tags,
		&metadata,
		&status,
		&validationError,
		&syncSource,
		&sourcePath,
		&sourceCommit,
		&createdBy,
		&t.CreatedAt,
		&t.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan scanner template: %w", err)
	}

	t.ID, _ = shared.IDFromString(id)
	t.TenantID, _ = shared.IDFromString(tenantID)
	t.TemplateType = scannertemplate.TemplateType(templateType)
	t.Status = scannertemplate.TemplateStatus(status)
	t.SyncSource = scannertemplate.SyncSource(syncSource)
	t.Tags = tags

	if sourceID.Valid {
		sid, _ := shared.IDFromString(sourceID.String)
		t.SourceID = &sid
	}
	if contentURL.Valid {
		t.ContentURL = &contentURL.String
	}
	if validationError.Valid {
		t.ValidationError = &validationError.String
	}
	if sourcePath.Valid {
		t.SourcePath = &sourcePath.String
	}
	if sourceCommit.Valid {
		t.SourceCommit = &sourceCommit.String
	}
	if createdBy.Valid {
		createdByID, _ := shared.IDFromString(createdBy.String)
		t.CreatedBy = &createdByID
	}

	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &t.Metadata)
	} else {
		t.Metadata = make(map[string]any)
	}

	return t, nil
}
