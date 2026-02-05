package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/rule"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// RuleRepository implements rule.RuleRepository using PostgreSQL.
type RuleRepository struct {
	db *DB
}

// NewRuleRepository creates a new RuleRepository.
func NewRuleRepository(db *DB) *RuleRepository {
	return &RuleRepository{db: db}
}

// Create persists a new rule.
func (r *RuleRepository) Create(ctx context.Context, rl *rule.Rule) error {
	query := `
		INSERT INTO rules (
			id, source_id, tenant_id, tool_id,
			rule_id, name, severity, category, subcategory, tags,
			description, recommendation, references, cwe_ids, owasp_ids,
			file_path, content_hash, metadata,
			created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
	`

	var toolID sql.NullString
	if rl.ToolID != nil {
		toolID = sql.NullString{String: rl.ToolID.String(), Valid: true}
	}

	metadata, _ := toJSONB(rl.Metadata)

	_, err := r.db.ExecContext(ctx, query,
		rl.ID.String(),
		rl.SourceID.String(),
		rl.TenantID.String(),
		toolID,
		rl.RuleID,
		rl.Name,
		string(rl.Severity),
		rl.Category,
		rl.Subcategory,
		pq.Array(rl.Tags),
		rl.Description,
		rl.Recommendation,
		pq.Array(rl.References),
		pq.Array(rl.CWEIDs),
		pq.Array(rl.OWASPIDs),
		rl.FilePath,
		rl.ContentHash,
		metadata,
		rl.CreatedAt,
		rl.UpdatedAt,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "rule already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to create rule: %w", err)
	}

	return nil
}

// CreateBatch creates multiple rules in batch.
func (r *RuleRepository) CreateBatch(ctx context.Context, rules []*rule.Rule) error {
	if len(rules) == 0 {
		return nil
	}

	// Use transaction for batch insert
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO rules (
			id, source_id, tenant_id, tool_id,
			rule_id, name, severity, category, subcategory, tags,
			description, recommendation, references, cwe_ids, owasp_ids,
			file_path, content_hash, metadata,
			created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
		ON CONFLICT (source_id, rule_id) DO UPDATE SET
			name = EXCLUDED.name,
			severity = EXCLUDED.severity,
			category = EXCLUDED.category,
			subcategory = EXCLUDED.subcategory,
			tags = EXCLUDED.tags,
			description = EXCLUDED.description,
			recommendation = EXCLUDED.recommendation,
			references = EXCLUDED.references,
			cwe_ids = EXCLUDED.cwe_ids,
			owasp_ids = EXCLUDED.owasp_ids,
			file_path = EXCLUDED.file_path,
			content_hash = EXCLUDED.content_hash,
			metadata = EXCLUDED.metadata,
			updated_at = EXCLUDED.updated_at
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, rl := range rules {
		var toolID sql.NullString
		if rl.ToolID != nil {
			toolID = sql.NullString{String: rl.ToolID.String(), Valid: true}
		}

		metadata, _ := toJSONB(rl.Metadata)

		_, err := stmt.ExecContext(ctx,
			rl.ID.String(),
			rl.SourceID.String(),
			rl.TenantID.String(),
			toolID,
			rl.RuleID,
			rl.Name,
			string(rl.Severity),
			rl.Category,
			rl.Subcategory,
			pq.Array(rl.Tags),
			rl.Description,
			rl.Recommendation,
			pq.Array(rl.References),
			pq.Array(rl.CWEIDs),
			pq.Array(rl.OWASPIDs),
			rl.FilePath,
			rl.ContentHash,
			metadata,
			rl.CreatedAt,
			rl.UpdatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert rule %s: %w", rl.RuleID, err)
		}
	}

	return tx.Commit()
}

// GetByID retrieves a rule by ID.
func (r *RuleRepository) GetByID(ctx context.Context, id shared.ID) (*rule.Rule, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanRule(row)
}

// GetBySourceAndRuleID retrieves a rule by source and rule ID.
func (r *RuleRepository) GetBySourceAndRuleID(ctx context.Context, sourceID shared.ID, ruleID string) (*rule.Rule, error) {
	query := r.selectQuery() + " WHERE source_id = $1 AND rule_id = $2"
	row := r.db.QueryRowContext(ctx, query, sourceID.String(), ruleID)
	return r.scanRule(row)
}

// List lists rules with filters and pagination.
func (r *RuleRepository) List(ctx context.Context, filter rule.RuleFilter, page pagination.Pagination) (pagination.Result[*rule.Rule], error) {
	var result pagination.Result[*rule.Rule]

	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM rules"
	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("failed to count rules: %w", err)
	}

	// Apply pagination
	offset := (page.Page - 1) * page.PerPage
	baseQuery += fmt.Sprintf(" ORDER BY severity, name ASC LIMIT %d OFFSET %d", page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list rules: %w", err)
	}
	defer rows.Close()

	var rules []*rule.Rule
	for rows.Next() {
		rl, err := r.scanRuleFromRows(rows)
		if err != nil {
			return result, err
		}
		rules = append(rules, rl)
	}

	return pagination.NewResult(rules, total, page), nil
}

// ListBySource lists all rules for a source.
func (r *RuleRepository) ListBySource(ctx context.Context, sourceID shared.ID) ([]*rule.Rule, error) {
	query := r.selectQuery() + " WHERE source_id = $1 ORDER BY rule_id"
	rows, err := r.db.QueryContext(ctx, query, sourceID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}
	defer rows.Close()

	var rules []*rule.Rule
	for rows.Next() {
		rl, err := r.scanRuleFromRows(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rl)
	}

	return rules, nil
}

// Update updates a rule.
func (r *RuleRepository) Update(ctx context.Context, rl *rule.Rule) error {
	query := `
		UPDATE rules
		SET name = $2, severity = $3, category = $4, subcategory = $5,
		    tags = $6, description = $7, recommendation = $8,
		    references = $9, cwe_ids = $10, owasp_ids = $11,
		    file_path = $12, content_hash = $13, metadata = $14,
		    updated_at = $15
		WHERE id = $1
	`

	metadata, _ := toJSONB(rl.Metadata)

	result, err := r.db.ExecContext(ctx, query,
		rl.ID.String(),
		rl.Name,
		string(rl.Severity),
		rl.Category,
		rl.Subcategory,
		pq.Array(rl.Tags),
		rl.Description,
		rl.Recommendation,
		pq.Array(rl.References),
		pq.Array(rl.CWEIDs),
		pq.Array(rl.OWASPIDs),
		rl.FilePath,
		rl.ContentHash,
		metadata,
		rl.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update rule: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// UpsertBatch upserts multiple rules.
func (r *RuleRepository) UpsertBatch(ctx context.Context, rules []*rule.Rule) error {
	return r.CreateBatch(ctx, rules) // CreateBatch already uses ON CONFLICT
}

// Delete deletes a rule.
func (r *RuleRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM rules WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete rule: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// DeleteBySource deletes all rules for a source.
func (r *RuleRepository) DeleteBySource(ctx context.Context, sourceID shared.ID) error {
	query := "DELETE FROM rules WHERE source_id = $1"
	_, err := r.db.ExecContext(ctx, query, sourceID.String())
	return err
}

// CountBySource counts rules for a source.
func (r *RuleRepository) CountBySource(ctx context.Context, sourceID shared.ID) (int, error) {
	var count int
	query := "SELECT COUNT(*) FROM rules WHERE source_id = $1"
	err := r.db.QueryRowContext(ctx, query, sourceID.String()).Scan(&count)
	return count, err
}

// CountByTenantAndTool counts rules for a tenant and tool.
func (r *RuleRepository) CountByTenantAndTool(ctx context.Context, tenantID shared.ID, toolID *shared.ID) (int, error) {
	var count int
	query := "SELECT COUNT(*) FROM rules WHERE tenant_id = $1"
	args := []any{tenantID.String()}

	if toolID != nil {
		query += " AND (tool_id = $2 OR tool_id IS NULL)"
		args = append(args, toolID.String())
	}

	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

func (r *RuleRepository) selectQuery() string {
	return `
		SELECT id, source_id, tenant_id, tool_id,
		       rule_id, name, severity, category, subcategory, tags,
		       description, recommendation, references, cwe_ids, owasp_ids,
		       file_path, content_hash, metadata,
		       created_at, updated_at
		FROM rules
	`
}

func (r *RuleRepository) buildWhereClause(filter rule.RuleFilter) (string, []any) {
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

	if filter.SourceID != nil {
		conditions = append(conditions, fmt.Sprintf("source_id = $%d", argIndex))
		args = append(args, filter.SourceID.String())
		argIndex++
	}

	if filter.Severity != nil {
		conditions = append(conditions, fmt.Sprintf("severity = $%d", argIndex))
		args = append(args, string(*filter.Severity))
		argIndex++
	}

	if filter.Category != "" {
		conditions = append(conditions, fmt.Sprintf("category = $%d", argIndex))
		args = append(args, filter.Category)
		argIndex++
	}

	if len(filter.Tags) > 0 {
		conditions = append(conditions, fmt.Sprintf("tags && $%d", argIndex))
		args = append(args, pq.Array(filter.Tags))
		argIndex++
	}

	if len(filter.RuleIDs) > 0 {
		conditions = append(conditions, fmt.Sprintf("rule_id = ANY($%d)", argIndex))
		args = append(args, pq.Array(filter.RuleIDs))
		argIndex++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR rule_id ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex, argIndex))
		args = append(args, wrapLikePattern(filter.Search))
		argIndex++
	}

	if len(conditions) == 0 {
		return "", nil
	}

	return strings.Join(conditions, " AND "), args
}

func (r *RuleRepository) scanRule(row *sql.Row) (*rule.Rule, error) {
	var (
		rl           rule.Rule
		id, sourceID string
		tenantID     string
		toolID       sql.NullString
		severity     string
		tags         pq.StringArray
		refs         pq.StringArray
		cweIDs       pq.StringArray
		owaspIDs     pq.StringArray
		metadata     []byte
	)

	err := row.Scan(
		&id, &sourceID, &tenantID, &toolID,
		&rl.RuleID, &rl.Name, &severity, &rl.Category, &rl.Subcategory, &tags,
		&rl.Description, &rl.Recommendation, &refs, &cweIDs, &owaspIDs,
		&rl.FilePath, &rl.ContentHash, &metadata,
		&rl.CreatedAt, &rl.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan rule: %w", err)
	}

	rl.ID, _ = shared.IDFromString(id)
	rl.SourceID, _ = shared.IDFromString(sourceID)
	rl.TenantID, _ = shared.IDFromString(tenantID)
	if toolID.Valid {
		tid, _ := shared.IDFromString(toolID.String)
		rl.ToolID = &tid
	}
	rl.Severity = rule.Severity(severity)
	rl.Tags = tags
	rl.References = refs
	rl.CWEIDs = cweIDs
	rl.OWASPIDs = owaspIDs

	if len(metadata) > 0 {
		if err := fromJSONB(metadata, &rl.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return &rl, nil
}

func (r *RuleRepository) scanRuleFromRows(rows *sql.Rows) (*rule.Rule, error) {
	var (
		rl           rule.Rule
		id, sourceID string
		tenantID     string
		toolID       sql.NullString
		severity     string
		tags         pq.StringArray
		refs         pq.StringArray
		cweIDs       pq.StringArray
		owaspIDs     pq.StringArray
		metadata     []byte
	)

	err := rows.Scan(
		&id, &sourceID, &tenantID, &toolID,
		&rl.RuleID, &rl.Name, &severity, &rl.Category, &rl.Subcategory, &tags,
		&rl.Description, &rl.Recommendation, &refs, &cweIDs, &owaspIDs,
		&rl.FilePath, &rl.ContentHash, &metadata,
		&rl.CreatedAt, &rl.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan rule: %w", err)
	}

	rl.ID, _ = shared.IDFromString(id)
	rl.SourceID, _ = shared.IDFromString(sourceID)
	rl.TenantID, _ = shared.IDFromString(tenantID)
	if toolID.Valid {
		tid, _ := shared.IDFromString(toolID.String)
		rl.ToolID = &tid
	}
	rl.Severity = rule.Severity(severity)
	rl.Tags = tags
	rl.References = refs
	rl.CWEIDs = cweIDs
	rl.OWASPIDs = owaspIDs

	if len(metadata) > 0 {
		if err := fromJSONB(metadata, &rl.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return &rl, nil
}

// Ensure interface compliance
var _ rule.RuleRepository = (*RuleRepository)(nil)
