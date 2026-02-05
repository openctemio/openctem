package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/rule"
	"github.com/openctemio/api/pkg/domain/shared"
)

// RuleBundleRepository implements rule.BundleRepository using PostgreSQL.
type RuleBundleRepository struct {
	db *DB
}

// NewRuleBundleRepository creates a new RuleBundleRepository.
func NewRuleBundleRepository(db *DB) *RuleBundleRepository {
	return &RuleBundleRepository{db: db}
}

// Create persists a new bundle.
func (r *RuleBundleRepository) Create(ctx context.Context, bundle *rule.Bundle) error {
	query := `
		INSERT INTO rule_bundles (
			id, tenant_id, tool_id, version, content_hash,
			rule_count, source_count, size_bytes,
			source_ids, source_hashes, storage_path,
			status, build_error, build_started_at, build_completed_at,
			created_at, expires_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
	`

	sourceIDs := make([]string, len(bundle.SourceIDs))
	for i, id := range bundle.SourceIDs {
		sourceIDs[i] = id.String()
	}

	sourceHashes, _ := toJSONB(bundle.SourceHashes)

	_, err := r.db.ExecContext(ctx, query,
		bundle.ID.String(),
		bundle.TenantID.String(),
		bundle.ToolID.String(),
		bundle.Version,
		bundle.ContentHash,
		bundle.RuleCount,
		bundle.SourceCount,
		bundle.SizeBytes,
		pq.Array(sourceIDs),
		sourceHashes,
		bundle.StoragePath,
		string(bundle.Status),
		nullString(bundle.BuildError),
		nullTime(bundle.BuildStartedAt),
		nullTime(bundle.BuildCompletedAt),
		bundle.CreatedAt,
		nullTime(bundle.ExpiresAt),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "bundle already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to create bundle: %w", err)
	}

	return nil
}

// GetByID retrieves a bundle by ID.
func (r *RuleBundleRepository) GetByID(ctx context.Context, id shared.ID) (*rule.Bundle, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanBundle(row)
}

// GetLatest retrieves the latest ready bundle for a tenant and tool.
func (r *RuleBundleRepository) GetLatest(ctx context.Context, tenantID, toolID shared.ID) (*rule.Bundle, error) {
	query := r.selectQuery() + `
		WHERE tenant_id = $1 AND tool_id = $2 AND status = 'ready'
		ORDER BY created_at DESC
		LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), toolID.String())
	return r.scanBundle(row)
}

// GetByContentHash retrieves a bundle by content hash.
func (r *RuleBundleRepository) GetByContentHash(ctx context.Context, hash string) (*rule.Bundle, error) {
	query := r.selectQuery() + " WHERE content_hash = $1"
	row := r.db.QueryRowContext(ctx, query, hash)
	return r.scanBundle(row)
}

// List lists bundles with filters.
func (r *RuleBundleRepository) List(ctx context.Context, filter rule.BundleFilter) ([]*rule.Bundle, error) {
	query := r.selectQuery()
	var conditions []string
	var args []any
	argIndex := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, filter.TenantID.String())
		argIndex++
	}

	if filter.ToolID != nil {
		conditions = append(conditions, fmt.Sprintf("tool_id = $%d", argIndex))
		args = append(args, filter.ToolID.String())
		argIndex++
	}

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, string(*filter.Status))
		argIndex++
	}

	if len(conditions) > 0 {
		query += " WHERE " + joinConditions(conditions)
	}

	query += " ORDER BY created_at DESC"

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list bundles: %w", err)
	}
	defer rows.Close()

	var bundles []*rule.Bundle
	for rows.Next() {
		bundle, err := r.scanBundleFromRows(rows)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, bundle)
	}

	return bundles, nil
}

// Update updates a bundle.
func (r *RuleBundleRepository) Update(ctx context.Context, bundle *rule.Bundle) error {
	query := `
		UPDATE rule_bundles
		SET version = $2, content_hash = $3,
		    rule_count = $4, source_count = $5, size_bytes = $6,
		    source_ids = $7, source_hashes = $8, storage_path = $9,
		    status = $10, build_error = $11, build_started_at = $12, build_completed_at = $13,
		    expires_at = $14
		WHERE id = $1
	`

	sourceIDs := make([]string, len(bundle.SourceIDs))
	for i, id := range bundle.SourceIDs {
		sourceIDs[i] = id.String()
	}

	sourceHashes, _ := toJSONB(bundle.SourceHashes)

	result, err := r.db.ExecContext(ctx, query,
		bundle.ID.String(),
		bundle.Version,
		bundle.ContentHash,
		bundle.RuleCount,
		bundle.SourceCount,
		bundle.SizeBytes,
		pq.Array(sourceIDs),
		sourceHashes,
		bundle.StoragePath,
		string(bundle.Status),
		nullString(bundle.BuildError),
		nullTime(bundle.BuildStartedAt),
		nullTime(bundle.BuildCompletedAt),
		nullTime(bundle.ExpiresAt),
	)

	if err != nil {
		return fmt.Errorf("failed to update bundle: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// Delete deletes a bundle.
func (r *RuleBundleRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM rule_bundles WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete bundle: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// DeleteExpired deletes all expired bundles.
func (r *RuleBundleRepository) DeleteExpired(ctx context.Context) (int64, error) {
	query := "DELETE FROM rule_bundles WHERE expires_at IS NOT NULL AND expires_at < NOW()"
	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired bundles: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	return rowsAffected, nil
}

func (r *RuleBundleRepository) selectQuery() string {
	return `
		SELECT id, tenant_id, tool_id, version, content_hash,
		       rule_count, source_count, size_bytes,
		       source_ids, source_hashes, storage_path,
		       status, build_error, build_started_at, build_completed_at,
		       created_at, expires_at
		FROM rule_bundles
	`
}

func (r *RuleBundleRepository) scanBundle(row *sql.Row) (*rule.Bundle, error) {
	var (
		b                rule.Bundle
		id               string
		tenantID         string
		toolID           string
		sourceIDStrings  pq.StringArray
		sourceHashes     []byte
		status           string
		buildError       sql.NullString
		buildStartedAt   sql.NullTime
		buildCompletedAt sql.NullTime
		expiresAt        sql.NullTime
	)

	err := row.Scan(
		&id, &tenantID, &toolID, &b.Version, &b.ContentHash,
		&b.RuleCount, &b.SourceCount, &b.SizeBytes,
		&sourceIDStrings, &sourceHashes, &b.StoragePath,
		&status, &buildError, &buildStartedAt, &buildCompletedAt,
		&b.CreatedAt, &expiresAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan bundle: %w", err)
	}

	b.ID, _ = shared.IDFromString(id)
	b.TenantID, _ = shared.IDFromString(tenantID)
	b.ToolID, _ = shared.IDFromString(toolID)

	b.SourceIDs = make([]shared.ID, len(sourceIDStrings))
	for i, s := range sourceIDStrings {
		b.SourceIDs[i], _ = shared.IDFromString(s)
	}

	if len(sourceHashes) > 0 {
		if err := fromJSONB(sourceHashes, &b.SourceHashes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal source hashes: %w", err)
		}
	} else {
		b.SourceHashes = make(map[string]string)
	}

	b.Status = rule.BundleStatus(status)
	if buildError.Valid {
		b.BuildError = buildError.String
	}
	if buildStartedAt.Valid {
		b.BuildStartedAt = &buildStartedAt.Time
	}
	if buildCompletedAt.Valid {
		b.BuildCompletedAt = &buildCompletedAt.Time
	}
	if expiresAt.Valid {
		b.ExpiresAt = &expiresAt.Time
	}

	return &b, nil
}

func (r *RuleBundleRepository) scanBundleFromRows(rows *sql.Rows) (*rule.Bundle, error) {
	var (
		b                rule.Bundle
		id               string
		tenantID         string
		toolID           string
		sourceIDStrings  pq.StringArray
		sourceHashes     []byte
		status           string
		buildError       sql.NullString
		buildStartedAt   sql.NullTime
		buildCompletedAt sql.NullTime
		expiresAt        sql.NullTime
	)

	err := rows.Scan(
		&id, &tenantID, &toolID, &b.Version, &b.ContentHash,
		&b.RuleCount, &b.SourceCount, &b.SizeBytes,
		&sourceIDStrings, &sourceHashes, &b.StoragePath,
		&status, &buildError, &buildStartedAt, &buildCompletedAt,
		&b.CreatedAt, &expiresAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan bundle: %w", err)
	}

	b.ID, _ = shared.IDFromString(id)
	b.TenantID, _ = shared.IDFromString(tenantID)
	b.ToolID, _ = shared.IDFromString(toolID)

	b.SourceIDs = make([]shared.ID, len(sourceIDStrings))
	for i, s := range sourceIDStrings {
		b.SourceIDs[i], _ = shared.IDFromString(s)
	}

	if len(sourceHashes) > 0 {
		if err := fromJSONB(sourceHashes, &b.SourceHashes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal source hashes: %w", err)
		}
	} else {
		b.SourceHashes = make(map[string]string)
	}

	b.Status = rule.BundleStatus(status)
	if buildError.Valid {
		b.BuildError = buildError.String
	}
	if buildStartedAt.Valid {
		b.BuildStartedAt = &buildStartedAt.Time
	}
	if buildCompletedAt.Valid {
		b.BuildCompletedAt = &buildCompletedAt.Time
	}
	if expiresAt.Valid {
		b.ExpiresAt = &expiresAt.Time
	}

	return &b, nil
}

func joinConditions(conditions []string) string {
	result := ""
	for i, c := range conditions {
		if i > 0 {
			result += " AND "
		}
		result += c
	}
	return result
}

// Ensure interface compliance
var _ rule.BundleRepository = (*RuleBundleRepository)(nil)
