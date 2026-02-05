package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/scope"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// ScopeTargetRepository implements scope.TargetRepository using PostgreSQL.
type ScopeTargetRepository struct {
	db *DB
}

// NewScopeTargetRepository creates a new ScopeTargetRepository.
func NewScopeTargetRepository(db *DB) *ScopeTargetRepository {
	return &ScopeTargetRepository{db: db}
}

const scopeTargetSelectQuery = `
	SELECT id, tenant_id, target_type, pattern, description, priority, status, tags,
	       created_by, created_at, updated_at
	FROM scope_targets
`

func (r *ScopeTargetRepository) scanTarget(row interface{ Scan(...any) error }) (*scope.Target, error) {
	var (
		id          string
		tenantID    string
		targetType  string
		pattern     string
		description sql.NullString
		priority    int
		status      string
		tags        pq.StringArray
		createdBy   sql.NullString
		createdAt   sql.NullTime
		updatedAt   sql.NullTime
	)

	err := row.Scan(
		&id, &tenantID, &targetType, &pattern, &description, &priority, &status, &tags,
		&createdBy, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	tid, _ := shared.IDFromString(id)
	tntID, _ := shared.IDFromString(tenantID)

	return scope.ReconstituteTarget(
		tid,
		tntID,
		scope.TargetType(targetType),
		pattern,
		description.String,
		priority,
		scope.Status(status),
		[]string(tags),
		createdBy.String,
		createdAt.Time,
		updatedAt.Time,
	), nil
}

// Create persists a new scope target.
func (r *ScopeTargetRepository) Create(ctx context.Context, target *scope.Target) error {
	query := `
		INSERT INTO scope_targets (
			id, tenant_id, target_type, pattern, description, priority, status, tags,
			created_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err := r.db.ExecContext(ctx, query,
		target.ID().String(),
		target.TenantID().String(),
		target.TargetType().String(),
		target.Pattern(),
		nullString(target.Description()),
		target.Priority(),
		target.Status().String(),
		pq.StringArray(target.Tags()),
		nullString(target.CreatedBy()),
		target.CreatedAt(),
		target.UpdatedAt(),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return scope.ErrTargetAlreadyExists
		}
		return fmt.Errorf("failed to create scope target: %w", err)
	}

	return nil
}

// GetByID retrieves a scope target by its ID.
func (r *ScopeTargetRepository) GetByID(ctx context.Context, id shared.ID) (*scope.Target, error) {
	query := scopeTargetSelectQuery + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())

	target, err := r.scanTarget(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, scope.ErrTargetNotFound
		}
		return nil, fmt.Errorf("failed to get scope target: %w", err)
	}

	return target, nil
}

// Update updates an existing scope target.
func (r *ScopeTargetRepository) Update(ctx context.Context, target *scope.Target) error {
	query := `
		UPDATE scope_targets SET
			description = $2,
			priority = $3,
			status = $4,
			tags = $5,
			updated_at = $6
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		target.ID().String(),
		nullString(target.Description()),
		target.Priority(),
		target.Status().String(),
		pq.StringArray(target.Tags()),
		target.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to update scope target: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return scope.ErrTargetNotFound
	}

	return nil
}

// Delete removes a scope target by its ID.
func (r *ScopeTargetRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM scope_targets WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete scope target: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return scope.ErrTargetNotFound
	}

	return nil
}

// List retrieves scope targets with filtering and pagination.
func (r *ScopeTargetRepository) List(ctx context.Context, filter scope.TargetFilter, page pagination.Pagination) (pagination.Result[*scope.Target], error) {
	var conditions []string
	var args []any
	argNum := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argNum))
		args = append(args, *filter.TenantID)
		argNum++
	}

	if len(filter.TargetTypes) > 0 {
		types := make([]string, len(filter.TargetTypes))
		for i, t := range filter.TargetTypes {
			types[i] = t.String()
		}
		conditions = append(conditions, fmt.Sprintf("target_type = ANY($%d)", argNum))
		args = append(args, pq.StringArray(types))
		argNum++
	}

	if len(filter.Statuses) > 0 {
		statuses := make([]string, len(filter.Statuses))
		for i, s := range filter.Statuses {
			statuses[i] = s.String()
		}
		conditions = append(conditions, fmt.Sprintf("status = ANY($%d)", argNum))
		args = append(args, pq.StringArray(statuses))
		argNum++
	}

	if filter.Search != nil && *filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(pattern ILIKE $%d OR description ILIKE $%d)", argNum, argNum))
		args = append(args, wrapLikePattern(*filter.Search))
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := "SELECT COUNT(*) FROM scope_targets" + whereClause
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return pagination.Result[*scope.Target]{}, fmt.Errorf("failed to count scope targets: %w", err)
	}

	// Query with pagination
	query := scopeTargetSelectQuery + whereClause + " ORDER BY priority DESC, created_at DESC" +
		fmt.Sprintf(" LIMIT $%d OFFSET $%d", argNum, argNum+1)
	args = append(args, page.Limit(), page.Offset())

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*scope.Target]{}, fmt.Errorf("failed to list scope targets: %w", err)
	}
	defer rows.Close()

	var targets []*scope.Target
	for rows.Next() {
		target, err := r.scanTarget(rows)
		if err != nil {
			return pagination.Result[*scope.Target]{}, fmt.Errorf("failed to scan scope target: %w", err)
		}
		targets = append(targets, target)
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*scope.Target]{}, fmt.Errorf("iterate scope targets: %w", err)
	}

	return pagination.NewResult(targets, total, page), nil
}

// ListActive retrieves all active scope targets for a tenant.
func (r *ScopeTargetRepository) ListActive(ctx context.Context, tenantID shared.ID) ([]*scope.Target, error) {
	query := scopeTargetSelectQuery + " WHERE tenant_id = $1 AND status = 'active' ORDER BY priority DESC"

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list active scope targets: %w", err)
	}
	defer rows.Close()

	var targets []*scope.Target
	for rows.Next() {
		target, err := r.scanTarget(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan scope target: %w", err)
		}
		targets = append(targets, target)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active scope targets: %w", err)
	}

	return targets, nil
}

// Count returns the total number of scope targets matching the filter.
func (r *ScopeTargetRepository) Count(ctx context.Context, filter scope.TargetFilter) (int64, error) {
	var conditions []string
	var args []any
	argNum := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argNum))
		args = append(args, *filter.TenantID)
		argNum++
	}

	if len(filter.Statuses) > 0 {
		statuses := make([]string, len(filter.Statuses))
		for i, s := range filter.Statuses {
			statuses[i] = s.String()
		}
		conditions = append(conditions, fmt.Sprintf("status = ANY($%d)", argNum))
		args = append(args, pq.StringArray(statuses))
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	query := "SELECT COUNT(*) FROM scope_targets" + whereClause
	var count int64
	if err := r.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count scope targets: %w", err)
	}

	return count, nil
}

// ExistsByPattern checks if a target with the given pattern exists.
func (r *ScopeTargetRepository) ExistsByPattern(ctx context.Context, tenantID shared.ID, targetType scope.TargetType, pattern string) (bool, error) {
	query := "SELECT EXISTS(SELECT 1 FROM scope_targets WHERE tenant_id = $1 AND target_type = $2 AND pattern = $3)"
	var exists bool
	if err := r.db.QueryRowContext(ctx, query, tenantID.String(), targetType.String(), pattern).Scan(&exists); err != nil {
		return false, fmt.Errorf("failed to check scope target existence: %w", err)
	}
	return exists, nil
}
