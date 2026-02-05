package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/scope"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// ScopeExclusionRepository implements scope.ExclusionRepository using PostgreSQL.
type ScopeExclusionRepository struct {
	db *DB
}

// NewScopeExclusionRepository creates a new ScopeExclusionRepository.
func NewScopeExclusionRepository(db *DB) *ScopeExclusionRepository {
	return &ScopeExclusionRepository{db: db}
}

const scopeExclusionSelectQuery = `
	SELECT id, tenant_id, exclusion_type, pattern, reason, status, expires_at,
	       approved_by, approved_at, created_by, created_at, updated_at
	FROM scope_exclusions
`

func (r *ScopeExclusionRepository) scanExclusion(row interface{ Scan(...any) error }) (*scope.Exclusion, error) {
	var (
		id            string
		tenantID      string
		exclusionType string
		pattern       string
		reason        string
		status        string
		expiresAt     sql.NullTime
		approvedBy    sql.NullString
		approvedAt    sql.NullTime
		createdBy     sql.NullString
		createdAt     sql.NullTime
		updatedAt     sql.NullTime
	)

	err := row.Scan(
		&id, &tenantID, &exclusionType, &pattern, &reason, &status, &expiresAt,
		&approvedBy, &approvedAt, &createdBy, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	eid, _ := shared.IDFromString(id)
	tntID, _ := shared.IDFromString(tenantID)

	var expAt *time.Time
	if expiresAt.Valid {
		expAt = &expiresAt.Time
	}

	var appAt *time.Time
	if approvedAt.Valid {
		appAt = &approvedAt.Time
	}

	return scope.ReconstituteExclusion(
		eid,
		tntID,
		scope.ExclusionType(exclusionType),
		pattern,
		reason,
		scope.Status(status),
		expAt,
		approvedBy.String,
		appAt,
		createdBy.String,
		createdAt.Time,
		updatedAt.Time,
	), nil
}

// Create persists a new scope exclusion.
func (r *ScopeExclusionRepository) Create(ctx context.Context, exclusion *scope.Exclusion) error {
	query := `
		INSERT INTO scope_exclusions (
			id, tenant_id, exclusion_type, pattern, reason, status, expires_at,
			approved_by, approved_at, created_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err := r.db.ExecContext(ctx, query,
		exclusion.ID().String(),
		exclusion.TenantID().String(),
		exclusion.ExclusionType().String(),
		exclusion.Pattern(),
		exclusion.Reason(),
		exclusion.Status().String(),
		nullTime(exclusion.ExpiresAt()),
		nullString(exclusion.ApprovedBy()),
		nullTime(exclusion.ApprovedAt()),
		nullString(exclusion.CreatedBy()),
		exclusion.CreatedAt(),
		exclusion.UpdatedAt(),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return scope.ErrExclusionAlreadyExists
		}
		return fmt.Errorf("failed to create scope exclusion: %w", err)
	}

	return nil
}

// GetByID retrieves a scope exclusion by its ID.
func (r *ScopeExclusionRepository) GetByID(ctx context.Context, id shared.ID) (*scope.Exclusion, error) {
	query := scopeExclusionSelectQuery + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())

	exclusion, err := r.scanExclusion(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, scope.ErrExclusionNotFound
		}
		return nil, fmt.Errorf("failed to get scope exclusion: %w", err)
	}

	return exclusion, nil
}

// Update updates an existing scope exclusion.
func (r *ScopeExclusionRepository) Update(ctx context.Context, exclusion *scope.Exclusion) error {
	query := `
		UPDATE scope_exclusions SET
			reason = $2,
			status = $3,
			expires_at = $4,
			approved_by = $5,
			approved_at = $6,
			updated_at = $7
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		exclusion.ID().String(),
		exclusion.Reason(),
		exclusion.Status().String(),
		nullTime(exclusion.ExpiresAt()),
		nullString(exclusion.ApprovedBy()),
		nullTime(exclusion.ApprovedAt()),
		exclusion.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to update scope exclusion: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return scope.ErrExclusionNotFound
	}

	return nil
}

// Delete removes a scope exclusion by its ID.
func (r *ScopeExclusionRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM scope_exclusions WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete scope exclusion: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return scope.ErrExclusionNotFound
	}

	return nil
}

// List retrieves scope exclusions with filtering and pagination.
func (r *ScopeExclusionRepository) List(ctx context.Context, filter scope.ExclusionFilter, page pagination.Pagination) (pagination.Result[*scope.Exclusion], error) {
	var conditions []string
	var args []any
	argNum := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argNum))
		args = append(args, *filter.TenantID)
		argNum++
	}

	if len(filter.ExclusionTypes) > 0 {
		types := make([]string, len(filter.ExclusionTypes))
		for i, t := range filter.ExclusionTypes {
			types[i] = t.String()
		}
		conditions = append(conditions, fmt.Sprintf("exclusion_type = ANY($%d)", argNum))
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

	if filter.IsApproved != nil {
		if *filter.IsApproved {
			conditions = append(conditions, "approved_by IS NOT NULL")
		} else {
			conditions = append(conditions, "approved_by IS NULL")
		}
	}

	if filter.Search != nil && *filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(pattern ILIKE $%d OR reason ILIKE $%d)", argNum, argNum))
		args = append(args, wrapLikePattern(*filter.Search))
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := "SELECT COUNT(*) FROM scope_exclusions" + whereClause
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return pagination.Result[*scope.Exclusion]{}, fmt.Errorf("failed to count scope exclusions: %w", err)
	}

	// Query with pagination
	query := scopeExclusionSelectQuery + whereClause + " ORDER BY created_at DESC" +
		fmt.Sprintf(" LIMIT $%d OFFSET $%d", argNum, argNum+1)
	args = append(args, page.Limit(), page.Offset())

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*scope.Exclusion]{}, fmt.Errorf("failed to list scope exclusions: %w", err)
	}
	defer rows.Close()

	var exclusions []*scope.Exclusion
	for rows.Next() {
		exclusion, err := r.scanExclusion(rows)
		if err != nil {
			return pagination.Result[*scope.Exclusion]{}, fmt.Errorf("failed to scan scope exclusion: %w", err)
		}
		exclusions = append(exclusions, exclusion)
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*scope.Exclusion]{}, fmt.Errorf("iterate scope exclusions: %w", err)
	}

	return pagination.NewResult(exclusions, total, page), nil
}

// ListActive retrieves all active scope exclusions for a tenant.
func (r *ScopeExclusionRepository) ListActive(ctx context.Context, tenantID shared.ID) ([]*scope.Exclusion, error) {
	query := scopeExclusionSelectQuery + `
		WHERE tenant_id = $1
		AND status = 'active'
		AND (expires_at IS NULL OR expires_at > NOW())
		ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list active scope exclusions: %w", err)
	}
	defer rows.Close()

	var exclusions []*scope.Exclusion
	for rows.Next() {
		exclusion, err := r.scanExclusion(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan scope exclusion: %w", err)
		}
		exclusions = append(exclusions, exclusion)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active scope exclusions: %w", err)
	}

	return exclusions, nil
}

// Count returns the total number of scope exclusions matching the filter.
func (r *ScopeExclusionRepository) Count(ctx context.Context, filter scope.ExclusionFilter) (int64, error) {
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

	query := "SELECT COUNT(*) FROM scope_exclusions" + whereClause
	var count int64
	if err := r.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count scope exclusions: %w", err)
	}

	return count, nil
}

// ExpireOld marks expired exclusions as expired.
func (r *ScopeExclusionRepository) ExpireOld(ctx context.Context) error {
	query := `
		UPDATE scope_exclusions
		SET status = 'expired', updated_at = NOW()
		WHERE status = 'active'
		AND expires_at IS NOT NULL
		AND expires_at < NOW()
	`
	_, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to expire old exclusions: %w", err)
	}
	return nil
}
