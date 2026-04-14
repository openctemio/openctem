package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/relationship"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// RelationshipSuggestionRepository implements relationship.SuggestionRepository using PostgreSQL.
type RelationshipSuggestionRepository struct {
	db *DB
}

// NewRelationshipSuggestionRepository creates a new RelationshipSuggestionRepository.
func NewRelationshipSuggestionRepository(db *DB) *RelationshipSuggestionRepository {
	return &RelationshipSuggestionRepository{db: db}
}

// Create persists a new suggestion.
func (r *RelationshipSuggestionRepository) Create(ctx context.Context, s *relationship.Suggestion) error {
	query := `
		INSERT INTO relationship_suggestions (
			id, tenant_id, source_asset_id, target_asset_id,
			relationship_type, reason, confidence, status, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err := r.db.ExecContext(ctx, query,
		s.ID().String(),
		s.TenantID().String(),
		s.SourceAssetID().String(),
		s.TargetAssetID().String(),
		s.RelationshipType(),
		s.Reason(),
		s.Confidence(),
		s.Status(),
		s.CreatedAt(),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: suggestion already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to create suggestion: %w", err)
	}

	return nil
}

// CreateBatch inserts multiple suggestions, skipping duplicates via ON CONFLICT DO NOTHING.
func (r *RelationshipSuggestionRepository) CreateBatch(ctx context.Context, suggestions []*relationship.Suggestion) (int, error) {
	if len(suggestions) == 0 {
		return 0, nil
	}

	query := `
		INSERT INTO relationship_suggestions (
			id, tenant_id, source_asset_id, target_asset_id,
			relationship_type, reason, confidence, status, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id, source_asset_id, target_asset_id, relationship_type) DO NOTHING
	`

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	created := 0
	for _, s := range suggestions {
		result, execErr := stmt.ExecContext(ctx,
			s.ID().String(),
			s.TenantID().String(),
			s.SourceAssetID().String(),
			s.TargetAssetID().String(),
			s.RelationshipType(),
			s.Reason(),
			s.Confidence(),
			s.Status(),
			s.CreatedAt(),
		)
		if execErr != nil {
			return created, fmt.Errorf("failed to insert suggestion: %w", execErr)
		}
		rowsAffected, _ := result.RowsAffected()
		if rowsAffected > 0 {
			created++
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return created, nil
}

// GetByID retrieves a suggestion by ID within a tenant.
func (r *RelationshipSuggestionRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*relationship.Suggestion, error) {
	query := `
		SELECT id, tenant_id, source_asset_id, target_asset_id,
		       relationship_type, reason, confidence, status,
		       reviewed_by, reviewed_at, created_at
		FROM relationship_suggestions
		WHERE tenant_id = $1 AND id = $2
	`

	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	s, err := r.scanSuggestion(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, relationship.ErrSuggestionNotFound
		}
		return nil, fmt.Errorf("failed to get suggestion: %w", err)
	}

	return s, nil
}

// ListPending retrieves pending suggestions for a tenant with pagination.
func (r *RelationshipSuggestionRepository) ListPending(ctx context.Context, tenantID shared.ID, page pagination.Pagination) (pagination.Result[*relationship.Suggestion], error) {
	// Count total pending
	countQuery := `SELECT COUNT(*) FROM relationship_suggestions WHERE tenant_id = $1 AND status = 'pending'`
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, tenantID.String()).Scan(&total); err != nil {
		return pagination.Result[*relationship.Suggestion]{}, fmt.Errorf("failed to count suggestions: %w", err)
	}

	if total == 0 {
		return pagination.NewResult(make([]*relationship.Suggestion, 0), 0, page), nil
	}

	// Fetch page
	query := `
		SELECT id, tenant_id, source_asset_id, target_asset_id,
		       relationship_type, reason, confidence, status,
		       reviewed_by, reviewed_at, created_at
		FROM relationship_suggestions
		WHERE tenant_id = $1 AND status = 'pending'
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), page.Limit(), page.Offset())
	if err != nil {
		return pagination.Result[*relationship.Suggestion]{}, fmt.Errorf("failed to list suggestions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	suggestions := make([]*relationship.Suggestion, 0, page.Limit())
	for rows.Next() {
		s, scanErr := r.scanSuggestion(rows)
		if scanErr != nil {
			return pagination.Result[*relationship.Suggestion]{}, fmt.Errorf("failed to scan suggestion: %w", scanErr)
		}
		suggestions = append(suggestions, s)
	}
	if err = rows.Err(); err != nil {
		return pagination.Result[*relationship.Suggestion]{}, fmt.Errorf("failed to iterate suggestions: %w", err)
	}

	return pagination.NewResult(suggestions, total, page), nil
}

// UpdateStatus updates the status, reviewed_by, and reviewed_at of a suggestion.
func (r *RelationshipSuggestionRepository) UpdateStatus(ctx context.Context, s *relationship.Suggestion) error {
	query := `
		UPDATE relationship_suggestions
		SET status = $3, reviewed_by = $4, reviewed_at = $5
		WHERE tenant_id = $1 AND id = $2
	`

	result, err := r.db.ExecContext(ctx, query,
		s.TenantID().String(),
		s.ID().String(),
		s.Status(),
		nullIDPtr(s.ReviewedBy()),
		s.ReviewedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to update suggestion status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return relationship.ErrSuggestionNotFound
	}

	return nil
}

// CountPending returns the number of pending suggestions for a tenant.
func (r *RelationshipSuggestionRepository) CountPending(ctx context.Context, tenantID shared.ID) (int64, error) {
	query := `SELECT COUNT(*) FROM relationship_suggestions WHERE tenant_id = $1 AND status = 'pending'`
	var count int64
	if err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count pending suggestions: %w", err)
	}
	return count, nil
}

// DeleteByAssetID deletes all suggestions involving a given asset.
func (r *RelationshipSuggestionRepository) DeleteByAssetID(ctx context.Context, tenantID, assetID shared.ID) error {
	query := `
		DELETE FROM relationship_suggestions
		WHERE tenant_id = $1 AND (source_asset_id = $2 OR target_asset_id = $2)
	`
	_, err := r.db.ExecContext(ctx, query, tenantID.String(), assetID.String())
	if err != nil {
		return fmt.Errorf("failed to delete suggestions by asset: %w", err)
	}
	return nil
}

// ApproveAll marks all pending suggestions as approved and returns them.
func (r *RelationshipSuggestionRepository) ApproveAll(ctx context.Context, tenantID, reviewerID shared.ID) ([]*relationship.Suggestion, error) {
	now := time.Now().UTC()

	query := `
		UPDATE relationship_suggestions
		SET status = 'approved', reviewed_by = $2, reviewed_at = $3
		WHERE tenant_id = $1 AND status = 'pending'
		RETURNING id, tenant_id, source_asset_id, target_asset_id,
		          relationship_type, reason, confidence, status,
		          reviewed_by, reviewed_at, created_at
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), reviewerID.String(), now)
	if err != nil {
		return nil, fmt.Errorf("failed to approve all suggestions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	suggestions := make([]*relationship.Suggestion, 0)
	for rows.Next() {
		s, scanErr := r.scanSuggestion(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("failed to scan approved suggestion: %w", scanErr)
		}
		suggestions = append(suggestions, s)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate approved suggestions: %w", err)
	}

	return suggestions, nil
}

// =============================================================================
// Internal helpers
// =============================================================================

// suggestionScanner is satisfied by both *sql.Row and *sql.Rows.
type suggestionScanner interface {
	Scan(dest ...any) error
}

func (r *RelationshipSuggestionRepository) scanSuggestion(row suggestionScanner) (*relationship.Suggestion, error) {
	var (
		id            string
		tenantID      string
		sourceAssetID string
		targetAssetID string
		relType       string
		reason        string
		confidence    float64
		status        string
		reviewedByStr sql.NullString
		reviewedAt    *time.Time
		createdAt     time.Time
	)

	err := row.Scan(
		&id, &tenantID, &sourceAssetID, &targetAssetID,
		&relType, &reason, &confidence, &status,
		&reviewedByStr, &reviewedAt, &createdAt,
	)
	if err != nil {
		return nil, err
	}

	var reviewedBy *shared.ID
	if reviewedByStr.Valid {
		parsedID := shared.MustIDFromString(reviewedByStr.String)
		reviewedBy = &parsedID
	}

	return relationship.ReconstituteSuggestion(
		shared.MustIDFromString(id),
		shared.MustIDFromString(tenantID),
		shared.MustIDFromString(sourceAssetID),
		shared.MustIDFromString(targetAssetID),
		relType,
		reason,
		confidence,
		status,
		reviewedBy,
		reviewedAt,
		createdAt,
	), nil
}
