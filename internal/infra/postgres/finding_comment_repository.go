package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// FindingCommentRepository handles finding comment persistence.
type FindingCommentRepository struct {
	db *DB
}

// NewFindingCommentRepository creates a new FindingCommentRepository.
func NewFindingCommentRepository(db *DB) *FindingCommentRepository {
	return &FindingCommentRepository{db: db}
}

// Create persists a new finding comment.
func (r *FindingCommentRepository) Create(ctx context.Context, comment *vulnerability.FindingComment) error {
	query := `
		INSERT INTO finding_comments (
			id, finding_id, author_id, content,
			is_status_change, old_status, new_status,
			created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err := r.db.ExecContext(ctx, query,
		comment.ID().String(),
		comment.FindingID().String(),
		comment.AuthorID().String(),
		comment.Content(),
		comment.IsStatusChange(),
		nullFindingStatus(comment.OldStatus()),
		nullFindingStatus(comment.NewStatus()),
		comment.CreatedAt(),
		comment.UpdatedAt(),
	)

	if err != nil {
		return fmt.Errorf("failed to create finding comment: %w", err)
	}

	return nil
}

// GetByID retrieves a comment by ID.
func (r *FindingCommentRepository) GetByID(ctx context.Context, id shared.ID) (*vulnerability.FindingComment, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanComment(row)
}

// Update updates an existing comment.
func (r *FindingCommentRepository) Update(ctx context.Context, comment *vulnerability.FindingComment) error {
	query := `
		UPDATE finding_comments SET
			content = $2, updated_at = $3
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		comment.ID().String(),
		comment.Content(),
		comment.UpdatedAt(),
	)

	if err != nil {
		return fmt.Errorf("failed to update finding comment: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("comment not found")
	}

	return nil
}

// Delete removes a comment.
func (r *FindingCommentRepository) Delete(ctx context.Context, id shared.ID) error {
	query := `DELETE FROM finding_comments WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete finding comment: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("comment not found")
	}

	return nil
}

// ListByFinding returns all comments for a finding.
func (r *FindingCommentRepository) ListByFinding(ctx context.Context, findingID shared.ID) ([]*vulnerability.FindingComment, error) {
	query := r.selectQuery() + " WHERE finding_id = $1 ORDER BY created_at ASC"

	rows, err := r.db.QueryContext(ctx, query, findingID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query finding comments: %w", err)
	}
	defer rows.Close()

	var comments []*vulnerability.FindingComment
	for rows.Next() {
		comment, err := r.scanCommentFromRows(rows)
		if err != nil {
			return nil, err
		}
		comments = append(comments, comment)
	}

	return comments, nil
}

// CountByFinding returns the comment count for a finding.
func (r *FindingCommentRepository) CountByFinding(ctx context.Context, findingID shared.ID) (int, error) {
	query := `SELECT COUNT(*) FROM finding_comments WHERE finding_id = $1`

	var count int
	err := r.db.QueryRowContext(ctx, query, findingID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count comments: %w", err)
	}

	return count, nil
}

// Helper methods

func (r *FindingCommentRepository) selectQuery() string {
	return `
		SELECT fc.id, fc.finding_id, fc.author_id,
			COALESCE(u.name, '') as author_name,
			COALESCE(u.email, '') as author_email,
			fc.content, fc.is_status_change, fc.old_status, fc.new_status,
			fc.created_at, fc.updated_at
		FROM finding_comments fc
		LEFT JOIN users u ON fc.author_id = u.id
	`
}

func (r *FindingCommentRepository) scanComment(row *sql.Row) (*vulnerability.FindingComment, error) {
	comment, err := r.doScan(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("comment not found")
		}
		return nil, fmt.Errorf("failed to scan finding comment: %w", err)
	}
	return comment, nil
}

func (r *FindingCommentRepository) scanCommentFromRows(rows *sql.Rows) (*vulnerability.FindingComment, error) {
	return r.doScan(rows.Scan)
}

func (r *FindingCommentRepository) doScan(scan func(dest ...any) error) (*vulnerability.FindingComment, error) {
	var (
		idStr          string
		findingIDStr   string
		authorIDStr    string
		authorName     string
		authorEmail    string
		content        string
		isStatusChange bool
		oldStatus      sql.NullString
		newStatus      sql.NullString
		createdAt      time.Time
		updatedAt      time.Time
	)

	err := scan(
		&idStr, &findingIDStr, &authorIDStr,
		&authorName, &authorEmail,
		&content, &isStatusChange, &oldStatus, &newStatus,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	parsedID, err := shared.IDFromString(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse id: %w", err)
	}

	parsedFindingID, err := shared.IDFromString(findingIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse finding_id: %w", err)
	}

	parsedAuthorID, err := shared.IDFromString(authorIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse author_id: %w", err)
	}

	var parsedOldStatus, parsedNewStatus vulnerability.FindingStatus
	if oldStatus.Valid {
		parsedOldStatus, _ = vulnerability.ParseFindingStatus(oldStatus.String)
	}
	if newStatus.Valid {
		parsedNewStatus, _ = vulnerability.ParseFindingStatus(newStatus.String)
	}

	return vulnerability.ReconstituteFindingComment(
		parsedID,
		parsedFindingID,
		parsedAuthorID,
		authorName,
		authorEmail,
		content,
		isStatusChange,
		parsedOldStatus,
		parsedNewStatus,
		createdAt,
		updatedAt,
	), nil
}

// Helper function for nullable finding status
func nullFindingStatus(status vulnerability.FindingStatus) interface{} {
	if status == "" {
		return nil
	}
	return status.String()
}
