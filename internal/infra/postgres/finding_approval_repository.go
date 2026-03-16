package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/pagination"
)

// FindingApprovalRepository implements vulnerability.ApprovalRepository using PostgreSQL.
type FindingApprovalRepository struct {
	db *DB
}

// NewFindingApprovalRepository creates a new FindingApprovalRepository.
func NewFindingApprovalRepository(db *DB) *FindingApprovalRepository {
	return &FindingApprovalRepository{db: db}
}

// Create persists a new approval request.
func (r *FindingApprovalRepository) Create(ctx context.Context, a *vulnerability.Approval) error {
	query := `
		INSERT INTO finding_status_approvals (
			id, tenant_id, finding_id, requested_status, requested_by,
			justification, status, expires_at, version, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	_, err := r.db.ExecContext(ctx, query,
		a.ID.String(), a.TenantID.String(), a.FindingID.String(),
		a.RequestedStatus, a.RequestedBy.String(),
		a.Justification, string(a.Status), a.ExpiresAt, a.Version, a.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create approval: %w", err)
	}

	return nil
}

// GetByTenantAndID retrieves an approval by tenant and ID.
func (r *FindingApprovalRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*vulnerability.Approval, error) {
	query := r.selectQuery() + " WHERE id = $1 AND tenant_id = $2"
	row := r.db.QueryRowContext(ctx, query, id.String(), tenantID.String())
	return r.scanApproval(row)
}

// ListByFinding retrieves all approvals for a finding.
func (r *FindingApprovalRepository) ListByFinding(ctx context.Context, tenantID, findingID shared.ID) ([]*vulnerability.Approval, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND finding_id = $2 ORDER BY created_at DESC"
	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), findingID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list approvals by finding: %w", err)
	}
	defer rows.Close()

	approvals := make([]*vulnerability.Approval, 0)
	for rows.Next() {
		a, err := r.scanApprovalFromRows(rows)
		if err != nil {
			return nil, err
		}
		approvals = append(approvals, a)
	}

	return approvals, rows.Err()
}

// ListPending retrieves all pending approvals for a tenant.
func (r *FindingApprovalRepository) ListPending(ctx context.Context, tenantID shared.ID, page pagination.Pagination) (pagination.Result[*vulnerability.Approval], error) {
	countQuery := "SELECT COUNT(*) FROM finding_status_approvals WHERE tenant_id = $1 AND status = 'pending'"
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, tenantID.String()).Scan(&total); err != nil {
		return pagination.Result[*vulnerability.Approval]{}, fmt.Errorf("failed to count pending approvals: %w", err)
	}

	query := r.selectQuery() + " WHERE tenant_id = $1 AND status = 'pending' ORDER BY created_at DESC LIMIT $2 OFFSET $3"
	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), page.Limit(), page.Offset())
	if err != nil {
		return pagination.Result[*vulnerability.Approval]{}, fmt.Errorf("failed to list pending approvals: %w", err)
	}
	defer rows.Close()

	limit := page.Limit()
	if limit < 0 {
		limit = 0
	}
	if limit > 100 {
		limit = 100
	}

	approvals := make([]*vulnerability.Approval, 0, limit)
	for rows.Next() {
		a, err := r.scanApprovalFromRows(rows)
		if err != nil {
			return pagination.Result[*vulnerability.Approval]{}, err
		}
		approvals = append(approvals, a)
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*vulnerability.Approval]{}, fmt.Errorf("failed to iterate approvals: %w", err)
	}

	return pagination.NewResult(approvals, total, page), nil
}

// Update updates an approval.
func (r *FindingApprovalRepository) Update(ctx context.Context, a *vulnerability.Approval) error {
	query := `
		UPDATE finding_status_approvals SET
			status = $2,
			approved_by = $3,
			approved_at = $4,
			rejected_by = $5,
			rejected_at = $6,
			rejection_reason = $7,
			version = $8
		WHERE id = $1 AND version = $9
	`

	var approvedBy, rejectedBy *string
	if a.ApprovedBy != nil {
		s := a.ApprovedBy.String()
		approvedBy = &s
	}
	if a.RejectedBy != nil {
		s := a.RejectedBy.String()
		rejectedBy = &s
	}

	result, err := r.db.ExecContext(ctx, query,
		a.ID.String(),
		string(a.Status),
		approvedBy,
		a.ApprovedAt,
		rejectedBy,
		a.RejectedAt,
		a.RejectionReason,
		a.Version,
		a.Version-1,
	)
	if err != nil {
		return fmt.Errorf("failed to update approval: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return vulnerability.ErrConcurrentModification
	}

	return nil
}

func (r *FindingApprovalRepository) selectQuery() string {
	return `
		SELECT id, tenant_id, finding_id, requested_status, requested_by,
			justification, approved_by, approved_at, rejected_by, rejected_at,
			rejection_reason, status, expires_at, created_at, version
		FROM finding_status_approvals
	`
}

type approvalScanner interface {
	Scan(dest ...any) error
}

func (r *FindingApprovalRepository) scanApprovalRow(scanner approvalScanner) (*vulnerability.Approval, error) {
	var (
		a               vulnerability.Approval
		id              string
		tenantID        string
		findingID       string
		requestedBy     string
		approvedBy      *string
		approvedAt      *time.Time
		rejectedBy      *string
		rejectedAt      *time.Time
		rejectionReason *string
		status          string
		expiresAt       *time.Time
	)

	err := scanner.Scan(
		&id, &tenantID, &findingID, &a.RequestedStatus, &requestedBy,
		&a.Justification, &approvedBy, &approvedAt, &rejectedBy, &rejectedAt,
		&rejectionReason, &status, &expiresAt, &a.CreatedAt, &a.Version,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: approval not found", shared.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to scan approval: %w", err)
	}

	a.ID, _ = shared.IDFromString(id)
	a.TenantID, _ = shared.IDFromString(tenantID)
	a.FindingID, _ = shared.IDFromString(findingID)
	a.RequestedBy, _ = shared.IDFromString(requestedBy)
	a.Status = vulnerability.ApprovalStatus(status)
	a.ApprovedAt = approvedAt
	a.RejectedAt = rejectedAt
	a.ExpiresAt = expiresAt

	if approvedBy != nil {
		aid, _ := shared.IDFromString(*approvedBy)
		a.ApprovedBy = &aid
	}
	if rejectedBy != nil {
		rid, _ := shared.IDFromString(*rejectedBy)
		a.RejectedBy = &rid
	}
	if rejectionReason != nil {
		a.RejectionReason = *rejectionReason
	}

	return &a, nil
}

func (r *FindingApprovalRepository) scanApproval(row *sql.Row) (*vulnerability.Approval, error) {
	return r.scanApprovalRow(row)
}

func (r *FindingApprovalRepository) scanApprovalFromRows(rows *sql.Rows) (*vulnerability.Approval, error) {
	return r.scanApprovalRow(rows)
}
