package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/pagination"
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

// approvalWhere is the tenant (and, for a restricted caller, data-scope)
// condition of an approval list; args start with the tenant id. The scope
// mirrors datascope.FilterFindings: the approval's finding must sit on an
// asset in the user's scope.
func approvalWhere(tenantID shared.ID, scope *shared.DataScope) (string, []any) {
	where := "a.tenant_id = $1"
	args := []any{tenantID.String()}
	if scope != nil {
		args = append(args, scope.UserID.String())
		where += fmt.Sprintf(` AND a.finding_id IN (
			SELECT f.id FROM findings f
			WHERE f.tenant_id = $1
			  AND f.asset_id IN (SELECT uaa.asset_id FROM user_accessible_assets uaa
			                     WHERE uaa.user_id = $%d AND uaa.tenant_id = $1))`, len(args))
	}
	return where, args
}

// List returns a tenant's approvals, newest first, filtered by status (empty
// = every status) and, for a restricted caller, by data scope. Total and the
// per-status counts use the same tenant and scope condition.
func (r *FindingApprovalRepository) List(ctx context.Context, tenantID shared.ID, filter vulnerability.ApprovalFilter, page pagination.Pagination, scope *shared.DataScope) (vulnerability.ApprovalPage, error) {
	where, args := approvalWhere(tenantID, scope)

	counts := make(map[vulnerability.ApprovalStatus]int64, len(vulnerability.ApprovalStatuses))
	countRows, err := r.db.QueryContext(ctx,
		"SELECT a.status, COUNT(*) FROM finding_status_approvals a WHERE "+where+" GROUP BY a.status", args...)
	if err != nil {
		return vulnerability.ApprovalPage{}, fmt.Errorf("failed to count approvals: %w", err)
	}
	defer countRows.Close()
	var all int64
	for countRows.Next() {
		var st string
		var n int64
		if err := countRows.Scan(&st, &n); err != nil {
			return vulnerability.ApprovalPage{}, fmt.Errorf("failed to scan approval count: %w", err)
		}
		counts[vulnerability.ApprovalStatus(st)] = n
		all += n
	}
	if err := countRows.Err(); err != nil {
		return vulnerability.ApprovalPage{}, fmt.Errorf("failed to count approvals: %w", err)
	}

	total := all
	if filter.Status != "" {
		args = append(args, string(filter.Status))
		where += fmt.Sprintf(" AND a.status = $%d", len(args))
		total = counts[filter.Status]
	}
	args = append(args, page.Limit(), page.Offset())
	query := r.selectQuery() + " a WHERE " + where +
		fmt.Sprintf(" ORDER BY a.created_at DESC, a.id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return vulnerability.ApprovalPage{}, fmt.Errorf("failed to list approvals: %w", err)
	}
	defer rows.Close()

	// Pre-allocate at the const cold-cap max so make() has ZERO
	// user-influenced size input (CodeQL go/unsafe-slice-allocation keeps
	// page.Limit() tainted even after the bounds clamp).
	const maxApprovalsCap = 100
	approvals := make([]*vulnerability.Approval, 0, maxApprovalsCap)
	for rows.Next() {
		a, err := r.scanApprovalFromRows(rows)
		if err != nil {
			return vulnerability.ApprovalPage{}, err
		}
		approvals = append(approvals, a)
	}
	if err := rows.Err(); err != nil {
		return vulnerability.ApprovalPage{}, fmt.Errorf("failed to iterate approvals: %w", err)
	}

	return vulnerability.ApprovalPage{
		Result:       pagination.NewResult(approvals, total, page),
		StatusCounts: counts,
	}, nil
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
		WHERE id = $1 AND version = $9 AND tenant_id = $10
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
		a.TenantID.String(),
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

// ListExpiredApproved retrieves all approved approvals that have expired.
// Cross-tenant query for the background expiration controller.
func (r *FindingApprovalRepository) ListExpiredApproved(ctx context.Context, limit int) ([]*vulnerability.Approval, error) {
	if limit <= 0 {
		limit = 100
	}

	query := r.selectQuery() + ` WHERE status = 'approved' AND expires_at IS NOT NULL AND expires_at < NOW() ORDER BY expires_at ASC LIMIT $1`
	rows, err := r.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list expired approved approvals: %w", err)
	}
	defer rows.Close()

	approvals := make([]*vulnerability.Approval, 0, limit)
	for rows.Next() {
		a, err := r.scanApprovalFromRows(rows)
		if err != nil {
			return nil, err
		}
		approvals = append(approvals, a)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate expired approvals: %w", err)
	}

	return approvals, nil
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
		requestedBy     sql.NullString // NULL once the requester is deleted
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
	a.RequestedBy, _ = shared.IDFromString(requestedBy.String)
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
