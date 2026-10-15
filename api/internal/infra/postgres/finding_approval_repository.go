package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
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
			justification, status, expires_at, version, created_at, requested_by_actor, decide_by, closure_reason
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	var requestedBy any
	if !a.RequestedBy.IsZero() {
		requestedBy = a.RequestedBy.String()
	}
	_, err := r.db.ExecContext(ctx, query,
		a.ID.String(), a.TenantID.String(), a.FindingID.String(),
		a.RequestedStatus, requestedBy,
		a.Justification, string(a.Status), a.ExpiresAt, a.Version, a.CreatedAt,
		nullString(a.RequestedByActor), a.DecideBy, nullString(a.ClosureReason.String()),
	)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return vulnerability.ErrPendingRequestExists
		}
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
		cond, scopeArgs := dataScopeCondAt("f.asset_id", scope, len(args)+1)
		args = append(args, scopeArgs...)
		where += ` AND a.finding_id IN (SELECT f.id FROM findings f WHERE f.tenant_id = $1 AND ` + cond + `)`
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
		  -- A request past its decide-by time can no longer be rejected (the
		  -- expiry job expires it); the database decides, not the caller's clock.
		  AND NOT ($2 = 'rejected' AND decide_by IS NOT NULL AND decide_by <= now())
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
			rejection_reason, status, expires_at, created_at, version, requested_by_actor, decide_by, closure_reason,
			self_approved, COALESCE(self_approval_reason, ''), single_person
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
		actor           sql.NullString
		decideBy        *time.Time
		closureReason   sql.NullString
	)

	err := scanner.Scan(
		&id, &tenantID, &findingID, &a.RequestedStatus, &requestedBy,
		&a.Justification, &approvedBy, &approvedAt, &rejectedBy, &rejectedAt,
		&rejectionReason, &status, &expiresAt, &a.CreatedAt, &a.Version, &actor, &decideBy, &closureReason,
		&a.SelfApproved, &a.SelfApprovalReason, &a.SinglePerson,
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
	if requestedBy.Valid {
		a.RequestedBy, _ = shared.IDFromString(requestedBy.String)
	}
	a.RequestedByActor = actor.String
	a.ClosureReason = vulnerability.ClosureReason(closureReason.String)
	a.Status = vulnerability.ApprovalStatus(status)
	a.ApprovedAt = approvedAt
	a.RejectedAt = rejectedAt
	a.ExpiresAt = expiresAt
	a.DecideBy = decideBy

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

// ApproveAndApply implements vulnerability.ApprovalRepository: the request
// row, the finding's status (and acceptance end) and the timeline entry are
// written in one transaction. The request is claimed with its version and
// pending status, so a concurrent approver or a cancel makes this one fail
// with ErrConcurrentModification; a finding that is no longer in a status
// the lifecycle allows to move from rolls everything back.
func (r *FindingApprovalRepository) ApproveAndApply(ctx context.Context, a *vulnerability.Approval, entry *vulnerability.FindingActivity) error {
	if a == nil || a.Status != vulnerability.ApprovalStatusApproved || a.ApprovedBy == nil {
		return fmt.Errorf("%w: only an approved request is applied", shared.ErrValidation)
	}
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE finding_status_approvals SET
				status = 'approved', approved_by = $3, approved_at = $4, expires_at = $5, version = $6,
				self_approved = $8, self_approval_reason = $9
			WHERE id = $1 AND tenant_id = $2 AND status = 'pending' AND version = $7
			  AND (decide_by IS NULL OR decide_by > now())`,
			a.ID.String(), a.TenantID.String(), a.ApprovedBy.String(), a.ApprovedAt, a.ExpiresAt,
			a.Version, a.Version-1, a.SelfApproved, nullString(a.SelfApprovalReason))
		if err != nil {
			return fmt.Errorf("failed to approve request: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("failed to approve request: %w", err)
		} else if n == 0 {
			return claimFailure(ctx, tx, a)
		}
		return applyApprovedInTx(ctx, tx, a, entry)
	})
}

// CreateApplied writes a request that is decided as it is made (a false
// positive one person may decide alone) and applies it, in one transaction:
// the request row (approved, single_person), the finding's status and the
// timeline entry. The one-pending-request index still applies to pending
// rows only, so an earlier pending request of another person is left as is.
func (r *FindingApprovalRepository) CreateApplied(ctx context.Context, a *vulnerability.Approval, entry *vulnerability.FindingActivity) error {
	if a == nil || a.Status != vulnerability.ApprovalStatusApproved || a.ApprovedBy == nil || !a.SinglePerson {
		return fmt.Errorf("%w: only a single-person decision is created applied", shared.ErrValidation)
	}
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		// The organization's level and the finding's facts are read again
		// inside the transaction, with the finding locked: a level raised or
		// a finding that became material since the caller decided makes the
		// decision fall back to a request for a second person.
		if err := recheckSinglePersonFP(ctx, tx, a.TenantID, a.FindingID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO finding_status_approvals (
				id, tenant_id, finding_id, requested_status, requested_by, justification, status,
				expires_at, version, created_at, closure_reason, approved_by, approved_at, single_person
			) VALUES ($1, $2, $3, $4, $5, $6, 'approved', $7, $8, $9, $10, $11, $12, true)`,
			a.ID.String(), a.TenantID.String(), a.FindingID.String(), a.RequestedStatus, a.RequestedBy.String(),
			a.Justification, a.ExpiresAt, a.Version, a.CreatedAt, nullString(a.ClosureReason.String()),
			a.ApprovedBy.String(), a.ApprovedAt); err != nil {
			return fmt.Errorf("failed to record the decision: %w", err)
		}
		return applyApprovedInTx(ctx, tx, a, entry)
	})
}

// applyApprovedInTx writes an approved request's effect inside tx: the
// finding's status (and acceptance end, and closure) and the timeline entry.
// A finding no longer in a status the lifecycle allows to move from fails
// the whole transaction.
func applyApprovedInTx(ctx context.Context, tx *sql.Tx, a *vulnerability.Approval, entry *vulnerability.FindingActivity) error {
	status := vulnerability.FindingStatus(a.RequestedStatus)
	var acceptanceEnd *time.Time
	if status == vulnerability.FindingStatusAccepted {
		if a.ExpiresAt == nil {
			return fmt.Errorf("%w: an accepted risk needs an end", shared.ErrValidation)
		}
		acceptanceEnd = a.ExpiresAt
	}
	closure := vulnerability.Closure{Reason: a.ClosureReason}
	if status == vulnerability.FindingStatusFalsePositive && !a.SelfApproved && !a.SinglePerson {
		// A false positive a second person approved is security-reviewed;
		// one person alone establishes no verification.
		closure.Verification = vulnerability.VerificationSecurityReview
	}
	query, args, err := statusWriteSQL(a.TenantID, []shared.ID{a.FindingID}, status, "", a.ApprovedBy, closure, acceptanceEnd, nil)
	if err != nil {
		return err
	}
	if err := markStatusWriteTx(ctx, tx); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to apply approved status: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("failed to apply approved status: %w", err)
	} else if n == 0 {
		return fmt.Errorf("%w: the finding changed since the request; it can no longer move to %s", shared.ErrValidation, status)
	}
	if entry != nil {
		if err := insertFindingActivity(ctx, tx, entry); err != nil {
			return err
		}
	}
	return nil
}

// FalsePositiveFacts reads the facts of a finding that decide whether one
// person may mark it a false positive (tenant-scoped; the asset's facts are
// false when it has none).
func (r *FindingApprovalRepository) FalsePositiveFacts(ctx context.Context, tenantID, findingID shared.ID) (vulnerability.FPFacts, error) {
	var (
		f        vulnerability.FPFacts
		severity string
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT f.severity, COALESCE(f.is_in_kev, false), COALESCE(f.priority_class, ''),
		       COALESCE(f.validation_outcome = 'reproducible', false),
		       COALESCE(a.is_crown_jewel, false), COALESCE(a.is_internet_accessible, false)
		FROM findings f
		LEFT JOIN assets a ON a.tenant_id = f.tenant_id AND a.id = f.asset_id
		WHERE f.tenant_id = $1 AND f.id = $2`,
		tenantID.String(), findingID.String()).Scan(&severity, &f.KEV, &f.PriorityClass, &f.ExploitValidated, &f.CrownJewel, &f.InternetExposed)
	if errors.Is(err, sql.ErrNoRows) {
		return f, fmt.Errorf("%w: finding not found", shared.ErrNotFound)
	}
	if err != nil {
		return f, fmt.Errorf("read false-positive facts: %w", err)
	}
	f.Severity = vulnerability.Severity(severity)
	return f, nil
}

// ExpireOverdueRequests expires pending requests whose decide-by time has
// passed, across tenants (the hourly approval expiration job). Each expired
// request gets a timeline entry on its finding and an audit row in its
// tenant, in the same statement. The finding itself is not touched. Returns
// how many requests it expired.
func (r *FindingApprovalRepository) ExpireOverdueRequests(ctx context.Context) (int64, error) {
	var n int64
	err := r.db.QueryRowContext(ctx, `
		WITH ended AS (
			UPDATE finding_status_approvals a SET status = 'expired', version = a.version + 1
			WHERE a.status = 'pending'
			  -- A row without a decide-by time (written by an older writer)
			  -- gets the default window from its creation.
			  AND COALESCE(a.decide_by, a.created_at + INTERVAL '14 days') < NOW()
			RETURNING a.id, a.tenant_id, a.finding_id, a.requested_status, a.decide_by
		), timeline AS (
			INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source, message)
			SELECT e.tenant_id, e.finding_id, 'approval_canceled', 'system', 'system: approval expiry',
			       jsonb_build_object('approval_id', e.id, 'approval_status', 'expired',
			                          'requested_status', e.requested_status,
			                          'reason', 'decision_overdue', 'decide_by', e.decide_by),
			       'auto', 'Nobody decided the request in time; it expired'
			FROM ended e
		), audit AS (
			INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id, result, severity, message, metadata, logged_at)
			SELECT gen_random_uuid(), e.tenant_id, 'finding_approval.expired', 'finding_approval', e.id::text, 'success', 'low',
			       'A pending finding approval request was not decided in time and expired',
			       jsonb_build_object('finding_id', e.finding_id, 'requested_status', e.requested_status,
			                          'decide_by', e.decide_by), NOW()
			FROM ended e
		)
		SELECT COUNT(*) FROM ended`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("expire overdue approval requests: %w", err)
	}
	return n, nil
}

// MarkReminded records a reminder for a pending request when the last one is
// at least minInterval old (atomic: two clicks at once remind once). It
// answers whether the reminder was recorded.
func (r *FindingApprovalRepository) MarkReminded(ctx context.Context, tenantID, id shared.ID, now time.Time, minInterval time.Duration) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE finding_status_approvals SET reminded_at = $3
		WHERE tenant_id = $1 AND id = $2 AND status = 'pending'
		  AND (reminded_at IS NULL OR reminded_at <= $4)`,
		tenantID.String(), id.String(), now, now.Add(-minInterval))
	if err != nil {
		return false, fmt.Errorf("mark approval reminded: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	return n == 1, nil
}

// claimFailure explains why an approve claimed no row: the request is past
// its decide-by time (ErrDecisionOverdue), or someone else decided or
// changed it first (ErrConcurrentModification).
func claimFailure(ctx context.Context, tx *sql.Tx, a *vulnerability.Approval) error {
	var overdue bool
	err := tx.QueryRowContext(ctx, `
		SELECT status = 'pending' AND decide_by IS NOT NULL AND decide_by <= now()
		FROM finding_status_approvals WHERE id = $1 AND tenant_id = $2`,
		a.ID.String(), a.TenantID.String()).Scan(&overdue)
	if err == nil && overdue {
		return vulnerability.ErrDecisionOverdue
	}
	return vulnerability.ErrConcurrentModification
}

// recheckSinglePersonFP answers vulnerability.ErrSinglePersonNotAllowed
// unless the organization's level in force still lets one person decide a
// false positive on the finding. The finding row is locked (FOR UPDATE) and
// the tenant's settings row is read FOR SHARE, so a concurrent change of
// either waits for this decision or is seen by it.
func recheckSinglePersonFP(ctx context.Context, tx *sql.Tx, tenantID, findingID shared.ID) error {
	var raw []byte
	if err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(settings->'finding_approvals', '{}'::jsonb) FROM tenants WHERE id = $1 FOR SHARE`,
		tenantID.String()).Scan(&raw); err != nil {
		return fmt.Errorf("read the approval level: %w", err)
	}
	var settings tenantdom.FindingApprovalSettings
	if err := json.Unmarshal(raw, &settings); err != nil {
		return vulnerability.ErrSinglePersonNotAllowed // unreadable: a second person decides
	}
	var (
		f        vulnerability.FPFacts
		severity string
	)
	err := tx.QueryRowContext(ctx, `
		SELECT f.severity, COALESCE(f.is_in_kev, false), COALESCE(f.priority_class, ''),
		       COALESCE(f.validation_outcome = 'reproducible', false),
		       COALESCE(a.is_crown_jewel, false), COALESCE(a.is_internet_accessible, false)
		FROM findings f
		LEFT JOIN assets a ON a.tenant_id = f.tenant_id AND a.id = f.asset_id
		WHERE f.tenant_id = $1 AND f.id = $2
		FOR UPDATE OF f`,
		tenantID.String(), findingID.String()).Scan(&severity, &f.KEV, &f.PriorityClass, &f.ExploitValidated, &f.CrownJewel, &f.InternetExposed)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: finding not found", shared.ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("read false-positive facts: %w", err)
	}
	f.Severity = vulnerability.Severity(severity)
	if !vulnerability.SinglePersonFP(settings.EffectiveFPApproval(time.Now()), f) {
		return vulnerability.ErrSinglePersonNotAllowed
	}
	return nil
}
