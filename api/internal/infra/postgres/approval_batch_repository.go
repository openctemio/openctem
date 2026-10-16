package postgres

// Group-level exceptions (api/docs/rfcs/RFC-111-approval-policy.md §7): the
// batch request, its member finding requests, sign-offs and decision. Every
// query is scoped to one tenant.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// signoffSubjectBatch is the subject type of a group exception's sign-offs.
const signoffSubjectBatch = "approval_batch"

// PendingFindingIDs answers which of the tenant's listed findings already
// have a pending request.
func (r *FindingApprovalRepository) PendingFindingIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]bool, error) {
	out := map[shared.ID]bool{}
	if len(ids) == 0 {
		return out, nil
	}
	strs := make([]string, len(ids))
	for i, id := range ids {
		strs[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT finding_id::text FROM finding_status_approvals
		WHERE tenant_id = $1 AND finding_id = ANY($2::uuid[]) AND status = 'pending'`, tenantID.String(), pq.Array(strs))
	if err != nil {
		return nil, fmt.Errorf("read pending requests: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("scan pending request: %w", err)
		}
		if id, err := shared.IDFromString(s); err == nil {
			out[id] = true
		}
	}
	return out, rows.Err()
}

// PendingBatchForSource reports whether the source (a task) already has a
// pending group exception.
func (r *FindingApprovalRepository) PendingBatchForSource(ctx context.Context, tenantID shared.ID, sourceType string, sourceID shared.ID) (bool, error) {
	var ok bool
	if err := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM approval_batches
		WHERE tenant_id = $1 AND source_type = $2 AND source_id = $3 AND status = 'pending')`,
		tenantID.String(), sourceType, sourceID.String()).Scan(&ok); err != nil {
		return false, fmt.Errorf("read pending group exception: %w", err)
	}
	return ok, nil
}

// CreateBatch writes a group exception and its member requests in one
// transaction. A member that got a pending request since the preview fails
// the whole batch (ErrPendingRequestExists); a second pending exception for
// the same task fails with ErrPendingRequestExists too.
func (r *FindingApprovalRepository) CreateBatch(ctx context.Context, b *vulnerability.ApprovalBatch, members []*vulnerability.Approval) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO approval_batches (id, tenant_id, source_type, source_id, requested_status, closure_reason, justification,
				expires_at, requested_by, tier, risk_class, required_approvals, policy_eval, status, decide_by, member_count, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'pending', $14, $15, $16)`,
			b.ID.String(), b.TenantID.String(), b.SourceType, b.SourceID.String(), string(b.RequestedStatus), b.ClosureReason.String(),
			b.Justification, b.ExpiresAt, b.RequestedBy.String(), b.Tier, b.RiskClass, b.RequiredApprovals, nullJSON(b.PolicyEval),
			b.DecideBy, b.MemberCount, b.CreatedAt)
		if err != nil {
			var pqErr *pq.Error
			if errors.As(err, &pqErr) && pqErr.Code == "23505" {
				return fmt.Errorf("%w: this task already has a pending exception", shared.ErrConflict)
			}
			return fmt.Errorf("create group exception: %w", err)
		}
		for _, a := range members {
			if err := insertApprovalTx(ctx, tx, a); err != nil {
				return err
			}
		}
		return nil
	})
}

// insertApprovalTx writes one member request (pending, batch_id set).
func insertApprovalTx(ctx context.Context, tx *sql.Tx, a *vulnerability.Approval) error {
	var batch any
	if a.BatchID != nil {
		batch = a.BatchID.String()
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO finding_status_approvals (
			id, tenant_id, finding_id, requested_status, requested_by, justification, status, expires_at, version,
			created_at, decide_by, closure_reason, tier, risk_class, required_approvals, policy_eval, batch_id
		) VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		a.ID.String(), a.TenantID.String(), a.FindingID.String(), a.RequestedStatus, a.RequestedBy.String(), a.Justification,
		a.ExpiresAt, a.Version, a.CreatedAt, a.DecideBy, nullString(a.ClosureReason.String()),
		nullString(a.Tier), nullString(a.RiskClass), nullRequired(a), nullJSON(a.PolicyEval), batch)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return vulnerability.ErrPendingRequestExists
		}
		return fmt.Errorf("create member request: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_id, actor_type, changes, source, message)
		VALUES ($1, $2, 'approval_requested', $3, 'user', jsonb_build_object('approval_id', $4::text, 'batch_id', $5::text,
			'requested_status', $6::text, 'closure_reason', $7::text), 'api', 'Requested with a group exception')`,
		a.TenantID.String(), a.FindingID.String(), a.RequestedBy.String(), a.ID.String(), batch, a.RequestedStatus,
		a.ClosureReason.String()); err != nil {
		return fmt.Errorf("record member request: %w", err)
	}
	return nil
}

const batchSelect = `
	SELECT b.id, b.tenant_id, b.source_type, b.source_id, b.requested_status, b.closure_reason, b.justification,
	       b.expires_at, COALESCE(b.requested_by::text, ''), b.tier, b.risk_class, b.required_approvals, b.policy_eval,
	       b.status, b.decide_by, b.member_count, b.decided_by::text, b.decided_at, COALESCE(b.rejection_reason, ''),
	       b.version, b.created_at,
	       (SELECT COUNT(*) FROM approval_signoffs so
	        WHERE so.tenant_id = b.tenant_id AND so.subject_type = 'approval_batch' AND so.subject_id = b.id),
	       COALESCE((SELECT t.title FROM remediation_tasks t WHERE t.tenant_id = b.tenant_id AND t.id = b.source_id), '')
	FROM approval_batches b`

type batchScanner interface {
	Scan(dest ...any) error
}

func scanBatch(row batchScanner) (*vulnerability.ApprovalBatch, error) {
	var (
		b                                  vulnerability.ApprovalBatch
		id, tenant, source, status, reason string
		requested, requestedBy             string
		decidedBy                          sql.NullString
		decidedAt                          sql.NullTime
		expiresAt                          sql.NullTime
	)
	if err := row.Scan(&id, &tenant, &b.SourceType, &source, &requested, &reason, &b.Justification,
		&expiresAt, &requestedBy, &b.Tier, &b.RiskClass, &b.RequiredApprovals, &b.PolicyEval,
		&status, &b.DecideBy, &b.MemberCount, &decidedBy, &decidedAt, &b.RejectionReason,
		&b.Version, &b.CreatedAt, &b.ApprovalsCollected, &b.SourceTitle); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: group exception not found", shared.ErrNotFound)
		}
		return nil, fmt.Errorf("scan group exception: %w", err)
	}
	b.ID, _ = shared.IDFromString(id)
	b.TenantID, _ = shared.IDFromString(tenant)
	b.SourceID, _ = shared.IDFromString(source)
	b.RequestedStatus = vulnerability.FindingStatus(requested)
	b.ClosureReason = vulnerability.ClosureReason(reason)
	b.Status = vulnerability.ApprovalStatus(status)
	if requestedBy != "" {
		b.RequestedBy, _ = shared.IDFromString(requestedBy)
	}
	if decidedBy.Valid {
		did, _ := shared.IDFromString(decidedBy.String)
		b.DecidedBy = &did
	}
	if decidedAt.Valid {
		t := decidedAt.Time
		b.DecidedAt = &t
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		b.ExpiresAt = &t
	}
	return &b, nil
}

// GetBatch reads one group exception of the tenant.
func (r *FindingApprovalRepository) GetBatch(ctx context.Context, tenantID, id shared.ID) (*vulnerability.ApprovalBatch, error) {
	return scanBatch(r.db.QueryRowContext(ctx, batchSelect+` WHERE b.tenant_id = $1 AND b.id = $2`, tenantID.String(), id.String()))
}

// ListBatches lists the tenant's group exceptions, newest first, filtered by
// status (empty: all) and source id (nil: all). A restricted caller sees only exceptions whose every
// member finding is in their data scope.
func (r *FindingApprovalRepository) ListBatches(ctx context.Context, tenantID shared.ID, status string, source *shared.ID, scope *shared.DataScope,
	page pagination.Pagination,
) (pagination.Result[*vulnerability.ApprovalBatch], error) {
	where := "b.tenant_id = $1"
	args := []any{tenantID.String()}
	if status != "" {
		args = append(args, status)
		where += fmt.Sprintf(" AND b.status = $%d", len(args))
	}
	if source != nil {
		args = append(args, source.String())
		where += fmt.Sprintf(" AND b.source_id = $%d", len(args))
	}
	if scope != nil {
		cond, scopeArgs := dataScopeCondAt("f.asset_id", scope, len(args)+1)
		args = append(args, scopeArgs...)
		where += ` AND NOT EXISTS (SELECT 1 FROM finding_status_approvals m JOIN findings f ON f.tenant_id = m.tenant_id AND f.id = m.finding_id
			WHERE m.tenant_id = b.tenant_id AND m.batch_id = b.id AND NOT (` + cond + `))`
	}
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM approval_batches b WHERE `+where, args...).Scan(&total); err != nil {
		return pagination.Result[*vulnerability.ApprovalBatch]{}, fmt.Errorf("count group exceptions: %w", err)
	}
	args = append(args, page.Limit(), page.Offset())
	rows, err := r.db.QueryContext(ctx, batchSelect+` WHERE `+where+
		fmt.Sprintf(` ORDER BY b.created_at DESC, b.id DESC LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return pagination.Result[*vulnerability.ApprovalBatch]{}, fmt.Errorf("list group exceptions: %w", err)
	}
	defer rows.Close()
	const maxPage = 100
	out := make([]*vulnerability.ApprovalBatch, 0, maxPage)
	for rows.Next() {
		b, err := scanBatch(rows)
		if err != nil {
			return pagination.Result[*vulnerability.ApprovalBatch]{}, err
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[*vulnerability.ApprovalBatch]{}, fmt.Errorf("list group exceptions: %w", err)
	}
	return pagination.NewResult(out, total, page), nil
}

// BatchMembers lists the member requests of a group exception.
func (r *FindingApprovalRepository) BatchMembers(ctx context.Context, tenantID, batchID shared.ID) ([]vulnerability.ApprovalBatchMember, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT m.id::text, m.finding_id::text, COALESCE(f.title, f.message, ''), COALESCE(f.severity, ''), m.status, m.expires_at
		FROM finding_status_approvals m
		LEFT JOIN findings f ON f.tenant_id = m.tenant_id AND f.id = m.finding_id
		WHERE m.tenant_id = $1 AND m.batch_id = $2
		ORDER BY m.created_at, m.id`, tenantID.String(), batchID.String())
	if err != nil {
		return nil, fmt.Errorf("list group exception members: %w", err)
	}
	defer rows.Close()
	var out []vulnerability.ApprovalBatchMember
	for rows.Next() {
		var (
			m            vulnerability.ApprovalBatchMember
			aid, fid, st string
			expires      sql.NullTime
		)
		if err := rows.Scan(&aid, &fid, &m.Title, &m.Severity, &st, &expires); err != nil {
			return nil, fmt.Errorf("scan group exception member: %w", err)
		}
		m.ApprovalID, _ = shared.IDFromString(aid)
		m.FindingID, _ = shared.IDFromString(fid)
		m.Status = vulnerability.ApprovalStatus(st)
		if expires.Valid {
			t := expires.Time
			m.ExpiresAt = &t
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// BatchSignoffs lists the sign-offs of a group exception.
func (r *FindingApprovalRepository) BatchSignoffs(ctx context.Context, tenantID, batchID shared.ID) ([]approvalpolicy.Signoff, error) {
	return listSignoffs(ctx, r.db, tenantID, signoffSubjectBatch, batchID)
}

// BatchMemberFinish prepares one member request for applying (approve it,
// set its end and decision facts) and returns its timeline entry; ok=false
// cancels the member instead.
type BatchMemberFinish func(a *vulnerability.Approval) (entry *vulnerability.FindingActivity, ok bool, err error)

// SignOffBatch records one approval of a pending group exception: the batch
// row is locked, decide judges the signer against the sign-offs in, the
// sign-off is inserted and, when it completes the batch, every pending member
// request is approved and applied in the same transaction (a member whose
// finding can no longer make the move is canceled, the others still apply).
// It answers the batch, how many members were applied and which were
// canceled.
func (r *FindingApprovalRepository) SignOffBatch(ctx context.Context, tenantID, batchID, signer shared.ID, rec finding.SignoffRecord,
	decide func(prior []approvalpolicy.Signoff) (bool, error),
	finish func(a *vulnerability.Approval) (*vulnerability.FindingActivity, bool, error),
) (*vulnerability.ApprovalBatch, int, []shared.ID, error) {
	var (
		out      *vulnerability.ApprovalBatch
		applied  int
		canceled []shared.ID
	)
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		b, err := scanBatch(tx.QueryRowContext(ctx, batchSelect+` WHERE b.tenant_id = $1 AND b.id = $2 FOR UPDATE OF b`,
			tenantID.String(), batchID.String()))
		if err != nil {
			return err
		}
		if b.Status != vulnerability.ApprovalStatusPending || !b.DecideBy.After(time.Now()) {
			return vulnerability.ErrBatchNotPending
		}
		prior, err := listSignoffs(ctx, tx, tenantID, signoffSubjectBatch, batchID)
		if err != nil {
			return err
		}
		complete, err := decide(prior)
		if err != nil {
			return err
		}
		if err := insertSignoff(ctx, tx, tenantID, signoffSubjectBatch, batchID,
			signoffRow{rec.UserID, rec.SecurityPool, rec.PoolFallback, rec.StepUp}); err != nil {
			return err
		}
		b.ApprovalsCollected = len(prior) + 1
		out = b
		if !complete {
			_, err := tx.ExecContext(ctx, `UPDATE approval_batches SET version = version + 1 WHERE tenant_id = $1 AND id = $2`,
				tenantID.String(), batchID.String())
			b.Version++
			return err
		}
		applied, canceled, err = r.applyBatchMembersTx(ctx, tx, tenantID, batchID, finish)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE approval_batches SET status = 'approved', decided_by = $3, decided_at = now(),
			version = version + 1 WHERE tenant_id = $1 AND id = $2`, tenantID.String(), batchID.String(), signer.String()); err != nil {
			return fmt.Errorf("approve group exception: %w", err)
		}
		b.Status = vulnerability.ApprovalStatusApproved
		return nil
	})
	if err != nil {
		return nil, 0, nil, err
	}
	return out, applied, canceled, nil
}

// applyBatchMembersTx approves and applies every pending member of a batch
// inside tx, each under a savepoint so one member that cannot move is
// canceled without undoing the others.
func (r *FindingApprovalRepository) applyBatchMembersTx(ctx context.Context, tx *sql.Tx, tenantID, batchID shared.ID, finish BatchMemberFinish) (int, []shared.ID, error) {
	members, canceled, err := r.lockBatchMembersTx(ctx, tx, tenantID, batchID)
	if err != nil {
		return 0, nil, err
	}
	applied := 0
	for _, a := range members {
		ok, err := applyBatchMemberTx(ctx, tx, a, finish)
		if err != nil {
			return 0, nil, err
		}
		if ok {
			applied++
		} else {
			canceled = append(canceled, a.FindingID)
		}
	}
	return applied, canceled, nil
}

// lockBatchMembersTx locks and reads the pending member requests of a batch
// that still stand: a member whose finding is no longer an active primary
// member of the batch's task (it left or moved to another task after the
// request was made) is canceled here, with a timeline entry, and its finding
// id returned in the second result: approving the batch must not decide a
// finding that is no longer part of what was asked about.
func (r *FindingApprovalRepository) lockBatchMembersTx(ctx context.Context, tx *sql.Tx, tenantID, batchID shared.ID) ([]*vulnerability.Approval, []shared.ID, error) {
	rows, err := tx.QueryContext(ctx, r.selectQuery()+` WHERE a.tenant_id = $1 AND a.batch_id = $2 AND a.status = 'pending'
		ORDER BY a.created_at, a.id FOR UPDATE OF a`, tenantID.String(), batchID.String())
	if err != nil {
		return nil, nil, fmt.Errorf("lock group exception members: %w", err)
	}
	defer rows.Close()
	var pending []*vulnerability.Approval
	for rows.Next() {
		a, err := r.scanApprovalFromRows(rows)
		if err != nil {
			return nil, nil, err
		}
		pending = append(pending, a)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("lock group exception members: %w", err)
	}
	if len(pending) == 0 {
		return nil, nil, nil
	}
	onTask, err := batchTaskMembersTx(ctx, tx, tenantID, batchID)
	if err != nil {
		return nil, nil, err
	}
	var kept []*vulnerability.Approval
	var canceled []shared.ID
	for _, a := range pending {
		if onTask[a.FindingID] {
			kept = append(kept, a)
			continue
		}
		if err := cancelBatchMemberTx(ctx, tx, a, "finding_left_task",
			"The group exception was approved but this finding is no longer part of the task"); err != nil {
			return nil, nil, err
		}
		canceled = append(canceled, a.FindingID)
	}
	return kept, canceled, nil
}

// batchTaskMembersTx lists the findings that are active primary members of
// the task the batch was requested on.
func batchTaskMembersTx(ctx context.Context, tx *sql.Tx, tenantID, batchID shared.ID) (map[shared.ID]bool, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT tm.finding_id::text
		FROM approval_batches b
		JOIN remediation_task_members tm ON tm.tenant_id = b.tenant_id AND tm.task_id = b.source_id
		WHERE b.tenant_id = $1 AND b.id = $2 AND b.source_type = 'remediation_task'
		  AND tm.left_at IS NULL AND tm.role = 'primary'`, tenantID.String(), batchID.String())
	if err != nil {
		return nil, fmt.Errorf("read the task members of a group exception: %w", err)
	}
	defer rows.Close()
	out := map[shared.ID]bool{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("read the task members of a group exception: %w", err)
		}
		if id, err := shared.IDFromString(s); err == nil {
			out[id] = true
		}
	}
	return out, rows.Err()
}

// applyBatchMemberTx applies one member under a savepoint; a member whose
// finding moved is canceled with a timeline entry instead.
func applyBatchMemberTx(ctx context.Context, tx *sql.Tx, a *vulnerability.Approval, finish BatchMemberFinish) (bool, error) {
	if _, err := tx.ExecContext(ctx, `SAVEPOINT batch_member`); err != nil {
		return false, fmt.Errorf("savepoint: %w", err)
	}
	entry, ok, err := finish(a)
	if err != nil {
		return false, err
	}
	if ok {
		res, err := tx.ExecContext(ctx, `
			UPDATE finding_status_approvals SET status = 'approved', approved_by = $3, approved_at = $4, expires_at = $5,
				version = version + 1, decision_facts = COALESCE($6, decision_facts)
			WHERE tenant_id = $1 AND id = $2 AND status = 'pending'`,
			a.TenantID.String(), a.ID.String(), a.ApprovedBy.String(), a.ApprovedAt, a.ExpiresAt, nullJSON(a.DecisionFacts))
		if err == nil {
			if n, _ := res.RowsAffected(); n == 1 {
				err = applyApprovedInTx(ctx, tx, a, entry)
			} else {
				err = vulnerability.ErrConcurrentModification
			}
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, `RELEASE SAVEPOINT batch_member`)
			return err == nil, err
		}
		if _, rbErr := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT batch_member`); rbErr != nil {
			return false, fmt.Errorf("rollback member: %w", rbErr)
		}
	}
	// The finding cannot take the decision any more: cancel this member.
	if err := cancelBatchMemberTx(ctx, tx, a, "finding_moved",
		"The group exception was approved but this finding had moved and could not take it"); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `RELEASE SAVEPOINT batch_member`); err != nil {
		return false, fmt.Errorf("release savepoint: %w", err)
	}
	return false, nil
}

// cancelBatchMemberTx cancels one pending member request of a batch and
// records why on its finding's timeline.
func cancelBatchMemberTx(ctx context.Context, tx *sql.Tx, a *vulnerability.Approval, reason, message string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE finding_status_approvals SET status = 'canceled', version = version + 1
		WHERE tenant_id = $1 AND id = $2 AND status = 'pending'`, a.TenantID.String(), a.ID.String()); err != nil {
		return fmt.Errorf("cancel member: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source, message)
		VALUES ($1, $2, 'approval_canceled', 'system', 'system: group exception', jsonb_build_object('approval_id', $3::text,
			'approval_status', 'canceled', 'reason', $5::text, 'batch_id', $4::text), 'auto', $6)`,
		a.TenantID.String(), a.FindingID.String(), a.ID.String(), a.BatchID.String(), reason, message); err != nil {
		return fmt.Errorf("record canceled member: %w", err)
	}
	return nil
}

// CloseBatch rejects or cancels a pending group exception and its pending
// member requests, in one transaction, with a timeline entry per member.
func (r *FindingApprovalRepository) CloseBatch(ctx context.Context, tenantID, batchID, actor shared.ID, status vulnerability.ApprovalStatus, reason string) (*vulnerability.ApprovalBatch, error) {
	if status != vulnerability.ApprovalStatusRejected && status != vulnerability.ApprovalStatusCanceled {
		return nil, fmt.Errorf("%w: a group exception closes as rejected or canceled", shared.ErrValidation)
	}
	var out *vulnerability.ApprovalBatch
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		b, err := scanBatch(tx.QueryRowContext(ctx, batchSelect+` WHERE b.tenant_id = $1 AND b.id = $2 FOR UPDATE OF b`,
			tenantID.String(), batchID.String()))
		if err != nil {
			return err
		}
		if b.Status != vulnerability.ApprovalStatusPending {
			return vulnerability.ErrBatchNotPending
		}
		if _, err := tx.ExecContext(ctx, `UPDATE approval_batches SET status = $3, decided_by = $4, decided_at = now(),
			rejection_reason = NULLIF($5, ''), version = version + 1 WHERE tenant_id = $1 AND id = $2`,
			tenantID.String(), batchID.String(), string(status), actor.String(), reason); err != nil {
			return fmt.Errorf("close group exception: %w", err)
		}
		activity := string(vulnerability.ActivityApprovalCanceled)
		if status == vulnerability.ApprovalStatusRejected {
			activity = string(vulnerability.ActivityApprovalRejected)
		}
		if _, err := tx.ExecContext(ctx, `
			WITH closed AS (
				UPDATE finding_status_approvals SET status = $3,
					rejected_by = CASE WHEN $3 = 'rejected' THEN $4::uuid END,
					rejected_at = CASE WHEN $3 = 'rejected' THEN now() END,
					rejection_reason = CASE WHEN $3 = 'rejected' THEN NULLIF($5, '') END,
					version = version + 1
				WHERE tenant_id = $1 AND batch_id = $2 AND status = 'pending'
				RETURNING id, finding_id
			)
			INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_id, actor_type, changes, source, message)
			SELECT $1, c.finding_id, $6, $4::uuid, 'user', jsonb_build_object('approval_id', c.id, 'batch_id', $2::text,
				'approval_status', $3::text, 'reason', NULLIF($5, '')), 'api', 'The group exception was ' || $3
			FROM closed c`,
			tenantID.String(), batchID.String(), string(status), actor.String(), reason, activity); err != nil {
			return fmt.Errorf("close group exception members: %w", err)
		}
		b.Status = status
		out = b
		return nil
	})
	return out, err
}

// ExpireOverdueBatches expires pending group exceptions past their decision
// deadline (their member requests expire with the hourly request expiry).
func (r *FindingApprovalRepository) ExpireOverdueBatches(ctx context.Context) (int64, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE approval_batches SET status = 'expired', version = version + 1
		WHERE status = 'pending' AND decide_by < now()`)
	if err != nil {
		return 0, fmt.Errorf("expire overdue group exceptions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
