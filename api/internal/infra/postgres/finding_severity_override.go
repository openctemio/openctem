package postgres

// Analyst severity decisions and severity requests
// (docs/architecture/finding-severity-override.md). Every statement carries
// the tenant; a decision applies only while the finding's effective
// severity is still the one the caller decided from (no lost update).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// SubjectTypeSeverityRequest is the approval_signoffs subject of a severity
// request.
const SubjectTypeSeverityRequest = "severity_request"

type severityExecer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// severityDecisionSQL writes the effective severity, its provenance and what
// was recomputed from it. A manual priority override stands. The SLA
// deadline is the one computed in memory from the row just read (the
// applier tightens; an approved downgrade may extend it), so it is written
// as is; the severity guard keeps a concurrent decision from being lost.
const severityDecisionSQL = `
	UPDATE findings SET
		severity = $3, source_severity = $4, severity_override_reason = $5,
		severity_overridden_by = $6, severity_overridden_at = $7,
		priority_class = CASE WHEN priority_class_override THEN priority_class ELSE $8 END,
		priority_class_reason = CASE WHEN priority_class_override THEN priority_class_reason ELSE $9 END,
		is_reachable = $10, reachable_from_count = $11,
		epss_score = $12, epss_percentile = $13, is_in_kev = $14, kev_due_date = $15,
		sla_deadline = COALESCE($16::timestamptz, sla_deadline),
		sla_status = CASE WHEN $16::timestamptz IS NULL THEN sla_status ELSE $17 END,
		updated_at = now()
	WHERE tenant_id = $1 AND id = $2 AND severity = $18
	  AND ($19::bigint IS NULL OR row_version = $19)
	RETURNING row_version`

func saveSeverityDecision(ctx context.Context, x severityExecer, f *vulnerability.Finding, expected vulnerability.Severity) error {
	p := f.SeverityProvenance()
	var reason sql.NullString
	if p.OverriddenAt != nil {
		reason = sql.NullString{String: p.OverrideReason, Valid: true}
	}
	// A caller that named the version it saw (an API If-Match) is refused
	// when the row moved on; the write also bumps the version (migration
	// 003055), which the finding carries back to the caller.
	var wantVersion sql.NullInt64
	if want, ok := vulnerability.ExpectedRowVersion(ctx, f.ID()); ok {
		wantVersion = sql.NullInt64{Int64: want, Valid: true}
	}
	var newVersion int64
	err := x.QueryRowContext(ctx, severityDecisionSQL,
		f.TenantID().String(), f.ID().String(),
		f.Severity().String(), nullString(string(p.Source)), reason, nullID(p.OverriddenBy), nullTime(p.OverriddenAt),
		nullPriorityClass(f.PriorityClass()), nullString(f.PriorityClassReason()),
		f.IsReachable(), f.ReachableFromCount(),
		nullFloat64(f.EPSSScore()), nullFloat64(f.EPSSPercentile()), f.IsInKEV(), nullTime(f.KEVDueDate()),
		nullTime(f.SLADeadline()), string(f.SLAStatus()),
		expected.String(), wantVersion).Scan(&newVersion)
	if errors.Is(err, sql.ErrNoRows) {
		if wantVersion.Valid {
			return &vulnerability.FindingConflictError{FindingID: f.ID()}
		}
		return vulnerability.ErrSeverityChangeConflict
	}
	if err != nil {
		return fmt.Errorf("save severity decision: %w", err)
	}
	f.RestoreRowVersion(newVersion)
	return nil
}

// SaveSeverityDecision implements vulnerability.SeverityWriter. With
// extendSLA the write runs in a transaction marked as an explicit SLA
// decision (openctem.sla_restart), the one way past the tighten-only guard.
func (r *FindingRepository) SaveSeverityDecision(ctx context.Context, f *vulnerability.Finding, expected vulnerability.Severity, extendSLA bool) error {
	if !extendSLA {
		return saveSeverityDecision(ctx, r.db, f, expected)
	}
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `SET LOCAL openctem.sla_restart = on`); err != nil {
			return fmt.Errorf("mark sla decision: %w", err)
		}
		return saveSeverityDecision(ctx, tx, f, expected)
	})
}

var _ vulnerability.SeverityWriter = (*FindingRepository)(nil)

type txSeverityWriter struct{ tx *sql.Tx }

func (w txSeverityWriter) SaveSeverityDecision(ctx context.Context, f *vulnerability.Finding, expected vulnerability.Severity, extendSLA bool) error {
	if extendSLA {
		return fmt.Errorf("%w: an SLA extension is written after the approval commits", shared.ErrValidation)
	}
	return saveSeverityDecision(ctx, w.tx, f, expected)
}

// SeverityRequestRepository stores severity requests.
type SeverityRequestRepository struct {
	db *DB
}

// NewSeverityRequestRepository returns the repository.
func NewSeverityRequestRepository(db *DB) *SeverityRequestRepository {
	return &SeverityRequestRepository{db: db}
}

var _ vulnerability.SeverityRequestRepository = (*SeverityRequestRepository)(nil)

const severityRequestColumns = `r.id, r.tenant_id, r.finding_id, r.requested_severity, r.previous_severity, r.restore,
	r.reason, r.requested_by, r.status, r.tier, r.required_approvals, r.decide_by, r.decided_by, r.decided_at,
	r.decision_note, r.created_at,
	(SELECT COUNT(*) FROM approval_signoffs so
	 WHERE so.tenant_id = r.tenant_id AND so.subject_type = '` + SubjectTypeSeverityRequest + `' AND so.subject_id = r.id)`

type severityRequestScanner interface {
	Scan(dest ...any) error
}

func scanSeverityRequest(row severityRequestScanner) (*vulnerability.SeverityRequest, error) {
	var (
		id, tenant, finding, requested, previous, status, tier string
		requestedBy, decidedBy, note                           sql.NullString
		decidedAt                                              sql.NullTime
		r                                                      vulnerability.SeverityRequest
	)
	if err := row.Scan(&id, &tenant, &finding, &requested, &previous, &r.Restore, &r.Reason, &requestedBy, &status, &tier,
		&r.RequiredApprovals, &r.DecideBy, &decidedBy, &decidedAt, &note, &r.CreatedAt, &r.ApprovalsCollected); err != nil {
		return nil, err
	}
	r.ID, _ = shared.IDFromString(id)
	r.TenantID, _ = shared.IDFromString(tenant)
	r.FindingID, _ = shared.IDFromString(finding)
	r.RequestedSeverity = vulnerability.Severity(requested)
	r.PreviousSeverity = vulnerability.Severity(previous)
	r.Status = vulnerability.ApprovalStatus(status)
	r.Tier = tier
	r.RequestedBy = parseNullID(requestedBy)
	r.DecidedBy = parseNullID(decidedBy)
	if decidedAt.Valid {
		t := decidedAt.Time
		r.DecidedAt = &t
	}
	r.DecisionNote = note.String
	return &r, nil
}

// Create implements vulnerability.SeverityRequestRepository.
func (r *SeverityRequestRepository) Create(ctx context.Context, req *vulnerability.SeverityRequest) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		// A pending request nobody decided in time stops blocking a new one.
		if _, err := tx.ExecContext(ctx, `UPDATE finding_severity_requests SET status = 'expired'
			WHERE tenant_id = $1 AND finding_id = $2 AND status = 'pending' AND decide_by <= now()`,
			req.TenantID.String(), req.FindingID.String()); err != nil {
			return fmt.Errorf("expire stale severity requests: %w", err)
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO finding_severity_requests (id, tenant_id, finding_id, requested_severity, previous_severity, restore,
				reason, requested_by, status, tier, required_approvals, decide_by, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', $9, $10, $11, $12)`,
			req.ID.String(), req.TenantID.String(), req.FindingID.String(), req.RequestedSeverity.String(),
			req.PreviousSeverity.String(), req.Restore, req.Reason, nullID(req.RequestedBy), req.Tier,
			req.RequiredApprovals, req.DecideBy, req.CreatedAt)
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return vulnerability.ErrPendingRequestExists
		}
		if err != nil {
			return fmt.Errorf("create severity request: %w", err)
		}
		return nil
	})
}

// Get implements vulnerability.SeverityRequestRepository.
func (r *SeverityRequestRepository) Get(ctx context.Context, tenantID, id shared.ID) (*vulnerability.SeverityRequest, error) {
	req, err := scanSeverityRequest(r.db.QueryRowContext(ctx, `SELECT `+severityRequestColumns+`
		FROM finding_severity_requests r WHERE r.tenant_id = $1 AND r.id = $2`, tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: severity request not found", shared.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get severity request: %w", err)
	}
	return req, nil
}

// Pending implements vulnerability.SeverityRequestRepository.
func (r *SeverityRequestRepository) Pending(ctx context.Context, tenantID, findingID shared.ID) (*vulnerability.SeverityRequest, error) {
	req, err := scanSeverityRequest(r.db.QueryRowContext(ctx, `SELECT `+severityRequestColumns+`
		FROM finding_severity_requests r
		WHERE r.tenant_id = $1 AND r.finding_id = $2 AND r.status = 'pending' AND r.decide_by > now()`,
		tenantID.String(), findingID.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil //nolint:nilnil // no pending request is not an error
	}
	if err != nil {
		return nil, fmt.Errorf("get pending severity request: %w", err)
	}
	return req, nil
}

// Signoffs implements vulnerability.SeverityRequestRepository.
func (r *SeverityRequestRepository) Signoffs(ctx context.Context, tenantID, id shared.ID) ([]approvalpolicy.Signoff, error) {
	return listSignoffs(ctx, r.db, tenantID, SubjectTypeSeverityRequest, id)
}

// SignOff implements vulnerability.SeverityRequestRepository.
func (r *SeverityRequestRepository) SignOff(ctx context.Context, tenantID, id shared.ID, s vulnerability.SeveritySignoff,
	decide func(prior []approvalpolicy.Signoff) (bool, error),
	apply func(ctx context.Context, w vulnerability.SeverityWriter) error,
) (bool, error) {
	applied := false
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		var (
			status   string
			decideBy time.Time
		)
		err := tx.QueryRowContext(ctx, `SELECT status, decide_by FROM finding_severity_requests
			WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID.String(), id.String()).Scan(&status, &decideBy)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: severity request not found", shared.ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("lock severity request: %w", err)
		}
		if status != string(vulnerability.ApprovalStatusPending) {
			return fmt.Errorf("%w: this request is %s", shared.ErrConflict, status)
		}
		if !time.Now().Before(decideBy) {
			return vulnerability.ErrDecisionOverdue
		}
		prior, err := listSignoffs(ctx, tx, tenantID, SubjectTypeSeverityRequest, id)
		if err != nil {
			return err
		}
		complete, err := decide(prior)
		if err != nil {
			return err
		}
		if err := insertSignoff(ctx, tx, tenantID, SubjectTypeSeverityRequest, id, signoffRow{
			userID: s.UserID, securityPool: s.SecurityPool, poolFallback: s.PoolFallback, stepUp: s.StepUp,
		}); err != nil {
			return err
		}
		if !complete {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE finding_severity_requests
			SET status = 'approved', decided_by = $3, decided_at = now()
			WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String(), s.UserID.String()); err != nil {
			return fmt.Errorf("approve severity request: %w", err)
		}
		if err := apply(ctx, txSeverityWriter{tx: tx}); err != nil {
			return err
		}
		applied = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return applied, nil
}

// Close implements vulnerability.SeverityRequestRepository.
func (r *SeverityRequestRepository) Close(ctx context.Context, tenantID, id shared.ID, status vulnerability.ApprovalStatus,
	actor shared.ID, note string, requester *shared.ID,
) error {
	if status != vulnerability.ApprovalStatusRejected && status != vulnerability.ApprovalStatusCanceled {
		return fmt.Errorf("%w: a severity request is closed as rejected or canceled", shared.ErrValidation)
	}
	q := `UPDATE finding_severity_requests SET status = $3, decided_by = $4, decided_at = now(), decision_note = NULLIF($5, '')
		WHERE tenant_id = $1 AND id = $2 AND status = 'pending'`
	args := []any{tenantID.String(), id.String(), string(status), actor.String(), note}
	if requester != nil {
		q += ` AND requested_by = $6`
		args = append(args, requester.String())
	}
	res, err := r.db.ExecContext(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("close severity request: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: no pending severity request to close", shared.ErrNotFound)
	}
	return nil
}
