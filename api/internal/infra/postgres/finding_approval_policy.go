package postgres

// Reads and writes of the approval policy on finding status requests
// (api/docs/rfcs/RFC-111-approval-policy.md): the facts the evaluator needs,
// the security pool group, and sign-offs. Every query is scoped to one
// tenant.

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
)

// nullRequired stores the request's required approvals, NULL when the
// request has no tier (written before the policy existed).
func nullRequired(a *vulnerability.Approval) any {
	if a.Tier == "" {
		return nil
	}
	return a.RequiredApprovals
}

// legacyRequired reads required_approvals: a request without one (-1) needs
// one other person, as every request did before the policy.
func legacyRequired(n int) int {
	if n < 0 {
		return 1
	}
	return n
}

// assetOwnersSQL lists the people who own an asset: user owners, and members
// of owner groups of the same tenant, with ownership primary or secondary.
// $1 is the tenant, the asset id expression is substituted.
const assetOwnersSQL = `
	SELECT ao.user_id FROM asset_owners ao
	WHERE ao.asset_id = %[1]s AND ao.user_id IS NOT NULL AND ao.ownership_type IN ('primary', 'secondary')
	UNION
	SELECT gm.user_id FROM asset_owners ao
	JOIN groups g ON g.id = ao.group_id AND g.tenant_id = $1
	JOIN group_members gm ON gm.group_id = g.id
	WHERE ao.asset_id = %[1]s AND ao.group_id IS NOT NULL AND ao.ownership_type IN ('primary', 'secondary')`

// PolicyFacts reads the facts the approval policy needs about one finding:
// severity, priority, KEV, EPSS, a validated exploit, its asset's exposure,
// the asset's owners and the finding's assignee.
func (r *FindingApprovalRepository) PolicyFacts(ctx context.Context, tenantID, findingID shared.ID) (finding.PolicyFacts, error) {
	var (
		pf       finding.PolicyFacts
		epss     sql.NullFloat64
		assignee sql.NullString
		owners   pq.StringArray
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT f.severity, COALESCE(f.priority_class, ''), COALESCE(f.is_in_kev, false), f.epss_score::float8,
		       COALESCE(f.validation_outcome = 'reproducible', false),
		       COALESCE(a.is_crown_jewel, false), COALESCE(a.is_internet_accessible, false),
		       f.assigned_to::text,
		       ARRAY(`+fmt.Sprintf(assetOwnersSQL, "f.asset_id")+`)::text[]
		FROM findings f
		LEFT JOIN assets a ON a.tenant_id = f.tenant_id AND a.id = f.asset_id
		WHERE f.tenant_id = $1 AND f.id = $2`,
		tenantID.String(), findingID.String()).Scan(
		&pf.Facts.Severity, &pf.Facts.PriorityClass, &pf.Facts.KEV, &epss, &pf.Facts.ExploitValidated,
		&pf.Facts.CrownJewel, &pf.Facts.InternetExposed, &assignee, &owners)
	if errors.Is(err, sql.ErrNoRows) {
		return pf, fmt.Errorf("%w: finding not found", shared.ErrNotFound)
	}
	if err != nil {
		return pf, fmt.Errorf("read approval policy facts: %w", err)
	}
	if epss.Valid {
		v := epss.Float64
		pf.Facts.EPSS = &v
	}
	if assignee.Valid {
		if id, err := shared.IDFromString(assignee.String); err == nil {
			pf.AssigneeID = &id
		}
	}
	for _, o := range owners {
		if id, err := shared.IDFromString(o); err == nil {
			pf.AssetOwners = append(pf.AssetOwners, id)
		}
	}
	return pf, nil
}

// GroupMemberIDs lists the members of a group of the tenant (none for a
// group of another tenant) who joined it at or before addedBefore and whose
// membership has not ended. A member who joined later is left out: the
// security pool's membership is read when someone signs off, so a person
// added a moment ago must not count.
func (r *FindingApprovalRepository) GroupMemberIDs(ctx context.Context, tenantID, groupID shared.ID, addedBefore time.Time) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT gm.user_id::text FROM group_members gm
		JOIN groups g ON g.id = gm.group_id
		WHERE g.tenant_id = $1 AND g.id = $2
		  AND (gm.joined_at IS NULL OR gm.joined_at <= $3)
		  AND (gm.expires_at IS NULL OR gm.expires_at > now())`, tenantID.String(), groupID.String(), addedBefore)
	if err != nil {
		return nil, fmt.Errorf("list security pool members: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("scan security pool member: %w", err)
		}
		if id, err := shared.IDFromString(s); err == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

// GroupInTenant reports whether the group belongs to the tenant.
func (r *FindingApprovalRepository) GroupInTenant(ctx context.Context, tenantID, groupID shared.ID) (bool, error) {
	var ok bool
	if err := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM groups WHERE tenant_id = $1 AND id = $2)`,
		tenantID.String(), groupID.String()).Scan(&ok); err != nil {
		return false, fmt.Errorf("check security pool group: %w", err)
	}
	return ok, nil
}

// Signoffs lists the sign-offs of one subject of the tenant.
func (r *FindingApprovalRepository) Signoffs(ctx context.Context, tenantID shared.ID, subjectType string, subjectID shared.ID) ([]approvalpolicy.Signoff, error) {
	return listSignoffs(ctx, r.db, tenantID, subjectType, subjectID)
}

type signoffQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func listSignoffs(ctx context.Context, q signoffQueryer, tenantID shared.ID, subjectType string, subjectID shared.ID) ([]approvalpolicy.Signoff, error) {
	return listSignoffsSince(ctx, q, tenantID, subjectType, subjectID, time.Time{})
}

// listSignoffsSince lists the sign-offs made at or after since (a sign-off
// made before the subject last changed does not count).
func listSignoffsSince(ctx context.Context, q signoffQueryer, tenantID shared.ID, subjectType string, subjectID shared.ID, since time.Time) ([]approvalpolicy.Signoff, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT user_id::text, security_pool FROM approval_signoffs
		WHERE tenant_id = $1 AND subject_type = $2 AND subject_id = $3 AND created_at >= $4
		ORDER BY created_at`, tenantID.String(), subjectType, subjectID.String(), since)
	if err != nil {
		return nil, fmt.Errorf("list sign-offs: %w", err)
	}
	defer rows.Close()
	var out []approvalpolicy.Signoff
	for rows.Next() {
		var (
			s    string
			pool bool
		)
		if err := rows.Scan(&s, &pool); err != nil {
			return nil, fmt.Errorf("scan sign-off: %w", err)
		}
		if id, err := shared.IDFromString(s); err == nil {
			out = append(out, approvalpolicy.Signoff{UserID: id, InSecurityPool: pool})
		}
	}
	return out, rows.Err()
}

// signoffRow is one sign-off to insert.
type signoffRow struct {
	userID                             shared.ID
	securityPool, poolFallback, stepUp bool
}

// insertSignoff records one sign-off inside tx; a second sign-off by the
// same person is refused.
func insertSignoff(ctx context.Context, tx *sql.Tx, tenantID shared.ID, subjectType string, subjectID shared.ID, rec signoffRow) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO approval_signoffs (tenant_id, subject_type, subject_id, user_id, security_pool, pool_fallback, step_up)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		tenantID.String(), subjectType, subjectID.String(), rec.userID.String(), rec.securityPool, rec.poolFallback, rec.stepUp)
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" {
		return approvalpolicy.NewRefusal(approvalpolicy.CodeApproverNotEligible, approvalpolicy.RefusedAlreadySigned,
			"you already approved this request; another person must approve it too")
	}
	if err != nil {
		return fmt.Errorf("record sign-off: %w", err)
	}
	return nil
}

// SignOff records one approval of a pending request in one transaction: the
// request row is locked, decide judges the signer against the sign-offs
// already in, the sign-off is inserted, and when it completes the request,
// finish approves it and the request, the finding's status and the timeline
// entry are written together; otherwise only the sign-off and finish's
// timeline entry. It answers the request and whether it was
// applied.
func (r *FindingApprovalRepository) SignOff(ctx context.Context, tenantID, approvalID shared.ID, rec finding.SignoffRecord,
	decide finding.SignoffDecider, finish finding.SignoffFinisher,
) (*vulnerability.Approval, bool, error) {
	var (
		out     *vulnerability.Approval
		applied bool
	)
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		a, err := r.scanApproval(tx.QueryRowContext(ctx, r.selectQuery()+` WHERE a.id = $1 AND a.tenant_id = $2 FOR UPDATE OF a`,
			approvalID.String(), tenantID.String()))
		if err != nil {
			return err
		}
		if a.Status != vulnerability.ApprovalStatusPending {
			return vulnerability.ErrConcurrentModification
		}
		if a.IsOverdue(time.Now()) {
			return vulnerability.ErrDecisionOverdue
		}
		prior, err := listSignoffs(ctx, tx, tenantID, finding.SignoffSubjectFindingApproval, approvalID)
		if err != nil {
			return err
		}
		complete, err := decide(a, prior)
		if err != nil {
			return err
		}
		if err := insertSignoff(ctx, tx, tenantID, finding.SignoffSubjectFindingApproval, approvalID,
			signoffRow{rec.UserID, rec.SecurityPool, rec.PoolFallback, rec.StepUp}); err != nil {
			return err
		}
		a.ApprovalsCollected = len(prior) + 1
		entry, err := finish(a, complete)
		if err != nil {
			return err
		}
		if !complete {
			if _, err := tx.ExecContext(ctx, `UPDATE finding_status_approvals SET version = version + 1
				WHERE id = $1 AND tenant_id = $2`, approvalID.String(), tenantID.String()); err != nil {
				return fmt.Errorf("record sign-off: %w", err)
			}
			a.Version++
			if entry != nil {
				if err := insertFindingActivity(ctx, tx, entry); err != nil {
					return err
				}
			}
			out = a
			return nil
		}
		res, err := tx.ExecContext(ctx, `
			UPDATE finding_status_approvals SET
				status = 'approved', approved_by = $3, approved_at = $4, expires_at = $5, version = $6,
				decision_facts = COALESCE($8, decision_facts)
			WHERE id = $1 AND tenant_id = $2 AND status = 'pending' AND version = $7`,
			a.ID.String(), a.TenantID.String(), a.ApprovedBy.String(), a.ApprovedAt, a.ExpiresAt,
			a.Version, a.Version-1, nullJSON(a.DecisionFacts))
		if err != nil {
			return fmt.Errorf("failed to approve request: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil || n == 0 {
			return vulnerability.ErrConcurrentModification
		}
		if err := applyApprovedInTx(ctx, tx, a, entry); err != nil {
			return err
		}
		out, applied = a, true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return out, applied, nil
}
