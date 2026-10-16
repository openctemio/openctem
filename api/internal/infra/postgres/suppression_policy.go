package postgres

// Suppression rules under the approval policy
// (api/docs/rfcs/RFC-111-approval-policy.md): the facts and owners over the
// open findings a rule matches, the rule approvers, and sign-offs. Every
// query is scoped to the rule's tenant.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
)

// signoffSubjectRule is the subject type of a suppression rule's sign-offs.
const signoffSubjectRule = "suppression_rule"

// RuleSignoffs lists the sign-offs of a rule made since it last changed.
func (r *SuppressionRepository) RuleSignoffs(ctx context.Context, tenantID, ruleID shared.ID) ([]approvalpolicy.Signoff, error) {
	var updatedAt time.Time
	err := r.db.QueryRowContext(ctx, `SELECT updated_at FROM suppression_rules WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), ruleID.String()).Scan(&updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, suppression.ErrRuleNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read suppression rule: %w", err)
	}
	return listSignoffsSince(ctx, r.db, tenantID, signoffSubjectRule, ruleID, updatedAt)
}

// ApproveWithSignoff records one approval of a pending rule and approves the
// rule when it completes it (see suppression.signoffRepository).
func (r *SuppressionRepository) ApproveWithSignoff(ctx context.Context, rule *suppression.Rule, reviewedUpdatedAt time.Time,
	rec suppression.SignoffRecord, decide func(prior []approvalpolicy.Signoff) (bool, error), finish func() error,
	details map[string]any, limit int,
) (suppression.ApplyResult, int, bool, error) {
	var (
		res       suppression.ApplyResult
		collected int
		complete  bool
	)
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		var (
			status    string
			updatedAt time.Time
		)
		err := tx.QueryRowContext(ctx, `
			SELECT status, updated_at FROM suppression_rules
			WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
			rule.TenantID().String(), rule.ID().String()).Scan(&status, &updatedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return suppression.ErrRuleNotFound
		}
		if err != nil {
			return fmt.Errorf("lock suppression rule: %w", err)
		}
		if status != string(suppression.RuleStatusPending) {
			return suppression.ErrRuleNotPending
		}
		if !updatedAt.Equal(reviewedUpdatedAt) {
			return suppression.ErrRuleChangedSinceReview
		}
		// Sign-offs made before the rule last changed approved other
		// content: they no longer count and are removed.
		if _, err := tx.ExecContext(ctx, `DELETE FROM approval_signoffs
			WHERE tenant_id = $1 AND subject_type = $2 AND subject_id = $3 AND created_at < $4`,
			rule.TenantID().String(), signoffSubjectRule, rule.ID().String(), updatedAt); err != nil {
			return fmt.Errorf("drop stale sign-offs: %w", err)
		}
		prior, err := listSignoffsSince(ctx, tx, rule.TenantID(), signoffSubjectRule, rule.ID(), updatedAt)
		if err != nil {
			return err
		}
		if complete, err = decide(prior); err != nil {
			return err
		}
		if err := insertSignoff(ctx, tx, rule.TenantID(), signoffSubjectRule, rule.ID(),
			signoffRow{rec.UserID, rec.SecurityPool, rec.PoolFallback, rec.StepUp}); err != nil {
			return err
		}
		collected = len(prior) + 1
		if !complete {
			return r.recordAuditInTx(ctx, tx, rule.ID(), "signed", &rec.UserID, map[string]any{
				"approvals_collected": collected, "security_pool": rec.SecurityPool, "step_up": rec.StepUp,
			})
		}
		if err := finish(); err != nil {
			return err
		}
		res, err = r.approveLockedInTx(ctx, tx, rule, rec.UserID, details, limit)
		return err
	})
	if err == nil && complete {
		observeSuppressionHits("approval", res.Applied)
	}
	return res, collected, complete, err
}

// RulePolicyInputs reads what the approval policy needs about a rule: the
// facts of the open findings it matches now (at most limit), the owners of
// their assets and of the rule's asset, and the members who may approve
// rules (owners, administrators, and roles with
// findings:suppressions:approve, active memberships).
func (r *SuppressionRepository) RulePolicyInputs(ctx context.Context, rule *suppression.Rule, limit int) ([]approvalpolicy.Facts, []shared.ID, []shared.ID, error) {
	ids, err := matchingOpenFindings(ctx, r.db, rule, limit)
	if err != nil {
		return nil, nil, nil, err
	}
	tenant := rule.TenantID().String()
	facts, err := r.findingFacts(ctx, tenant, ids)
	if err != nil {
		return nil, nil, nil, err
	}
	var ruleAsset any
	if a := rule.AssetID(); a != nil {
		ruleAsset = a.String()
	}
	owners, err := r.uuidColumn(ctx, `
		WITH assets_of AS (
			SELECT DISTINCT f.asset_id FROM findings f
			WHERE f.tenant_id = $1 AND f.id = ANY($2::uuid[]) AND f.asset_id IS NOT NULL
			UNION SELECT a.id FROM assets a WHERE a.tenant_id = $1 AND a.id = $3::uuid
		)
		SELECT ao.user_id::text FROM asset_owners ao JOIN assets_of x ON x.asset_id = ao.asset_id
		WHERE ao.user_id IS NOT NULL AND ao.ownership_type IN ('primary', 'secondary')
		UNION
		SELECT gm.user_id::text FROM asset_owners ao JOIN assets_of x ON x.asset_id = ao.asset_id
		JOIN groups g ON g.id = ao.group_id AND g.tenant_id = $1
		JOIN group_members gm ON gm.group_id = g.id
		WHERE ao.ownership_type IN ('primary', 'secondary')`, tenant, pq.Array(ids), ruleAsset)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read rule asset owners: %w", err)
	}
	approvers, err := r.uuidColumn(ctx, `
		SELECT DISTINCT tm.user_id::text
		FROM tenant_members tm
		WHERE tm.tenant_id = $1 AND tm.status = 'active'
		  AND (tm.role IN ('owner', 'admin')
		       OR EXISTS (SELECT 1 FROM v_user_role_grants ur
		                  JOIN role_permissions rp ON rp.role_id = ur.role_id
		                  WHERE ur.tenant_id = tm.tenant_id AND ur.user_id = tm.user_id AND rp.permission_id = $2))`,
		tenant, suppressionApprovePermission)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("list rule approvers: %w", err)
	}
	return facts, owners, approvers, nil
}

// findingFacts reads the approval-policy facts of the listed findings of
// the tenant.
func (r *SuppressionRepository) findingFacts(ctx context.Context, tenant string, ids []string) ([]approvalpolicy.Facts, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT f.severity, COALESCE(f.priority_class, ''), COALESCE(f.is_in_kev, false), f.epss_score::float8,
		       COALESCE(f.validation_outcome = 'reproducible', false),
		       COALESCE(a.is_crown_jewel, false), COALESCE(a.is_internet_accessible, false)
		FROM findings f
		LEFT JOIN assets a ON a.tenant_id = f.tenant_id AND a.id = f.asset_id
		WHERE f.tenant_id = $1 AND f.id = ANY($2::uuid[])`, tenant, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("read rule facts: %w", err)
	}
	defer rows.Close()
	facts := make([]approvalpolicy.Facts, 0, len(ids))
	for rows.Next() {
		var (
			f    approvalpolicy.Facts
			epss sql.NullFloat64
		)
		if err := rows.Scan(&f.Severity, &f.PriorityClass, &f.KEV, &epss, &f.ExploitValidated, &f.CrownJewel, &f.InternetExposed); err != nil {
			return nil, fmt.Errorf("scan rule facts: %w", err)
		}
		if epss.Valid {
			v := epss.Float64
			f.EPSS = &v
		}
		facts = append(facts, f)
	}
	return facts, rows.Err()
}

func (r *SuppressionRepository) uuidColumn(ctx context.Context, query string, args ...any) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if id, err := shared.IDFromString(s); err == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}
