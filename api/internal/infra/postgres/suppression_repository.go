package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// SuppressionRepository handles suppression rule persistence.
type SuppressionRepository struct {
	db *DB
}

// NewSuppressionRepository creates a new SuppressionRepository.
func NewSuppressionRepository(db *DB) *SuppressionRepository {
	return &SuppressionRepository{db: db}
}

// Save persists a suppression rule.
func (r *SuppressionRepository) Save(ctx context.Context, rule *suppression.Rule) error {
	return r.saveInTx(ctx, r.db, rule)
}

// SaveWithAudit persists a suppression rule and records its audit entry in a
// single transaction, so the rule's state and its audit trail can never
// diverge on a mid-operation failure. Previously the two were separate,
// autocommitted Execs (the audit write being best-effort), which allowed a
// rule to change state with no matching audit row — or, on a partial failure,
// an audit row describing a state that was never persisted.
func (r *SuppressionRepository) SaveWithAudit(
	ctx context.Context,
	rule *suppression.Rule,
	action string,
	actorID *shared.ID,
	details map[string]any,
) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := r.saveInTx(ctx, tx, rule); err != nil {
		return err
	}
	if err := r.recordAuditInTx(ctx, tx, rule.ID(), action, actorID, details); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

// saveInTx persists a suppression rule using the given executor (a *DB or a *sql.Tx).
func (r *SuppressionRepository) saveInTx(ctx context.Context, exec executor, rule *suppression.Rule) error {
	query := `
		INSERT INTO suppression_rules (
			id, tenant_id, rule_id, tool_name, path_pattern, asset_id,
			name, description, suppression_type, status,
			requested_by, requested_at, approved_by, approved_at,
			rejected_by, rejected_at, rejection_reason, expires_at,
			created_at, updated_at, review_flagged_at, review_reason,
			reason_code, tier, required_approvals
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25)
		ON CONFLICT (id) DO UPDATE SET
			rule_id = EXCLUDED.rule_id,
			tool_name = EXCLUDED.tool_name,
			path_pattern = EXCLUDED.path_pattern,
			asset_id = EXCLUDED.asset_id,
			name = EXCLUDED.name,
			description = EXCLUDED.description,
			suppression_type = EXCLUDED.suppression_type,
			status = EXCLUDED.status,
			approved_by = EXCLUDED.approved_by,
			approved_at = EXCLUDED.approved_at,
			rejected_by = EXCLUDED.rejected_by,
			rejected_at = EXCLUDED.rejected_at,
			rejection_reason = EXCLUDED.rejection_reason,
			expires_at = EXCLUDED.expires_at,
			updated_at = EXCLUDED.updated_at,
			review_flagged_at = EXCLUDED.review_flagged_at,
			review_reason = EXCLUDED.review_reason,
			reason_code = COALESCE(EXCLUDED.reason_code, suppression_rules.reason_code),
			tier = COALESCE(EXCLUDED.tier, suppression_rules.tier),
			required_approvals = COALESCE(EXCLUDED.required_approvals, suppression_rules.required_approvals)
	`

	_, err := exec.ExecContext(ctx, query,
		rule.ID().String(),
		rule.TenantID().String(),
		nullString(rule.RuleID()),
		nullString(rule.ToolName()),
		nullString(rule.PathPattern()),
		nullIDPtr(rule.AssetID()),
		rule.Name(),
		nullString(rule.Description()),
		string(rule.SuppressionType()),
		string(rule.Status()),
		rule.RequestedBy().String(),
		rule.RequestedAt(),
		nullIDPtr(rule.ApprovedBy()),
		nullTime(rule.ApprovedAt()),
		nullIDPtr(rule.RejectedBy()),
		nullTime(rule.RejectedAt()),
		nullString(rule.RejectionReason()),
		nullTime(rule.ExpiresAt()),
		rule.CreatedAt(),
		rule.UpdatedAt(),
		nullTime(rule.ReviewFlaggedAt()),
		rule.ReviewReason(),
		nullString(rule.ReasonCode()),
		nullString(rule.Tier()),
		nullRuleRequired(rule),
	)

	if err != nil {
		return fmt.Errorf("failed to save suppression rule: %w", err)
	}

	return nil
}

// FindByID retrieves a suppression rule by ID.
func (r *SuppressionRepository) FindByID(ctx context.Context, tenantID, id shared.ID) (*suppression.Rule, error) {
	query := r.selectQuery() + " WHERE sr.tenant_id = $1 AND sr.id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanRule(row)
}

// Delete removes a suppression rule and lifts its suppressions in the same
// transaction (finding_suppressions rows cascade with the rule, so the lift
// must run first).
func (r *SuppressionRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := r.liftSuppressionsInTx(ctx, tx, tenantID, id, "suppression rule deleted"); err != nil {
		return err
	}

	query := `DELETE FROM suppression_rules WHERE tenant_id = $1 AND id = $2`
	result, err := tx.ExecContext(ctx, query, tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("failed to delete suppression rule: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return suppression.ErrRuleNotFound
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

// suppressedCandidate is a finding a rule suppressed that is still in the
// disposition the suppression gave it.
type suppressedCandidate struct {
	id       string
	status   string
	toolName string
	ruleID   string
	filePath string
	assetID  sql.NullString
}

// liftSuppressionsInTx undoes what a rule that stops applying (expired or
// deleted) did to findings. Every finding linked to the rule that is still in
// the suppression's disposition (resolution 'suppressed', status
// false_positive or accepted) is either re-linked to another active rule of
// the tenant that matches it, or reopened as 'new' with a 'reopened' activity.
// A finding someone has since moved to another status is left alone. All
// queries are tenant-scoped. Returns the number of findings reopened.
func (r *SuppressionRepository) liftSuppressionsInTx(
	ctx context.Context, tx *sql.Tx, tenantID, ruleID shared.ID, reason string,
) (int, error) {
	candidates, err := loadSuppressedCandidates(ctx, tx, tenantID, ruleID)
	if err != nil {
		return 0, err
	}
	if len(candidates) == 0 {
		return 0, nil
	}
	others, err := r.loadOtherActiveRules(ctx, tx, tenantID, ruleID)
	if err != nil {
		return 0, err
	}

	reopened := 0
	for _, c := range candidates {
		match := suppression.FindingMatch{ToolName: c.toolName, RuleID: c.ruleID, FilePath: c.filePath}
		if c.assetID.Valid {
			match.AssetID, _ = shared.IDFromString(c.assetID.String)
		}
		var cover *suppression.Rule
		for _, o := range others {
			if o.Matches(match) {
				cover = o
				break
			}
		}
		if cover != nil {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO finding_suppressions (finding_id, suppression_rule_id, applied_by)
				VALUES ($1, $2, 'system')
				ON CONFLICT (finding_id, suppression_rule_id) DO NOTHING`, c.id, cover.ID().String()); err != nil {
				return 0, fmt.Errorf("re-link suppressed finding: %w", err)
			}
			if err := setFindingTransition(ctx, tx, findingTransition{
				Source: "suppression_rule", Reason: "suppression_relinked", ActorName: "system: suppression rule",
				Message: "Its suppression rule was lifted; another active rule covers it",
				Changes: map[string]any{"suppression_rule_id": cover.ID().String(), "previous_rule_id": ruleID.String()},
			}); err != nil {
				return 0, err
			}
			if _, err := tx.ExecContext(ctx, `
				UPDATE findings SET status = $3, updated_at = NOW()
				WHERE tenant_id = $1 AND id = $2 AND status <> $3 AND status IN `+suppressionRelinkFromSQL+``,
				tenantID.String(), c.id, cover.SuppressionType().Disposition()); err != nil {
				return 0, fmt.Errorf("re-apply suppression disposition: %w", err)
			}
			// An accepted risk now held by the covering rule ends when that
			// rule's acceptance ends.
			if _, err := tx.ExecContext(ctx, `
				UPDATE findings SET acceptance_expires_at = `+acceptanceCappedSQL("$3::timestamptz", "findings")+`
				WHERE tenant_id = $1 AND id = $2 AND status = 'accepted'`,
				tenantID.String(), c.id, ruleAcceptanceEnd(cover.ExpiresAt(), time.Now())); err != nil {
				return 0, fmt.Errorf("re-apply acceptance end: %w", err)
			}
			// The lift below records its own entries.
			if err := clearFindingTransition(ctx, tx); err != nil {
				return 0, err
			}
			continue
		}

		if _, err := tx.ExecContext(ctx, `
			UPDATE findings
			   SET status = 'new', resolution = NULL, closure_reason = NULL, verification = NULL,
			       resolved_at = NULL, resolved_by = NULL, updated_at = NOW()
			 WHERE tenant_id = $1 AND id = $2 AND resolution = 'suppressed'
			   AND status IN `+suppressionLiftFromSQL+``,
			tenantID.String(), c.id); err != nil {
			return 0, fmt.Errorf("reopen suppressed finding: %w", err)
		}
		changes, err := json.Marshal(map[string]any{
			"reason":              reason,
			"suppression_rule_id": ruleID.String(),
			"previous_status":     c.status,
			"new_status":          "new",
		})
		if err != nil {
			return 0, fmt.Errorf("marshal reopen activity: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO finding_activities (id, tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source, created_at)
			VALUES ($1, $2, $3, 'reopened', 'system', 'system: suppression lifted', $4, 'auto', NOW())`,
			shared.NewID().String(), tenantID.String(), c.id, changes); err != nil {
			return 0, fmt.Errorf("record reopen activity: %w", err)
		}
		reopened++
	}
	return reopened, nil
}

// loadSuppressedCandidates locks and returns the findings a rule suppressed
// that are still in the suppression's disposition.
func loadSuppressedCandidates(ctx context.Context, tx *sql.Tx, tenantID, ruleID shared.ID) ([]suppressedCandidate, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT f.id, f.status, COALESCE(f.tool_name, ''), COALESCE(f.rule_id, ''),
		       COALESCE(f.file_path, ''), f.asset_id
		FROM finding_suppressions fs
		JOIN findings f ON f.id = fs.finding_id AND f.tenant_id = $1
		WHERE fs.suppression_rule_id = $2
		  AND f.resolution = 'suppressed'
		  AND f.status IN `+vulnerability.StatusListSQL(vulnerability.SuppressedStatuses())+`
		FOR UPDATE OF f`, tenantID.String(), ruleID.String())
	if err != nil {
		return nil, fmt.Errorf("load suppressed findings: %w", err)
	}
	defer rows.Close()
	var candidates []suppressedCandidate
	for rows.Next() {
		var c suppressedCandidate
		if err := rows.Scan(&c.id, &c.status, &c.toolName, &c.ruleID, &c.filePath, &c.assetID); err != nil {
			return nil, fmt.Errorf("scan suppressed finding: %w", err)
		}
		candidates = append(candidates, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate suppressed findings: %w", err)
	}
	return candidates, nil
}

// loadOtherActiveRules returns the tenant's other approved, unexpired rules.
func (r *SuppressionRepository) loadOtherActiveRules(ctx context.Context, tx *sql.Tx, tenantID, ruleID shared.ID) ([]*suppression.Rule, error) {
	rows, err := tx.QueryContext(ctx, r.selectQuery()+`
		WHERE sr.tenant_id = $1 AND sr.id <> $2
		  AND sr.status = 'approved'
		  AND (sr.expires_at IS NULL OR sr.expires_at > NOW())
		ORDER BY sr.created_at DESC`, tenantID.String(), ruleID.String())
	if err != nil {
		return nil, fmt.Errorf("load other active rules: %w", err)
	}
	defer rows.Close()
	return r.scanRules(rows)
}

// FindByTenant retrieves suppression rules for a tenant with filters.
func (r *SuppressionRepository) FindByTenant(ctx context.Context, tenantID shared.ID, filter suppression.RuleFilter) ([]*suppression.Rule, error) {
	query := r.selectQuery() + " WHERE sr.tenant_id = $1"
	args := []any{tenantID.String()}
	argIdx := 2

	if filter.Status != nil {
		query += fmt.Sprintf(" AND sr.status = $%d", argIdx)
		args = append(args, string(*filter.Status))
		argIdx++
	}

	if filter.SuppressionType != nil {
		query += fmt.Sprintf(" AND sr.suppression_type = $%d", argIdx)
		args = append(args, string(*filter.SuppressionType))
		argIdx++
	}

	if filter.ToolName != nil {
		query += fmt.Sprintf(" AND sr.tool_name = $%d", argIdx)
		args = append(args, *filter.ToolName)
		argIdx++
	}

	if filter.AssetID != nil {
		query += fmt.Sprintf(" AND sr.asset_id = $%d", argIdx)
		args = append(args, filter.AssetID.String())
		argIdx++
	}

	if filter.RequestedBy != nil {
		query += fmt.Sprintf(" AND sr.requested_by = $%d", argIdx)
		args = append(args, filter.RequestedBy.String())
		// argIdx not incremented — no further conditions
	}

	if !filter.IncludeExpired {
		query += " AND (sr.expires_at IS NULL OR sr.expires_at > NOW())"
	}

	query += " ORDER BY sr.created_at DESC"

	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", filter.Offset)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query suppression rules: %w", err)
	}
	defer rows.Close()

	return r.scanRules(rows)
}

// FindActiveByTenant retrieves all active (approved, not expired) rules.
func (r *SuppressionRepository) FindActiveByTenant(ctx context.Context, tenantID shared.ID) ([]*suppression.Rule, error) {
	query := r.selectQuery() + `
		WHERE sr.tenant_id = $1
		AND sr.status = 'approved'
		AND (sr.expires_at IS NULL OR sr.expires_at > NOW())
		ORDER BY sr.created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query active suppression rules: %w", err)
	}
	defer rows.Close()

	return r.scanRules(rows)
}

// FindPendingByTenant retrieves all pending rules.
func (r *SuppressionRepository) FindPendingByTenant(ctx context.Context, tenantID shared.ID) ([]*suppression.Rule, error) {
	query := r.selectQuery() + `
		WHERE sr.tenant_id = $1
		AND sr.status = 'pending'
		ORDER BY sr.created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query pending suppression rules: %w", err)
	}
	defer rows.Close()

	return r.scanRules(rows)
}

// FindMatchingRules finds rules that match a given finding.
func (r *SuppressionRepository) FindMatchingRules(ctx context.Context, tenantID shared.ID, match suppression.FindingMatch) ([]*suppression.Rule, error) {
	// Get all active rules and filter in Go for complex matching
	rules, err := r.FindActiveByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	var matchingRules []*suppression.Rule
	for _, rule := range rules {
		if rule.Matches(match) {
			matchingRules = append(matchingRules, rule)
		}
	}

	return matchingRules, nil
}

// ExpireRules marks approved rules past expires_at as expired and lifts their
// suppressions, one rule per transaction so one failure does not hold back the
// rest. A rule whose lift fails stays approved (and inactive by its
// expires_at) and is retried on the next run.
func (r *SuppressionRepository) ExpireRules(ctx context.Context) (int64, error) {
	due, err := r.listDueForExpiry(ctx)
	if err != nil {
		return 0, err
	}

	var expired int64
	var firstErr error
	for _, e := range due {
		if err := r.expireOne(ctx, e.tenantID, e.id); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		expired++
	}
	return expired, firstErr
}

type expiringRule struct{ id, tenantID shared.ID }

// listDueForExpiry returns the approved rules whose expires_at has passed.
// This is the system job: it spans tenants, and every rule is then expired and
// lifted within its own tenant.
func (r *SuppressionRepository) listDueForExpiry(ctx context.Context) ([]expiringRule, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, tenant_id FROM suppression_rules
		WHERE status = 'approved' AND expires_at IS NOT NULL AND expires_at < NOW()`)
	if err != nil {
		return nil, fmt.Errorf("failed to list expired suppression rules: %w", err)
	}
	defer rows.Close()
	var due []expiringRule
	for rows.Next() {
		var id, tid string
		if err := rows.Scan(&id, &tid); err != nil {
			return nil, fmt.Errorf("scan expired suppression rule: %w", err)
		}
		pid, err1 := shared.IDFromString(id)
		ptid, err2 := shared.IDFromString(tid)
		if err1 != nil || err2 != nil {
			continue
		}
		due = append(due, expiringRule{id: pid, tenantID: ptid})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate expired suppression rules: %w", err)
	}
	return due, nil
}

func (r *SuppressionRepository) expireOne(ctx context.Context, tenantID, ruleID shared.ID) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, `
		UPDATE suppression_rules SET status = 'expired', updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2 AND status = 'approved'
		  AND expires_at IS NOT NULL AND expires_at < NOW()`, tenantID.String(), ruleID.String())
	if err != nil {
		return fmt.Errorf("expire suppression rule: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil // another replica got there first
	}
	if _, err := r.liftSuppressionsInTx(ctx, tx, tenantID, ruleID, "suppression rule expired"); err != nil {
		return err
	}
	if err := r.recordAuditInTx(ctx, tx, ruleID, "expired", nil, nil); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

// CountEligibleApprovers counts the tenant's active members who may approve
// suppression rules: owners and admins (who pass every permission check) and
// members holding a role with findings:suppressions:approve.
func (r *SuppressionRepository) CountEligibleApprovers(ctx context.Context, tenantID shared.ID) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT tm.user_id)
		FROM tenant_members tm
		WHERE tm.tenant_id = $1
		  AND tm.status = 'active'
		  AND (
		      tm.role IN ('owner', 'admin')
		      OR EXISTS (
		          SELECT 1 FROM v_user_role_grants ur
		          JOIN role_permissions rp ON rp.role_id = ur.role_id
		          WHERE ur.tenant_id = tm.tenant_id AND ur.user_id = tm.user_id
		            AND rp.permission_id = $2
		      )
		  )`, tenantID.String(), suppressionApprovePermission).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count eligible suppression approvers: %w", err)
	}
	return n, nil
}

// suppressionApprovePermission is permission.SuppressionsApprove (not imported
// here to keep the repository free of the permission package).
const suppressionApprovePermission = "findings:suppressions:approve"

// RecentMemberRemoval answers the latest time after since at which the
// tenant lost a possible second approver: a member suspended, offboarded,
// removed, expired, demoted, or a role change that can strip the approve
// permission (recentApproverChange; nil: none).
func (r *SuppressionRepository) RecentMemberRemoval(ctx context.Context, tenantID shared.ID, since time.Time) (*time.Time, error) {
	return recentApproverChange(ctx, r.db, tenantID, since)
}

// IsTenantOwner reports whether the user is an active owner of the tenant.
func (r *SuppressionRepository) IsTenantOwner(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM tenant_members
			WHERE tenant_id = $1 AND user_id = $2 AND role = 'owner' AND status = 'active'
		)`, tenantID.String(), userID.String()).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check tenant owner: %w", err)
	}
	return ok, nil
}

// RecordSuppression records that a finding was suppressed by a rule. A
// finding the rule made accepted takes the rule's expiry as the end of its
// acceptance (findings.acceptance_expires_at, read by the CI gate), or the
// default acceptance length when the rule has none: an accepted risk always
// ends. Either is capped by the finding's priority. The rule and the finding must belong to the same tenant.
func (r *SuppressionRepository) RecordSuppression(ctx context.Context, findingID, ruleID shared.ID, appliedBy string) error {
	query := `
		WITH rec AS (
			INSERT INTO finding_suppressions (finding_id, suppression_rule_id, applied_by)
			VALUES ($1, $2, $3)
			ON CONFLICT (finding_id, suppression_rule_id) DO NOTHING
			RETURNING 1
		), acc AS (
			UPDATE findings f
			SET acceptance_expires_at = ` + acceptanceCappedSQL("COALESCE(sr.expires_at, $4)", "f") + `
			FROM suppression_rules sr
			WHERE f.id = $1 AND sr.id = $2 AND sr.tenant_id = f.tenant_id
			  AND f.status = 'accepted'
			RETURNING 1
		)
		SELECT (SELECT count(*) FROM rec), (SELECT count(*) FROM acc)
	`

	var recorded, accepted int
	err := r.db.QueryRowContext(ctx, query, findingID.String(), ruleID.String(), appliedBy,
		ruleAcceptanceEnd(nil, time.Now())).Scan(&recorded, &accepted)
	if err != nil {
		return fmt.Errorf("failed to record finding suppression: %w", err)
	}
	observeSuppressionHits(appliedBy, recorded)

	return nil
}

// FindSuppressionsByFinding retrieves suppressions for a finding.
func (r *SuppressionRepository) FindSuppressionsByFinding(ctx context.Context, findingID shared.ID) ([]*suppression.FindingSuppression, error) {
	query := `
		SELECT id, finding_id, suppression_rule_id, applied_at, applied_by
		FROM finding_suppressions
		WHERE finding_id = $1
	`

	rows, err := r.db.QueryContext(ctx, query, findingID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query finding suppressions: %w", err)
	}
	defer rows.Close()

	var suppressions []*suppression.FindingSuppression
	for rows.Next() {
		var (
			id        string
			findingID string
			ruleID    string
			appliedAt time.Time
			appliedBy string
		)

		if err := rows.Scan(&id, &findingID, &ruleID, &appliedAt, &appliedBy); err != nil {
			return nil, fmt.Errorf("failed to scan finding suppression: %w", err)
		}

		idParsed, _ := shared.IDFromString(id)
		findingIDParsed, _ := shared.IDFromString(findingID)
		ruleIDParsed, _ := shared.IDFromString(ruleID)

		suppressions = append(suppressions, &suppression.FindingSuppression{
			ID:                idParsed,
			FindingID:         findingIDParsed,
			SuppressionRuleID: ruleIDParsed,
			AppliedAt:         appliedAt.Format(time.RFC3339),
			AppliedBy:         appliedBy,
		})
	}

	return suppressions, rows.Err()
}

// RemoveSuppression removes a suppression from a finding.
func (r *SuppressionRepository) RemoveSuppression(ctx context.Context, findingID, ruleID shared.ID) error {
	query := `DELETE FROM finding_suppressions WHERE finding_id = $1 AND suppression_rule_id = $2`
	_, err := r.db.ExecContext(ctx, query, findingID.String(), ruleID.String())
	if err != nil {
		return fmt.Errorf("failed to remove finding suppression: %w", err)
	}
	return nil
}

// RecordAudit records an audit log entry for a suppression rule.
func (r *SuppressionRepository) RecordAudit(ctx context.Context, ruleID shared.ID, action string, actorID *shared.ID, details map[string]any) error {
	return r.recordAuditInTx(ctx, r.db, ruleID, action, actorID, details)
}

// recordAuditInTx records an audit log entry using the given executor (a *DB or a *sql.Tx).
func (r *SuppressionRepository) recordAuditInTx(ctx context.Context, exec executor, ruleID shared.ID, action string, actorID *shared.ID, details map[string]any) error {
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("failed to marshal audit details: %w", err)
	}

	query := `
		INSERT INTO suppression_rule_audit (suppression_rule_id, action, actor_id, details)
		VALUES ($1, $2, $3, $4)
	`

	_, err = exec.ExecContext(ctx, query, ruleID.String(), action, nullIDPtr(actorID), detailsJSON)
	if err != nil {
		return fmt.Errorf("failed to record audit: %w", err)
	}

	return nil
}

// selectQuery returns the base SELECT query for suppression rules.
func (r *SuppressionRepository) selectQuery() string {
	return `
		SELECT
			sr.id, sr.tenant_id, sr.rule_id, sr.tool_name, sr.path_pattern, sr.asset_id,
			sr.name, sr.description, sr.suppression_type, sr.status,
			sr.requested_by, sr.requested_at, sr.approved_by, sr.approved_at,
			sr.rejected_by, sr.rejected_at, sr.rejection_reason, sr.expires_at,
			sr.created_at, sr.updated_at, sr.requested_by_actor,
			sr.review_flagged_at, sr.review_reason,
			COALESCE(sr.reason_code, ''), COALESCE(sr.tier, ''), COALESCE(sr.required_approvals, -1),
			(SELECT COUNT(*) FROM approval_signoffs so
			 WHERE so.tenant_id = sr.tenant_id AND so.subject_type = 'suppression_rule' AND so.subject_id = sr.id
			   AND (sr.status <> 'pending' OR so.created_at >= sr.updated_at))
		FROM suppression_rules sr
	`
}

// scanRule scans a single row into a Rule.
func (r *SuppressionRepository) scanRule(row *sql.Row) (*suppression.Rule, error) {
	var (
		id               string
		tenantID         string
		ruleID           sql.NullString
		toolName         sql.NullString
		pathPattern      sql.NullString
		assetID          sql.NullString
		name             string
		description      sql.NullString
		suppressionType  string
		status           string
		requestedBy      sql.NullString // NULL once the requester is deleted
		requestedAt      time.Time
		approvedBy       sql.NullString
		approvedAt       sql.NullTime
		rejectedBy       sql.NullString
		rejectedAt       sql.NullTime
		rejectionReason  sql.NullString
		expiresAt        sql.NullTime
		createdAt        time.Time
		updatedAt        time.Time
		requestedByActor sql.NullString
		reviewFlaggedAt  sql.NullTime
		reviewReason     string
		pol              rulePolicyColumns
	)

	err := row.Scan(
		&id, &tenantID, &ruleID, &toolName, &pathPattern, &assetID,
		&name, &description, &suppressionType, &status,
		&requestedBy, &requestedAt, &approvedBy, &approvedAt,
		&rejectedBy, &rejectedAt, &rejectionReason, &expiresAt,
		&createdAt, &updatedAt, &requestedByActor,
		&reviewFlaggedAt, &reviewReason,
		&pol.reasonCode, &pol.tier, &pol.required, &pol.collected,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan suppression rule: %w", err)
	}

	return pol.apply(r.buildRule(
		id, tenantID, ruleID, toolName, pathPattern, assetID,
		name, description, suppressionType, status,
		requestedBy.String, requestedAt, approvedBy, approvedAt,
		rejectedBy, rejectedAt, rejectionReason, expiresAt,
		createdAt, updatedAt, requestedByActor.String,
		reviewFlaggedAt, reviewReason,
	)), nil
}

// scanRules scans multiple rows into Rules.
func (r *SuppressionRepository) scanRules(rows *sql.Rows) ([]*suppression.Rule, error) {
	var rules []*suppression.Rule

	for rows.Next() {
		var (
			id               string
			tenantID         string
			ruleID           sql.NullString
			toolName         sql.NullString
			pathPattern      sql.NullString
			assetID          sql.NullString
			name             string
			description      sql.NullString
			suppressionType  string
			status           string
			requestedBy      sql.NullString // NULL once the requester is deleted
			requestedAt      time.Time
			approvedBy       sql.NullString
			approvedAt       sql.NullTime
			rejectedBy       sql.NullString
			rejectedAt       sql.NullTime
			rejectionReason  sql.NullString
			expiresAt        sql.NullTime
			createdAt        time.Time
			updatedAt        time.Time
			requestedByActor sql.NullString
			reviewFlaggedAt  sql.NullTime
			reviewReason     string
			pol              rulePolicyColumns
		)

		err := rows.Scan(
			&id, &tenantID, &ruleID, &toolName, &pathPattern, &assetID,
			&name, &description, &suppressionType, &status,
			&requestedBy, &requestedAt, &approvedBy, &approvedAt,
			&rejectedBy, &rejectedAt, &rejectionReason, &expiresAt,
			&createdAt, &updatedAt, &requestedByActor,
			&reviewFlaggedAt, &reviewReason,
			&pol.reasonCode, &pol.tier, &pol.required, &pol.collected,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan suppression rule: %w", err)
		}

		rules = append(rules, pol.apply(r.buildRule(
			id, tenantID, ruleID, toolName, pathPattern, assetID,
			name, description, suppressionType, status,
			requestedBy.String, requestedAt, approvedBy, approvedAt,
			rejectedBy, rejectedAt, rejectionReason, expiresAt,
			createdAt, updatedAt, requestedByActor.String,
			reviewFlaggedAt, reviewReason,
		)))
	}

	return rules, rows.Err()
}

// buildRule constructs a Rule from scanned values.
func (r *SuppressionRepository) buildRule(
	id, tenantID string,
	ruleID, toolName, pathPattern, assetID sql.NullString,
	name string, description sql.NullString,
	suppressionType, status string,
	requestedBy string, requestedAt time.Time,
	approvedBy sql.NullString, approvedAt sql.NullTime,
	rejectedBy sql.NullString, rejectedAt sql.NullTime,
	rejectionReason sql.NullString, expiresAt sql.NullTime,
	createdAt, updatedAt time.Time,
	requestedByActor string,
	reviewFlaggedAt sql.NullTime, reviewReason string,
) *suppression.Rule {
	idParsed, _ := shared.IDFromString(id)
	tenantIDParsed, _ := shared.IDFromString(tenantID)
	requestedByParsed, _ := shared.IDFromString(requestedBy)

	data := suppression.RuleData{
		ID:               idParsed,
		TenantID:         tenantIDParsed,
		RuleID:           ruleID.String,
		ToolName:         toolName.String,
		PathPattern:      pathPattern.String,
		Name:             name,
		Description:      description.String,
		SuppressionType:  suppression.SuppressionType(suppressionType),
		Status:           suppression.RuleStatus(status),
		RequestedBy:      requestedByParsed,
		RequestedAt:      requestedAt,
		RejectionReason:  rejectionReason.String,
		CreatedAt:        createdAt,
		UpdatedAt:        updatedAt,
		RequestedByActor: requestedByActor,
		ReviewReason:     reviewReason,
	}
	if reviewFlaggedAt.Valid {
		data.ReviewFlaggedAt = &reviewFlaggedAt.Time
	}

	if assetID.Valid {
		assetIDParsed, _ := shared.IDFromString(assetID.String)
		data.AssetID = &assetIDParsed
	}

	if approvedBy.Valid {
		approvedByParsed, _ := shared.IDFromString(approvedBy.String)
		data.ApprovedBy = &approvedByParsed
	}
	if approvedAt.Valid {
		data.ApprovedAt = &approvedAt.Time
	}

	if rejectedBy.Valid {
		rejectedByParsed, _ := shared.IDFromString(rejectedBy.String)
		data.RejectedBy = &rejectedByParsed
	}
	if rejectedAt.Valid {
		data.RejectedAt = &rejectedAt.Time
	}

	if expiresAt.Valid {
		data.ExpiresAt = &expiresAt.Time
	}

	return suppression.ReconstituteRule(data)
}

// ruleAcceptanceEnd is when an acceptance given by a suppression rule ends:
// the rule's expiry, or the default acceptance length from now when the rule
// has none (an accepted risk always ends; vulnerability.DefaultAcceptanceDuration).
// acceptanceCappedSQL is the end of an acceptance a suppression rule gives
// one finding: the rule's end, but never past the cap of that finding's
// priority (finding_max_acceptance_days: P0 or KEV 30 days, P1 90, P2 180,
// otherwise 365, the same as vulnerability.MaxAcceptanceFor). A rule that
// matches findings of several priorities gives each the stricter of the two;
// the rule itself keeps its end.
func acceptanceCappedSQL(endExpr, alias string) string {
	return "LEAST(" + endExpr + ", NOW() + make_interval(days => finding_max_acceptance_days(" +
		alias + ".priority_class, " + alias + ".is_in_kev)))"
}

func ruleAcceptanceEnd(ruleExpiry *time.Time, now time.Time) time.Time {
	if ruleExpiry != nil {
		return *ruleExpiry
	}
	return now.Add(vulnerability.DefaultAcceptanceDuration)
}

// rulePolicyColumns are the approval-policy columns of a rule row.
type rulePolicyColumns struct {
	reasonCode, tier string
	required         int
	collected        int
}

func (c rulePolicyColumns) apply(rule *suppression.Rule) *suppression.Rule {
	if rule == nil {
		return nil
	}
	required := c.required
	if required < 0 {
		required = 1 // a rule made before the policy needs one other person
	}
	rule.SetPolicyInfo(c.reasonCode, c.tier, required, c.collected)
	return rule
}

// nullRuleRequired stores the rule's required approvals, NULL without a tier.
func nullRuleRequired(rule *suppression.Rule) any {
	if rule.Tier() == "" {
		return nil
	}
	return rule.RequiredApprovals()
}
