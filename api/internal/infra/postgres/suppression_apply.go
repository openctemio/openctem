package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Approving a suppression rule also closes the open findings it matches
// (research 134 decision 2), not only the findings ingest sees afterwards.
// Matching uses the rule's own matcher (suppression.Rule.MatchesCriteria):
// SQL narrows the candidates by tenant, open status, source, tool, rule id and
// asset; Go applies the exact match, path globs included, so the preview, the
// approval, ingest and the lift agree on what the rule covers.

// suppressionApplyPage is the number of candidate findings read, and of
// findings updated, per statement (a variable so tests can cross pages).
var suppressionApplyPage = 1000

// matchingOpenFindings returns the ids of the tenant's open findings the
// rule's criteria match, at most max of them, in id order. Findings from
// people (pentest, manual, bug bounty, red team) are never matched: a person
// reported them, a rule does not overrule that.
func matchingOpenFindings(ctx context.Context, q executor, rule *suppression.Rule, maxIDs int) ([]string, error) {
	from := suppressionApplyFrom[vulnerability.FindingStatus(rule.SuppressionType().Disposition())]
	if len(from) == 0 || maxIDs <= 0 {
		return nil, nil
	}

	var exactRule, prefixRule string
	if rid := rule.RuleID(); rid != "" {
		if p, ok := strings.CutSuffix(rid, "*"); ok {
			prefixRule = likeEscape(p) + "%"
		} else {
			exactRule = rid
		}
	}
	var assetID any
	if a := rule.AssetID(); a != nil {
		assetID = a.String()
	}

	args := []any{rule.TenantID().String(), pq.Array(from), rule.ToolName(), exactRule, prefixRule,
		assetID, rule.PathPattern() != ""}

	var out []string
	after := "00000000-0000-0000-0000-000000000000" // keyset start: below every id
	for {
		page, err := suppressionCandidatePage(ctx, q, args, after)
		if err != nil {
			return nil, err
		}
		for _, c := range page {
			if rule.MatchesCriteria(c.match) {
				out = append(out, c.id)
				if len(out) >= maxIDs {
					return out, nil
				}
			}
		}
		if len(page) < suppressionApplyPage {
			return out, nil
		}
		after = page[len(page)-1].id
	}
}

type suppressionCandidate struct {
	id    string
	match suppression.FindingMatch
}

// suppressionCandidatePage reads one page of candidates after the given id.
// args are the tenant, from-statuses, tool, exact rule id, rule id LIKE
// prefix, asset id and whether the rule has a path condition.
func suppressionCandidatePage(ctx context.Context, q executor, args []any, after string) ([]suppressionCandidate, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT id::text, COALESCE(tool_name, ''), COALESCE(rule_id, ''), COALESCE(file_path, ''), asset_id
		FROM findings
		WHERE tenant_id = $1
		  AND status = ANY($2)
		  AND source NOT IN `+coverageProtectedSources+`
		  AND ($3 = '' OR lower(tool_name) = lower($3))
		  AND ($4 = '' OR rule_id = $4)
		  AND ($5 = '' OR COALESCE(rule_id, '') LIKE $5)
		  AND ($6::uuid IS NULL OR asset_id = $6::uuid)
		  AND (NOT $7 OR COALESCE(file_path, '') <> '')
		  AND id > $8::uuid
		ORDER BY id
		LIMIT $9`, append(args, after, suppressionApplyPage)...)
	if err != nil {
		return nil, fmt.Errorf("load suppression candidates: %w", err)
	}
	defer rows.Close()
	page := make([]suppressionCandidate, 0, suppressionApplyPage)
	for rows.Next() {
		var c suppressionCandidate
		var asset sql.NullString
		if err := rows.Scan(&c.id, &c.match.ToolName, &c.match.RuleID, &c.match.FilePath, &asset); err != nil {
			return nil, fmt.Errorf("scan suppression candidate: %w", err)
		}
		if asset.Valid {
			c.match.AssetID, _ = shared.IDFromString(asset.String)
		}
		page = append(page, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate suppression candidates: %w", err)
	}
	return page, nil
}

// likeEscape escapes the LIKE wildcards of a literal prefix.
func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// CountMatchingOpenFindings counts the tenant's open findings an approval of
// the rule would change, at most limit+1 (see suppression.Repository).
func (r *SuppressionRepository) CountMatchingOpenFindings(ctx context.Context, rule *suppression.Rule, limit int) (int, error) {
	ids, err := matchingOpenFindings(ctx, r.db, rule, limit+1)
	if err != nil {
		return 0, err
	}
	return len(ids), nil
}

// Approve persists the approved rule, closes the open findings it matches and
// records the audit entry in one transaction (see suppression.Repository).
func (r *SuppressionRepository) Approve(
	ctx context.Context,
	rule *suppression.Rule,
	reviewedUpdatedAt time.Time,
	actorID shared.ID,
	details map[string]any,
	limit int,
) (suppression.ApplyResult, error) {
	var res suppression.ApplyResult
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Lock the stored rule and re-check it is still the pending version the
	// approver reviewed: two concurrent approvals, or an edit between the
	// service's read and this write, must not both pass.
	var status string
	var updatedAt time.Time
	err = tx.QueryRowContext(ctx, `
		SELECT status, updated_at FROM suppression_rules
		WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
		rule.TenantID().String(), rule.ID().String()).Scan(&status, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return res, suppression.ErrRuleNotFound
	}
	if err != nil {
		return res, fmt.Errorf("lock suppression rule: %w", err)
	}
	if status != string(suppression.RuleStatusPending) {
		return res, suppression.ErrRuleNotPending
	}
	if !updatedAt.Equal(reviewedUpdatedAt) {
		return res, suppression.ErrRuleChangedSinceReview
	}

	res, err = r.approveLockedInTx(ctx, tx, rule, actorID, details, limit)
	if err != nil {
		return res, err
	}

	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("commit transaction: %w", err)
	}
	return res, nil
}

// approveLockedInTx saves the approved rule (locked and checked by the
// caller), gives the open findings it matches its disposition and records
// the audit entry, inside tx.
func (r *SuppressionRepository) approveLockedInTx(ctx context.Context, tx *sql.Tx, rule *suppression.Rule,
	actorID shared.ID, details map[string]any, limit int,
) (suppression.ApplyResult, error) {
	var res suppression.ApplyResult
	if err := r.saveInTx(ctx, tx, rule); err != nil {
		return res, err
	}

	// An approved rule whose expiry has already passed covers nothing.
	if rule.IsActive() {
		ids, err := matchingOpenFindings(ctx, tx, rule, limit+1)
		if err != nil {
			return res, err
		}
		if len(ids) > limit {
			ids = ids[:limit]
			res.Capped = true
		}
		for start := 0; start < len(ids); start += suppressionApplyPage {
			end := min(start+suppressionApplyPage, len(ids))
			n, err := applySuppressionChunk(ctx, tx, rule, actorID, ids[start:end])
			if err != nil {
				return res, err
			}
			res.Applied += n
		}
	}

	audit := map[string]any{"applied_findings": res.Applied, "capped": res.Capped}
	if res.Capped {
		audit["limit"] = limit
	}
	for k, v := range details {
		audit[k] = v
	}
	if err := r.recordAuditInTx(ctx, tx, rule.ID(), "approved", &actorID, audit); err != nil {
		return res, err
	}

	return res, nil
}

// applySuppressionChunk gives the listed findings the rule's disposition,
// links them to the rule and records a status_changed activity on each. The
// update re-checks tenant, open status and source under a row lock, so a
// finding someone moved since it was read is skipped. Returns the number
// changed.
func applySuppressionChunk(ctx context.Context, tx *sql.Tx, rule *suppression.Rule, actorID shared.ID, ids []string) (int, error) {
	target := rule.SuppressionType().Disposition()
	from := suppressionApplyFrom[vulnerability.FindingStatus(target)]
	rows, err := tx.QueryContext(ctx, `
		WITH old AS (
			SELECT id, status FROM findings
			WHERE tenant_id = $1 AND id = ANY($2::uuid[])
			  AND status = ANY($3)
			  AND source NOT IN `+coverageProtectedSources+`
			FOR UPDATE
		)
		UPDATE findings f SET
			status = $4, resolution = 'suppressed', closure_reason = CASE WHEN $4::varchar = 'accepted' THEN 'risk_accepted' END, verification = NULL,
			resolved_at = NOW(), resolved_by = NULL, updated_at = NOW(),
			acceptance_expires_at = CASE WHEN $4::varchar = 'accepted' THEN `+acceptanceCappedSQL("$5::timestamptz", "f")+` END
		FROM old
		WHERE f.tenant_id = $1 AND f.id = old.id
		RETURNING f.id::text, old.status`,
		rule.TenantID().String(), pq.Array(ids), pq.Array(from), target,
		ruleAcceptanceEnd(rule.ExpiresAt(), time.Now()))
	if err != nil {
		return 0, fmt.Errorf("apply suppression disposition: %w", err)
	}
	changed, oldStatuses, err := scanAppliedFindings(rows)
	if err != nil {
		return 0, err
	}
	if len(changed) == 0 {
		return 0, nil
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO finding_suppressions (finding_id, suppression_rule_id, applied_by)
		SELECT id, $2, 'approval' FROM unnest($1::uuid[]) AS id
		ON CONFLICT (finding_id, suppression_rule_id) DO NOTHING`,
		pq.Array(changed), rule.ID().String()); err != nil {
		return 0, fmt.Errorf("link applied findings: %w", err)
	}

	changes, err := json.Marshal(map[string]any{
		"new_status":          target,
		"resolution":          "suppressed",
		"reason":              "suppression rule approved",
		"suppression_rule_id": rule.ID().String(),
	})
	if err != nil {
		return 0, fmt.Errorf("marshal apply activity: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO finding_activities (id, tenant_id, finding_id, activity_type, actor_type, actor_id, changes, source, created_at)
		SELECT gen_random_uuid(), $1, c.id, 'status_changed', 'user', $4,
		       $5::jsonb || jsonb_build_object('old_status', c.old_status), 'suppression_rule', NOW()
		FROM unnest($2::uuid[], $3::text[]) AS c(id, old_status)`,
		rule.TenantID().String(), pq.Array(changed), pq.Array(oldStatuses), actorID.String(), changes); err != nil {
		return 0, fmt.Errorf("record apply activity: %w", err)
	}
	return len(changed), nil
}

// scanAppliedFindings reads the (id, previous status) rows of the apply
// update and closes them.
func scanAppliedFindings(rows *sql.Rows) (ids, oldStatuses []string, err error) {
	defer rows.Close()
	for rows.Next() {
		var id, old string
		if err := rows.Scan(&id, &old); err != nil {
			return nil, nil, fmt.Errorf("scan applied finding: %w", err)
		}
		ids = append(ids, id)
		oldStatuses = append(oldStatuses, old)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate applied findings: %w", err)
	}
	return ids, oldStatuses, nil
}
