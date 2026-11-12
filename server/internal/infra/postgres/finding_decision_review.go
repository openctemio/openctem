package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Review flags on decided findings (migration 002154). An automatic signal
// never reverses a decision a person made (false positive, accepted risk,
// duplicate): it raises a flag in finding_decision_reviews with a
// decision_review timeline entry, and a person with the approve permission
// decides. The flag clears when the finding's status changes.

// Decision review reasons.
const (
	DecisionReviewTaintSourceChanged = "taint_source_changed"
	DecisionReviewIOCMatch           = "ioc_match"
	// DecisionReviewAcceptanceExceedsCap: an accepted risk runs longer than
	// its priority allows (raised by migration acceptance_cap_review).
	DecisionReviewAcceptanceExceedsCap = "acceptance_exceeds_cap"
)

// raiseDecisionReview flags the finding for review, in one transaction with
// its timeline entry, only while it holds a decision (false positive,
// accepted, duplicate). It returns false when the finding holds no decision
// or already has an open flag for the reason.
func raiseDecisionReview(ctx context.Context, db *DB, tenantID, findingID, reason string, evidence map[string]any) (bool, error) {
	if evidence == nil {
		evidence = map[string]any{}
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		return false, fmt.Errorf("marshal review evidence: %w", err)
	}
	raised := false
	err = db.Transaction(ctx, func(tx *sql.Tx) error {
		var status string
		err := tx.QueryRowContext(ctx, `SELECT status FROM findings WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
			tenantID, findingID).Scan(&status)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("lock decided finding: %w", err)
		}
		if !vulnerability.IsDispositionedStatus(vulnerability.FindingStatus(status)) {
			return nil
		}
		res, err := tx.ExecContext(ctx, `
			INSERT INTO finding_decision_reviews (tenant_id, finding_id, decision_status, reason, evidence)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (tenant_id, finding_id, reason) WHERE cleared_at IS NULL DO NOTHING`,
			tenantID, findingID, status, reason, raw)
		if err != nil {
			return fmt.Errorf("raise decision review: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil
		}
		changes, err := json.Marshal(map[string]any{"decision_status": status, "reason": reason, "evidence": evidence})
		if err != nil {
			return fmt.Errorf("marshal review entry: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source, message)
			VALUES ($1, $2, $3, 'system', $4, $5, 'auto', $6)`,
			tenantID, findingID, string(vulnerability.ActivityDecisionReview), "system: "+reason, changes,
			"The "+status+" decision may need review ("+reason+"); it stands until a person decides"); err != nil {
			return fmt.Errorf("record decision review: %w", err)
		}
		raised = true
		return nil
	})
	return raised, err
}

// RaiseDecisionReview flags a decided finding for review (see
// raiseDecisionReview); the IOC correlator uses it instead of reopening.
func (r *FindingRepository) RaiseDecisionReview(ctx context.Context, tenantID, findingID shared.ID, reason string, evidence map[string]any) (bool, error) {
	return raiseDecisionReview(ctx, r.db, tenantID.String(), findingID.String(), reason, evidence)
}

// ReopenResolved moves a resolved finding back to confirmed, only while it is
// still resolved (the status is re-checked in the UPDATE itself, so a finding
// someone changed since it was read is left alone). The resolution fields are
// cleared. With a vulnerability.StatusTransition in ctx the move and its
// timeline entry commit together. Returns whether it moved the finding.
func (r *FindingRepository) ReopenResolved(ctx context.Context, tenantID, findingID shared.ID) (bool, error) {
	res, err := r.db.execStatusWrite(ctx, `
		UPDATE findings SET status = 'confirmed', resolution = NULL, closure_reason = NULL, verification = NULL,
			resolved_at = NULL, resolved_by = NULL, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2 AND status IN `+fixedReopenFromSQL,
		tenantID.String(), findingID.String())
	if err != nil {
		return false, fmt.Errorf("reopen resolved finding: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}
