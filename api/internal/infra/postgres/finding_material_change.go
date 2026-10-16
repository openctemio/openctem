package postgres

// Material change of standing decisions
// (api/docs/rfcs/RFC-111-approval-policy.md §6): the approved accepted risks
// and one-person false positives whose finding moved up since their baseline,
// and the writes that end, flag or withdraw them. Every write is one
// transaction scoped to the decision's tenant, with its timeline entry and
// audit row.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Audit actions of the material-change controller (audit.ActionFindingApproval*).
const (
	auditMaterialChangeEnded   = "finding_approval.material_change_ended"
	auditMaterialChangeFlagged = "finding_approval.material_change_flagged"
	auditMaterialChangeRevoked = "finding_approval.material_change_revoked"
)

// FindingMaterialChangeRepository reads and writes standing decisions for the
// material-change controller. It reads across tenants (a platform job); every
// write names the decision's tenant.
type FindingMaterialChangeRepository struct {
	db     *DB
	expiry *FindingAcceptanceExpiryRepository
}

// NewFindingMaterialChangeRepository returns the repository.
func NewFindingMaterialChangeRepository(db *DB) *FindingMaterialChangeRepository {
	return &FindingMaterialChangeRepository{db: db, expiry: NewFindingAcceptanceExpiryRepository(db)}
}

// standingFactsSQL is the facts of the finding now, as the evaluator's JSON.
const standingFactsSQL = `jsonb_build_object(
	'severity', f.severity, 'priority_class', COALESCE(f.priority_class, ''),
	'kev', COALESCE(f.is_in_kev, false), 'epss', f.epss_score::float8,
	'exploit_validated', COALESCE(f.validation_outcome = 'reproducible', false),
	'crown_jewel', COALESCE(a.is_crown_jewel, false), 'internet_exposed', COALESCE(a.is_internet_accessible, false))`

// ListStandingDecisions answers up to limit standing decisions whose finding
// facts moved up since their baseline (or that have no baseline yet): severity
// or priority up, KEV added, EPSS higher, an exploit newly validated, the
// asset newly internet exposed or a crown jewel. Only the latest approved
// request of each finding counts, and only while the finding still holds it.
func (r *FindingMaterialChangeRepository) ListStandingDecisions(ctx context.Context, limit int) ([]vulnerability.StandingDecision, error) {
	rows, err := r.db.QueryContext(ctx, `
		WITH standing AS (
			SELECT DISTINCT ON (a.tenant_id, a.finding_id)
			       a.id, a.tenant_id, a.finding_id, a.requested_status, COALESCE(a.tier, '') AS tier,
			       COALESCE(a.facts_baseline, a.decision_facts) AS baseline, a.expires_at,
			       a.requested_by, a.approved_by, a.single_person, a.self_approved
			FROM finding_status_approvals a
			WHERE a.status = 'approved' AND a.requested_status IN ('accepted', 'false_positive')
			ORDER BY a.tenant_id, a.finding_id, a.approved_at DESC NULLS LAST, a.created_at DESC
		)
		SELECT s.id, s.tenant_id, s.finding_id, COALESCE(f.asset_id::text, ''), s.requested_status, s.tier,
		       s.baseline, `+standingFactsSQL+`, s.expires_at,
		       COALESCE(f.priority_class, ''), f.severity, f.sla_deadline, COALESCE(f.sla_status, ''),
		       COALESCE(s.requested_by::text, ''),
		       ARRAY(SELECT DISTINCT x FROM (
		           SELECT s.approved_by AS x WHERE s.approved_by IS NOT NULL
		           UNION SELECT so.user_id FROM approval_signoffs so
		           WHERE so.tenant_id = s.tenant_id AND so.subject_type = 'finding_approval' AND so.subject_id = s.id) u)::text[]
		FROM standing s
		JOIN findings f ON f.tenant_id = s.tenant_id AND f.id = s.finding_id
		LEFT JOIN assets a ON a.tenant_id = f.tenant_id AND a.id = f.asset_id
		WHERE f.status = s.requested_status
		  AND (s.requested_status = 'accepted' OR s.single_person OR s.self_approved)
		  AND (s.baseline IS NULL
		       OR finding_severity_rank(f.severity) > finding_severity_rank(s.baseline->>'severity')
		       OR (CASE upper(COALESCE(f.priority_class, '')) WHEN 'P0' THEN 4 WHEN 'P1' THEN 3 WHEN 'P2' THEN 2 WHEN 'P3' THEN 1 ELSE 0 END)
		          > (CASE upper(COALESCE(s.baseline->>'priority_class', '')) WHEN 'P0' THEN 4 WHEN 'P1' THEN 3 WHEN 'P2' THEN 2 WHEN 'P3' THEN 1 ELSE 0 END)
		       OR (COALESCE(f.is_in_kev, false) AND NOT COALESCE((s.baseline->>'kev')::boolean, false))
		       OR COALESCE(f.epss_score::float8, 0) > COALESCE((s.baseline->>'epss')::float8, 0)
		       OR (COALESCE(f.validation_outcome = 'reproducible', false) AND NOT COALESCE((s.baseline->>'exploit_validated')::boolean, false))
		       OR (COALESCE(a.is_crown_jewel, false) AND NOT COALESCE((s.baseline->>'crown_jewel')::boolean, false))
		       OR (COALESCE(a.is_internet_accessible, false) AND NOT COALESCE((s.baseline->>'internet_exposed')::boolean, false)))
		ORDER BY s.tenant_id, s.finding_id
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list standing decisions: %w", err)
	}
	defer rows.Close()
	var out []vulnerability.StandingDecision
	for rows.Next() {
		d, err := scanStandingDecision(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func scanStandingDecision(rows *sql.Rows) (vulnerability.StandingDecision, error) {
	var (
		d                                    vulnerability.StandingDecision
		id, tenant, findingID, asset, status string
		baseline, current                    []byte
		requester                            string
		approvers                            pq.StringArray
	)
	if err := rows.Scan(&id, &tenant, &findingID, &asset, &status, &d.Tier, &baseline, &current, &d.ExpiresAt,
		&d.PriorityClass, &d.Severity, &d.SLADeadline, &d.SLAStatus, &requester, &approvers); err != nil {
		return d, fmt.Errorf("scan standing decision: %w", err)
	}
	d.ApprovalID, _ = shared.IDFromString(id)
	d.TenantID, _ = shared.IDFromString(tenant)
	d.FindingID, _ = shared.IDFromString(findingID)
	if asset != "" {
		d.AssetID, _ = shared.IDFromString(asset)
	}
	d.Status = vulnerability.FindingStatus(status)
	if len(baseline) > 0 {
		var b approvalpolicy.Facts
		if err := json.Unmarshal(baseline, &b); err == nil {
			d.Baseline = &b
		}
	}
	if err := json.Unmarshal(current, &d.Current); err != nil {
		return d, fmt.Errorf("decode finding facts: %w", err)
	}
	if requester != "" {
		d.RequesterID, _ = shared.IDFromString(requester)
	}
	for _, a := range approvers {
		if uid, err := shared.IDFromString(a); err == nil {
			d.ApproverIDs = append(d.ApproverIDs, uid)
		}
	}
	return d, nil
}

// SetBaseline records the facts a decision was last checked against.
func (r *FindingMaterialChangeRepository) SetBaseline(ctx context.Context, d vulnerability.StandingDecision, facts approvalpolicy.Facts) error {
	return setBaseline(ctx, r.db, d, facts)
}

func setBaseline(ctx context.Context, db execer, d vulnerability.StandingDecision, facts approvalpolicy.Facts) error {
	raw, err := json.Marshal(facts)
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE finding_status_approvals SET facts_baseline = $3 WHERE tenant_id = $1 AND id = $2`,
		d.TenantID.String(), d.ApprovalID.String(), raw); err != nil {
		return fmt.Errorf("record decision baseline: %w", err)
	}
	return nil
}

func signalStrings(signals []approvalpolicy.Signal) []string {
	out := make([]string, 0, len(signals))
	for _, s := range signals {
		out = append(out, string(s))
	}
	return out
}

// EndAcceptance ends an accepted risk whose finding changed: the expiry
// path (reopen, new SLA clock, request expired, timeline) with reason
// material_change and the signals, and an audit row, in one transaction.
func (r *FindingMaterialChangeRepository) EndAcceptance(ctx context.Context, d vulnerability.StandingDecision, signals []approvalpolicy.Signal,
	newDeadline *time.Time, now time.Time,
) (bool, error) {
	return r.expiry.endAcceptance(ctx, d.AcceptanceDue(), newDeadline, now, acceptanceEnding{
		reason:  vulnerability.ReasonMaterialChange,
		message: "Risk acceptance ended: the finding changed since the decision and is open again",
		extra:   map[string]any{"signals": signalStrings(signals), "approval_id": d.ApprovalID.String()},
		audit:   auditMaterialChangeEnded,
	})
}

// FlagDecision raises a review flag on a standing decision whose finding
// changed (the decision stands), records the new baseline, and audits it.
func (r *FindingMaterialChangeRepository) FlagDecision(ctx context.Context, d vulnerability.StandingDecision, reason string,
	signals []approvalpolicy.Signal,
) (bool, error) {
	evidence := map[string]any{"signals": signalStrings(signals), "approval_id": d.ApprovalID.String()}
	raw, err := json.Marshal(evidence)
	if err != nil {
		return false, fmt.Errorf("marshal review evidence: %w", err)
	}
	raised := false
	err = r.db.Transaction(ctx, func(tx *sql.Tx) error {
		var status string
		err := tx.QueryRowContext(ctx, `SELECT status FROM findings WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
			d.TenantID.String(), d.FindingID.String()).Scan(&status)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && status != string(d.Status)) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("lock decided finding: %w", err)
		}
		if err := setBaseline(ctx, tx, d, d.Current); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `
			INSERT INTO finding_decision_reviews (tenant_id, finding_id, decision_status, reason, evidence)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (tenant_id, finding_id, reason) WHERE cleared_at IS NULL DO NOTHING`,
			d.TenantID.String(), d.FindingID.String(), status, reason, raw)
		if err != nil {
			return fmt.Errorf("raise decision review: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil // already flagged and not cleared
		}
		changes, err := json.Marshal(map[string]any{"decision_status": status, "reason": reason, "evidence": evidence})
		if err != nil {
			return fmt.Errorf("marshal review entry: %w", err)
		}
		msg := "The " + status + " decision was made on facts that changed since; it stands until a person reviews it"
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source, message)
			VALUES ($1, $2, $3, 'system', $4, $5, 'auto', $6)`,
			d.TenantID.String(), d.FindingID.String(), string(vulnerability.ActivityDecisionReview), "system: "+reason, changes, msg); err != nil {
			return fmt.Errorf("record decision review: %w", err)
		}
		if err := insertDecisionAudit(ctx, tx, d.TenantID, d.FindingID, auditMaterialChangeFlagged, "medium", msg, evidence); err != nil {
			return err
		}
		raised = true
		return nil
	})
	return raised, err
}

// RevokeFalsePositive withdraws a false positive one person decided whose
// finding changed: the finding is open again (confirmed, new SLA clock), the
// request is marked expired, the move is on the timeline (transition) and in
// the audit log, in one transaction.
func (r *FindingMaterialChangeRepository) RevokeFalsePositive(ctx context.Context, d vulnerability.StandingDecision, signals []approvalpolicy.Signal,
	newDeadline *time.Time, now time.Time,
) (bool, error) {
	extra := map[string]any{"signals": signalStrings(signals), "approval_id": d.ApprovalID.String()}
	msg := "False positive withdrawn: one person decided it and the finding changed since; it is open again"
	moved := false
	err := r.db.withFindingTransition(ctx, vulnerability.StatusTransition{
		Source: "approval_policy", Reason: vulnerability.ReasonMaterialChange, ActorName: "system: material change",
		Message: msg, Changes: extra,
	}, func(tx *sql.Tx) error {
		if newDeadline != nil {
			if err := markSLARestart(ctx, tx); err != nil {
				return err
			}
		}
		res, err := tx.ExecContext(ctx, `
			UPDATE findings SET status = 'confirmed', resolution = NULL, closure_reason = NULL, verification = NULL,
				resolved_at = NULL, resolved_by = NULL,
				sla_deadline = COALESCE($3, sla_deadline),
				sla_status = CASE WHEN $3::timestamptz IS NULL THEN sla_status ELSE 'on_track' END,
				updated_at = $4
			WHERE tenant_id = $1 AND id = $2 AND status = 'false_positive'`,
			d.TenantID.String(), d.FindingID.String(), newDeadline, now)
		if err != nil {
			return fmt.Errorf("withdraw false positive: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE finding_status_approvals SET status = 'expired', version = version + 1
			WHERE tenant_id = $1 AND id = $2 AND status = 'approved'`, d.TenantID.String(), d.ApprovalID.String()); err != nil {
			return fmt.Errorf("expire withdrawn decision: %w", err)
		}
		if err := insertDecisionAudit(ctx, tx, d.TenantID, d.FindingID, auditMaterialChangeRevoked, "high", msg, extra); err != nil {
			return err
		}
		moved = true
		return nil
	})
	return moved, err
}

// insertDecisionAudit writes the tenant audit row of a decision the
// controller changed, in tx.
func insertDecisionAudit(ctx context.Context, tx *sql.Tx, tenantID, findingID shared.ID, action, severity, message string, meta map[string]any) error {
	raw, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal audit metadata: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id, result, severity, message, metadata, logged_at)
		VALUES (gen_random_uuid(), $1, $2, 'finding', $3, 'success', $4, $5, $6, NOW())`,
		tenantID.String(), action, findingID.String(), severity, message, raw); err != nil {
		return fmt.Errorf("record decision audit: %w", err)
	}
	return nil
}
