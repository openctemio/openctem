package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Ready to close (docs/architecture/finding-verification-plan.md): the
// proposals store and the "Recently auto-closed" read. Every statement is
// tenant-scoped ($1) and, for a person's read or decision, narrowed to the
// caller's data scope like the findings list (asset scope, or the finding's
// assignee).

var _ vulnerability.ClosureProposalRepository = (*FindingRepository)(nil)

// maxProposalEvidenceBytes bounds the evidence a proposal stores.
const maxProposalEvidenceBytes = 4096

// proposalEligibleSQL is true for a pending proposal that a person may still
// confirm: the finding is open (a status a platform close starts from), not
// a secret or a protected source, and not seen after the proposal's
// evidence.
var proposalEligibleSQL = `p.state = 'pending'
	AND f.status IN ` + autoResolveFromSQL + `
	AND f.branch_id IS NULL
	AND f.source NOT IN ` + coverageProtectedSources + `
	AND NOT ` + secretFindingSQL("f") + `
	AND COALESCE(f.last_seen_at, f.created_at) <= p.evidence_at`

// proposalScope is the caller's data scope over the finding f, with its
// arguments numbered from first. A nil scope (an internal call) is not
// narrowed.
func proposalScope(scope *shared.DataScope, first int) (string, []any) {
	if scope == nil {
		return "TRUE", nil
	}
	return filterspec.AssigneeScopeSQL("f.asset_id", "f.assigned_to", scope, first)
}

func proposalIDStrings(ids []shared.ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

// RecordClosureProposals inserts one pending proposal per open finding, or
// refreshes the evidence and evidence_at of the pending one.
func (r *FindingRepository) RecordClosureProposals(ctx context.Context, tenantID shared.ID, recs []vulnerability.ClosureProposalRecord) (int, error) {
	if len(recs) == 0 {
		return 0, nil
	}
	findings := make([]string, 0, len(recs))
	methods := make([]string, 0, len(recs))
	commands := make([]sql.NullString, 0, len(recs))
	evidence := make([]string, 0, len(recs))
	evidenceAt := make([]time.Time, 0, len(recs))
	now := time.Now().UTC()
	for _, rec := range recs {
		raw, err := json.Marshal(rec.Evidence)
		if err != nil || len(raw) > maxProposalEvidenceBytes || rec.Evidence == nil {
			raw = []byte(`{}`)
		}
		findings = append(findings, rec.FindingID.String())
		methods = append(methods, string(rec.Method))
		var cmd sql.NullString
		if !rec.CommandID.IsZero() {
			cmd = sql.NullString{String: rec.CommandID.String(), Valid: true}
		}
		commands = append(commands, cmd)
		evidence = append(evidence, string(raw))
		at := rec.EvidenceAt.UTC()
		if at.IsZero() || at.After(now) {
			at = now
		}
		evidenceAt = append(evidenceAt, at)
	}
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO finding_closure_proposals (tenant_id, finding_id, method, command_id, evidence, evidence_at)
		SELECT $1, f.id, x.method, x.command_id::uuid, x.evidence::jsonb, x.evidence_at
		FROM unnest($2::uuid[], $3::text[], $4::text[], $5::text[], $6::timestamptz[]) AS x(finding_id, method, command_id, evidence, evidence_at)
		JOIN findings f ON f.tenant_id = $1 AND f.id = x.finding_id
		WHERE f.status IN `+autoResolveFromSQL+`
		ON CONFLICT (tenant_id, finding_id) WHERE state = 'pending'
		DO UPDATE SET method = EXCLUDED.method, command_id = EXCLUDED.command_id,
			evidence = EXCLUDED.evidence, evidence_at = EXCLUDED.evidence_at`,
		tenantID.String(), pq.Array(findings), pq.Array(methods), pq.Array(commands), pq.Array(evidence), pq.Array(evidenceAt))
	if err != nil {
		return 0, fmt.Errorf("record closure proposals: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// CancelStaleClosureProposals cancels the tenant's pending proposals whose
// finding was seen after the evidence (seen_again) or is no longer open
// (status_changed).
func (r *FindingRepository) CancelStaleClosureProposals(ctx context.Context, tenantID shared.ID) (int, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE finding_closure_proposals p
		SET state = 'canceled', decided_at = now(),
			reason = CASE WHEN f.status IN `+autoResolveFromSQL+` THEN 'seen_again' ELSE 'status_changed' END
		FROM findings f
		WHERE p.tenant_id = $1 AND p.state = 'pending'
			AND f.tenant_id = p.tenant_id AND f.id = p.finding_id
			AND (f.status NOT IN `+autoResolveFromSQL+` OR COALESCE(f.last_seen_at, f.created_at) > p.evidence_at)`,
		tenantID.String())
	if err != nil {
		return 0, fmt.Errorf("cancel stale closure proposals: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

const proposalFromSQL = `
	FROM finding_closure_proposals p
	JOIN findings f ON f.tenant_id = p.tenant_id AND f.id = p.finding_id
	LEFT JOIN assets a ON a.tenant_id = f.tenant_id AND a.id = f.asset_id
	WHERE p.tenant_id = $1 AND `

// ListClosureProposals lists the pending, eligible proposals in the caller's
// scope: critical first, then the oldest proposal.
func (r *FindingRepository) ListClosureProposals(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, page pagination.Pagination) (pagination.Result[*vulnerability.ClosureProposalItem], error) {
	cond, args := proposalScope(scope, 2)
	args = append([]any{tenantID.String()}, args...)
	where := proposalFromSQL + proposalEligibleSQL + " AND " + cond
	var total int64
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*)"+where, args...).Scan(&total); err != nil {
		return pagination.Result[*vulnerability.ClosureProposalItem]{}, fmt.Errorf("count closure proposals: %w", err)
	}
	args = append(args, page.Limit(), page.Offset())
	rows, err := r.db.QueryContext(ctx, `
		SELECT p.id::text, p.finding_id::text, p.method, p.evidence, p.proposed_at, p.evidence_at,
			COALESCE(NULLIF(f.title, ''), LEFT(f.message, 300), ''), LOWER(f.severity::text), f.status, COALESCE(f.tool_name, ''),
			COALESCE(f.asset_id::text, ''), COALESCE(a.name, ''), COALESCE(f.priority_class, ''), COALESCE(f.is_in_kev, false)`+
		where+fmt.Sprintf(`
		ORDER BY CASE LOWER(f.severity::text) WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
			p.proposed_at, p.id
		LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return pagination.Result[*vulnerability.ClosureProposalItem]{}, fmt.Errorf("list closure proposals: %w", err)
	}
	defer rows.Close()
	const maxCap = 100
	items := make([]*vulnerability.ClosureProposalItem, 0, maxCap)
	for rows.Next() {
		var (
			it                       vulnerability.ClosureProposalItem
			id, fid, method, sev, st string
			assetID, pc              string
			evidence                 []byte
			kev                      bool
		)
		if err := rows.Scan(&id, &fid, &method, &evidence, &it.ProposedAt, &it.EvidenceAt,
			&it.Title, &sev, &st, &it.ToolName, &assetID, &it.AssetName, &pc, &kev); err != nil {
			return pagination.Result[*vulnerability.ClosureProposalItem]{}, fmt.Errorf("scan closure proposal: %w", err)
		}
		it.ID, _ = shared.IDFromString(id)
		it.FindingID, _ = shared.IDFromString(fid)
		if assetID != "" {
			it.AssetID, _ = shared.IDFromString(assetID)
		}
		it.Method = vulnerability.ClosureMethod(method)
		it.Severity = vulnerability.Severity(sev)
		it.Status = vulnerability.FindingStatus(st)
		it.Tier = vulnerability.FindingRiskTier(it.Severity, pc, kev)
		_ = json.Unmarshal(evidence, &it.Evidence)
		items = append(items, &it)
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[*vulnerability.ClosureProposalItem]{}, fmt.Errorf("list closure proposals: %w", err)
	}
	return pagination.NewResult(items, total, page), nil
}

// CountClosureProposals counts what ListClosureProposals would list.
func (r *FindingRepository) CountClosureProposals(ctx context.Context, tenantID shared.ID, scope *shared.DataScope) (int, error) {
	cond, args := proposalScope(scope, 2)
	args = append([]any{tenantID.String()}, args...)
	var n int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*)"+proposalFromSQL+proposalEligibleSQL+" AND "+cond, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("count closure proposals: %w", err)
	}
	return n, nil
}

// decideSkipped fills Skipped for every requested id not in decided: a
// pending proposal in the caller's scope whose finding is no longer
// eligible is not_eligible, anything else not_found.
func (r *FindingRepository) decideSkipped(ctx context.Context, tx *sql.Tx, tenantID shared.ID, scope *shared.DataScope, ids []shared.ID, decided map[string]bool) (map[shared.ID]string, error) {
	skipped := map[shared.ID]string{}
	rest := make([]string, 0, len(ids))
	for _, id := range ids {
		if !decided[id.String()] {
			rest = append(rest, id.String())
			skipped[id] = "not_found"
		}
	}
	if len(rest) == 0 {
		return skipped, nil
	}
	cond, args := proposalScope(scope, 3)
	args = append([]any{tenantID.String(), pq.Array(rest)}, args...)
	//nolint:gosec // G202: cond is fixed SQL with numbered placeholders
	rows, err := tx.QueryContext(ctx, `SELECT p.id::text`+proposalFromSQL+`p.state = 'pending' AND p.id = ANY($2::uuid[]) AND `+cond, args...)
	if err != nil {
		return nil, fmt.Errorf("closure proposals not decided: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if id, err := shared.IDFromString(s); err == nil {
			skipped[id] = "not_eligible"
		}
	}
	return skipped, rows.Err()
}

// ConfirmClosureProposals closes the findings of the eligible proposals as
// fixed, as the person's decision, in one transaction: the proposal rows,
// the finding moves and their timeline entries commit together. The
// verification is the proposal's method.
func (r *FindingRepository) ConfirmClosureProposals(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, ids []shared.ID,
	actorID shared.ID, actorName, note string) (vulnerability.ClosureDecisionResult, error) {
	out := vulnerability.ClosureDecisionResult{}
	if len(ids) == 0 {
		return out, nil
	}
	t := findingTransition{
		Source: "closure_review", Reason: "closure_proposal_confirmed", ActorType: "user", ActorID: actorID.String(), ActorName: actorName,
		Message: "Closed after review: a covered scan no longer found it", Changes: map[string]any{"note": note},
	}
	cond, args := proposalScope(scope, 4)
	args = append([]any{tenantID.String(), pq.Array(proposalIDStrings(ids)), actorID.String()}, args...)
	err := r.db.withFindingTransition(ctx, t, func(tx *sql.Tx) error {
		// A person's move: the regression trigger does not count it.
		if _, err := tx.ExecContext(ctx, `SELECT set_config('openctem.person_move', 'on', true)`); err != nil {
			return fmt.Errorf("mark person move: %w", err)
		}
		decided, err := collectDecided(ctx, tx, &out, `
			WITH chosen AS (
				SELECT p.id, p.finding_id, p.method`+proposalFromSQL+proposalEligibleSQL+` AND p.id = ANY($2::uuid[]) AND `+cond+`
				ORDER BY p.finding_id
				FOR UPDATE OF p, f
			), closed AS (
				UPDATE findings f
				SET status = 'resolved', resolution = 'fixed', closure_reason = 'fixed',
					verification = CASE WHEN chosen.method IN ('covered_scan', 'source_reported') THEN chosen.method ELSE 'unknown' END, resolved_at = NOW(), resolved_by = $3::uuid, updated_at = NOW()
				FROM chosen
				WHERE f.tenant_id = $1 AND f.id = chosen.finding_id
				RETURNING f.id
			)
			UPDATE finding_closure_proposals p
			SET state = 'confirmed', decided_by = $3::uuid, decided_at = now()
			FROM chosen
			WHERE p.tenant_id = $1 AND p.id = chosen.id AND chosen.finding_id IN (SELECT id FROM closed)
			RETURNING p.id::text, p.finding_id::text, p.method`, args...)
		if err != nil {
			return err
		}
		out.Skipped, err = r.decideSkipped(ctx, tx, tenantID, scope, ids, decided)
		return err
	})
	if err != nil {
		return vulnerability.ClosureDecisionResult{}, fmt.Errorf("confirm closure proposals: %w", err)
	}
	return out, nil
}

// collectDecided runs a decision statement returning (proposal id, finding
// id) rows and records them in out. The statement is fixed SQL; its scope
// condition has numbered placeholders only.
func collectDecided(ctx context.Context, tx *sql.Tx, out *vulnerability.ClosureDecisionResult, query string, args ...any) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	decided := map[string]bool{}
	for rows.Next() {
		var pid, fid, method string
		if err := rows.Scan(&pid, &fid, &method); err != nil {
			return nil, err
		}
		decided[pid] = true
		if !slices.Contains(out.Methods, method) {
			out.Methods = append(out.Methods, method)
		}
		if id, err := shared.IDFromString(pid); err == nil {
			out.Applied = append(out.Applied, id)
		}
		if id, err := shared.IDFromString(fid); err == nil {
			out.Findings = append(out.Findings, id)
		}
	}
	return decided, rows.Err()
}

// DismissClosureProposals keeps the findings open and records the reason.
// Eligibility is not re-checked: keeping a finding open is always allowed.
func (r *FindingRepository) DismissClosureProposals(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, ids []shared.ID,
	actorID shared.ID, reason vulnerability.ClosureDismissReason, note string) (vulnerability.ClosureDecisionResult, error) {
	out := vulnerability.ClosureDecisionResult{}
	if len(ids) == 0 {
		return out, nil
	}
	cond, args := proposalScope(scope, 6)
	args = append([]any{tenantID.String(), pq.Array(proposalIDStrings(ids)), actorID.String(), string(reason), note}, args...)
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		decided, err := collectDecided(ctx, tx, &out, `
			UPDATE finding_closure_proposals p
			SET state = 'dismissed', decided_by = $3::uuid, decided_at = now(), reason = $4, note = $5
			FROM findings f
			WHERE p.tenant_id = $1 AND p.state = 'pending' AND p.id = ANY($2::uuid[])
				AND f.tenant_id = p.tenant_id AND f.id = p.finding_id AND `+cond+`
			RETURNING p.id::text, p.finding_id::text, p.method`, args...)
		if err != nil {
			return err
		}
		out.Skipped, err = r.decideSkipped(ctx, tx, tenantID, scope, ids, decided)
		return err
	})
	if err != nil {
		return vulnerability.ClosureDecisionResult{}, fmt.Errorf("dismiss closure proposals: %w", err)
	}
	return out, nil
}

// autoClosedSQL selects the findings the platform closed by itself within
// the window ($2, seconds) and still closed: no person resolved them.
const autoClosedSQL = `
	FROM findings f
	LEFT JOIN assets a ON a.tenant_id = f.tenant_id AND a.id = f.asset_id
	WHERE f.tenant_id = $1 AND f.status = 'resolved' AND f.resolution = 'auto_fixed'
		AND f.resolved_by IS NULL AND f.resolved_at >= NOW() - make_interval(secs => $2)
		AND f.source <> 'pentest' AND `

// ListRecentlyAutoClosed lists the findings the platform closed by itself
// within RecentlyAutoClosedWindow, newest first, with the evidence of their
// latest automatic close entry.
func (r *FindingRepository) ListRecentlyAutoClosed(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, page pagination.Pagination) (pagination.Result[*vulnerability.AutoClosedItem], error) {
	cond, args := proposalScope(scope, 3)
	args = append([]any{tenantID.String(), vulnerability.RecentlyAutoClosedWindow.Seconds()}, args...)
	var total int64
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*)"+autoClosedSQL+cond, args...).Scan(&total); err != nil {
		return pagination.Result[*vulnerability.AutoClosedItem]{}, fmt.Errorf("count auto-closed findings: %w", err)
	}
	args = append(args, page.Limit(), page.Offset())
	rows, err := r.db.QueryContext(ctx, `
		SELECT f.id::text, COALESCE(NULLIF(f.title, ''), LEFT(f.message, 300), ''), LOWER(f.severity::text), COALESCE(f.tool_name, ''), COALESCE(f.asset_id::text, ''),
			COALESCE(a.name, ''), COALESCE(f.verification, ''), f.resolved_at,
			COALESCE((SELECT fa.changes FROM finding_activities fa
				WHERE fa.tenant_id = f.tenant_id AND fa.finding_id = f.id AND fa.activity_type = 'auto_resolved'
				ORDER BY fa.created_at DESC LIMIT 1), '{}'::jsonb)`+
		autoClosedSQL+cond+fmt.Sprintf(` ORDER BY f.resolved_at DESC, f.id LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return pagination.Result[*vulnerability.AutoClosedItem]{}, fmt.Errorf("list auto-closed findings: %w", err)
	}
	defer rows.Close()
	const maxCap = 100
	items := make([]*vulnerability.AutoClosedItem, 0, maxCap)
	for rows.Next() {
		var (
			it               vulnerability.AutoClosedItem
			id, sev, assetID string
			changes          []byte
			resolvedAt       sql.NullTime
		)
		if err := rows.Scan(&id, &it.Title, &sev, &it.ToolName, &assetID, &it.AssetName, &it.Verification, &resolvedAt, &changes); err != nil {
			return pagination.Result[*vulnerability.AutoClosedItem]{}, fmt.Errorf("scan auto-closed finding: %w", err)
		}
		it.FindingID, _ = shared.IDFromString(id)
		if assetID != "" {
			it.AssetID, _ = shared.IDFromString(assetID)
		}
		it.Severity = vulnerability.Severity(sev)
		if resolvedAt.Valid {
			it.ResolvedAt = resolvedAt.Time
		}
		it.Evidence = autoCloseEvidence(changes)
		items = append(items, &it)
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[*vulnerability.AutoClosedItem]{}, fmt.Errorf("list auto-closed findings: %w", err)
	}
	return pagination.NewResult(items, total, page), nil
}

// autoCloseEvidenceKeys are the timeline evidence fields shown with an
// automatic close (the scan behind it); anything else stays on the timeline.
var autoCloseEvidenceKeys = []string{"scanner", "scan_id", "profile_id", "reason", "run_id", "pipeline_run_id"}

func autoCloseEvidence(raw []byte) map[string]any {
	var all map[string]any
	if json.Unmarshal(raw, &all) != nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(autoCloseEvidenceKeys))
	for _, k := range autoCloseEvidenceKeys {
		if v, ok := all[k]; ok {
			if s, isStr := v.(string); isStr && len(s) > 256 {
				v = strings.ToValidUTF8(s[:256], "")
			}
			out[k] = v
		}
	}
	return out
}

// ReopenAutoClosedNotFixed reopens one finding the platform closed by itself
// within the window, as a person saying the close was wrong. It reopens as
// confirmed (a person says it is real) and is not counted as a regression:
// the fix never happened.
func (r *FindingRepository) ReopenAutoClosedNotFixed(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, findingID, actorID shared.ID,
	actorName, note string) (bool, error) {
	t := findingTransition{
		Source: "closure_review", Reason: "auto_close_not_fixed", ActorType: "user",
		ActorID: actorID.String(), ActorName: actorName,
		Message: "Reopened: the automatic close was wrong, it is not fixed", Changes: map[string]any{"note": note},
	}
	cond, args := proposalScope(scope, 4)
	args = append([]any{tenantID.String(), vulnerability.RecentlyAutoClosedWindow.Seconds(), findingID.String()}, args...)
	var n int64
	err := r.db.withFindingTransition(ctx, t, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('openctem.person_move', 'on', true)`); err != nil {
			return fmt.Errorf("mark person move: %w", err)
		}
		//nolint:gosec // G202: cond is fixed SQL with numbered placeholders
		res, err := tx.ExecContext(ctx, `
			UPDATE findings
			SET status = 'confirmed', resolution = NULL, closure_reason = NULL, verification = NULL,
				resolved_at = NULL, resolved_by = NULL, updated_at = NOW()
			WHERE tenant_id = $1 AND id = $3::uuid AND id IN (SELECT f.id`+autoClosedSQL+cond+`)`, args...)
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("reopen auto-closed finding: %w", err)
	}
	return n == 1, nil
}
