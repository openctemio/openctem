package postgres

// Suspension of a decision when a taint finding's source changes
// (research/134 section 4.1; vulnerability.TaintSourceHash).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// ResolutionDecisionSuspended marks a finding whose decision was suspended.
const ResolutionDecisionSuspended = "decision_suspended"

// SuspendOnTaintSourceChange checks, before the traces are stored, each
// decided (false positive or accepted) finding the traces name: when the
// source of its stored trace and of the reported one both exist and differ,
// the decision is suspended (the finding is confirmed again, for review),
// the earlier decision is kept in finding_decision_suspensions and the change
// is audited. Returns the suspended findings.
func (r *DataFlowRepository) SuspendOnTaintSourceChange(ctx context.Context, tenantID shared.ID, traces []vulnerability.FindingTrace) ([]shared.ID, error) {
	if len(traces) == 0 {
		return nil, nil
	}
	newHash := map[string]string{}
	fps := make([]string, 0, len(traces))
	for _, t := range traces {
		if h := vulnerability.TaintSourceHash(t.Flows); h != "" {
			newHash[t.Fingerprint] = h
			fps = append(fps, t.Fingerprint)
		}
	}
	if len(fps) == 0 {
		return nil, nil
	}
	cands, err := r.changedTaintSources(ctx, tenantID, fps, newHash)
	if err != nil {
		return nil, err
	}
	var out []shared.ID
	for _, c := range cands {
		done, err := r.suspendDecision(ctx, tenantID.String(), c.id, c.status, c.old, c.new)
		if err != nil {
			return out, err
		}
		if done {
			if id, err := shared.IDFromString(c.id); err == nil {
				out = append(out, id)
			}
		}
	}
	return out, nil
}

func (r *DataFlowRepository) suspendDecision(ctx context.Context, tenant, id, status, oldHash, newHash string) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	var resolution sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT resolution FROM findings WHERE tenant_id = $1 AND id = $2 AND status = $3 FOR UPDATE`,
		tenant, id, status).Scan(&resolution)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO finding_decision_suspensions (tenant_id, finding_id, prior_status, prior_resolution, reason, old_source_hash, new_source_hash)
		VALUES ($1, $2, $3, $4, 'taint_source_changed', $5, $6)`, tenant, id, status, resolution, oldHash, newHash); err != nil {
		return false, fmt.Errorf("record suspension: %w", err)
	}
	if err := setFindingTransition(ctx, tx, findingTransition{
		Source: "taint_source", Reason: "decision_suspended", ActorName: "system: taint source changed",
		Message: "The " + status + " decision is suspended for review: the finding's taint source changed",
	}); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE findings SET status = 'confirmed', resolution = $3, acceptance_expires_at = NULL, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2`, tenant, id, ResolutionDecisionSuspended); err != nil {
		return false, err
	}
	meta, _ := json.Marshal(map[string]string{"prior_status": status, "reason": "taint_source_changed"})
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id, result, severity, message, metadata, logged_at)
		VALUES (gen_random_uuid(), $1, 'finding.status_changed', 'finding', $2, 'success', 'medium', $3, $4::jsonb, NOW())`,
		tenant, id, "The "+status+" decision is suspended for review: the finding's taint source changed", string(meta)); err != nil {
		return false, fmt.Errorf("audit suspension: %w", err)
	}
	return true, tx.Commit()
}

type taintCand struct{ id, status, old, new string }

// changedTaintSources lists the decided findings whose stored source differs
// from the reported one.
func (r *DataFlowRepository) changedTaintSources(ctx context.Context, tenantID shared.ID, fps []string, newHash map[string]string) ([]taintCand, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT f.id, f.fingerprint, f.status, COALESCE(l.location_type, ''), COALESCE(l.file_path, ''), COALESCE(l.snippet, ''), COALESCE(l.function_name, '')
		FROM findings f
		JOIN LATERAL (
			SELECT fl.location_type, fl.file_path, fl.snippet, fl.function_name
			FROM finding_data_flows df JOIN finding_flow_locations fl ON fl.data_flow_id = df.id
			WHERE df.finding_id = f.id
			ORDER BY df.flow_index, (fl.location_type = 'source') DESC, fl.step_index
			LIMIT 1) l ON TRUE
		WHERE f.tenant_id = $1 AND f.fingerprint = ANY($2) AND f.status IN ('false_positive', 'accepted')`,
		tenantID.String(), pq.Array(fps))
	if err != nil {
		return nil, fmt.Errorf("load decided taint findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var cands []taintCand
	for rows.Next() {
		var id, fp, status, ltype, path, snippet, fn string
		if err := rows.Scan(&id, &fp, &status, &ltype, &path, &snippet, &fn); err != nil {
			return nil, err
		}
		old := vulnerability.TaintSourceHash([]vulnerability.DataFlow{{Steps: []vulnerability.DataFlowStep{{
			LocationType: ltype, FunctionName: fn, Location: &vulnerability.FindingLocation{Path: path, Snippet: snippet}}}}})
		if old != "" && old != newHash[fp] {
			cands = append(cands, taintCand{id: id, status: status, old: old, new: newHash[fp]})
		}
	}
	return cands, rows.Err()
}
