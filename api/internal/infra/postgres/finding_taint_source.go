package postgres

// Review of a decision when a taint finding's source changes
// (research/134 section 4.1; vulnerability.TaintSourceHash).

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// ReviewOnTaintSourceChange checks, before the traces are stored, each
// decided (false positive or accepted) finding the traces name: when the
// source of its stored trace and of the reported one both exist and differ,
// the decision stands and a review flag is raised for it
// (finding_decision_reviews, reason taint_source_changed) with a timeline
// entry and an audit event. A changed taint source is a reason to look again,
// never proof the decision was wrong, so the finding is not reopened. Returns
// the flagged findings.
func (r *DataFlowRepository) ReviewOnTaintSourceChange(ctx context.Context, tenantID shared.ID, traces []vulnerability.FindingTrace) ([]shared.ID, error) {
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
		raised, err := raiseDecisionReview(ctx, r.db, tenantID.String(), c.id, DecisionReviewTaintSourceChanged,
			map[string]any{"old_source_hash": c.old, "new_source_hash": c.new})
		if err != nil {
			return out, err
		}
		if !raised {
			continue
		}
		meta, _ := json.Marshal(map[string]string{"decision_status": c.status, "reason": DecisionReviewTaintSourceChanged})
		if _, err := r.db.ExecContext(ctx, `INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id, result, severity, message, metadata, logged_at)
			VALUES (gen_random_uuid(), $1, 'finding.status_changed', 'finding', $2, 'success', 'medium', $3, $4::jsonb, NOW())`,
			tenantID.String(), c.id, "The "+c.status+" decision is flagged for review: the finding's taint source changed", string(meta)); err != nil {
			return out, fmt.Errorf("audit decision review: %w", err)
		}
		if id, err := shared.IDFromString(c.id); err == nil {
			out = append(out, id)
		}
	}
	return out, nil
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
		WHERE f.tenant_id = $1 AND f.fingerprint = ANY($2) AND f.status IN `+vulnerability.StatusListSQL(vulnerability.SuppressedStatuses()),
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
