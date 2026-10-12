package postgres

// Retention of CI runs (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md,
// "Data model"). Every statement is scoped to one tenant and bounded.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ cirun.RetentionRepository = (*CIRunRepository)(nil)

// ciRetainedRuns selects, for tenant $1, the runs retention never removes:
// each pipeline's latest run and its latest default-branch run
// (idx_ci_runs_tenant_pipeline).
const ciRetainedRuns = `
	SELECT id FROM (SELECT DISTINCT ON (pipeline_id) id FROM ci_runs
		WHERE tenant_id = $1 AND pipeline_id IS NOT NULL ORDER BY pipeline_id, created_at DESC) latest
	UNION
	SELECT id FROM (SELECT DISTINCT ON (pipeline_id) id FROM ci_runs
		WHERE tenant_id = $1 AND pipeline_id IS NOT NULL AND is_default_branch ORDER BY pipeline_id, created_at DESC) latest_default`

// RetentionTenantsForPlatform lists the tenants that have CI pipelines or a
// trust configuration (every run came through one of them); small tables,
// no scan of ci_runs.
func (r *CIRunRepository) RetentionTenantsForPlatform(ctx context.Context) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT tenant_id FROM ci_pipelines UNION SELECT tenant_id FROM ci_trust_configs`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []shared.ID{}
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

// ClearExpiredRunTokens clears the token hash of the tenant's runs whose
// token expired before the time, and deletes the expired job tokens of its
// aggregate runs.
func (r *CIRunRepository) ClearExpiredRunTokens(ctx context.Context, tenantID shared.ID, before time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE ci_runs SET token_hash = NULL, updated_at = NOW()
		WHERE tenant_id = $1 AND token_hash IS NOT NULL AND token_expires_at < $2`, tenantID.String(), before)
	if err != nil {
		return 0, err
	}
	cleared, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	res, err = r.db.ExecContext(ctx, `DELETE FROM ci_run_tokens WHERE tenant_id = $1 AND expires_at < $2`,
		tenantID.String(), before)
	if err != nil {
		return cleared, err
	}
	deleted, err := res.RowsAffected()
	return cleared + deleted, err
}

// PurgeRunFindings deletes the sighted fingerprints of up to limit of the
// tenant's runs created before the time, except the retained runs.
func (r *CIRunRepository) PurgeRunFindings(ctx context.Context, tenantID shared.ID, before time.Time, limit int) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		WITH keep AS (`+ciRetainedRuns+`),
		victims AS (
			SELECT run.id FROM ci_runs run
			WHERE run.tenant_id = $1 AND run.created_at < $2 AND run.id NOT IN (SELECT id FROM keep)
			  AND EXISTS (SELECT 1 FROM ci_run_findings f WHERE f.tenant_id = $1 AND f.run_id = run.id)
			LIMIT $3)
		DELETE FROM ci_run_findings f USING victims v WHERE f.tenant_id = $1 AND f.run_id = v.id`,
		tenantID.String(), before, limit)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PurgeRuns deletes up to limit of the tenant's runs created before the time,
// except the retained runs. Their sighted fingerprints cascade.
func (r *CIRunRepository) PurgeRuns(ctx context.Context, tenantID shared.ID, before time.Time, limit int) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		WITH keep AS (`+ciRetainedRuns+`)
		DELETE FROM ci_runs WHERE tenant_id = $1 AND id IN (
			SELECT run.id FROM ci_runs run
			WHERE run.tenant_id = $1 AND run.created_at < $2 AND run.id NOT IN (SELECT id FROM keep)
			LIMIT $3)`,
		tenantID.String(), before, limit)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
