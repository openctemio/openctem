package postgres

// CI pipelines (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md, migration
// 001069): the logical identity of a CI scanner. Every query is
// tenant-scoped.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const ciPipelineColumns = `id, tenant_id, provider, issuer, external_repo_id, workflow_path, repository_asset_id,
	trust_config_id, repository_name, workflow_name, template_ref, template_sha, default_branch, first_run_at,
	last_run_at, last_run_id, last_run_status, last_fork_run_at, runs_count, last_default_run_at,
	last_default_verdict, last_default_verdict_at, last_pr_verdict, last_pr_verdict_at, last_scan_failures,
	sensor_version, tools, median_interval_seconds, schedule_interval_seconds, revoked_at, created_at, updated_at`

func scanCIPipeline(row ciScanner) (cirun.Pipeline, error) {
	var (
		p                                     cirun.Pipeline
		id, tid, prov, asset                  string
		trust, lastRun, defVerdict, prVerdict sql.NullString
		firstRun, lastRunAt, lastFork         sql.NullTime
		lastDefRun, defAt, prAt, revoked      sql.NullTime
		failures, median, schedule            sql.NullInt64
		tools                                 []byte
	)
	if err := row.Scan(&id, &tid, &prov, &p.Issuer, &p.ExternalRepoID, &p.WorkflowPath, &asset, &trust,
		&p.RepositoryName, &p.WorkflowName, &p.TemplateRef, &p.TemplateSHA, &p.DefaultBranch, &firstRun,
		&lastRunAt, &lastRun, &p.LastRunStatus, &lastFork, &p.RunsCount, &lastDefRun, &defVerdict, &defAt,
		&prVerdict, &prAt, &failures, &p.SensorVersion, &tools, &median, &schedule, &revoked,
		&p.CreatedAt, &p.UpdatedAt); err != nil {
		return p, err
	}
	p.ID, _ = shared.IDFromString(id)
	p.TenantID, _ = shared.IDFromString(tid)
	p.Provider = cirun.Provider(prov)
	p.RepositoryAssetID, _ = shared.IDFromString(asset)
	p.TrustConfigID = parseOptID(trust)
	p.FirstRunAt, p.LastRunAt, p.LastForkRunAt = optTime(firstRun), optTime(lastRunAt), optTime(lastFork)
	p.LastRunID = parseOptID(lastRun)
	p.LastDefaultRunAt, p.LastDefaultVerdictAt, p.LastPRVerdictAt = optTime(lastDefRun), optTime(defAt), optTime(prAt)
	p.LastDefaultVerdict, p.LastPRVerdict = defVerdict.String, prVerdict.String
	if failures.Valid {
		n := int(failures.Int64)
		p.LastScanFailures = &n
	}
	p.Tools = decodeToolLabels(tools)
	if median.Valid {
		p.MedianInterval = time.Duration(median.Int64) * time.Second
	}
	if schedule.Valid {
		p.ScheduleInterval = time.Duration(schedule.Int64) * time.Second
	}
	p.RevokedAt = optTime(revoked)
	return p, nil
}

func decodeToolLabels(b []byte) []cirun.ToolLabel {
	out := []cirun.ToolLabel{}
	if len(b) > 0 {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

// UpsertPipeline finds or creates the pipeline with p's key. It runs under a
// per-tenant advisory lock so the caps hold under concurrent exchanges.
func (r *CIRunRepository) UpsertPipeline(ctx context.Context, p *cirun.Pipeline, fork bool, caps cirun.PipelineCaps) (*cirun.Pipeline, bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback() }()
	tid := p.TenantID.String()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('ci_pipelines:' || $1, 0))`, tid); err != nil {
		return nil, false, fmt.Errorf("lock tenant pipelines: %w", err)
	}

	var id string
	err = tx.QueryRowContext(ctx, `SELECT id FROM ci_pipelines
		WHERE tenant_id = $1 AND provider = $2 AND issuer = $3 AND external_repo_id = $4 AND workflow_path = $5`,
		tid, string(p.Provider), p.Issuer, p.ExternalRepoID, p.WorkflowPath).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		// A pipeline backfilled from runs recorded before pipelines existed:
		// same repository asset and workflow file, no repository id yet.
		err = tx.QueryRowContext(ctx, `SELECT id FROM ci_pipelines
			WHERE tenant_id = $1 AND provider = $2 AND issuer = $3 AND repository_asset_id = $4
			  AND workflow_path = $5 AND external_repo_id LIKE 'legacy:%'
			ORDER BY created_at LIMIT 1`,
			tid, string(p.Provider), p.Issuer, p.RepositoryAssetID.String(), p.WorkflowPath).Scan(&id)
		if err == nil {
			if _, err := tx.ExecContext(ctx, `UPDATE ci_pipelines SET external_repo_id = $3, updated_at = NOW()
				WHERE tenant_id = $1 AND id = $2`, tid, id, p.ExternalRepoID); err != nil {
				return nil, false, fmt.Errorf("adopt legacy pipeline: %w", err)
			}
		}
	}
	created := false
	switch {
	case err == nil:
		if fork {
			_, err = tx.ExecContext(ctx, `UPDATE ci_pipelines SET trust_config_id = $3, revoked_at = NULL,
				updated_at = NOW() WHERE tenant_id = $1 AND id = $2`, tid, id, nullID(p.TrustConfigID))
		} else {
			_, err = tx.ExecContext(ctx, `UPDATE ci_pipelines SET trust_config_id = $3, revoked_at = NULL,
				repository_asset_id = $4, repository_name = $5, workflow_name = $6, template_ref = $7,
				template_sha = $8, default_branch = $9, updated_at = NOW()
				WHERE tenant_id = $1 AND id = $2`, tid, id, nullID(p.TrustConfigID), p.RepositoryAssetID.String(),
				p.RepositoryName, p.WorkflowName, p.TemplateRef, p.TemplateSHA, p.DefaultBranch)
		}
		if err != nil {
			return nil, false, fmt.Errorf("update pipeline: %w", err)
		}
	case errors.Is(err, sql.ErrNoRows):
		if err := checkPipelineCaps(ctx, tx, p, caps); err != nil {
			return nil, false, err
		}
		id = p.ID.String()
		if _, err := tx.ExecContext(ctx, `INSERT INTO ci_pipelines (id, tenant_id, provider, issuer,
			external_repo_id, workflow_path, repository_asset_id, trust_config_id, repository_name, workflow_name,
			template_ref, template_sha, default_branch, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $14)`,
			id, tid, string(p.Provider), p.Issuer, p.ExternalRepoID, p.WorkflowPath, p.RepositoryAssetID.String(),
			nullID(p.TrustConfigID), p.RepositoryName, p.WorkflowName, p.TemplateRef, p.TemplateSHA,
			p.DefaultBranch, p.CreatedAt); err != nil {
			return nil, false, fmt.Errorf("create pipeline: %w", err)
		}
		created = true
	default:
		return nil, false, fmt.Errorf("find pipeline: %w", err)
	}
	out, err := scanCIPipeline(tx.QueryRowContext(ctx, `SELECT `+ciPipelineColumns+` FROM ci_pipelines
		WHERE tenant_id = $1 AND id = $2`, tid, id))
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return &out, created, nil
}

func checkPipelineCaps(ctx context.Context, tx *sql.Tx, p *cirun.Pipeline, caps cirun.PipelineCaps) error {
	if caps.PerTenant > 0 {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM ci_pipelines WHERE tenant_id = $1`,
			p.TenantID.String()).Scan(&n); err != nil {
			return err
		}
		if n >= caps.PerTenant {
			return cirun.ErrPipelineCap
		}
	}
	if caps.PerTrustConfig > 0 && p.TrustConfigID != nil {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM ci_pipelines WHERE tenant_id = $1 AND trust_config_id = $2`,
			p.TenantID.String(), p.TrustConfigID.String()).Scan(&n); err != nil {
			return err
		}
		if n >= caps.PerTrustConfig {
			return cirun.ErrPipelineCap
		}
	}
	return nil
}

// RefreshPipeline recomputes the pipeline's run summary from its runs. Fork
// runs count only as last_fork_run_at: they never make a pipeline fresh,
// set its gates or its cadence. Several jobs of one CI run (same external
// run id) count once for the cadence.
func (r *CIRunRepository) RefreshPipeline(ctx context.Context, tenantID, pipelineID shared.ID) error {
	res, err := r.db.ExecContext(ctx, `
WITH runs AS (
    SELECT id, created_at, status, fork, is_default_branch, pull_request, verdict, evaluated_at, scan_failures,
           sensor_version, tools, event, external_run_id
    FROM ci_runs WHERE tenant_id = $1 AND pipeline_id = $2
), own AS (SELECT * FROM runs WHERE NOT fork),
last_run AS (SELECT id, created_at, status FROM own ORDER BY created_at DESC, id DESC LIMIT 1),
def_verdict AS (SELECT verdict, evaluated_at FROM own
    WHERE is_default_branch AND verdict IS NOT NULL ORDER BY evaluated_at DESC LIMIT 1),
pr_verdict AS (SELECT verdict, evaluated_at FROM own
    WHERE NOT is_default_branch AND verdict IS NOT NULL ORDER BY evaluated_at DESC LIMIT 1),
last_eval AS (SELECT scan_failures FROM own WHERE scan_failures IS NOT NULL ORDER BY evaluated_at DESC NULLS LAST LIMIT 1),
last_version AS (SELECT sensor_version FROM own WHERE sensor_version <> '' ORDER BY created_at DESC LIMIT 1),
last_tools AS (SELECT tools FROM own WHERE tools <> '[]'::jsonb ORDER BY created_at DESC LIMIT 1),
starts AS (SELECT min(created_at) AS at, bool_or(event = 'schedule') AS scheduled FROM own
    GROUP BY CASE WHEN external_run_id = '' THEN id::text ELSE external_run_id END),
recent AS (SELECT at FROM starts ORDER BY at DESC LIMIT 21),
recent_sched AS (SELECT at FROM starts WHERE scheduled ORDER BY at DESC LIMIT 21),
gaps AS (SELECT EXTRACT(EPOCH FROM at - lag(at) OVER (ORDER BY at)) AS gap FROM recent),
sched_gaps AS (SELECT EXTRACT(EPOCH FROM at - lag(at) OVER (ORDER BY at)) AS gap FROM recent_sched)
UPDATE ci_pipelines p SET
    first_run_at = (SELECT min(created_at) FROM own),
    last_run_at = (SELECT created_at FROM last_run),
    last_run_id = (SELECT id FROM last_run),
    last_run_status = COALESCE((SELECT status FROM last_run), ''),
    last_fork_run_at = (SELECT max(created_at) FROM runs WHERE fork),
    runs_count = (SELECT count(*) FROM own),
    last_default_run_at = (SELECT max(created_at) FROM own WHERE is_default_branch),
    last_default_verdict = (SELECT verdict FROM def_verdict),
    last_default_verdict_at = (SELECT evaluated_at FROM def_verdict),
    last_pr_verdict = (SELECT verdict FROM pr_verdict),
    last_pr_verdict_at = (SELECT evaluated_at FROM pr_verdict),
    last_scan_failures = (SELECT scan_failures FROM last_eval),
    sensor_version = COALESCE((SELECT sensor_version FROM last_version), ''),
    tools = COALESCE((SELECT tools FROM last_tools), '[]'::jsonb),
    -- NULL without two runs (LEAST would turn a NULL median into the cap).
    median_interval_seconds = (SELECT CASE WHEN count(gap) = 0 THEN NULL
        ELSE LEAST(percentile_cont(0.5) WITHIN GROUP (ORDER BY gap), 2147483647)::int END
        FROM gaps WHERE gap IS NOT NULL),
    schedule_interval_seconds = (SELECT CASE WHEN count(gap) = 0 THEN NULL
        ELSE LEAST(percentile_cont(0.5) WITHIN GROUP (ORDER BY gap), 2147483647)::int END
        FROM sched_gaps WHERE gap IS NOT NULL),
    updated_at = NOW()
WHERE p.tenant_id = $1 AND p.id = $2`, tenantID.String(), pipelineID.String())
	if err != nil {
		return err
	}
	return requireOneRow(res, cirun.ErrPipelineNotFound)
}

// GetPipeline returns one pipeline of the tenant.
func (r *CIRunRepository) GetPipeline(ctx context.Context, tenantID, id shared.ID) (*cirun.Pipeline, error) {
	p, err := scanCIPipeline(r.db.QueryRowContext(ctx, `SELECT `+ciPipelineColumns+` FROM ci_pipelines
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, cirun.ErrPipelineNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// ListPipelines returns the tenant's pipelines, by repository and workflow.
func (r *CIRunRepository) ListPipelines(ctx context.Context, tenantID shared.ID, f cirun.PipelineFilter) ([]cirun.Pipeline, error) {
	args := []any{tenantID.String()}
	where := []string{"tenant_id = $1"}
	if f.RepositoryAssetID != nil {
		args = append(args, f.RepositoryAssetID.String())
		where = append(where, fmt.Sprintf("repository_asset_id = $%d", len(args)))
	}
	if f.TrustConfigID != nil {
		args = append(args, f.TrustConfigID.String())
		where = append(where, fmt.Sprintf("trust_config_id = $%d", len(args)))
	}
	if f.Provider != "" {
		args = append(args, f.Provider)
		where = append(where, fmt.Sprintf("provider = $%d", len(args)))
	}
	var cond string
	cond, args = dataScopeCond("repository_asset_id", f.DataScope, args)
	where = append(where, cond)
	args = append(args, cirun.MaxListedPipelines)
	rows, err := r.db.QueryContext(ctx, `SELECT `+ciPipelineColumns+` FROM ci_pipelines WHERE `+
		strings.Join(where, " AND ")+fmt.Sprintf(` ORDER BY repository_name, workflow_path, id LIMIT $%d`, len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []cirun.Pipeline{}
	for rows.Next() {
		p, err := scanCIPipeline(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PipelineBranches summarizes the pipeline's non-fork runs per branch.
func (r *CIRunRepository) PipelineBranches(ctx context.Context, tenantID, pipelineID shared.ID) ([]cirun.PipelineBranch, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT branch, bool_or(is_default_branch), count(*)::int, max(created_at),
		(array_agg(verdict ORDER BY created_at DESC) FILTER (WHERE verdict IS NOT NULL))[1]
		FROM ci_runs WHERE tenant_id = $1 AND pipeline_id = $2 AND NOT fork
		GROUP BY branch ORDER BY bool_or(is_default_branch) DESC, max(created_at) DESC LIMIT $3`,
		tenantID.String(), pipelineID.String(), cirun.MaxPipelineBranches)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []cirun.PipelineBranch{}
	for rows.Next() {
		var b cirun.PipelineBranch
		var verdict sql.NullString
		if err := rows.Scan(&b.Branch, &b.IsDefaultBranch, &b.Runs, &b.LastRunAt, &verdict); err != nil {
			return nil, err
		}
		b.LastVerdict = verdict.String
		out = append(out, b)
	}
	return out, rows.Err()
}

// PipelineGateTrend returns the newest evaluated default-branch runs.
func (r *CIRunRepository) PipelineGateTrend(ctx context.Context, tenantID, pipelineID shared.ID, limit int) ([]cirun.GatePoint, error) {
	if limit <= 0 || limit > 100 {
		limit = 30
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id, verdict, commit_sha, evaluated_at FROM ci_runs
		WHERE tenant_id = $1 AND pipeline_id = $2 AND NOT fork AND is_default_branch AND verdict IS NOT NULL
		ORDER BY evaluated_at DESC, id DESC LIMIT $3`, tenantID.String(), pipelineID.String(), limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []cirun.GatePoint{}
	for rows.Next() {
		var g cirun.GatePoint
		var id string
		if err := rows.Scan(&id, &g.Verdict, &g.CommitSHA, &g.EvaluatedAt); err != nil {
			return nil, err
		}
		g.RunID, _ = shared.IDFromString(id)
		out = append(out, g)
	}
	return out, rows.Err()
}

// RevokeTrustConfigPipelines revokes the configuration's pipelines and the
// upload tokens of its running runs, in one transaction.
func (r *CIRunRepository) RevokeTrustConfigPipelines(ctx context.Context, tenantID, trustConfigID shared.ID, at time.Time) (int64, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE ci_pipelines SET revoked_at = $3, updated_at = NOW()
		WHERE tenant_id = $1 AND trust_config_id = $2 AND revoked_at IS NULL`,
		tenantID.String(), trustConfigID.String(), at)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if _, err := tx.ExecContext(ctx, `UPDATE ci_runs SET token_hash = NULL, token_expires_at = NULL, updated_at = NOW()
		WHERE tenant_id = $1 AND trust_config_id = $2 AND status = 'running' AND token_hash IS NOT NULL`,
		tenantID.String(), trustConfigID.String()); err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

// RecordRunOutcome stores the scanner failures the runner reported.
func (r *CIRunRepository) RecordRunOutcome(ctx context.Context, tenantID, runID shared.ID, scanFailures int) error {
	res, err := r.db.ExecContext(ctx, `UPDATE ci_runs SET scan_failures = $3, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), runID.String(), max(scanFailures, 0))
	if err != nil {
		return err
	}
	return requireOneRow(res, cirun.ErrRunNotFound)
}

// RecordRunTools merges tool labels into the run's, under a row lock.
func (r *CIRunRepository) RecordRunTools(ctx context.Context, tenantID, runID shared.ID, tools []cirun.ToolLabel) error {
	if len(tools) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var current []byte
	if err := tx.QueryRowContext(ctx, `SELECT tools FROM ci_runs WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
		tenantID.String(), runID.String()).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return cirun.ErrRunNotFound
		}
		return err
	}
	merged := cirun.SanitizeTools(append(decodeToolLabels(current), tools...))
	b, err := json.Marshal(merged)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE ci_runs SET tools = $3, updated_at = NOW() WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), runID.String(), b); err != nil {
		return err
	}
	return tx.Commit()
}
