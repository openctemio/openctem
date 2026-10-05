package postgres

// CI coverage, alerts and stale sources (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md
// §10.6, migration 001086). Every query is tenant-scoped except
// PipelineTenantsForPlatform (the alert job's tenant list).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ cirun.CoverageRepository = (*CIRunRepository)(nil)

// repositoryCapabilities are the tool capabilities coverage counts.
const repositoryCapabilities = `('sast', 'sca', 'secrets', 'iac')`

// ListRepositories returns the tenant's repository assets within a data
// scope, by name, at most limit.
func (r *CIRunRepository) ListRepositories(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, limit int) ([]cirun.RepositoryRef, error) {
	args := []any{tenantID.String()}
	var cond string
	cond, args = dataScopeCond("a.id", scope, args)
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, `SELECT a.id, a.name, a.criticality FROM assets a
		WHERE a.tenant_id = $1 AND a.asset_type = 'repository' AND a.deleted_at IS NULL AND `+cond+
		fmt.Sprintf(` ORDER BY a.name, a.id LIMIT $%d`, len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []cirun.RepositoryRef{}
	for rows.Next() {
		var ref cirun.RepositoryRef
		var id string
		if err := rows.Scan(&id, &ref.Name, &ref.Criticality); err != nil {
			return nil, err
		}
		ref.ID, _ = shared.IDFromString(id)
		out = append(out, ref)
	}
	return out, rows.Err()
}

// CoverageObservations returns, per repository and capability, the newest
// observation by a pipeline (non-fork default-branch runs, through the tools
// they reported) and by a daemon scan (completed scan sessions), since a
// time. A tool's capabilities come from the tool catalog (platform tools and
// the tenant's own).
func (r *CIRunRepository) CoverageObservations(ctx context.Context, tenantID shared.ID, since time.Time) ([]cirun.CoverageObservation, error) {
	out := []cirun.CoverageObservation{}
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT ON (r.repository_asset_id, cap.c) r.repository_asset_id, cap.c, r.created_at, r.pipeline_id,
			p.workflow_path
		FROM ci_runs r
		JOIN ci_pipelines p ON p.tenant_id = r.tenant_id AND p.id = r.pipeline_id
		CROSS JOIN LATERAL jsonb_array_elements(r.tools) AS tl(t)
		JOIN tools tt ON lower(tt.name) = lower(tl.t->>'name') AND (tt.tenant_id IS NULL OR tt.tenant_id = r.tenant_id)
		CROSS JOIN LATERAL unnest(tt.capabilities) AS cap(c)
		WHERE r.tenant_id = $1 AND NOT r.fork AND r.is_default_branch AND r.created_at >= $2
		  AND cap.c IN `+repositoryCapabilities+`
		ORDER BY r.repository_asset_id, cap.c, r.created_at DESC`, tenantID.String(), since)
	if err != nil {
		return nil, fmt.Errorf("pipeline observations: %w", err)
	}
	for rows.Next() {
		var o cirun.CoverageObservation
		var asset, capability, pipeline string
		if err := rows.Scan(&asset, &capability, &o.At, &pipeline, &o.SourceName); err != nil {
			_ = rows.Close()
			return nil, err
		}
		o.RepositoryAssetID, _ = shared.IDFromString(asset)
		o.Capability = cirun.Capability(capability)
		o.SourceKind = cirun.SourcePipeline
		if id, err := shared.IDFromString(pipeline); err == nil {
			o.PipelineID = &id
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()

	rows, err = r.db.QueryContext(ctx, `
		SELECT DISTINCT ON (s.asset_id, cap.c) s.asset_id, cap.c, s.completed_at, s.scanner_name
		FROM scan_sessions s
		JOIN assets a ON a.tenant_id = s.tenant_id AND a.id = s.asset_id AND a.asset_type = 'repository'
		JOIN tools tt ON lower(tt.name) = lower(s.scanner_name) AND (tt.tenant_id IS NULL OR tt.tenant_id = s.tenant_id)
		CROSS JOIN LATERAL unnest(tt.capabilities) AS cap(c)
		WHERE s.tenant_id = $1 AND s.status = 'completed' AND s.asset_id IS NOT NULL AND s.completed_at >= $2
		  AND cap.c IN `+repositoryCapabilities+`
		ORDER BY s.asset_id, cap.c, s.completed_at DESC`, tenantID.String(), since)
	if err != nil {
		return nil, fmt.Errorf("scan observations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var o cirun.CoverageObservation
		var asset, capability string
		if err := rows.Scan(&asset, &capability, &o.At, &o.SourceName); err != nil {
			return nil, err
		}
		o.RepositoryAssetID, _ = shared.IDFromString(asset)
		o.Capability = cirun.Capability(capability)
		o.SourceKind = cirun.SourceScan
		out = append(out, o)
	}
	return out, rows.Err()
}

// ListExpectations returns the tenant's expected repositories.
func (r *CIRunRepository) ListExpectations(ctx context.Context, tenantID shared.ID) (map[shared.ID]cirun.Expectation, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT repository_asset_id, capabilities, created_by, created_at, updated_at
		FROM ci_coverage_expectations WHERE tenant_id = $1`, tenantID.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[shared.ID]cirun.Expectation{}
	for rows.Next() {
		var e cirun.Expectation
		var asset string
		var caps []string
		var by sql.NullString
		if err := rows.Scan(&asset, pq.Array(&caps), &by, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		e.TenantID = tenantID
		e.RepositoryAssetID, _ = shared.IDFromString(asset)
		for _, c := range caps {
			e.Capabilities = append(e.Capabilities, cirun.Capability(c))
		}
		e.CreatedBy = parseOptID(by)
		out[e.RepositoryAssetID] = e
	}
	return out, rows.Err()
}

// UpsertExpectation marks a repository as expected (or changes its
// capabilities).
func (r *CIRunRepository) UpsertExpectation(ctx context.Context, e *cirun.Expectation) error {
	caps := make([]string, 0, len(e.Capabilities))
	for _, c := range e.Capabilities {
		caps = append(caps, string(c))
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO ci_coverage_expectations (tenant_id, repository_asset_id, capabilities,
		created_by, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $5)
		ON CONFLICT (tenant_id, repository_asset_id) DO UPDATE SET capabilities = EXCLUDED.capabilities, updated_at = EXCLUDED.updated_at`,
		e.TenantID.String(), e.RepositoryAssetID.String(), pq.Array(caps), nullID(e.CreatedBy), e.UpdatedAt)
	return err
}

// DeleteExpectation removes a repository's expectation.
func (r *CIRunRepository) DeleteExpectation(ctx context.Context, tenantID, assetID shared.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM ci_coverage_expectations WHERE tenant_id = $1 AND repository_asset_id = $2`,
		tenantID.String(), assetID.String())
	if err != nil {
		return err
	}
	return requireOneRow(res, cirun.ErrExpectationNotFound)
}

// RepositoryExists reports whether the asset is one of the tenant's
// repositories.
func (r *CIRunRepository) RepositoryExists(ctx context.Context, tenantID, assetID shared.ID) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM assets WHERE tenant_id = $1 AND id = $2
		AND asset_type = 'repository' AND deleted_at IS NULL)`, tenantID.String(), assetID.String()).Scan(&ok)
	return ok, err
}

// ListAlertState returns the alerts firing for the tenant.
func (r *CIRunRepository) ListAlertState(ctx context.Context, tenantID shared.ID) ([]cirun.AlertState, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT subject_id, kind, fired_at FROM ci_alert_state WHERE tenant_id = $1`,
		tenantID.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []cirun.AlertState{}
	for rows.Next() {
		var s cirun.AlertState
		var subject, kind string
		if err := rows.Scan(&subject, &kind, &s.FiredAt); err != nil {
			return nil, err
		}
		s.SubjectID, _ = shared.IDFromString(subject)
		s.Kind = cirun.AlertKind(kind)
		out = append(out, s)
	}
	return out, rows.Err()
}

// FireAlert records an alert; false when it was already firing (no new
// notification).
func (r *CIRunRepository) FireAlert(ctx context.Context, tenantID shared.ID, a cirun.Alert, at time.Time) (bool, error) {
	detail, err := json.Marshal(a.Detail)
	if err != nil || a.Detail == nil {
		detail = []byte(`{}`)
	}
	res, err := r.db.ExecContext(ctx, `INSERT INTO ci_alert_state (tenant_id, subject_id, kind, fired_at, detail)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
		tenantID.String(), a.SubjectID.String(), string(a.Kind), at, detail)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// ClearAlert ends a firing alert (its condition no longer holds).
func (r *CIRunRepository) ClearAlert(ctx context.Context, tenantID, subjectID shared.ID, kind cirun.AlertKind) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM ci_alert_state WHERE tenant_id = $1 AND subject_id = $2 AND kind = $3`,
		tenantID.String(), subjectID.String(), string(kind))
	return err
}

// PipelineTenantsForPlatform lists the tenants that have CI pipelines (the
// alert job walks them one by one; every later query is tenant-scoped).
func (r *CIRunRepository) PipelineTenantsForPlatform(ctx context.Context) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT tenant_id FROM ci_pipelines`)
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

// soleSourceFindings selects the open findings on the pipeline's repository
// that only this pipeline reported: its runs sighted the fingerprint, no
// other pipeline did in the coverage window, and nothing saw the finding
// after the pipeline's last run (another source would have moved
// last_seen_at). Findings from people (pentest, manual, bug bounty, red team)
// are never touched. $1 tenant, $2 pipeline, $3 asset, $4 last run (nullable).
const soleSourceFindings = `
	f.tenant_id = $1 AND f.asset_id = $3
	AND f.source NOT IN ` + coverageProtectedSources + `
	AND EXISTS (SELECT 1 FROM ci_run_findings rf JOIN ci_runs r ON r.tenant_id = rf.tenant_id AND r.id = rf.run_id
		WHERE rf.tenant_id = $1 AND rf.fingerprint = f.fingerprint AND r.pipeline_id = $2)
	AND NOT EXISTS (SELECT 1 FROM ci_run_findings rf JOIN ci_runs r ON r.tenant_id = rf.tenant_id AND r.id = rf.run_id
		WHERE rf.tenant_id = $1 AND rf.fingerprint = f.fingerprint AND r.pipeline_id IS DISTINCT FROM $2
		  AND r.created_at >= NOW() - interval '90 days')
	AND ($4::timestamptz IS NULL OR f.last_seen_at IS NULL OR f.last_seen_at <= $4::timestamptz + interval '1 hour')`

func scanIDs(rows *sql.Rows) ([]shared.ID, error) {
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

// MarkStaleSourceFindings moves the open findings only this (stale or
// archived) pipeline reported to not_observed with the reason
// "source_stale": not fixed, not current. A sighting reopens them.
func (r *CIRunRepository) MarkStaleSourceFindings(ctx context.Context, tenantID shared.ID, p *cirun.Pipeline) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `UPDATE findings f SET status = 'not_observed', resolution = 'source_stale',
		resolution_method = NULL, resolved_at = NULL, resolved_by = NULL, updated_at = NOW()
		WHERE `+soleSourceFindings+` AND f.status IN `+coverageOpenStatuses+`
		RETURNING f.id::text`, tenantID.String(), p.ID.String(), p.RepositoryAssetID.String(), p.LastRunAt)
	if err != nil {
		return nil, fmt.Errorf("mark stale-source findings: %w", err)
	}
	return scanIDs(rows)
}

// RetirePipeline retires a pipeline and closes the open findings only it
// reported as "source_retired", in one transaction. Returns the pipeline as
// it was and the closed finding ids.
func (r *CIRunRepository) RetirePipeline(ctx context.Context, tenantID, pipelineID shared.ID, by *shared.ID, reason string, at time.Time) (*cirun.Pipeline, []shared.ID, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback() }()
	p, err := scanCIPipeline(tx.QueryRowContext(ctx, `SELECT `+ciPipelineColumns+` FROM ci_pipelines
		WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID.String(), pipelineID.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, cirun.ErrPipelineNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	if p.RetiredAt != nil {
		return nil, nil, cirun.ErrPipelineRetired
	}
	if _, err := tx.ExecContext(ctx, `UPDATE ci_pipelines SET retired_at = $3, retired_by = $4, retire_reason = $5,
		updated_at = NOW() WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), pipelineID.String(), at, nullID(by), reason); err != nil {
		return nil, nil, err
	}
	rows, err := tx.QueryContext(ctx, `UPDATE findings f SET status = 'resolved', resolution = 'source_retired',
		resolution_method = 'source_retired', resolved_at = $5, resolved_by = $6, updated_at = NOW()
		WHERE `+soleSourceFindings+` AND (f.status IN `+coverageOpenStatuses+` OR f.status = 'not_observed')
		RETURNING f.id::text`, tenantID.String(), pipelineID.String(), p.RepositoryAssetID.String(), p.LastRunAt, at, nullID(by))
	if err != nil {
		return nil, nil, fmt.Errorf("close retired-source findings: %w", err)
	}
	ids, err := scanIDs(rows)
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	return &p, ids, nil
}
