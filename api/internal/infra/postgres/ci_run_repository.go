package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CIRunRepository stores CI trust configurations, runs, gate policies and
// overrides (RFC-051, migration 001077). Every query is tenant-scoped except
// the upload-token lookup (the token is the credential) and the OIDC replay
// table (global by design).
type CIRunRepository struct {
	db         *DB
	planLimits // ci_trusts
}

var _ cirun.Repository = (*CIRunRepository)(nil)

// NewCIRunRepository creates the repository.
func NewCIRunRepository(db *DB) *CIRunRepository { return &CIRunRepository{db: db} }

type ciScanner interface{ Scan(...any) error }

func parseOptID(ns sql.NullString) *shared.ID {
	if !ns.Valid {
		return nil
	}
	id, err := shared.IDFromString(ns.String)
	if err != nil {
		return nil
	}
	return &id
}

func optTime(nt sql.NullTime) *time.Time {
	if !nt.Valid {
		return nil
	}
	t := nt.Time
	return &t
}

// ---------------------------------------------------------------- trust ---

const ciTrustColumns = `id, tenant_id, name, provider, issuer, audience, rules, default_branch, enabled,
	created_by, last_used_at, created_at, updated_at, COALESCE(legacy_audience, ''), legacy_audience_until, manage_scope`

func scanCITrust(row ciScanner) (cirun.TrustConfig, error) {
	var (
		c              cirun.TrustConfig
		id, tid, prov  string
		rules          []byte
		createdBy      sql.NullString
		lastUsed       sql.NullTime
		createdAt, upd time.Time
		legacyUntil    sql.NullTime
	)
	if err := row.Scan(&id, &tid, &c.Name, &prov, &c.Issuer, &c.Audience, &rules, &c.DefaultBranch, &c.Enabled,
		&createdBy, &lastUsed, &createdAt, &upd, &c.LegacyAudience, &legacyUntil, &c.ManageScope); err != nil {
		return c, err
	}
	c.LegacyAudienceUntil = optTime(legacyUntil)
	c.ID, _ = shared.IDFromString(id)
	c.TenantID, _ = shared.IDFromString(tid)
	c.Provider = cirun.Provider(prov)
	if len(rules) > 0 {
		if err := json.Unmarshal(rules, &c.Rules); err != nil {
			return c, fmt.Errorf("decode trust rules: %w", err)
		}
	}
	c.CreatedBy = parseOptID(createdBy)
	c.LastUsedAt = optTime(lastUsed)
	c.CreatedAt, c.UpdatedAt = createdAt, upd
	return c, nil
}

// CreateTrustConfig inserts a configuration.
func (r *CIRunRepository) CreateTrustConfig(ctx context.Context, c *cirun.TrustConfig) error {
	if err := r.checkLimit(ctx, c.TenantID, plan.CITrusts, 1); err != nil {
		return err
	}
	rules, err := json.Marshal(c.Rules)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO ci_trust_configs
		(id, tenant_id, name, provider, issuer, audience, rules, default_branch, enabled, created_by, created_at, updated_at, manage_scope)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11, $12)`,
		c.ID.String(), c.TenantID.String(), c.Name, string(c.Provider), c.Issuer, c.Audience, rules,
		c.DefaultBranch, c.Enabled, nullID(c.CreatedBy), c.CreatedAt, c.ManageScope)
	if isUniqueViolation(err) {
		return cirun.ErrTrustConfigExists
	}
	return err
}

// UpdateTrustConfig changes a configuration of the tenant.
func (r *CIRunRepository) UpdateTrustConfig(ctx context.Context, c *cirun.TrustConfig) error {
	rules, err := json.Marshal(c.Rules)
	if err != nil {
		return err
	}
	res, err := r.db.ExecContext(ctx, `UPDATE ci_trust_configs
		SET name = $3, issuer = $4, audience = $5::text, rules = $6, default_branch = $7, enabled = $8, manage_scope = $9, updated_at = NOW(),
			-- A changed audience withdraws the trust: no legacy audience survives it.
			legacy_audience = CASE WHEN audience = $5::text THEN legacy_audience END,
			legacy_audience_until = CASE WHEN audience = $5::text THEN legacy_audience_until END
		WHERE tenant_id = $1 AND id = $2`,
		c.TenantID.String(), c.ID.String(), c.Name, c.Issuer, c.Audience, rules, c.DefaultBranch, c.Enabled, c.ManageScope)
	if isUniqueViolation(err) {
		return cirun.ErrTrustConfigExists
	}
	if err != nil {
		return err
	}
	return requireOneRow(res, cirun.ErrTrustConfigNotFound)
}

// TrustConfigTenants lists the tenants that have trust configurations
// (the CI trust scope backfill walks them one by one).
func (r *CIRunRepository) TrustConfigTenants(ctx context.Context) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT tenant_id FROM ci_trust_configs ORDER BY tenant_id`)
	if err != nil {
		return nil, fmt.Errorf("list trust configuration tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if tid, err := shared.IDFromString(id); err == nil {
			out = append(out, tid)
		}
	}
	return out, rows.Err()
}

// DeleteTrustConfig removes a configuration of the tenant. Its runs stay.
func (r *CIRunRepository) DeleteTrustConfig(ctx context.Context, tenantID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM ci_trust_configs WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String())
	if err != nil {
		return err
	}
	return requireOneRow(res, cirun.ErrTrustConfigNotFound)
}

// GetTrustConfig returns one configuration of the tenant.
func (r *CIRunRepository) GetTrustConfig(ctx context.Context, tenantID, id shared.ID) (*cirun.TrustConfig, error) {
	c, err := scanCITrust(r.db.QueryRowContext(ctx, `SELECT `+ciTrustColumns+`
		FROM ci_trust_configs WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, cirun.ErrTrustConfigNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ListTrustConfigs returns the tenant's configurations, by name.
func (r *CIRunRepository) ListTrustConfigs(ctx context.Context, tenantID shared.ID) ([]cirun.TrustConfig, error) {
	return r.queryTrust(ctx, `SELECT `+ciTrustColumns+` FROM ci_trust_configs
		WHERE tenant_id = $1 ORDER BY name LIMIT 500`, tenantID.String())
}

// EnabledTrustConfigs returns the tenant's enabled configurations for an issuer.
func (r *CIRunRepository) EnabledTrustConfigs(ctx context.Context, tenantID shared.ID, issuer string) ([]cirun.TrustConfig, error) {
	return r.queryTrust(ctx, `SELECT `+ciTrustColumns+` FROM ci_trust_configs
		WHERE tenant_id = $1 AND issuer = $2 AND enabled ORDER BY created_at LIMIT 100`, tenantID.String(), issuer)
}

func (r *CIRunRepository) queryTrust(ctx context.Context, q string, args ...any) ([]cirun.TrustConfig, error) {
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []cirun.TrustConfig{}
	for rows.Next() {
		c, err := scanCITrust(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// PipelineAudienceState reports whether the pipeline with the key exists and
// whether it has exchanged a token with its configuration's current
// audience (ci_pipelines.audience_upgraded_at).
func (r *CIRunRepository) PipelineAudienceState(ctx context.Context, tenantID shared.ID, key cirun.PipelineKey) (exists, upgraded bool, err error) {
	var at sql.NullTime
	err = r.db.QueryRowContext(ctx, `SELECT audience_upgraded_at FROM ci_pipelines
		WHERE tenant_id = $1 AND provider = $2 AND issuer = $3 AND external_repo_id = $4 AND workflow_path = $5`,
		tenantID.String(), string(key.Provider), key.Issuer, key.ExternalRepoID, key.WorkflowPath).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	return true, at.Valid, nil
}

// MarkPipelineAudienceUpgraded records that the pipeline exchanged a token
// with its configuration's current audience: its legacy audience is refused
// from now on.
func (r *CIRunRepository) MarkPipelineAudienceUpgraded(ctx context.Context, tenantID shared.ID, key cirun.PipelineKey, at time.Time) error {
	_, err := r.db.ExecContext(ctx, `UPDATE ci_pipelines SET audience_upgraded_at = $6
		WHERE tenant_id = $1 AND provider = $2 AND issuer = $3 AND external_repo_id = $4 AND workflow_path = $5
		  AND audience_upgraded_at IS NULL`,
		tenantID.String(), string(key.Provider), key.Issuer, key.ExternalRepoID, key.WorkflowPath, at)
	return err
}

// TouchTrustConfig records the configuration's last use.
func (r *CIRunRepository) TouchTrustConfig(ctx context.Context, tenantID, id shared.ID, at time.Time) error {
	_, err := r.db.ExecContext(ctx, `UPDATE ci_trust_configs SET last_used_at = $3 WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String(), at)
	return err
}

// --------------------------------------------------------------- replay ---

// ClaimReplay records a token's first exchange; when the token id was
// claimed before it returns the earlier record.
func (r *CIRunRepository) ClaimReplay(ctx context.Context, rp cirun.Replay) (bool, *cirun.Replay, error) {
	res, err := r.db.ExecContext(ctx, `INSERT INTO ci_oidc_replay (issuer, jti, expires_at, tenant_id, token_sha256, run_id)
		VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (issuer, jti) DO NOTHING`,
		rp.Issuer, rp.JTI, rp.ExpiresAt, nullID(rp.TenantID), rp.TokenSHA256, nullID(rp.RunID))
	if err != nil {
		return false, nil, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, nil, err
	}
	if n == 1 {
		return true, nil, nil
	}
	prior, err := scanReplay(r.db.QueryRowContext(ctx, `SELECT `+replayColumns+` FROM ci_oidc_replay
		WHERE issuer = $1 AND jti = $2`, rp.Issuer, rp.JTI))
	if errors.Is(err, sql.ErrNoRows) {
		// Purged between the insert and the read: a replay all the same.
		return false, &cirun.Replay{Issuer: rp.Issuer, JTI: rp.JTI}, nil
	}
	if err != nil {
		return false, nil, err
	}
	return false, prior, nil
}

// ReuseReplay counts one more exchange of the same token, atomically, while
// it is under max.
func (r *CIRunRepository) ReuseReplay(ctx context.Context, issuer, jti string, tenantID shared.ID, digest []byte, max int) (*cirun.Replay, error) {
	rp, err := scanReplay(r.db.QueryRowContext(ctx, `UPDATE ci_oidc_replay SET exchanges = exchanges + 1
		WHERE issuer = $1 AND jti = $2 AND tenant_id = $3 AND token_sha256 = $4 AND exchanges < $5
		RETURNING `+replayColumns, issuer, jti, tenantID.String(), digest, max))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return rp, err
}

// BindReplayRun records the run a token's exchange produced.
func (r *CIRunRepository) BindReplayRun(ctx context.Context, issuer, jti string, tenantID, runID shared.ID) error {
	_, err := r.db.ExecContext(ctx, `UPDATE ci_oidc_replay SET run_id = $4
		WHERE issuer = $1 AND jti = $2 AND tenant_id = $3 AND (run_id IS NULL OR run_id = $4)`,
		issuer, jti, tenantID.String(), runID.String())
	return err
}

const replayColumns = `issuer, jti, tenant_id, token_sha256, run_id, exchanges, first_at, expires_at`

func scanReplay(row *sql.Row) (*cirun.Replay, error) {
	var rp cirun.Replay
	var tenant, run sql.NullString
	if err := row.Scan(&rp.Issuer, &rp.JTI, &tenant, &rp.TokenSHA256, &run, &rp.Exchanges, &rp.FirstAt, &rp.ExpiresAt); err != nil {
		return nil, err
	}
	if id, err := shared.IDFromString(tenant.String); tenant.Valid && err == nil {
		rp.TenantID = &id
	}
	if id, err := shared.IDFromString(run.String); run.Valid && err == nil {
		rp.RunID = &id
	}
	return &rp, nil
}

// PurgeExpiredJTIs drops token ids that expired before the given time.
func (r *CIRunRepository) PurgeExpiredJTIs(ctx context.Context, before time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM ci_oidc_replay WHERE expires_at < $1`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CIRequireOIDC reads the tenant's "OIDC required for CI" setting.
func (r *CIRunRepository) CIRequireOIDC(ctx context.Context, tenantID shared.ID) (bool, error) {
	var v bool
	err := r.db.QueryRowContext(ctx, `SELECT ci_require_oidc FROM tenants WHERE id = $1`, tenantID.String()).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return false, shared.ErrNotFound
	}
	return v, err
}

// SetCIRequireOIDC writes the tenant's "OIDC required for CI" setting.
func (r *CIRunRepository) SetCIRequireOIDC(ctx context.Context, tenantID shared.ID, require bool) error {
	res, err := r.db.ExecContext(ctx, `UPDATE tenants SET ci_require_oidc = $2 WHERE id = $1`, tenantID.String(), require)
	if err != nil {
		return err
	}
	return requireOneRow(res, shared.ErrNotFound)
}

// ----------------------------------------------------------------- runs ---

const ciRunColumns = `id, tenant_id, trust_config_id, repository_asset_id, provider, issuer, repository, ref, branch,
	commit_sha, pull_request, default_branch, is_default_branch, event, environment, actor, external_run_id,
	run_attempt, workflow, pipeline_url, fork, token_expires_at, status, verdict, verdict_detail, evaluated_at,
	reports_count, findings_count, pipeline_id, sensor_version, scan_failures, tools, template_ref, created_at, updated_at,
	external_job_id, aggregate, commit_verified, base_ref, decoration_state, decoration_detail, carried_scan_failures,
	carried_failed_capabilities`

func scanCIRun(row ciScanner) (cirun.Run, error) {
	var (
		run                  cirun.Run
		id, tid, asset, prov string
		trust, verdict       sql.NullString
		pipeline             sql.NullString
		tokenExp, evaluated  sql.NullTime
		detail, tools        []byte
		failures             sql.NullInt64
	)
	if err := row.Scan(&id, &tid, &trust, &asset, &prov, &run.Issuer, &run.Repository, &run.Ref, &run.Branch,
		&run.CommitSHA, &run.PullRequest, &run.DefaultBranch, &run.IsDefaultBranch, &run.Event, &run.Environment,
		&run.Actor, &run.ExternalRunID, &run.RunAttempt, &run.Workflow, &run.PipelineURL, &run.Fork, &tokenExp,
		&run.Status, &verdict, &detail, &evaluated, &run.ReportsCount, &run.FindingsCount, &pipeline,
		&run.SensorVersion, &failures, &tools, &run.TemplateRef, &run.CreatedAt, &run.UpdatedAt,
		&run.ExternalJobID, &run.Aggregate, &run.CommitVerified, &run.BaseRef, &run.DecorationState, &run.DecorationDetail, &run.CarriedScanFailures,
		pq.Array(&run.CarriedFailedCapabilities)); err != nil {
		return run, err
	}
	run.ID, _ = shared.IDFromString(id)
	run.TenantID, _ = shared.IDFromString(tid)
	run.RepositoryAssetID, _ = shared.IDFromString(asset)
	run.TrustConfigID = parseOptID(trust)
	run.Provider = cirun.Provider(prov)
	run.TokenExpiresAt = optTime(tokenExp)
	run.Verdict = verdict.String
	if len(detail) > 0 {
		run.VerdictDetail = json.RawMessage(detail)
	}
	run.EvaluatedAt = optTime(evaluated)
	run.PipelineID = parseOptID(pipeline)
	if failures.Valid {
		n := int(failures.Int64)
		run.ScanFailures = &n
	}
	run.Tools = decodeToolLabels(tools)
	return run, nil
}

// CreateRun inserts a run with its upload token hash.
func (r *CIRunRepository) CreateRun(ctx context.Context, run *cirun.Run) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO ci_runs (id, tenant_id, trust_config_id, repository_asset_id,
		provider, issuer, repository, ref, branch, commit_sha, pull_request, default_branch, is_default_branch, event,
		environment, actor, external_run_id, run_attempt, workflow, pipeline_url, fork, token_hash, token_expires_at,
		status, created_at, updated_at, pipeline_id, sensor_version, template_ref, external_job_id, aggregate, commit_verified,
		base_ref)
		VALUES (`+ciRunInsertValues+`)`, ciRunInsertArgs(run)...)
	return err
}

// ciRunInsertValues are the placeholders of ciRunInsertArgs ($25 is both
// created_at and updated_at).
const ciRunInsertValues = `$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
	$20, $21, $22, $23, $24, $25, $25, $26, $27, $28, $29, $30, $31, $32`

func ciRunInsertArgs(run *cirun.Run) []any {
	return []any{run.ID.String(), run.TenantID.String(), nullID(run.TrustConfigID), run.RepositoryAssetID.String(),
		string(run.Provider), run.Issuer, run.Repository, run.Ref, run.Branch, run.CommitSHA, run.PullRequest,
		run.DefaultBranch, run.IsDefaultBranch, run.Event, run.Environment, run.Actor, run.ExternalRunID,
		run.RunAttempt, run.Workflow, run.PipelineURL, run.Fork, run.TokenHash, run.TokenExpiresAt,
		run.Status, run.CreatedAt, nullID(run.PipelineID), run.SensorVersion, run.TemplateRef, run.ExternalJobID,
		run.Aggregate, run.CommitVerified, run.BaseRef}
}

// OpenAggregateRun returns the aggregate run of the run's pipeline run (same
// pipeline, external run id and commit, whatever the attempt), creating it
// from run when there is none. Every job, retry and re-run attempt reports
// into it: an attempt that finds it evaluated re-opens it (running again,
// the attempt recorded, the verdict's scanner failures carried until a new
// report arrives), so a re-run of only the gate job is judged on the
// evidence already uploaded, never on an empty run. Two jobs racing here get
// the same run: the second insert conflicts on idx_ci_runs_pipeline_run and
// reads the first. created says whether this call created it.
func (r *CIRunRepository) OpenAggregateRun(ctx context.Context, run *cirun.Run) (*cirun.Run, bool, error) {
	if !run.Aggregate || run.PipelineID == nil || run.ExternalRunID == "" {
		return nil, false, fmt.Errorf("%w: an aggregate run needs a pipeline and an external run id", shared.ErrValidation)
	}
	res, err := r.db.ExecContext(ctx, `INSERT INTO ci_runs (id, tenant_id, trust_config_id, repository_asset_id,
		provider, issuer, repository, ref, branch, commit_sha, pull_request, default_branch, is_default_branch, event,
		environment, actor, external_run_id, run_attempt, workflow, pipeline_url, fork, token_hash, token_expires_at,
		status, created_at, updated_at, pipeline_id, sensor_version, template_ref, external_job_id, aggregate, commit_verified,
		base_ref, evidence_union)
		VALUES (`+ciRunInsertValues+`, true)
		ON CONFLICT (tenant_id, pipeline_id, external_run_id, commit_sha)
		WHERE aggregate AND evidence_union DO NOTHING`, ciRunInsertArgs(run)...)
	if err != nil {
		return nil, false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, false, err
	}
	// A later attempt re-opens an evaluated run for its reports; the
	// verdict's scanner failures keep failing it until a report arrives.
	if _, err := r.db.ExecContext(ctx, `UPDATE ci_runs SET status = 'running', run_attempt = $5,
			carried_scan_failures = GREATEST(carried_scan_failures, COALESCE(scan_failures, 0)),
			carried_failed_capabilities = ARRAY(SELECT DISTINCT c FROM unnest(carried_failed_capabilities || failed_capabilities) AS c),
			updated_at = NOW()
		WHERE tenant_id = $1 AND pipeline_id = $2 AND external_run_id = $3 AND commit_sha = $4
		  AND aggregate AND evidence_union AND status = 'evaluated'`,
		run.TenantID.String(), run.PipelineID.String(), run.ExternalRunID, run.CommitSHA, run.RunAttempt); err != nil {
		return nil, false, err
	}
	open, err := scanCIRun(r.db.QueryRowContext(ctx, `SELECT `+ciRunColumns+` FROM ci_runs
		WHERE tenant_id = $1 AND pipeline_id = $2 AND external_run_id = $3 AND commit_sha = $4
		  AND aggregate AND evidence_union`, run.TenantID.String(), run.PipelineID.String(), run.ExternalRunID,
		run.CommitSHA))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, cirun.ErrRunNotFound
	}
	if err != nil {
		return nil, false, err
	}
	return &open, n == 1, nil
}

// ClearCarriedCapabilities drops the carried failed capabilities that the
// named tool provides: the report's tool name is matched against the tool
// registry (the platform's tools and the tenant's own), whose capabilities
// decide what is cleared.
func (r *CIRunRepository) ClearCarriedCapabilities(ctx context.Context, tenantID, runID shared.ID, tool string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE ci_runs r SET carried_failed_capabilities = ARRAY(
			SELECT c FROM unnest(r.carried_failed_capabilities) AS c
			WHERE NOT EXISTS (SELECT 1 FROM tools tt WHERE lower(tt.name) = lower($3)
				AND (tt.tenant_id IS NULL OR tt.tenant_id = r.tenant_id) AND c = ANY(tt.capabilities)))
		WHERE r.tenant_id = $1 AND r.id = $2 AND cardinality(r.carried_failed_capabilities) > 0`,
		tenantID.String(), runID.String(), tool)
	return err
}

// AddRunToken adds an upload token to a running run (a job of an aggregate
// run, or a re-exchange of the token that opened a run).
func (r *CIRunRepository) AddRunToken(ctx context.Context, tenantID, runID shared.ID, hash []byte, jobID string, expiresAt time.Time) error {
	res, err := r.db.ExecContext(ctx, `INSERT INTO ci_run_tokens (token_hash, tenant_id, run_id, external_job_id, expires_at)
		SELECT $3, tenant_id, id, $4, $5 FROM ci_runs
		WHERE tenant_id = $1 AND id = $2 AND status = 'running'`,
		tenantID.String(), runID.String(), hash, jobID, expiresAt)
	if err != nil {
		return err
	}
	return requireOneRow(res, cirun.ErrRunNotFound)
}

// CountPipelineRunsSince counts the runs a pipeline started since the time
// (idx_ci_runs_tenant_pipeline).
func (r *CIRunRepository) CountPipelineRunsSince(ctx context.Context, tenantID, pipelineID shared.ID, since time.Time) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM ci_runs WHERE tenant_id = $1 AND pipeline_id = $2 AND created_at > $3`,
		tenantID.String(), pipelineID.String(), since).Scan(&n)
	return n, err
}

// GetRun returns one run of the tenant.
func (r *CIRunRepository) GetRun(ctx context.Context, tenantID, id shared.ID) (*cirun.Run, error) {
	run, err := scanCIRun(r.db.QueryRowContext(ctx, `SELECT `+ciRunColumns+` FROM ci_runs
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, cirun.ErrRunNotFound
	}
	if err != nil {
		return nil, err
	}
	return &run, nil
}

// GetRunByTokenHash returns the run an unexpired upload token belongs to.
func (r *CIRunRepository) GetRunByTokenHash(ctx context.Context, hash []byte, now time.Time) (*cirun.Run, error) {
	run, err := scanCIRun(r.db.QueryRowContext(ctx, `SELECT `+ciRunColumns+` FROM ci_runs
		WHERE token_hash = $1 AND token_expires_at > $2`, hash, now))
	if errors.Is(err, sql.ErrNoRows) {
		// A job token of an aggregate run.
		run, err = scanCIRun(r.db.QueryRowContext(ctx, `SELECT `+ciRunColumns+` FROM ci_runs
			WHERE (tenant_id, id) = (SELECT tenant_id, run_id FROM ci_run_tokens WHERE token_hash = $1 AND expires_at > $2)`,
			hash, now))
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, cirun.ErrRunNotFound
	}
	if err != nil {
		return nil, err
	}
	return &run, nil
}

// RotateRunToken replaces a running run's upload token.
func (r *CIRunRepository) RotateRunToken(ctx context.Context, tenantID, runID shared.ID, hash []byte, expiresAt time.Time) error {
	res, err := r.db.ExecContext(ctx, `UPDATE ci_runs SET token_hash = $3, token_expires_at = $4, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2 AND status = 'running'`, tenantID.String(), runID.String(), hash, expiresAt)
	if err != nil {
		return err
	}
	return requireOneRow(res, cirun.ErrRunNotFound)
}

// ListRuns returns the tenant's runs, newest first, and the total.
func (r *CIRunRepository) ListRuns(ctx context.Context, tenantID shared.ID, f cirun.RunFilter) ([]cirun.Run, int, error) {
	args := []any{tenantID.String()}
	where := []string{"tenant_id = $1"}
	if f.RepositoryAssetID != nil {
		args = append(args, f.RepositoryAssetID.String())
		where = append(where, fmt.Sprintf("repository_asset_id = $%d", len(args)))
	}
	if f.PipelineID != nil {
		args = append(args, f.PipelineID.String())
		where = append(where, fmt.Sprintf("pipeline_id = $%d", len(args)))
	}
	if f.Verdict != "" {
		if f.Verdict == cirun.VerdictNone {
			where = append(where, "verdict IS NULL")
		} else {
			args = append(args, f.Verdict)
			where = append(where, fmt.Sprintf("verdict = $%d", len(args)))
		}
	}
	if f.Provider != "" {
		args = append(args, f.Provider)
		where = append(where, fmt.Sprintf("provider = $%d", len(args)))
	}
	var cond string
	cond, args = dataScopeCond("repository_asset_id", f.DataScope, args)
	where = append(where, cond)
	clause := strings.Join(where, " AND ")

	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM ci_runs WHERE `+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	perPage := f.PerPage
	if perPage <= 0 || perPage > 100 {
		perPage = 25
	}
	page := max(f.Page, 1)
	args = append(args, perPage, (page-1)*perPage)
	rows, err := r.db.QueryContext(ctx, `SELECT `+ciRunColumns+` FROM ci_runs WHERE `+clause+
		fmt.Sprintf(` ORDER BY created_at DESC, id DESC LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	out := []cirun.Run{}
	for rows.Next() {
		run, err := scanCIRun(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, run)
	}
	return out, total, rows.Err()
}

// ReserveRunReport takes a report slot of a running run in one statement,
// so concurrent uploads (or the files of one ZIP) cannot pass the cap or
// land after the verdict.
func (r *CIRunRepository) ReserveRunReport(ctx context.Context, tenantID, runID shared.ID) error {
	var n int
	err := r.db.QueryRowContext(ctx, `UPDATE ci_runs SET reports_count = reports_count + 1, carried_scan_failures = 0, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2 AND status = 'running' AND reports_count < $3
		RETURNING reports_count`, tenantID.String(), runID.String(), cirun.MaxRunReports).Scan(&n)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var status string
	if err := r.db.QueryRowContext(ctx, `SELECT status FROM ci_runs WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), runID.String()).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return cirun.ErrRunNotFound
		}
		return err
	}
	if status != string(cirun.StatusRunning) {
		return cirun.ErrRunEvaluated
	}
	return cirun.ErrRunReportCap
}

// RecordRunReport adds a report's sighted fingerprints to the run, up to
// MaxRunFindings. The report's slot was reserved (ReserveRunReport).
func (r *CIRunRepository) RecordRunReport(ctx context.Context, tenantID, runID shared.ID, fingerprints []string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// Lock the run row so concurrent reports cap correctly and a verdict
	// stored meanwhile is seen (SaveVerdict checks findings_count).
	var (
		current int
		status  string
	)
	if err := tx.QueryRowContext(ctx, `SELECT findings_count, status FROM ci_runs WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
		tenantID.String(), runID.String()).Scan(&current, &status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return cirun.ErrRunNotFound
		}
		return err
	}
	if status != string(cirun.StatusRunning) {
		return cirun.ErrRunEvaluated
	}
	overCap := false
	if room := max(cirun.MaxRunFindings-current, 0); len(fingerprints) > room {
		// Keep only what the run has not recorded yet: a report that repeats
		// sightings already recorded does not overflow the cap.
		fresh, err := unrecordedFingerprints(ctx, tx, tenantID, runID, fingerprints)
		if err != nil {
			return err
		}
		if len(fresh) > room {
			fresh, overCap = fresh[:room], true
		}
		fingerprints = fresh
	}
	added := int64(0)
	if len(fingerprints) > 0 {
		res, err := tx.ExecContext(ctx, `INSERT INTO ci_run_findings (tenant_id, run_id, fingerprint)
			SELECT $1, $2, fp FROM unnest($3::text[]) AS fp
			ON CONFLICT (run_id, fingerprint) DO NOTHING`, tenantID.String(), runID.String(), pq.Array(fingerprints))
		if err != nil {
			return err
		}
		added, _ = res.RowsAffected()
	}
	// A run past the cap is marked: the gate cannot judge what it did not
	// record, so the verdict fails (ReasonTooManyFindings) instead of
	// judging a prefix.
	if _, err := tx.ExecContext(ctx, `UPDATE ci_runs SET
		findings_count = findings_count + $3, findings_over_cap = findings_over_cap OR $4, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), runID.String(), added, overCap); err != nil {
		return err
	}
	return tx.Commit()
}

// unrecordedFingerprints returns the distinct fingerprints the run has not
// recorded yet, in their first-seen order.
func unrecordedFingerprints(ctx context.Context, tx *sql.Tx, tenantID, runID shared.ID, fingerprints []string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT fp FROM (
			SELECT fp, MIN(ord) AS ord FROM unnest($3::text[]) WITH ORDINALITY AS u(fp, ord) GROUP BY fp
		) d
		WHERE NOT EXISTS (SELECT 1 FROM ci_run_findings f
			WHERE f.tenant_id = $1 AND f.run_id = $2 AND f.fingerprint = d.fp)
		ORDER BY d.ord`, tenantID.String(), runID.String(), pq.Array(fingerprints))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, err
		}
		out = append(out, fp)
	}
	return out, rows.Err()
}

// RunFindingsOverCap reports whether the run reported more findings than
// it could record (MaxRunFindings).
func (r *CIRunRepository) RunFindingsOverCap(ctx context.Context, tenantID, runID shared.ID) (bool, error) {
	var over bool
	err := r.db.QueryRowContext(ctx, `SELECT findings_over_cap FROM ci_runs WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), runID.String()).Scan(&over)
	if errors.Is(err, sql.ErrNoRows) {
		return false, cirun.ErrRunNotFound
	}
	return over, err
}

// runFindingColumns are the columns scanRunFindings reads, from findings f.
const runFindingColumns = `f.id, f.fingerprint, COALESCE(f.title, ''), COALESCE(f.rule_id, ''),
			f.severity, f.status, COALESCE(f.finding_type, ''), COALESCE(f.source, ''), COALESCE(f.tool_name, ''),
			COALESCE(f.file_path, ''), COALESCE(f.start_line, 0),
			COALESCE(f.is_in_kev, FALSE), f.epss_score,
			COALESCE((f.remediation->>'fix_available')::boolean, FALSE),
			EXISTS (SELECT 1 FROM finding_suppressions s
				JOIN suppression_rules sr ON sr.id = s.suppression_rule_id AND sr.tenant_id = f.tenant_id
				WHERE s.finding_id = f.id AND sr.status = 'approved'
				  AND (sr.expires_at IS NULL OR sr.expires_at > NOW())),
			f.acceptance_expires_at, f.first_detected_at, f.last_reopened_at,
			NULL::boolean, COALESCE(f.secret_type, ''), COALESCE(f.type_details->'secret'->>'fingerprint', '')`

// RunFindings returns the findings on the run's asset that the run recorded.
//
// A finding counts as suppressed only through a rule that applies now:
// approved, unexpired and the tenant's own. The expiry job reopens a finding
// and keeps its link row, and a link can name a rule that was never approved,
// so the link alone must not let a finding pass the gate.
func (r *CIRunRepository) RunFindings(ctx context.Context, tenantID, runID, assetID shared.ID) ([]cirun.RunFinding, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+runFindingColumns+`
		FROM ci_run_findings rf
		JOIN findings f ON f.tenant_id = rf.tenant_id AND f.fingerprint = rf.fingerprint
		WHERE rf.tenant_id = $1 AND rf.run_id = $2 AND f.asset_id = $3
		ORDER BY f.severity, f.id
		LIMIT 100000`, tenantID.String(), runID.String(), assetID.String())
	if err != nil {
		return nil, err
	}
	return scanRunFindings(rows)
}

// FindingsByFingerprints returns the findings on assetID holding the given
// fingerprints, tenant scoped.
func (r *CIRunRepository) FindingsByFingerprints(ctx context.Context, tenantID, assetID shared.ID, fingerprints []string) ([]cirun.RunFinding, error) {
	if len(fingerprints) == 0 {
		return []cirun.RunFinding{}, nil
	}
	if len(fingerprints) > cirun.MaxRunFindings {
		fingerprints = fingerprints[:cirun.MaxRunFindings]
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+runFindingColumns+`
		FROM findings f
		WHERE f.tenant_id = $1 AND f.asset_id = $2 AND f.fingerprint = ANY($3)`,
		tenantID.String(), assetID.String(), pq.Array(fingerprints))
	if err != nil {
		return nil, err
	}
	return scanRunFindings(rows)
}

// The gate never reads findings.secret_valid: that column was written from
// the uploaded report, and a fork pull request could report a live secret as
// dead. The query selects NULL in its place until the platform records its own
// validation result.
func scanRunFindings(rows *sql.Rows) ([]cirun.RunFinding, error) {
	defer func() { _ = rows.Close() }()
	out := []cirun.RunFinding{}
	for rows.Next() {
		var (
			f                          cirun.RunFinding
			id                         string
			epss                       sql.NullFloat64
			accExp, firstDet, reopened sql.NullTime
			secretValid                sql.NullBool
		)
		if err := rows.Scan(&id, &f.Fingerprint, &f.Title, &f.RuleID, &f.Severity, &f.Status, &f.FindingType, &f.Source, &f.ToolName,
			&f.FilePath, &f.StartLine, &f.IsInKEV, &epss, &f.FixAvailable, &f.Suppressed, &accExp, &firstDet, &reopened,
			&secretValid, &f.SecretType, &f.SecretFingerprint); err != nil {
			return nil, err
		}
		f.ID, _ = shared.IDFromString(id)
		if epss.Valid {
			v := epss.Float64
			f.EPSSScore = &v
		}
		if secretValid.Valid {
			v := secretValid.Bool
			f.SecretValid = &v
		}
		f.AcceptanceExpiresAt = optTime(accExp)
		f.FirstDetectedAt = optTime(firstDet)
		f.LastReopenedAt = optTime(reopened)
		out = append(out, f)
	}
	return out, rows.Err()
}

// SaveVerdict stores the run's verdict. The first verdict is final: a run
// that is no longer running keeps the verdict it has (cirun.ErrRunEvaluated).
// A run marked over the findings cap stores only a verdict that names the
// cap (ReasonTooManyFindings): one computed before the mark is refused as
// changed and judged again.
func (r *CIRunRepository) SaveVerdict(ctx context.Context, tenantID, runID shared.ID, verdict string, detail []byte, at time.Time, expectFindings int, failedCapabilities []string) error {
	if failedCapabilities == nil {
		failedCapabilities = []string{}
	}
	// The failed capabilities are written with the verdict, in one
	// statement: a later attempt re-opening the run carries exactly the list
	// of the verdict it re-opens.
	res, err := r.db.ExecContext(ctx, `UPDATE ci_runs SET status = 'evaluated', verdict = $3, verdict_detail = $4,
		evaluated_at = $5, failed_capabilities = $7, updated_at = NOW(),`+decorationQueued+`
		WHERE tenant_id = $1 AND id = $2 AND status = 'running' AND findings_count = $6
		  AND (NOT findings_over_cap OR $4::jsonb @> '{"reasons":[{"code":"`+cirun.ReasonTooManyFindings+`"}]}')`,
		tenantID.String(), runID.String(), verdict, detail, at, expectFindings, pq.Array(failedCapabilities))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		var status string
		if err := r.db.QueryRowContext(ctx, `SELECT status FROM ci_runs WHERE tenant_id = $1 AND id = $2`,
			tenantID.String(), runID.String()).Scan(&status); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return cirun.ErrRunNotFound
			}
			return err
		}
		if status != string(cirun.StatusRunning) {
			return cirun.ErrRunEvaluated
		}
		return cirun.ErrRunChanged
	}
	return nil
}

// ------------------------------------------------------------- policies ---

// The scope id is the repository or the business unit, each its own column
// with a foreign key (migration 001144).
const ciPolicyColumns = `id, tenant_id, scope_type, COALESCE(repository_asset_id, business_unit_id), enabled, mode,
	fail_on_severity, new_findings_only, fail_on_kev, epss_threshold, created_by, updated_by, created_at, updated_at, modes, allow_repo_policy,
	fixable_only, fields, locked_fields, reason, expires_at, baseline_on_first_run, baseline_grace_days, baseline_secrets_block`

func scanCIPolicy(row ciScanner) (cirun.GatePolicy, error) {
	var (
		p                    cirun.GatePolicy
		id, tid              string
		scopeID, cby, uby    sql.NullString
		epss                 sql.NullFloat64
		createdAt, updatedAt time.Time
		modes                []byte
		expires              sql.NullTime
		grace                sql.NullInt64
	)
	if err := row.Scan(&id, &tid, &p.ScopeType, &scopeID, &p.Enabled, &p.Mode, &p.FailOnSeverity,
		&p.NewFindingsOnly, &p.FailOnKEV, &epss, &cby, &uby, &createdAt, &updatedAt, &modes, &p.AllowRepoPolicy, &p.FixableOnly,
		pq.Array(&p.Fields), pq.Array(&p.LockedFields), &p.Reason, &expires, &p.BaselineOnFirstRun, &grace, &p.BaselineSecretsBlock); err != nil {
		return p, err
	}
	if expires.Valid {
		t := expires.Time
		p.ExpiresAt = &t
	}
	if grace.Valid {
		g := int(grace.Int64)
		p.BaselineGraceDays = &g
	}
	if len(modes) > 0 {
		_ = json.Unmarshal(modes, &p.Modes)
	}
	p.ID, _ = shared.IDFromString(id)
	p.TenantID, _ = shared.IDFromString(tid)
	p.ScopeID = parseOptID(scopeID)
	if epss.Valid {
		v := epss.Float64
		p.EPSSThreshold = &v
	}
	p.CreatedBy, p.UpdatedBy = parseOptID(cby), parseOptID(uby)
	p.CreatedAt, p.UpdatedAt = createdAt, updatedAt
	return p, nil
}

// modesJSON stores a policy's modes ('{}' when none).
func modesJSON(m cirun.PolicyModes) []byte {
	b, err := json.Marshal(m)
	if err != nil || len(b) == 0 {
		return []byte("{}")
	}
	return b
}

// nonNilFields stores an empty array, never NULL.
func nonNilFields(f []string) []string {
	if f == nil {
		return []string{}
	}
	return f
}

// nullGraceDays stores the baseline grace (NULL: no end).
func nullGraceDays(v *int) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*v), Valid: true}
}

// policyExpiry stores a policy's end (NULL: none).
func policyExpiry(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

func nullFloat(v *float64) sql.NullFloat64 {
	if v == nil {
		return sql.NullFloat64{}
	}
	return sql.NullFloat64{Float64: *v, Valid: true}
}

// ListGatePolicies returns the tenant's policies.
func (r *CIRunRepository) ListGatePolicies(ctx context.Context, tenantID shared.ID) ([]cirun.GatePolicy, error) {
	return r.queryPolicies(ctx, `SELECT `+ciPolicyColumns+` FROM ci_gate_policies WHERE tenant_id = $1
		ORDER BY CASE scope_type WHEN 'tenant' THEN 0 WHEN 'business_unit' THEN 1 ELSE 2 END, created_at LIMIT 1000`,
		tenantID.String())
}

// GatePoliciesFor returns the policies, enabled or not, that may apply to an
// asset: the tenant's, its business units' and its own.
func (r *CIRunRepository) GatePoliciesFor(ctx context.Context, tenantID, assetID shared.ID) ([]cirun.GatePolicy, error) {
	return r.queryPolicies(ctx, `SELECT `+ciPolicyColumns+` FROM ci_gate_policies p
		WHERE p.tenant_id = $1 AND (
			p.scope_type = 'tenant'
			OR (p.scope_type = 'repository' AND p.repository_asset_id = $2)
			OR (p.scope_type = 'business_unit' AND p.business_unit_id IN (
				SELECT bua.business_unit_id FROM business_unit_assets bua
				WHERE bua.tenant_id = $1 AND bua.asset_id = $2)))
		LIMIT 100`, tenantID.String(), assetID.String())
}

func (r *CIRunRepository) queryPolicies(ctx context.Context, q string, args ...any) ([]cirun.GatePolicy, error) {
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []cirun.GatePolicy{}
	for rows.Next() {
		p, err := scanCIPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetGatePolicy returns one policy of the tenant.
func (r *CIRunRepository) GetGatePolicy(ctx context.Context, tenantID, id shared.ID) (*cirun.GatePolicy, error) {
	p, err := scanCIPolicy(r.db.QueryRowContext(ctx, `SELECT `+ciPolicyColumns+` FROM ci_gate_policies
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, cirun.ErrPolicyNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// CreateGatePolicy inserts a policy; one per scope.
func (r *CIRunRepository) CreateGatePolicy(ctx context.Context, p *cirun.GatePolicy) error {
	var repoID, unitID *shared.ID
	switch p.ScopeType {
	case cirun.ScopeRepository:
		repoID = p.ScopeID
	case cirun.ScopeBusinessUnit:
		unitID = p.ScopeID
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO ci_gate_policies (id, tenant_id, scope_type, repository_asset_id,
		business_unit_id, enabled, mode, fail_on_severity, new_findings_only, fail_on_kev, epss_threshold, created_by,
		updated_by, created_at, updated_at, modes, allow_repo_policy, fixable_only, fields, locked_fields, reason, expires_at,
		baseline_on_first_run, baseline_grace_days, baseline_secrets_block)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12, $13, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)`,
		p.ID.String(), p.TenantID.String(), p.ScopeType, nullID(repoID), nullID(unitID), p.Enabled, p.Mode,
		p.FailOnSeverity, p.NewFindingsOnly, p.FailOnKEV, nullFloat(p.EPSSThreshold), nullID(p.CreatedBy), p.CreatedAt,
		modesJSON(p.Modes), p.AllowRepoPolicy, p.FixableOnly, pq.Array(nonNilFields(p.Fields)),
		pq.Array(nonNilFields(p.LockedFields)), p.Reason, policyExpiry(p.ExpiresAt), p.BaselineOnFirstRun,
		nullGraceDays(p.BaselineGraceDays), p.BaselineSecretsBlock)
	if isUniqueViolation(err) {
		return cirun.ErrPolicyExists
	}
	return err
}

// UpdateGatePolicy changes a policy of the tenant (not its scope).
func (r *CIRunRepository) UpdateGatePolicy(ctx context.Context, p *cirun.GatePolicy) error {
	res, err := r.db.ExecContext(ctx, `UPDATE ci_gate_policies SET enabled = $3, mode = $4, fail_on_severity = $5,
		new_findings_only = $6, fail_on_kev = $7, epss_threshold = $8, updated_by = $9, modes = $10,
		allow_repo_policy = $11, fixable_only = $12, fields = $13, locked_fields = $14, reason = $15, expires_at = $16,
		baseline_on_first_run = $17, baseline_grace_days = $18, baseline_secrets_block = $19, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2`,
		p.TenantID.String(), p.ID.String(), p.Enabled, p.Mode, p.FailOnSeverity, p.NewFindingsOnly, p.FailOnKEV,
		nullFloat(p.EPSSThreshold), nullID(p.UpdatedBy), modesJSON(p.Modes), p.AllowRepoPolicy, p.FixableOnly,
		pq.Array(nonNilFields(p.Fields)), pq.Array(nonNilFields(p.LockedFields)), p.Reason, policyExpiry(p.ExpiresAt),
		p.BaselineOnFirstRun, nullGraceDays(p.BaselineGraceDays), p.BaselineSecretsBlock)
	if err != nil {
		return err
	}
	return requireOneRow(res, cirun.ErrPolicyNotFound)
}

// DeleteGatePolicy removes a policy of the tenant.
func (r *CIRunRepository) DeleteGatePolicy(ctx context.Context, tenantID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM ci_gate_policies WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String())
	if err != nil {
		return err
	}
	return requireOneRow(res, cirun.ErrPolicyNotFound)
}

// ------------------------------------------------------------ overrides ---

// The creator's email is read from users when the override is read; it is
// never copied into the CI table (migration 001144).
const ciOverrideColumns = `id, tenant_id, repository_asset_id, commit_sha, reason, created_by,
	COALESCE((SELECT u.email FROM users u WHERE u.id = ci_gate_overrides.created_by), ''),
	expires_at, revoked_at, revoked_by, created_at`

func scanCIOverride(row ciScanner) (cirun.GateOverride, error) {
	var (
		o                 cirun.GateOverride
		id, tid, asset    string
		createdBy, revBy  sql.NullString
		revokedAt         sql.NullTime
		expires, createdA time.Time
	)
	if err := row.Scan(&id, &tid, &asset, &o.CommitSHA, &o.Reason, &createdBy, &o.CreatedByEmail, &expires,
		&revokedAt, &revBy, &createdA); err != nil {
		return o, err
	}
	o.ID, _ = shared.IDFromString(id)
	o.TenantID, _ = shared.IDFromString(tid)
	o.RepositoryAssetID, _ = shared.IDFromString(asset)
	o.CreatedBy, o.RevokedBy = parseOptID(createdBy), parseOptID(revBy)
	o.RevokedAt = optTime(revokedAt)
	o.ExpiresAt, o.CreatedAt = expires, createdA
	return o, nil
}

// CreateOverride inserts a break-glass override.
func (r *CIRunRepository) CreateOverride(ctx context.Context, o *cirun.GateOverride) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO ci_gate_overrides (id, tenant_id, repository_asset_id, commit_sha,
		reason, created_by, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		o.ID.String(), o.TenantID.String(), o.RepositoryAssetID.String(), o.CommitSHA, o.Reason, nullID(o.CreatedBy),
		o.ExpiresAt, o.CreatedAt)
	return err
}

// ListOverrides returns the tenant's overrides, newest first, optionally for
// one asset and within a data scope.
func (r *CIRunRepository) ListOverrides(ctx context.Context, tenantID shared.ID, assetID *shared.ID, scope *shared.DataScope) ([]cirun.GateOverride, error) {
	args := []any{tenantID.String()}
	where := "tenant_id = $1"
	if assetID != nil {
		args = append(args, assetID.String())
		where += fmt.Sprintf(" AND repository_asset_id = $%d", len(args))
	}
	var cond string
	cond, args = dataScopeCond("repository_asset_id", scope, args)
	rows, err := r.db.QueryContext(ctx, `SELECT `+ciOverrideColumns+` FROM ci_gate_overrides WHERE `+where+
		` AND `+cond+` ORDER BY created_at DESC LIMIT 200`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []cirun.GateOverride{}
	for rows.Next() {
		o, err := scanCIOverride(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// GetOverride returns one override of the tenant.
func (r *CIRunRepository) GetOverride(ctx context.Context, tenantID, id shared.ID) (*cirun.GateOverride, error) {
	o, err := scanCIOverride(r.db.QueryRowContext(ctx, `SELECT `+ciOverrideColumns+` FROM ci_gate_overrides
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, cirun.ErrOverrideNotFound
	}
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// RevokeOverride ends an override of the tenant now.
func (r *CIRunRepository) RevokeOverride(ctx context.Context, tenantID, id, by shared.ID, at time.Time) error {
	res, err := r.db.ExecContext(ctx, `UPDATE ci_gate_overrides SET revoked_at = $3, revoked_by = $4
		WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL`, tenantID.String(), id.String(), at, nullIDValue(by))
	if err != nil {
		return err
	}
	return requireOneRow(res, cirun.ErrOverrideNotFound)
}

// ActiveOverride returns the newest active override for exactly this commit.
func (r *CIRunRepository) ActiveOverride(ctx context.Context, tenantID, assetID shared.ID, sha string, now time.Time) (*cirun.GateOverride, error) {
	if sha == "" {
		return nil, nil
	}
	o, err := scanCIOverride(r.db.QueryRowContext(ctx, `SELECT `+ciOverrideColumns+` FROM ci_gate_overrides
		WHERE tenant_id = $1 AND repository_asset_id = $2 AND revoked_at IS NULL AND expires_at > $3
		  AND commit_sha = $4
		ORDER BY created_at DESC LIMIT 1`, tenantID.String(), assetID.String(), now, strings.ToLower(sha)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// requireOneRow maps "no row changed" to notFound.
func requireOneRow(res sql.Result, notFound error) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return notFound
	}
	return nil
}

// BusinessUnitExists reports whether the business unit belongs to the tenant.
func (r *CIRunRepository) BusinessUnitExists(ctx context.Context, tenantID, id shared.ID) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM business_units WHERE tenant_id = $1 AND id = $2)`,
		tenantID.String(), id.String()).Scan(&ok)
	return ok, err
}

// RequestRepoExceptions stores a repository file's exceptions as pending
// suppression rules on the repository asset (tenant-scoped). An exception
// with the same rule and path already pending or approved on the asset is
// skipped, so a file seen on every run asks once.
func (r *CIRunRepository) RequestRepoExceptions(ctx context.Context, tenantID, assetID shared.ID, repository, actor string, exceptions []cirun.RepoException) (int, error) {
	created := 0
	if len(actor) > 255 {
		actor = actor[:255]
	}
	var requester sql.NullString
	if actor != "" {
		requester = sql.NullString{String: actor, Valid: true}
	}
	for _, e := range exceptions {
		expires, err := time.Parse("2006-01-02", e.Expires)
		if err != nil {
			continue
		}
		var rule, path sql.NullString
		if e.RuleID != "" {
			rule = sql.NullString{String: e.RuleID, Valid: true}
		}
		if e.Path != "" {
			path = sql.NullString{String: e.Path, Valid: true}
		}
		if !rule.Valid && !path.Valid {
			continue
		}
		subject := e.RuleID
		if subject == "" {
			subject = "all rules on " + e.Path
		}
		name := subject + " in " + repository
		if len(name) > 255 {
			name = name[:255]
		}
		desc := "Requested by the repository's .openctem.yml: " + e.Reason
		switch e.Source {
		case cirun.ExceptionSourceInline:
			desc = "Requested by an inline ignore comment in the repository: " + e.Reason
		case cirun.ExceptionSourceIgnoreFile:
			desc = "Requested by the repository's scanner ignore file: " + e.Reason
		}
		id := shared.NewID().String()
		res, err := r.db.ExecContext(ctx, `INSERT INTO suppression_rules (id, tenant_id, rule_id, path_pattern, asset_id,
				name, description, suppression_type, status, expires_at, requested_by_actor, reason_code)
			SELECT $1::uuid, $2::uuid, $3::varchar, $4::varchar, $5::uuid, $6::varchar, $7::text, 'accepted_risk', 'pending', $8::timestamptz, $9::varchar,
			       'risk_accepted'
			WHERE NOT EXISTS (SELECT 1 FROM suppression_rules
				WHERE tenant_id = $2::uuid AND asset_id = $5::uuid AND rule_id IS NOT DISTINCT FROM $3::varchar
				  AND path_pattern IS NOT DISTINCT FROM $4::varchar AND status IN ('pending', 'approved'))`,
			id, tenantID.String(), rule, path, assetID.String(), name, desc, expires.Add(24*time.Hour-time.Second), requester)
		if err != nil {
			return created, err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			continue
		}
		created++
		details, _ := json.Marshal(map[string]string{"requested_by_actor": actor, "source": nonEmptyOr(e.Source, "repo_file"), "repository": repository})
		if _, err := r.db.ExecContext(ctx, `INSERT INTO suppression_rule_audit (suppression_rule_id, action, details)
			VALUES ($1, 'created', $2::jsonb)`, id, string(details)); err != nil {
			return created, fmt.Errorf("audit exception request: %w", err)
		}
	}
	return created, nil
}

func nonEmptyOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// ------------------------------------------------------------ decoration ---

// decorationQueued is the SET clause that queues a GitHub or GitLab run's
// verdict for posting to the code host (RFC-077 phase C), in the same
// statement that stores the verdict, so no later step can lose it. Other
// providers have nothing to post.
const decorationQueued = `
		decoration_state = CASE WHEN provider IN ('github', 'gitlab') THEN 'pending' ELSE decoration_state END,
		decoration_attempts = 0, decoration_detail = '', decoration_updated_at = NOW()`

// ClaimDecorations takes up to limit runs waiting to be posted, across
// tenants (a system job; each run carries its tenant). A run queued again
// after a failed attempt waits 30 seconds doubling with each attempt, at
// most 30 minutes (decoration_updated_at is when the last attempt
// finished). A claim older than ten minutes (a crashed replica) is taken
// again; runs evaluated more than a day ago are no longer posted.
func (r *CIRunRepository) ClaimDecorations(ctx context.Context, limit int) ([]cirun.Run, error) {
	rows, err := r.db.QueryContext(ctx, `UPDATE ci_runs SET decoration_state = 'posting',
			decoration_attempts = decoration_attempts + 1, decoration_updated_at = NOW()
		WHERE id IN (
			SELECT id FROM ci_runs
			WHERE ((decoration_state = 'pending' AND (decoration_attempts = 0 OR decoration_updated_at <= NOW()
			        - LEAST(INTERVAL '30 seconds' * power(2, decoration_attempts - 1), INTERVAL '30 minutes')))
			    OR (decoration_state = 'posting' AND decoration_updated_at < NOW() - INTERVAL '10 minutes'))
			  AND evaluated_at > NOW() - INTERVAL '1 day'
			ORDER BY decoration_updated_at
			LIMIT $1
			FOR UPDATE SKIP LOCKED)
		RETURNING `+ciRunColumns, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []cirun.Run{}
	for rows.Next() {
		run, err := scanCIRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

// FinishDecoration records how posting a run went (tenant-scoped). The state
// cirun.DecorationRetry queues the run again, up to cirun.MaxDecorationAttempts
// attempts, then marks it failed.
func (r *CIRunRepository) FinishDecoration(ctx context.Context, tenantID, runID shared.ID, state, detail string) error {
	if len(detail) > 255 {
		detail = detail[:255]
	}
	_, err := r.db.ExecContext(ctx, `UPDATE ci_runs SET
			decoration_state = CASE WHEN $3 <> 'retry' THEN $3
				WHEN decoration_attempts >= $5 THEN 'failed' ELSE 'pending' END,
			decoration_detail = $4, decoration_updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), runID.String(), state, detail, cirun.MaxDecorationAttempts)
	return err
}

// PullRequestPassed reports whether the last judged non-fork run of a pull
// request on the repository passed the gate (tenant-scoped). A run a later
// attempt re-opened keeps its last verdict until it is judged again.
func (r *CIRunRepository) PullRequestPassed(ctx context.Context, tenantID, assetID shared.ID, pullRequest string) (bool, error) {
	var verdict sql.NullString
	err := r.db.QueryRowContext(ctx, `SELECT verdict FROM ci_runs
		WHERE tenant_id = $1 AND repository_asset_id = $2 AND pull_request = $3 AND verdict IS NOT NULL AND NOT fork
		ORDER BY evaluated_at DESC NULLS LAST LIMIT 1`, tenantID.String(), assetID.String(), pullRequest).Scan(&verdict)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return verdict.String == cirun.VerdictPass, nil
}

// CommitVerdicts returns the latest verdict of each pipeline on any of the
// commits of the repository (tenant-scoped). A run without a pipeline counts
// on its own. A run a later attempt re-opened keeps its last verdict until it
// is judged again, so re-opening a failed run never hides its failure.
func (r *CIRunRepository) CommitVerdicts(ctx context.Context, tenantID, assetID shared.ID, shas []string) ([]cirun.CommitVerdict, error) {
	clean := make([]string, 0, len(shas))
	for _, s := range shas {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			clean = append(clean, s)
		}
	}
	if len(clean) == 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT ON (COALESCE(pipeline_id::text, id::text))
			id, verdict, COALESCE((verdict_detail->>'would_fail')::boolean, false)
		FROM ci_runs
		WHERE tenant_id = $1 AND repository_asset_id = $2 AND lower(commit_sha) = ANY($3)
		  AND verdict IS NOT NULL
		ORDER BY COALESCE(pipeline_id::text, id::text), evaluated_at DESC NULLS LAST`,
		tenantID.String(), assetID.String(), pq.Array(clean))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []cirun.CommitVerdict
	for rows.Next() {
		var id, verdict string
		var v cirun.CommitVerdict
		if err := rows.Scan(&id, &verdict, &v.WouldFail); err != nil {
			return nil, err
		}
		v.RunID, _ = shared.IDFromString(id)
		v.Verdict = verdict
		out = append(out, v)
	}
	return out, rows.Err()
}

// AssetsWithImageDigest returns up to limit of the tenant's assets whose
// properties mention the image digest (an image asset's own digest, a
// workload's or host's list of running images), excluding one asset (the
// repository). The digest is a full "sha256:<64 hex>" value, so a text
// match on the properties cannot hit another image.
func (r *CIRunRepository) AssetsWithImageDigest(ctx context.Context, tenantID shared.ID, digest string, exclude shared.ID, limit int) ([]cirunapp.DigestAsset, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, asset_type, COALESCE(sub_type, '') FROM assets
		WHERE tenant_id = $1 AND id <> $2 AND properties IS NOT NULL
		  AND position($3 in properties::text) > 0
		ORDER BY id LIMIT $4`, tenantID.String(), exclude.String(), digest, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []cirunapp.DigestAsset{}
	for rows.Next() {
		var (
			id string
			a  cirunapp.DigestAsset
		)
		if err := rows.Scan(&id, &a.Type, &a.SubType); err != nil {
			return nil, err
		}
		a.ID, _ = shared.IDFromString(id)
		out = append(out, a)
	}
	return out, rows.Err()
}

// PromoteSecretFindings makes secret findings of the run's repository
// organization findings: a secret pushed to any non-fork branch is exposed
// whether or not the branch merges, so it must not stay hidden as seen only
// on a branch that is no exposure. Same SLA shift as promoting on a counting
// branch (promote_branch_only_findings). Returns the ids it changed.
func (r *CIRunRepository) PromoteSecretFindings(ctx context.Context, tenantID, assetID shared.ID, ids []shared.ID) ([]shared.ID, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		UPDATE findings f
		SET branch_only = FALSE,
		    sla_deadline = f.sla_deadline + (NOW() - COALESCE(f.first_detected_at, f.created_at)),
		    sla_status = CASE WHEN f.sla_deadline IS NULL THEN f.sla_status ELSE 'on_track' END,
		    updated_at = NOW()
		WHERE f.tenant_id = $1 AND f.asset_id = $2 AND f.id = ANY($3::uuid[])
		  AND f.branch_only AND f.finding_type = 'secret'
		RETURNING f.id::text`, tenantID.String(), assetID.String(), pq.Array(rtIDStrings(ids)))
	if err != nil {
		return nil, fmt.Errorf("promote secret findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
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
