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

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CIRunRepository stores CI trust configurations, runs, gate policies and
// overrides (RFC-051, migration 001077). Every query is tenant-scoped except
// the upload-token lookup (the token is the credential) and the OIDC replay
// table (global by design).
type CIRunRepository struct {
	db *DB
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
	created_by, last_used_at, created_at, updated_at`

func scanCITrust(row ciScanner) (cirun.TrustConfig, error) {
	var (
		c              cirun.TrustConfig
		id, tid, prov  string
		rules          []byte
		createdBy      sql.NullString
		lastUsed       sql.NullTime
		createdAt, upd time.Time
	)
	if err := row.Scan(&id, &tid, &c.Name, &prov, &c.Issuer, &c.Audience, &rules, &c.DefaultBranch, &c.Enabled,
		&createdBy, &lastUsed, &createdAt, &upd); err != nil {
		return c, err
	}
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
	rules, err := json.Marshal(c.Rules)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO ci_trust_configs
		(id, tenant_id, name, provider, issuer, audience, rules, default_branch, enabled, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)`,
		c.ID.String(), c.TenantID.String(), c.Name, string(c.Provider), c.Issuer, c.Audience, rules,
		c.DefaultBranch, c.Enabled, nullID(c.CreatedBy), c.CreatedAt)
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
		SET name = $3, issuer = $4, audience = $5, rules = $6, default_branch = $7, enabled = $8, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2`,
		c.TenantID.String(), c.ID.String(), c.Name, c.Issuer, c.Audience, rules, c.DefaultBranch, c.Enabled)
	if isUniqueViolation(err) {
		return cirun.ErrTrustConfigExists
	}
	if err != nil {
		return err
	}
	return requireOneRow(res, cirun.ErrTrustConfigNotFound)
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

// TouchTrustConfig records the configuration's last use.
func (r *CIRunRepository) TouchTrustConfig(ctx context.Context, tenantID, id shared.ID, at time.Time) error {
	_, err := r.db.ExecContext(ctx, `UPDATE ci_trust_configs SET last_used_at = $3 WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String(), at)
	return err
}

// --------------------------------------------------------------- replay ---

// ClaimJTI records a token id; false when it was exchanged before.
func (r *CIRunRepository) ClaimJTI(ctx context.Context, issuer, jti string, expiresAt time.Time) (bool, error) {
	res, err := r.db.ExecContext(ctx, `INSERT INTO ci_oidc_replay (issuer, jti, expires_at) VALUES ($1, $2, $3)
		ON CONFLICT (issuer, jti) DO NOTHING`, issuer, jti, expiresAt)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// PurgeExpiredJTIs drops token ids that expired before the given time.
func (r *CIRunRepository) PurgeExpiredJTIs(ctx context.Context, before time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM ci_oidc_replay WHERE expires_at < $1`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ----------------------------------------------------------------- runs ---

const ciRunColumns = `id, tenant_id, trust_config_id, repository_asset_id, provider, issuer, repository, ref, branch,
	commit_sha, pull_request, default_branch, is_default_branch, event, environment, actor, external_run_id,
	run_attempt, workflow, pipeline_url, fork, token_expires_at, status, verdict, verdict_detail, evaluated_at,
	reports_count, findings_count, pipeline_id, sensor_version, scan_failures, tools, template_ref, created_at, updated_at,
	external_job_id`

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
		&run.ExternalJobID); err != nil {
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
		status, created_at, updated_at, pipeline_id, sensor_version, template_ref, external_job_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22,
		$23, $24, $25, $25, $26, $27, $28, $29)`,
		run.ID.String(), run.TenantID.String(), nullID(run.TrustConfigID), run.RepositoryAssetID.String(),
		string(run.Provider), run.Issuer, run.Repository, run.Ref, run.Branch, run.CommitSHA, run.PullRequest,
		run.DefaultBranch, run.IsDefaultBranch, run.Event, run.Environment, run.Actor, run.ExternalRunID,
		run.RunAttempt, run.Workflow, run.PipelineURL, run.Fork, run.TokenHash, run.TokenExpiresAt,
		run.Status, run.CreatedAt, nullID(run.PipelineID), run.SensorVersion, run.TemplateRef, run.ExternalJobID)
	return err
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

// RecordRunReport adds a report's sighted fingerprints to the run, up to
// MaxRunFindings, and counts the report.
func (r *CIRunRepository) RecordRunReport(ctx context.Context, tenantID, runID shared.ID, fingerprints []string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// Lock the run row so concurrent reports count and cap correctly.
	var current int
	if err := tx.QueryRowContext(ctx, `SELECT findings_count FROM ci_runs WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
		tenantID.String(), runID.String()).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return cirun.ErrRunNotFound
		}
		return err
	}
	if room := cirun.MaxRunFindings - current; len(fingerprints) > room {
		fingerprints = fingerprints[:max(room, 0)]
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
	if _, err := tx.ExecContext(ctx, `UPDATE ci_runs SET reports_count = reports_count + 1,
		findings_count = findings_count + $3, updated_at = NOW() WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), runID.String(), added); err != nil {
		return err
	}
	return tx.Commit()
}

// RunFindings returns the findings on the run's asset that the run recorded.
func (r *CIRunRepository) RunFindings(ctx context.Context, tenantID, runID, assetID shared.ID) ([]cirun.RunFinding, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT f.id, f.fingerprint, COALESCE(f.title, ''), COALESCE(f.rule_id, ''),
			f.severity, f.status, COALESCE(f.finding_type, ''), COALESCE(f.file_path, ''), COALESCE(f.start_line, 0),
			COALESCE(f.is_in_kev, FALSE), f.epss_score,
			EXISTS (SELECT 1 FROM finding_suppressions s WHERE s.finding_id = f.id),
			f.acceptance_expires_at, f.first_detected_at, f.last_reopened_at
		FROM ci_run_findings rf
		JOIN findings f ON f.tenant_id = rf.tenant_id AND f.fingerprint = rf.fingerprint
		WHERE rf.tenant_id = $1 AND rf.run_id = $2 AND f.asset_id = $3
		ORDER BY f.severity, f.id
		LIMIT 100000`, tenantID.String(), runID.String(), assetID.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []cirun.RunFinding{}
	for rows.Next() {
		var (
			f                          cirun.RunFinding
			id                         string
			epss                       sql.NullFloat64
			accExp, firstDet, reopened sql.NullTime
		)
		if err := rows.Scan(&id, &f.Fingerprint, &f.Title, &f.RuleID, &f.Severity, &f.Status, &f.FindingType,
			&f.FilePath, &f.StartLine, &f.IsInKEV, &epss, &f.Suppressed, &accExp, &firstDet, &reopened); err != nil {
			return nil, err
		}
		f.ID, _ = shared.IDFromString(id)
		if epss.Valid {
			v := epss.Float64
			f.EPSSScore = &v
		}
		f.AcceptanceExpiresAt = optTime(accExp)
		f.FirstDetectedAt = optTime(firstDet)
		f.LastReopenedAt = optTime(reopened)
		out = append(out, f)
	}
	return out, rows.Err()
}

// SaveVerdict stores the run's verdict.
func (r *CIRunRepository) SaveVerdict(ctx context.Context, tenantID, runID shared.ID, verdict string, detail []byte, at time.Time) error {
	res, err := r.db.ExecContext(ctx, `UPDATE ci_runs SET status = 'evaluated', verdict = $3, verdict_detail = $4,
		evaluated_at = $5, updated_at = NOW() WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), runID.String(), verdict, detail, at)
	if err != nil {
		return err
	}
	return requireOneRow(res, cirun.ErrRunNotFound)
}

// ------------------------------------------------------------- policies ---

const ciPolicyColumns = `id, tenant_id, scope_type, scope_id, enabled, mode, fail_on_severity, new_findings_only,
	fail_on_kev, epss_threshold, created_by, updated_by, created_at, updated_at`

func scanCIPolicy(row ciScanner) (cirun.GatePolicy, error) {
	var (
		p                    cirun.GatePolicy
		id, tid              string
		scopeID, cby, uby    sql.NullString
		epss                 sql.NullFloat64
		createdAt, updatedAt time.Time
	)
	if err := row.Scan(&id, &tid, &p.ScopeType, &scopeID, &p.Enabled, &p.Mode, &p.FailOnSeverity,
		&p.NewFindingsOnly, &p.FailOnKEV, &epss, &cby, &uby, &createdAt, &updatedAt); err != nil {
		return p, err
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

// GatePoliciesFor returns the enabled policies that may apply to an asset.
func (r *CIRunRepository) GatePoliciesFor(ctx context.Context, tenantID, assetID shared.ID) ([]cirun.GatePolicy, error) {
	return r.queryPolicies(ctx, `SELECT `+ciPolicyColumns+` FROM ci_gate_policies p
		WHERE p.tenant_id = $1 AND p.enabled AND (
			p.scope_type = 'tenant'
			OR (p.scope_type = 'repository' AND p.scope_id = $2)
			OR (p.scope_type = 'business_unit' AND p.scope_id IN (
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
	_, err := r.db.ExecContext(ctx, `INSERT INTO ci_gate_policies (id, tenant_id, scope_type, scope_id, enabled, mode,
		fail_on_severity, new_findings_only, fail_on_kev, epss_threshold, created_by, updated_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11, $12, $12)`,
		p.ID.String(), p.TenantID.String(), p.ScopeType, nullID(p.ScopeID), p.Enabled, p.Mode, p.FailOnSeverity,
		p.NewFindingsOnly, p.FailOnKEV, nullFloat(p.EPSSThreshold), nullID(p.CreatedBy), p.CreatedAt)
	if isUniqueViolation(err) {
		return cirun.ErrPolicyExists
	}
	return err
}

// UpdateGatePolicy changes a policy of the tenant (not its scope).
func (r *CIRunRepository) UpdateGatePolicy(ctx context.Context, p *cirun.GatePolicy) error {
	res, err := r.db.ExecContext(ctx, `UPDATE ci_gate_policies SET enabled = $3, mode = $4, fail_on_severity = $5,
		new_findings_only = $6, fail_on_kev = $7, epss_threshold = $8, updated_by = $9, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2`,
		p.TenantID.String(), p.ID.String(), p.Enabled, p.Mode, p.FailOnSeverity, p.NewFindingsOnly, p.FailOnKEV,
		nullFloat(p.EPSSThreshold), nullID(p.UpdatedBy))
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

const ciOverrideColumns = `id, tenant_id, repository_asset_id, commit_sha, reason, created_by, created_by_email,
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
		reason, created_by, created_by_email, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		o.ID.String(), o.TenantID.String(), o.RepositoryAssetID.String(), o.CommitSHA, o.Reason, nullID(o.CreatedBy),
		o.CreatedByEmail, o.ExpiresAt, o.CreatedAt)
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

// ActiveOverride returns the newest active override covering the commit.
func (r *CIRunRepository) ActiveOverride(ctx context.Context, tenantID, assetID shared.ID, sha string, now time.Time) (*cirun.GateOverride, error) {
	if sha == "" {
		return nil, nil
	}
	o, err := scanCIOverride(r.db.QueryRowContext(ctx, `SELECT `+ciOverrideColumns+` FROM ci_gate_overrides
		WHERE tenant_id = $1 AND repository_asset_id = $2 AND revoked_at IS NULL AND expires_at > $3
		  AND $4 LIKE commit_sha || '%'
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
