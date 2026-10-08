package postgres

// Scan stage chaining storage (research/27 P0-3, docs/architecture/scan-stages.md):
// scan_step_outputs, scan_run_stage_plans and scan_run_targets (migration
// 001049). Every statement is scoped to the tenant it is given; the
// composite foreign keys refuse a row that points across tenants.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScanHopRepository implements scanrun.HopRepository.
type ScanHopRepository struct {
	db *DB
}

// NewScanHopRepository constructs a ScanHopRepository.
func NewScanHopRepository(db *DB) *ScanHopRepository { return &ScanHopRepository{db: db} }

var _ scanrun.HopRepository = (*ScanHopRepository)(nil)

// hopBatch bounds the rows of one multi-row INSERT.
const hopBatch = 1000

func hopIDStrings(ids []shared.ID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !id.IsZero() {
			out = append(out, id.String())
		}
	}
	return out
}

// RecordStepOutputs inserts the step run's outputs in one statement that
// resolves the run and the tenant from the step run itself: a step run or
// an asset of another tenant matches nothing and writes nothing.
func (r *ScanHopRepository) RecordStepOutputs(ctx context.Context, tenantID, stepRunID shared.ID, assetIDs []shared.ID) (int, error) {
	ids := hopIDStrings(assetIDs)
	if len(ids) == 0 || stepRunID.IsZero() {
		return 0, nil
	}
	total := 0
	for start := 0; start < len(ids); start += hopBatch {
		end := min(start+hopBatch, len(ids))
		res, err := r.db.ExecContext(ctx, `
			INSERT INTO scan_step_outputs (tenant_id, run_id, scan_run_step_id, asset_id)
			SELECT pr.tenant_id, pr.id, sr.id, a.id
			FROM scan_run_steps sr
			JOIN scan_runs pr ON pr.id = sr.scan_run_id AND pr.tenant_id = $1
			JOIN assets a ON a.tenant_id = pr.tenant_id AND a.id = ANY($3::uuid[]) AND a.deleted_at IS NULL
			WHERE sr.id = $2
			ON CONFLICT (scan_run_step_id, asset_id) DO NOTHING`,
			tenantID.String(), stepRunID.String(), pq.Array(ids[start:end]))
		if err != nil {
			return total, fmt.Errorf("record step outputs: %w", err)
		}
		n, _ := res.RowsAffected()
		total += int(n)
	}
	return total, nil
}

// ListStepOutputs returns the live assets the step runs produced, oldest
// first, up to limit, and the total count.
// CountStepOutputs counts, per step run and asset type, the live assets the
// run's step runs produced; with a scope, only assets the caller may see.
func (r *ScanHopRepository) CountStepOutputs(ctx context.Context, tenantID, runID shared.ID, scope *shared.DataScope) ([]scanrun.StepOutputCount, error) {
	q := `
		SELECT o.scan_run_step_id, a.asset_type, COUNT(DISTINCT a.id)
		FROM scan_step_outputs o
		JOIN assets a ON a.tenant_id = o.tenant_id AND a.id = o.asset_id AND a.deleted_at IS NULL
		WHERE o.tenant_id = $1 AND o.run_id = $2`
	args := []any{tenantID.String(), runID.String()}
	if scope != nil {
		cond, scopeArgs := dataScopeCondAt("a.id", scope, 3)
		q += " AND " + cond
		args = append(args, scopeArgs...)
	}
	q += " GROUP BY o.scan_run_step_id, a.asset_type"
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("count step outputs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []scanrun.StepOutputCount
	for rows.Next() {
		var sr string
		var c scanrun.StepOutputCount
		if err := rows.Scan(&sr, &c.AssetType, &c.Count); err != nil {
			return nil, fmt.Errorf("scan step output count: %w", err)
		}
		c.StepRunID, _ = shared.IDFromString(sr)
		out = append(out, c)
	}
	return out, rows.Err()
}

// PreviousRun returns the latest completed or partial run of the run's scan
// created before it (zero id: none, or a run without a scan).
func (r *ScanHopRepository) PreviousRun(ctx context.Context, tenantID, runID shared.ID) (shared.ID, error) {
	var id string
	err := r.db.QueryRowContext(ctx, `
		SELECT p.id
		FROM scan_runs r
		JOIN scan_runs p ON p.tenant_id = r.tenant_id AND p.scan_id = r.scan_id
			AND p.id <> r.id AND p.created_at < r.created_at
			AND p.status IN ('completed', 'partial')
		WHERE r.tenant_id = $1 AND r.id = $2 AND r.scan_id IS NOT NULL
		ORDER BY p.created_at DESC
		LIMIT 1`, tenantID.String(), runID.String()).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return shared.ID{}, nil
	}
	if err != nil {
		return shared.ID{}, fmt.Errorf("previous run: %w", err)
	}
	return shared.IDFromString(id)
}

// stepOutputsOfRuns is the live assets two runs of the tenant produced, one
// row per step key and asset, with which run produced it ($1 tenant, $2
// run, $3 previous run). The caller appends the scope condition on a.id.
const stepOutputsOfRuns = `
		SELECT s.step_key, o.asset_id, a.name, a.asset_type, COALESCE(a.sub_type, '') AS sub_type,
			bool_or(o.run_id = $2) AS in_run, bool_or(o.run_id = $3) AS in_previous
		FROM scan_step_outputs o
		JOIN scan_run_steps s ON s.id = o.scan_run_step_id AND s.scan_run_id = o.run_id
		JOIN assets a ON a.tenant_id = o.tenant_id AND a.id = o.asset_id AND a.deleted_at IS NULL
		WHERE o.tenant_id = $1 AND o.run_id IN ($2, $3)`

func (r *ScanHopRepository) CompareStepOutputs(ctx context.Context, tenantID, runID, previousRunID shared.ID, scope *shared.DataScope) ([]scanrun.StepOutputDelta, error) {
	if previousRunID.IsZero() {
		return nil, nil
	}
	inner := stepOutputsOfRuns
	args := []any{tenantID.String(), runID.String(), previousRunID.String()}
	if scope != nil {
		cond, scopeArgs := dataScopeCondAt("a.id", scope, 4)
		inner += " AND " + cond
		args = append(args, scopeArgs...)
	}
	inner += " GROUP BY s.step_key, o.asset_id, a.name, a.asset_type, a.sub_type"
	rows, err := r.db.QueryContext(ctx, `
		SELECT step_key,
			COUNT(*) FILTER (WHERE in_previous),
			COUNT(*) FILTER (WHERE in_run AND NOT in_previous),
			COUNT(*) FILTER (WHERE in_previous AND NOT in_run)
		FROM (`+inner+`) x
		GROUP BY step_key`, args...)
	if err != nil {
		return nil, fmt.Errorf("compare step outputs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []scanrun.StepOutputDelta
	for rows.Next() {
		var d scanrun.StepOutputDelta
		if err := rows.Scan(&d.StepKey, &d.Previous, &d.Added, &d.Gone); err != nil {
			return nil, fmt.Errorf("scan step output delta: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (r *ScanHopRepository) PreviewStepOutputs(ctx context.Context, tenantID, runID, previousRunID shared.ID, stepKey string, scope *shared.DataScope, limit int) ([]scanrun.StepOutput, int, error) {
	if limit <= 0 {
		return nil, 0, nil
	}
	// The zero id never matches a run: without a previous run nothing is new
	// (in_previous is false for every row, and New is cleared below).
	inner := stepOutputsOfRuns + " AND s.step_key = $4"
	args := []any{tenantID.String(), runID.String(), previousRunID.String(), stepKey}
	if scope != nil {
		cond, scopeArgs := dataScopeCondAt("a.id", scope, 5)
		inner += " AND " + cond
		args = append(args, scopeArgs...)
	}
	inner += " GROUP BY s.step_key, o.asset_id, a.name, a.asset_type, a.sub_type"
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT asset_id, name, asset_type, sub_type, NOT in_previous, COUNT(*) OVER ()
		FROM (%s) x
		WHERE in_run
		ORDER BY in_previous, name, asset_id
		LIMIT $%d`, inner, len(args)), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("preview step outputs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]scanrun.StepOutput, 0, min(limit, maxStepOutputPreview))
	total := 0
	for rows.Next() {
		var id string
		var o scanrun.StepOutput
		if err := rows.Scan(&id, &o.Name, &o.Type, &o.SubType, &o.New, &total); err != nil {
			return nil, 0, fmt.Errorf("scan step output: %w", err)
		}
		o.AssetID, _ = shared.IDFromString(id)
		o.New = o.New && !previousRunID.IsZero()
		out = append(out, o)
	}
	return out, total, rows.Err()
}

// maxStepOutputPreview sizes the preview's first allocation (the service
// caps the limit the same way).
const maxStepOutputPreview = 50

func (r *ScanHopRepository) ListStepOutputs(ctx context.Context, tenantID, runID shared.ID, stepRunIDs []shared.ID, limit int) ([]scanrun.StepOutput, int, error) {
	ids := hopIDStrings(stepRunIDs)
	if len(ids) == 0 || limit <= 0 {
		return nil, 0, nil
	}
	var total int
	if err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT o.asset_id)
		FROM scan_step_outputs o
		JOIN assets a ON a.tenant_id = o.tenant_id AND a.id = o.asset_id AND a.deleted_at IS NULL
		WHERE o.tenant_id = $1 AND o.run_id = $2 AND o.scan_run_step_id = ANY($3::uuid[])`,
		tenantID.String(), runID.String(), pq.Array(ids)).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count step outputs: %w", err)
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT ON (a.id) o.scan_run_step_id, a.id, a.name, a.asset_type, COALESCE(a.sub_type, '')
		FROM scan_step_outputs o
		JOIN assets a ON a.tenant_id = o.tenant_id AND a.id = o.asset_id AND a.deleted_at IS NULL
		WHERE o.tenant_id = $1 AND o.run_id = $2 AND o.scan_run_step_id = ANY($3::uuid[])
		ORDER BY a.id, o.created_at
		LIMIT $4`,
		tenantID.String(), runID.String(), pq.Array(ids), limit)
	if err != nil {
		return nil, 0, fmt.Errorf("list step outputs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []scanrun.StepOutput
	for rows.Next() {
		var sr, id string
		var o scanrun.StepOutput
		if err := rows.Scan(&sr, &id, &o.Name, &o.Type, &o.SubType); err != nil {
			return nil, 0, fmt.Errorf("scan step output: %w", err)
		}
		o.StepRunID, _ = shared.IDFromString(sr)
		o.AssetID, _ = shared.IDFromString(id)
		out = append(out, o)
	}
	return out, total, rows.Err()
}

// PendingStepIngest reports whether a v2 report of the step runs' commands
// is still open (receiving, queued or being processed). A v1 report bound
// to a command is ingested in the request, before the command completes.
func (r *ScanHopRepository) PendingStepIngest(ctx context.Context, tenantID shared.ID, stepRunIDs []shared.ID) (bool, error) {
	ids := hopIDStrings(stepRunIDs)
	if len(ids) == 0 {
		return false, nil
	}
	var pending bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM ingest_reports ir
			JOIN commands c ON c.id = ir.command_id AND c.tenant_id = ir.tenant_id
			WHERE ir.tenant_id = $1 AND c.scan_run_step_id = ANY($2::uuid[])
			  AND ir.state IN ('receiving', 'queued', 'processing'))`,
		tenantID.String(), pq.Array(ids)).Scan(&pending)
	if err != nil {
		return false, fmt.Errorf("check pending ingest: %w", err)
	}
	return pending, nil
}

func clampSmallint(v int) int {
	if v < 0 {
		return 0
	}
	return min(v, math.MaxInt16)
}

// SaveStagePlan claims the (run, stage) key and writes the targets in the
// same transaction. A second planner of the same stage writes nothing.
func (r *ScanHopRepository) SaveStagePlan(ctx context.Context, plan *scanrun.StagePlan, targets []scanrun.RunTarget) (bool, error) {
	if plan == nil {
		return false, fmt.Errorf("%w: plan is required", shared.ErrValidation)
	}
	skipped := plan.Skipped
	if skipped == nil {
		skipped = map[string]int{}
	}
	skippedJSON, err := json.Marshal(skipped)
	if err != nil {
		return false, fmt.Errorf("encode skipped counts: %w", err)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, `
		INSERT INTO scan_run_stage_plans
			(tenant_id, run_id, stage_key, stage, tool, tier, chained, inputs, planned, max_hop, skipped)
		SELECT pr.tenant_id, pr.id, $3, $4, $5, $6, $7, $8, $9, $10, $11
		FROM scan_runs pr WHERE pr.tenant_id = $1 AND pr.id = $2
		ON CONFLICT (run_id, stage_key) DO NOTHING`,
		plan.TenantID.String(), plan.RunID.String(), plan.StageKey, plan.Stage, plan.Tool,
		clampSmallint(plan.Tier), plan.Chained, max(plan.Inputs, 0), max(plan.Planned, 0),
		clampSmallint(plan.MaxHop), skippedJSON)
	if err != nil {
		return false, fmt.Errorf("claim stage plan: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil // planned already, or not a run of this tenant
	}
	for start := 0; start < len(targets); start += hopBatch {
		if err := insertRunTargets(ctx, tx, plan, targets[start:min(start+hopBatch, len(targets))]); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func hopNullID(id *shared.ID) any {
	if id == nil || id.IsZero() {
		return nil
	}
	return id.String()
}

func hopNullText(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func insertRunTargets(ctx context.Context, tx *sql.Tx, plan *scanrun.StagePlan, targets []scanrun.RunTarget) error {
	if len(targets) == 0 {
		return nil
	}
	const cols = 12
	args := make([]any, 0, len(targets)*cols)
	values := make([]byte, 0, len(targets)*72)
	for i, t := range targets {
		if i > 0 {
			values = append(values, ',')
		}
		b := i * cols
		values = fmt.Appendf(values, "($%d::uuid,$%d::uuid,$%d,$%d,$%d::uuid,$%d,$%d::uuid,$%d,$%d,$%d::smallint,$%d,$%d)",
			b+1, b+2, b+3, b+4, b+5, b+6, b+7, b+8, b+9, b+10, b+11, b+12)
		args = append(args, plan.TenantID.String(), plan.RunID.String(), plan.StageKey, t.TargetKey,
			hopNullID(t.AssetID), t.Origin, hopNullID(t.ParentAssetID), hopNullText(t.ParentStageKey),
			hopNullText(t.Relation), clampSmallint(t.Hop), t.Decision, t.Reason)
	}
	const insertRunTargetsSQL = `INSERT INTO scan_run_targets
			(tenant_id, run_id, stage_key, target_key, asset_id, origin, parent_asset_id,
			 parent_stage_key, relation, hop, decision, reason)
		VALUES %s
		ON CONFLICT (run_id, stage_key, target_key) DO NOTHING`
	// Only $n placeholders are formatted in; every value is a parameter.
	q := fmt.Sprintf(insertRunTargetsSQL, values) //nolint:gosec // placeholders only, no data

	if _, err := tx.ExecContext(ctx, q, args...); err != nil {
		return fmt.Errorf("record run targets: %w", err)
	}
	return nil
}

// PlannedTargets returns the planned targets of the given stages.
func (r *ScanHopRepository) PlannedTargets(ctx context.Context, tenantID, runID shared.ID, stageKeys []string) ([]scanrun.RunTarget, error) {
	if len(stageKeys) == 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT stage_key, target_key, asset_id, origin, hop
		FROM scan_run_targets
		WHERE tenant_id = $1 AND run_id = $2 AND stage_key = ANY($3) AND decision = 'planned'`,
		tenantID.String(), runID.String(), pq.Array(stageKeys))
	if err != nil {
		return nil, fmt.Errorf("list planned targets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []scanrun.RunTarget
	for rows.Next() {
		var t scanrun.RunTarget
		var asset sql.NullString
		if err := rows.Scan(&t.StageKey, &t.TargetKey, &asset, &t.Origin, &t.Hop); err != nil {
			return nil, fmt.Errorf("scan planned target: %w", err)
		}
		if asset.Valid {
			if id, err := shared.IDFromString(asset.String); err == nil {
				t.AssetID = &id
			}
		}
		t.TenantID, t.RunID, t.Decision = tenantID, runID, scanrun.TargetPlanned
		out = append(out, t)
	}
	return out, rows.Err()
}

// ListStagePlans returns the run's stage plans in planning order.
func (r *ScanHopRepository) ListStagePlans(ctx context.Context, tenantID, runID shared.ID) ([]scanrun.StagePlan, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT stage_key, stage, tool, tier, chained, inputs, planned, max_hop, skipped, planned_at
		FROM scan_run_stage_plans
		WHERE tenant_id = $1 AND run_id = $2
		ORDER BY planned_at, stage_key`,
		tenantID.String(), runID.String())
	if err != nil {
		return nil, fmt.Errorf("list stage plans: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []scanrun.StagePlan
	for rows.Next() {
		p := scanrun.StagePlan{TenantID: tenantID, RunID: runID}
		var skipped []byte
		if err := rows.Scan(&p.StageKey, &p.Stage, &p.Tool, &p.Tier, &p.Chained, &p.Inputs, &p.Planned,
			&p.MaxHop, &skipped, &p.PlannedAt); err != nil {
			return nil, fmt.Errorf("scan stage plan: %w", err)
		}
		p.Skipped = map[string]int{}
		if len(skipped) > 0 {
			if err := json.Unmarshal(skipped, &p.Skipped); err != nil {
				return nil, fmt.Errorf("decode skipped counts: %w", err)
			}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// StepRunOfCommand resolves a command of the tenant to its run and step.
func (r *ScanHopRepository) StepRunOfCommand(ctx context.Context, tenantID, commandID shared.ID) (shared.ID, string, error) {
	var runID, stepKey string
	err := r.db.QueryRowContext(ctx, `
		SELECT pr.id, sr.step_key
		FROM commands c
		JOIN scan_run_steps sr ON sr.id = c.scan_run_step_id
		JOIN scan_runs pr ON pr.id = sr.scan_run_id AND pr.tenant_id = c.tenant_id
		WHERE c.tenant_id = $1 AND c.id = $2`,
		tenantID.String(), commandID.String()).Scan(&runID, &stepKey)
	if errors.Is(err, sql.ErrNoRows) {
		return shared.ID{}, "", shared.ErrNotFound
	}
	if err != nil {
		return shared.ID{}, "", fmt.Errorf("resolve command step: %w", err)
	}
	id, err := shared.IDFromString(runID)
	if err != nil {
		return shared.ID{}, "", fmt.Errorf("parse run id: %w", err)
	}
	return id, stepKey, nil
}
