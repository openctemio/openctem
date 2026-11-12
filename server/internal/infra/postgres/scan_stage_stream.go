package postgres

// Stage streaming storage (RFC-137, docs/architecture/scan-stages.md §3.6):
// the waves that hand a chained stage its predecessor's results as each
// task of the predecessor finishes. Every statement is scoped to the tenant
// it is given; the run's composite foreign keys refuse a row that points
// across tenants.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ scanrun.StageStreamStore = (*ScanHopRepository)(nil)

// stageStreamLockWait bounds how long a wave waits for another wave of the
// same stage.
const stageStreamLockWait = 30 * time.Second

// LockStageStream takes a session advisory lock keyed by the run and the
// stage on a connection of its own, so two servers never plan a wave of
// the same stage at once. The lock holds no row; the tenant is not part of
// the key because a run id names one tenant's run.
func (r *ScanHopRepository) LockStageStream(ctx context.Context, tenantID, runID shared.ID, stageKey string) (func(), error) {
	if tenantID.IsZero() || runID.IsZero() || stageKey == "" {
		return func() {}, fmt.Errorf("%w: tenant, run and stage are required", shared.ErrValidation)
	}
	conn, err := r.db.Conn(ctx)
	if err != nil {
		return func() {}, fmt.Errorf("stage stream lock: %w", err)
	}
	key := runID.String() + "/" + stageKey
	lockCtx, cancel := context.WithTimeout(ctx, stageStreamLockWait)
	defer cancel()
	if _, err := conn.ExecContext(lockCtx, `SELECT pg_advisory_lock(hashtext('scan_stage_stream'), hashtext($1))`, key); err != nil {
		_ = conn.Close()
		return func() {}, fmt.Errorf("stage stream lock: %w", err)
	}
	return func() {
		uctx, ucancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer ucancel()
		if _, err := conn.ExecContext(uctx, `SELECT pg_advisory_unlock(hashtext('scan_stage_stream'), hashtext($1))`, key); err != nil {
			// Closing the connection below would leave a session lock on a
			// pooled connection: mark it bad so the pool discards it (the
			// session, and its lock, end with it).
			_ = conn.Raw(func(any) error { return errors.New("discard") })
		}
		_ = conn.Close()
	}, nil
}

// StageStream reads one stage plan of the tenant's run.
func (r *ScanHopRepository) StageStream(ctx context.Context, tenantID, runID shared.ID, stageKey string) (scanrun.StagePlan, bool, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT `+stagePlanColumns+`
		FROM scan_run_stage_plans
		WHERE tenant_id = $1 AND run_id = $2 AND stage_key = $3`,
		tenantID.String(), runID.String(), stageKey)
	p, err := scanStagePlan(row, tenantID, runID)
	if errors.Is(err, sql.ErrNoRows) {
		return scanrun.StagePlan{}, false, nil
	}
	if err != nil {
		return scanrun.StagePlan{}, false, err
	}
	return p, true, nil
}

// StageTargets returns every target one stage of the run decided.
func (r *ScanHopRepository) StageTargets(ctx context.Context, tenantID, runID shared.ID, stageKey string) ([]scanrun.RunTarget, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT target_key, asset_id, origin, parent_asset_id, COALESCE(parent_stage_key, ''),
		       COALESCE(relation, ''), hop, decision, reason
		FROM scan_run_targets
		WHERE tenant_id = $1 AND run_id = $2 AND stage_key = $3`,
		tenantID.String(), runID.String(), stageKey)
	if err != nil {
		return nil, fmt.Errorf("list stage targets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []scanrun.RunTarget
	for rows.Next() {
		t := scanrun.RunTarget{TenantID: tenantID, RunID: runID, StageKey: stageKey}
		var asset, parent sql.NullString
		if err := rows.Scan(&t.TargetKey, &asset, &t.Origin, &parent, &t.ParentStageKey, &t.Relation,
			&t.Hop, &t.Decision, &t.Reason); err != nil {
			return nil, fmt.Errorf("scan stage target: %w", err)
		}
		t.AssetID = parseNullID(asset)
		t.ParentAssetID = parseNullID(parent)
		out = append(out, t)
	}
	return out, rows.Err()
}

// SaveStageWave records one later wave of an open stream (see the
// interface). The plan row is locked for the transaction, so the counts
// and the close never interleave with a wave.
func (r *ScanHopRepository) SaveStageWave(ctx context.Context, plan *scanrun.StagePlan, targets []scanrun.RunTarget) ([]string, error) {
	if plan == nil {
		return nil, fmt.Errorf("%w: plan is required", shared.ErrValidation)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var open bool
	err = tx.QueryRowContext(ctx, `
		SELECT stream_open FROM scan_run_stage_plans
		WHERE tenant_id = $1 AND run_id = $2 AND stage_key = $3
		FOR UPDATE`,
		plan.TenantID.String(), plan.RunID.String(), plan.StageKey).Scan(&open)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lock stage plan: %w", err)
	}
	if !open {
		return nil, nil
	}
	var added []string
	for start := 0; start < len(targets); start += hopBatch {
		keys, err := insertWaveTargets(ctx, tx, plan, targets[start:min(start+hopBatch, len(targets))])
		if err != nil {
			return nil, err
		}
		added = append(added, keys...)
	}

	// The counts: planned and the furthest hop from the stored targets,
	// the skipped reasons stored as targets plus the ones that are not
	// (plan.Skipped: invalid names, duplicates, ...).
	var planned, maxHop int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE decision = 'planned'),
		       COALESCE(max(hop) FILTER (WHERE decision = 'planned'), 0)
		FROM scan_run_targets
		WHERE tenant_id = $1 AND run_id = $2 AND stage_key = $3`,
		plan.TenantID.String(), plan.RunID.String(), plan.StageKey).Scan(&planned, &maxHop); err != nil {
		return nil, fmt.Errorf("count stage targets: %w", err)
	}
	skipped := map[string]int{}
	for k, v := range plan.Skipped {
		if v > 0 {
			skipped[k] += v
		}
	}
	if err := addSkippedTargetCounts(ctx, tx, plan, skipped); err != nil {
		return nil, err
	}
	skippedJSON, err := json.Marshal(skipped)
	if err != nil {
		return nil, fmt.Errorf("encode skipped counts: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE scan_run_stage_plans
		SET inputs = $4, planned = $5, max_hop = $6, skipped = $7,
		    waves = waves + CASE WHEN $8 THEN 1 ELSE 0 END,
		    first_dispatch_at = COALESCE(first_dispatch_at, CASE WHEN $8 THEN now() END)
		WHERE tenant_id = $1 AND run_id = $2 AND stage_key = $3`,
		plan.TenantID.String(), plan.RunID.String(), plan.StageKey, max(plan.Inputs, 0), planned,
		clampSmallint(maxHop), skippedJSON, len(added) > 0); err != nil {
		return nil, fmt.Errorf("update stage plan: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return added, nil
}

// addSkippedTargetCounts adds the stage's stored skipped targets, by reason.
func addSkippedTargetCounts(ctx context.Context, tx *sql.Tx, plan *scanrun.StagePlan, skipped map[string]int) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT reason, count(*) FROM scan_run_targets
		WHERE tenant_id = $1 AND run_id = $2 AND stage_key = $3 AND decision = 'skipped'
		GROUP BY reason`,
		plan.TenantID.String(), plan.RunID.String(), plan.StageKey)
	if err != nil {
		return fmt.Errorf("count skipped stage targets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var reason string
		var n int
		if err := rows.Scan(&reason, &n); err != nil {
			return fmt.Errorf("scan skipped count: %w", err)
		}
		skipped[reason] += n
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("count skipped stage targets: %w", err)
	}
	return nil
}

// insertWaveTargets inserts a batch of a wave's targets and returns the
// planned ones it inserted (a key the stage decided already is kept as it
// was and not returned).
func insertWaveTargets(ctx context.Context, tx *sql.Tx, plan *scanrun.StagePlan, targets []scanrun.RunTarget) ([]string, error) {
	if len(targets) == 0 {
		return nil, nil
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
	const insertWaveTargetsSQL = `INSERT INTO scan_run_targets
			(tenant_id, run_id, stage_key, target_key, asset_id, origin, parent_asset_id,
			 parent_stage_key, relation, hop, decision, reason)
		VALUES %s
		ON CONFLICT (run_id, stage_key, target_key) DO NOTHING
		RETURNING target_key, decision`
	// Only $n placeholders are formatted in; every value is a parameter.
	q := fmt.Sprintf(insertWaveTargetsSQL, values) //nolint:gosec // placeholders only, no data
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("record wave targets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var added []string
	for rows.Next() {
		var key, decision string
		if err := rows.Scan(&key, &decision); err != nil {
			return nil, fmt.Errorf("scan wave target: %w", err)
		}
		if decision == scanrun.TargetPlanned {
			added = append(added, key)
		}
	}
	return added, rows.Err()
}

// CloseStageStream closes an open stream of the tenant's run.
func (r *ScanHopRepository) CloseStageStream(ctx context.Context, tenantID, runID shared.ID, stageKey string) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE scan_run_stage_plans SET stream_open = false, closed_at = now()
		WHERE tenant_id = $1 AND run_id = $2 AND stage_key = $3 AND stream_open`,
		tenantID.String(), runID.String(), stageKey)
	if err != nil {
		return false, fmt.Errorf("close stage stream: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("close stage stream: %w", err)
	}
	return n == 1, nil
}
