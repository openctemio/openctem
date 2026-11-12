package postgres

// Precomputed exploration figures (docs/architecture/exploration.md,
// "Rollups"). One statement per refresh, bound to the tenant; every count
// uses ix_exploration_leads_state or the leads of one exploration.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/exploration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ exploration.RollupStore = (*ExplorationRepository)(nil)

// rollupFiguresSQL computes the figures of exploration $2 of tenant $1 over
// the leads that pass cond (a data scope condition on alias l, or TRUE).
func rollupFiguresSQL(cond string) string {
	return `
	WITH l AS (SELECT * FROM exploration_leads l WHERE l.tenant_id = $1 AND l.exploration_id = $2 AND ` + cond + `),
	     v AS (SELECT l.id, min(v.created_at) - l.created_at AS took
	           FROM l JOIN exploration_verdicts v ON v.tenant_id = $1 AND v.lead_id = l.id
	           WHERE v.created_at > now() - interval '30 days' GROUP BY l.id, l.created_at)
	SELECT
		(SELECT count(*) FROM l WHERE state = 'open'),
		(SELECT count(*) FROM l WHERE state = 'awaiting_approval'),
		(SELECT count(*) FROM l WHERE state = 'running'),
		(SELECT count(*) FROM l WHERE state = 'blocked'),
		(SELECT count(*) FROM l WHERE closed_at > now() - interval '30 days'),
		(SELECT count(*) FROM l WHERE state = 'done' AND closed_at > now() - interval '30 days'),
		(SELECT count(*) FROM l WHERE state = 'refuted' AND closed_at > now() - interval '30 days'),
		(SELECT count(*) FROM exploration_links k JOIN l ON l.id = k.lead_id
		 WHERE k.tenant_id = $1 AND k.rel = 'dispatched_as' AND k.created_at > now() - interval '30 days'),
		(SELECT (count(*) FILTER (WHERE origin = 'rule'))::real / NULLIF(count(*), 0) FROM l),
		(SELECT extract(epoch FROM percentile_cont(0.5) WITHIN GROUP (ORDER BY took))::int FROM v),
		(SELECT max(k.created_at) FROM exploration_links k JOIN l ON l.id = k.lead_id
		 WHERE k.tenant_id = $1 AND k.rel IN ('dispatched_as', 'yields'))`
}

// RefreshRollup implements exploration.RollupStore.
func (r *ExplorationRepository) RefreshRollup(ctx context.Context, tenantID, explorationID shared.ID) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO exploration_rollups (tenant_id, exploration_id, open_leads, awaiting_approval, running, blocked,
			done_30d, proven_30d, refuted_30d, dispatches_30d, rule_share, median_verdict_seconds, last_step_at, computed_at)
		SELECT $1, $2, f.*, now() FROM (`+rollupFiguresSQL(sqlTrue)+`) f
		ON CONFLICT (tenant_id, exploration_id) DO UPDATE SET
			open_leads = EXCLUDED.open_leads, awaiting_approval = EXCLUDED.awaiting_approval,
			running = EXCLUDED.running, blocked = EXCLUDED.blocked, done_30d = EXCLUDED.done_30d,
			proven_30d = EXCLUDED.proven_30d, refuted_30d = EXCLUDED.refuted_30d,
			dispatches_30d = EXCLUDED.dispatches_30d, rule_share = EXCLUDED.rule_share,
			median_verdict_seconds = EXCLUDED.median_verdict_seconds, last_step_at = EXCLUDED.last_step_at,
			computed_at = EXCLUDED.computed_at`, tenantID.String(), explorationID.String())
	if err != nil {
		return fmt.Errorf("refresh exploration rollup: %w", err)
	}
	return nil
}

func scanSummary(sc interface{ Scan(...any) error }, withComputed bool) (*exploration.Summary, error) {
	var (
		s      exploration.Summary
		share  sql.NullFloat64
		median sql.NullInt64
		last   sql.NullTime
	)
	dest := []any{&s.Open, &s.AwaitingApproval, &s.Running, &s.Blocked, &s.Done30d, &s.Proven30d, &s.Refuted30d,
		&s.Dispatches30d, &share, &median, &last}
	if withComputed {
		dest = append(dest, &s.ComputedAt)
	}
	if err := sc.Scan(dest...); err != nil {
		return nil, err
	}
	if share.Valid {
		s.RuleShare = &share.Float64
	}
	if median.Valid {
		m := int(median.Int64)
		s.MedianVerdictSeconds = &m
	}
	if last.Valid {
		s.LastStepAt = &last.Time
	}
	return &s, nil
}

// Rollup implements exploration.RollupStore.
func (r *ExplorationRepository) Rollup(ctx context.Context, tenantID, explorationID shared.ID) (*exploration.Summary, error) {
	s, err := scanSummary(r.db.QueryRowContext(ctx, `
		SELECT open_leads, awaiting_approval, running, blocked, done_30d, proven_30d, refuted_30d, dispatches_30d,
		       rule_share, median_verdict_seconds, last_step_at, computed_at
		FROM exploration_rollups WHERE tenant_id = $1 AND exploration_id = $2`, tenantID.String(), explorationID.String()), true)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read exploration rollup: %w", err)
	}
	return s, nil
}

// ScopedSummary implements exploration.RollupStore.
func (r *ExplorationRepository) ScopedSummary(ctx context.Context, tenantID, explorationID shared.ID, scope *shared.DataScope) (*exploration.Summary, error) {
	cond, args := dataScopeCond(leadScopeAsset, scope, []any{tenantID.String(), explorationID.String()})
	s, err := scanSummary(r.db.QueryRowContext(ctx, rollupFiguresSQL(cond), args...), false)
	if err != nil {
		return nil, fmt.Errorf("read scoped exploration summary: %w", err)
	}
	s.Scoped = true
	return s, nil
}
