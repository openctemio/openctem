package postgres

// Learned per-target durations: research/122 and
// pkg/domain/toolbudget/learned.go.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/toolbudget"
)

// ToolDurationStatsRepository keeps the learned per-target durations.
type ToolDurationStatsRepository struct {
	db *DB
}

var _ toolbudget.StatsStore = (*ToolDurationStatsRepository)(nil)

// NewToolDurationStatsRepository returns the repository.
func NewToolDurationStatsRepository(db *DB) *ToolDurationStatsRepository {
	return &ToolDurationStatsRepository{db: db}
}

// learnRate is the weight of a new sample in the decayed mean.
const learnRate = 0.2

// ObservePerTarget folds one sample into (tenantID, tool) in one statement:
// the mean moves toward the sample by learnRate; the p95 estimate moves up by
// 0.95 or down by 0.05 of half the mean (it settles where 5% of the samples
// are above it). Both stay within [floor, ceiling].
func (r *ToolDurationStatsRepository) ObservePerTarget(ctx context.Context, tenantID shared.ID, tool string, sample, floor, ceiling time.Duration) error {
	tool = strings.ToLower(strings.TrimSpace(tool))
	if tool == "" || len(tool) > 100 || sample <= 0 {
		return nil
	}
	ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
	s, lo, hi := ms(max(floor, min(ceiling, sample))), ms(floor), ms(ceiling)
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO tool_duration_stats AS t (tenant_id, tool, samples, mean_ms, p95_ms, updated_at)
		VALUES ($1, $2, 1, $3, $3, NOW())
		ON CONFLICT (tenant_id, tool) DO UPDATE SET
		    samples = LEAST(t.samples, 1000000) + 1,
		    mean_ms = LEAST(GREATEST(t.mean_ms + $6 * ($3 - t.mean_ms), $4), $5),
		    p95_ms = LEAST(GREATEST(t.p95_ms
		        + (CASE WHEN $3 > t.p95_ms THEN 0.95 ELSE -0.05 END) * GREATEST(t.mean_ms, 1) * 0.5, $4), $5),
		    updated_at = NOW()`,
		tenantID.String(), tool, s, lo, hi, learnRate)
	if err != nil {
		return fmt.Errorf("failed to record a tool duration: %w", err)
	}
	return nil
}

// ToolStats returns what was learned for (tenantID, tool).
func (r *ToolDurationStatsRepository) ToolStats(ctx context.Context, tenantID shared.ID, tool string) (toolbudget.Stats, bool, error) {
	var (
		n         int
		mean, p95 float64
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT samples, mean_ms, p95_ms FROM tool_duration_stats WHERE tenant_id = $1 AND tool = $2`,
		tenantID.String(), strings.ToLower(strings.TrimSpace(tool))).Scan(&n, &mean, &p95)
	if errors.Is(err, sql.ErrNoRows) {
		return toolbudget.Stats{}, false, nil
	}
	if err != nil {
		return toolbudget.Stats{}, false, fmt.Errorf("failed to read tool duration stats: %w", err)
	}
	d := func(ms float64) time.Duration { return time.Duration(ms * float64(time.Millisecond)) }
	return toolbudget.Stats{Samples: n, Mean: d(mean), P95: d(p95)}, true, nil
}
