package toolbudget

// Learned per-target durations (research/122 §6.0.1, the data loop): every
// completed scan command is one sample of its tool's time per target for its
// tenant; the platform keeps a decayed mean and p95 per (tenant, tool) and
// sizes the next jobs' budgets from them. Every sample and every learned value
// is clamped to the tool's [Floor, Ceiling], so a slow or hostile target or
// sensor cannot stretch a budget without bound; failed, canceled and
// re-queued attempts are never samples.

import (
	"context"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MinLearnedSamples is how many samples a learned value needs before it
// replaces the tool's default.
const MinLearnedSamples = 5

// Stats is what the platform learned about one tool in one tenant.
type Stats struct {
	Samples int
	// Mean and P95 are per target, decayed (recent runs weigh more).
	Mean, P95 time.Duration
}

// StatsStore keeps the learned per-target durations, per tenant and tool.
type StatsStore interface {
	// ObservePerTarget folds one completed command's per-target time into
	// (tenantID, tool); sample, floor and ceiling are already the tool's.
	ObservePerTarget(ctx context.Context, tenantID shared.ID, tool string, sample, floor, ceiling time.Duration) error
	// ToolStats returns what was learned for (tenantID, tool); ok is false
	// when nothing was.
	ToolStats(ctx context.Context, tenantID shared.ID, tool string) (Stats, bool, error)
}

// Sample is one completed command's time per target: its duration over its
// targets, times the targets the tool works on at once, within [Floor,
// Ceiling]. ok is false when there is nothing to learn (no target, no time).
func (b Budget) Sample(d time.Duration, targets int) (time.Duration, bool) {
	if d <= 0 || targets <= 0 {
		return 0, false
	}
	per := d * time.Duration(min(b.Concurrency, targets)) / time.Duration(targets)
	return max(b.Floor, min(b.Ceiling, per)), true
}

// WithStats is the budget with what was learned: once there are
// MinLearnedSamples samples, the expected time per target becomes half the
// learned p95 (so the per-target budget, three expected times, is 1.5 × p95),
// within [Floor, Ceiling]. Fewer samples keep the default.
func (b Budget) WithStats(s Stats) Budget {
	if s.Samples < MinLearnedSamples || s.P95 <= 0 {
		return b
	}
	b.Expected = max(b.Floor, min(b.Ceiling, s.P95/2))
	return b
}

// Lookup is the budget of tool in tenantID: its default with what the
// platform learned (WithStats). A store error or no store gives the default:
// a budget is never unavailable. The target pool sizes claim-time tasks with
// it, the planner sizes commands with it.
func Lookup(ctx context.Context, store StatsStore, tenantID shared.ID, tool string) Budget {
	b := For(tool)
	if store == nil {
		return b
	}
	s, ok, err := store.ToolStats(ctx, tenantID, normalize(tool))
	if err != nil || !ok {
		return b
	}
	return b.WithStats(s)
}

// normalize is the key a tool's stats are kept under.
func normalize(tool string) string { return strings.ToLower(strings.TrimSpace(tool)) }
