package coverage

// Discovery management (docs/architecture/easm.md, "Discovery management"):
// the tenant's coverage work grouped into four stages, with Run per
// stage, Run all and Abort all. It adds no scheduler and never dispatches by
// itself:
//
//   - Run makes the stage's covered, due and failed pairs due now (queued,
//     blocked, paused and not applicable pairs are left alone, so readiness
//     pauses, not-claimed holds and gate refusals still hold). The coverage
//     loop, which runs on one replica at a time, plans them on its next pass
//     through StartCoverage and the full dispatch gate, within the tenant's
//     daily budget and one active run per capability.
//   - Abort all cancels the tenant's active coverage runs through the
//     run-cancel path; the next pass settles their pairs as any canceled run.

import (
	"context"
	"errors"
	"fmt"
	"time"

	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// RunNowInterval is how often one stage of one tenant may be run by hand.
const RunNowInterval = time.Minute

// Refusals of Run.
var (
	// ErrLoopOff: the coverage loop does not run on this server
	// (ASSET_COVERAGE_ENABLED=false), so nothing would plan the pairs.
	ErrLoopOff = errors.New("the coverage loop is not running on this server")
	// ErrCoverageOff: the organization's automatic coverage is off.
	ErrCoverageOff = errors.New("automatic coverage is off for the organization")
	// ErrBudgetSpent: the tenant's daily coverage budget is used up.
	ErrBudgetSpent = errors.New("the daily coverage budget is used up")
)

// TooSoonError: every asked stage was run less than RunNowInterval ago.
type TooSoonError struct{ Until time.Time }

func (e *TooSoonError) Error() string { return "the stage was run less than a minute ago" }

// RunCanceller cancels one scan run of the tenant (scanrun.Service).
type RunCanceller interface {
	CancelRun(ctx context.Context, tenantID, runID string) error
}

// RunLimiter is the cross-replica run-now limiter: Acquire takes key for
// window (false and its expiry when it is held); AvailableAt returns the
// expiry of each held key.
type RunLimiter interface {
	Acquire(ctx context.Context, key string, window time.Duration) (bool, time.Time, error)
	AvailableAt(ctx context.Context, keys []string) (map[string]time.Time, error)
}

// BudgetReader counts the pairs attempted since t (the daily budget).
type BudgetReader interface {
	AttemptsSince(ctx context.Context, tenantID shared.ID, t time.Time) (int, error)
}

// DiscoveryConfig are the coverage loop's settings the view reports.
type DiscoveryConfig struct {
	// LoopEnabled: ASSET_COVERAGE_ENABLED.
	LoopEnabled bool
	// Interval is how often the loop passes.
	Interval    time.Duration
	DailyBudget int
}

// Discovery serves the discovery stages.
type Discovery struct {
	store   covdom.DiscoveryStore
	budget  BudgetReader
	sw      TenantSwitch
	cancel  RunCanceller
	limiter RunLimiter
	rules   []covdom.Rule
	cfg     DiscoveryConfig
	now     func() time.Time
	logger  *logger.Logger
}

// NewDiscovery creates the service. sw decides the organization's automatic
// coverage (GovernanceSwitch); a nil switch is off (fail closed).
func NewDiscovery(store covdom.DiscoveryStore, budget BudgetReader, sw TenantSwitch, cancel RunCanceller,
	limiter RunLimiter, cfg DiscoveryConfig, log *logger.Logger,
) *Discovery {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	if cfg.DailyBudget <= 0 {
		cfg.DailyBudget = DefaultDailyBudget
	}
	return &Discovery{store: store, budget: budget, sw: sw, cancel: cancel, limiter: limiter,
		rules: covdom.Rules(), cfg: cfg, now: time.Now, logger: log.With("component", "discovery-management")}
}

// Overview is the discovery stages as shown to the organization.
type Overview struct {
	GeneratedAt     time.Time
	LoopEnabled     bool
	CoverageEnabled bool
	PassEvery       time.Duration
	DailyBudget     int
	BudgetUsed      int
	Stages          []covdom.StageSummary
	// RunAvailableAt is, per stage, when Run is allowed again (absent: now).
	RunAvailableAt map[covdom.DiscoveryStage]time.Time
	AutoValidation covdom.AutoValidation
}

func (d *Discovery) planned() []string { return plannedCapabilities(d.rules) }

func (d *Discovery) enabled(ctx context.Context, tenantID shared.ID) (bool, error) {
	if d.sw == nil {
		return false, nil
	}
	return d.sw.CoverageEnabled(ctx, tenantID)
}

func runKey(tenantID shared.ID, stage covdom.DiscoveryStage) string {
	return "easm_discovery_run:" + tenantID.String() + ":" + string(stage)
}

// Overview reads the tenant's discovery stages.
func (d *Discovery) Overview(ctx context.Context, tenantID shared.ID) (*Overview, error) {
	on, err := d.enabled(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("read coverage setting: %w", err)
	}
	planned := d.planned()
	stats, err := d.store.DiscoveryStats(ctx, tenantID, covdom.DiscoveryCapabilities(planned, covdom.DiscoveryStages()...))
	if err != nil {
		return nil, err
	}
	used, err := d.budget.AttemptsSince(ctx, tenantID, d.now().Add(-24*time.Hour))
	if err != nil {
		return nil, err
	}
	auto, err := d.store.LastAutoValidation(ctx, tenantID, covdom.DiscoveryCapabilities(planned, covdom.StageValidation))
	if err != nil {
		return nil, err
	}
	o := &Overview{GeneratedAt: d.now().UTC(), LoopEnabled: d.cfg.LoopEnabled, CoverageEnabled: on,
		PassEvery: d.cfg.Interval, DailyBudget: d.cfg.DailyBudget, BudgetUsed: used,
		RunAvailableAt: map[covdom.DiscoveryStage]time.Time{}, AutoValidation: auto}
	keys := make([]string, 0, 4)
	for _, st := range covdom.DiscoveryStages() {
		var caps []covdom.CapabilityDiscovery
		for _, c := range covdom.DiscoveryCapabilities(planned, st) {
			row := covdom.CapabilityDiscovery{Capability: c, Stage: st}
			for _, s := range stats {
				if s.Capability == c {
					row = s
				}
			}
			caps = append(caps, row)
		}
		o.Stages = append(o.Stages, covdom.SummarizeStage(st, caps, !on))
		keys = append(keys, runKey(tenantID, st))
	}
	if d.limiter != nil {
		until, err := d.limiter.AvailableAt(ctx, keys)
		if err != nil {
			return nil, err
		}
		for _, st := range covdom.DiscoveryStages() {
			if t, ok := until[runKey(tenantID, st)]; ok && t.After(d.now()) {
				o.RunAvailableAt[st] = t
			}
		}
	}
	return o, nil
}

// RunResult is what a Run did.
type RunResult struct {
	// Started are the stages whose pairs were made due; Skipped the ones
	// run less than RunNowInterval ago (Run all only).
	Started []covdom.DiscoveryStage
	Skipped []covdom.DiscoveryStage
	// Capabilities are the capabilities of the started stages.
	Capabilities []string
	// PairsMadeDue counts the pairs whose due time moved.
	PairsMadeDue int
	// NextPassWithin is the loop's interval: the pass that plans them
	// starts within it.
	NextPassWithin time.Duration
}

// Run makes the stages' pairs due now (see the file comment). It refuses
// when the loop is off, the organization's automatic coverage is off or the
// daily budget is spent; a stage run less than RunNowInterval ago is skipped,
// and when every asked stage is, it returns *TooSoonError.
func (d *Discovery) Run(ctx context.Context, tenantID shared.ID, stages []covdom.DiscoveryStage) (*RunResult, error) {
	for _, st := range stages {
		if !st.Valid() {
			return nil, fmt.Errorf("%w: unknown discovery stage", shared.ErrValidation)
		}
	}
	if len(stages) == 0 {
		return nil, fmt.Errorf("%w: no discovery stage", shared.ErrValidation)
	}
	if !d.cfg.LoopEnabled {
		return nil, ErrLoopOff
	}
	on, err := d.enabled(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("read coverage setting: %w", err)
	}
	if !on {
		return nil, ErrCoverageOff
	}
	used, err := d.budget.AttemptsSince(ctx, tenantID, d.now().Add(-24*time.Hour))
	if err != nil {
		return nil, err
	}
	if used >= d.cfg.DailyBudget {
		return nil, ErrBudgetSpent
	}
	if d.limiter == nil {
		return nil, errors.New("discovery run limiter not configured")
	}
	res := &RunResult{NextPassWithin: d.cfg.Interval}
	var soonest time.Time
	for _, st := range stages {
		ok, until, err := d.limiter.Acquire(ctx, runKey(tenantID, st), RunNowInterval)
		if err != nil {
			return nil, err
		}
		if !ok {
			res.Skipped = append(res.Skipped, st)
			if soonest.IsZero() || until.Before(soonest) {
				soonest = until
			}
			continue
		}
		res.Started = append(res.Started, st)
	}
	if len(res.Started) == 0 {
		return nil, &TooSoonError{Until: soonest}
	}
	res.Capabilities = covdom.DiscoveryCapabilities(d.planned(), res.Started...)
	waits := make(map[string]time.Duration, len(res.Capabilities))
	for _, c := range res.Capabilities {
		waits[c] = covdom.RunNowWait(d.ruleOf(c).Every)
	}
	n, err := d.store.MakeDueNow(ctx, tenantID, waits)
	if err != nil {
		return nil, err
	}
	res.PairsMadeDue = n
	d.logger.Info("discovery stages made due", "tenant_id", tenantID.String(), "stages", len(res.Started), "pairs", n)
	return res, nil
}

func (d *Discovery) ruleOf(capability string) covdom.Rule {
	for _, r := range d.rules {
		if r.Capability == capability {
			return r
		}
	}
	return covdom.Rule{Capability: capability, Every: 24 * time.Hour}
}

// AbortResult is what Abort all did.
type AbortResult struct {
	Canceled int
	// Failed counts runs the cancel refused (finished meanwhile) or that
	// failed; they are left to the loop.
	Failed int
}

// AbortAll cancels the tenant's active coverage runs through the run-cancel
// path (its own audit entry per run, sensors told to stop). Runs of
// people's scans are never touched: only runs of the tenant's managed
// coverage scans are listed.
func (d *Discovery) AbortAll(ctx context.Context, tenantID shared.ID) (*AbortResult, error) {
	if d.cancel == nil {
		return nil, errors.New("run cancel not configured")
	}
	runs, err := d.store.ActiveCoverageRuns(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	res := &AbortResult{}
	for _, id := range runs {
		if err := d.cancel.CancelRun(ctx, tenantID.String(), id.String()); err != nil {
			res.Failed++
			d.logger.Warn("coverage run not canceled", "tenant_id", tenantID.String(), "run_id", id.String(),
				"error", logger.SanitizeError(err))
			continue
		}
		res.Canceled++
	}
	return res, nil
}
