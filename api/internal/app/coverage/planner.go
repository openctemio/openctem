package coverage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Planning bounds. A batch is one run of one capability; a tenant has at
// most one active run per capability (the next batch waits), and a daily
// budget of attempted pairs.
const (
	DefaultBatch       = 200
	DefaultDailyBudget = 5000
	// BlockedRecheck is when a pair the gate refused is tried again (scope
	// may have changed).
	BlockedRecheck = 6 * time.Hour
	// StallAfter fails a queued pair whose run never finished.
	StallAfter = 24 * time.Hour
)

// RunStarter starts one capability on a batch of targets (scan.Service).
type RunStarter interface {
	StartCoverage(ctx context.Context, in scanapp.CoverageInput) (*scanapp.CoverageResult, error)
}

// TenantSwitch says whether automatic coverage runs for a tenant.
type TenantSwitch interface {
	CoverageEnabled(ctx context.Context, tenantID shared.ID) (bool, error)
}

// Config bounds the planner.
type Config struct {
	Batch       int
	DailyBudget int
}

// EnablePlanning wires dispatch. Without it the service only reconciles.
func (s *Service) EnablePlanning(planner covdom.Planner, starter RunStarter, sw TenantSwitch, cfg Config) {
	if cfg.Batch <= 0 || cfg.Batch > 500 {
		cfg.Batch = DefaultBatch
	}
	if cfg.DailyBudget <= 0 {
		cfg.DailyBudget = DefaultDailyBudget
	}
	s.planner, s.starter, s.tenantSwitch, s.cfg = planner, starter, sw, cfg
}

// plannedCapabilities are the capabilities of the policy the planner
// starts: stages up to the active tier. Platform checks (dns.*) run on
// their own schedule and write the ledger themselves.
func plannedCapabilities(rules []covdom.Rule) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		st, ok := stage.Lookup(stage.Key(r.Capability))
		if !ok || st.Tier >= stage.TierIntrusive || seen[r.Capability] {
			continue
		}
		seen[r.Capability] = true
		out = append(out, r.Capability)
	}
	return out
}

// ruleOf returns the rule of a capability (the first: cadences of one
// capability are the same across types in the default policy; settlement
// uses it for the next due time and the output check).
func (s *Service) ruleOf(capability string) covdom.Rule {
	for _, r := range s.rules {
		if r.Capability == capability {
			return r
		}
	}
	return covdom.Rule{Capability: capability, Every: 24 * time.Hour}
}

// settle settles the queued pairs of every finished run of the tenant.
func (s *Service) settle(ctx context.Context, tenantID shared.ID) (int, error) {
	runs, err := s.planner.QueuedRuns(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, rs := range runs {
		var success bool
		switch rs.Status {
		case "completed", "partial":
			success = true
		case "failed", "canceled", "timeout", "blocked":
		default:
			if s.now().Sub(rs.QueuedAt) < StallAfter {
				continue // still running
			}
			rs.Error = "the run did not finish within a day"
		}
		var unfinished []shared.ID
		if success && len(rs.Unfinished) > 0 {
			if unfinished, err = s.unfinishedAssets(ctx, tenantID, rs); err != nil {
				return total, err
			}
		}
		n, err := s.planner.SettleRun(ctx, tenantID, rs, s.ruleOf(rs.Capability), success, unfinished)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// unfinishedAssets maps a run's unfinished targets back to the queued pairs'
// assets.
func (s *Service) unfinishedAssets(ctx context.Context, tenantID shared.ID, rs covdom.RunState) ([]shared.ID, error) {
	want := map[string]bool{}
	for _, t := range rs.Unfinished {
		want[strings.ToLower(t)] = true
	}
	queued, err := s.planner.QueuedTargets(ctx, tenantID, rs.RunID, rs.Capability)
	if err != nil {
		return nil, err
	}
	var out []shared.ID
	for _, d := range queued {
		if want[strings.ToLower(d.Target())] {
			out = append(out, d.AssetID)
		}
	}
	return out, nil
}

// plan starts every planned capability on its due pairs, within the
// tenant's daily budget.
func (s *Service) plan(ctx context.Context, tenantID shared.ID) (int, error) {
	used, err := s.planner.AttemptsSince(ctx, tenantID, s.now().Add(-24*time.Hour))
	if err != nil {
		return 0, err
	}
	left := s.cfg.DailyBudget - used
	total := 0
	for _, capability := range plannedCapabilities(s.rules) {
		if left <= 0 {
			break
		}
		due, err := s.planner.DueBatch(ctx, tenantID, capability, min(s.cfg.Batch, left))
		if err != nil {
			return total, err
		}
		if len(due) == 0 {
			continue
		}
		byTarget := make(map[string][]shared.ID, len(due))
		targets := make([]string, 0, len(due))
		for _, d := range due {
			t := d.Target()
			key := strings.ToLower(t)
			if _, dup := byTarget[key]; !dup {
				targets = append(targets, t)
			}
			byTarget[key] = append(byTarget[key], d.AssetID)
		}
		res, err := s.starter.StartCoverage(ctx, scanapp.CoverageInput{TenantID: tenantID, Capability: capability, Targets: targets})
		if errors.Is(err, scanapp.ErrCoverageBusy) {
			continue // the previous batch is still running: back-pressure
		}
		if err != nil {
			s.logger.Warn("coverage run not started", "tenant_id", tenantID.String(), "capability", capability,
				"targets", len(targets), "error", logger.SanitizeError(err))
			continue
		}
		blocked := map[shared.ID]string{}
		for _, r := range res.Refused {
			code := r.Code
			if code == "" {
				code = "refused"
			}
			for _, id := range byTarget[strings.ToLower(strings.TrimSpace(r.Target))] {
				blocked[id] = code
			}
		}
		if err := s.planner.MarkBlocked(ctx, tenantID, capability, blocked, BlockedRecheck); err != nil {
			return total, err
		}
		if res.RunID != nil {
			kept := make([]shared.ID, 0, len(res.Kept))
			for _, t := range res.Kept {
				kept = append(kept, byTarget[strings.ToLower(t)]...)
			}
			if err := s.planner.MarkQueued(ctx, tenantID, capability, kept, *res.RunID, res.Tool); err != nil {
				return total, fmt.Errorf("record queued coverage: %w", err)
			}
			total += len(kept)
			left -= len(kept)
		}
	}
	return total, nil
}
