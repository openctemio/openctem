package coverage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
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

// settle settles the queued pairs of every finished run of the tenant, per
// target: from what happened to each pair's own target across every task of
// the run (claim-time splits and follow-ups included), never from the run's
// overall status. A target no task carried fails as not dispatched, with the
// run's error; a run unfinished after a day fails its pairs as stalled.
func (s *Service) settle(ctx context.Context, tenantID shared.ID) (int, error) {
	runs, err := s.planner.QueuedRuns(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, rs := range runs {
		stalled := false
		switch rs.Status {
		case "completed", "partial", "failed", "canceled", "timeout", "blocked":
		default:
			if s.now().Sub(rs.QueuedAt) < StallAfter {
				continue // still running
			}
			stalled = true
		}
		n, err := s.settleRun(ctx, tenantID, rs, stalled)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (s *Service) settleRun(ctx context.Context, tenantID shared.ID, rs covdom.RunState, stalled bool) (int, error) {
	rule := s.ruleOf(rs.Capability)
	queued, err := s.planner.QueuedTargets(ctx, tenantID, rs.RunID, rs.Capability)
	if err != nil {
		return 0, err
	}
	var verdicts map[string]covdom.Verdict
	if !stalled {
		tasks, err := s.planner.RunTasks(ctx, tenantID, rs.RunID)
		if err != nil {
			return 0, err
		}
		verdicts = covdom.Verdicts(tasks, rs.Unfinished)
	}
	var covered []shared.ID
	var failed []covdom.FailedPair
	blocked := map[shared.ID]string{}
	for _, d := range queued {
		v, ok := verdicts[covdom.TargetKey(d.Target())]
		switch {
		case stalled:
			failed = append(failed, covdom.FailedPair{AssetID: d.AssetID, Outcome: covdom.OutcomeStalled,
				Error: "the run did not finish within a day"})
		case !ok:
			msg := rs.Error
			if msg == "" {
				msg = "no task of the run carried this target"
			}
			failed = append(failed, covdom.FailedPair{AssetID: d.AssetID, Outcome: covdom.OutcomeNotDispatched, Error: msg})
		case v.Kind == covdom.VerdictCovered:
			covered = append(covered, d.AssetID)
		case v.Kind == covdom.VerdictBlocked:
			blocked[d.AssetID] = v.Reason
		default:
			msg := v.Error
			if msg == "" {
				msg = rs.Error
			}
			failed = append(failed, covdom.FailedPair{AssetID: d.AssetID, Outcome: v.Outcome, Error: msg})
		}
	}
	n, err := s.planner.SettleCovered(ctx, tenantID, rs.RunID, rs.Capability, covered, rule.Every, rule.Expects == "http_service")
	if err != nil {
		return n, err
	}
	k, err := s.planner.SettleFailed(ctx, tenantID, rs.RunID, rs.Capability, failed, rule.Every)
	n += k
	if err != nil {
		return n, err
	}
	if err := s.planner.MarkBlocked(ctx, tenantID, rs.Capability, blocked, BlockedRecheck); err != nil {
		return n, err
	}
	return n + len(blocked), nil
}

// ReasonRepositoryCodeOnly blocks a pair of a repository and a capability
// that takes network kinds: a repository is scanned by code tools only, a
// network tool would probe the code host.
const ReasonRepositoryCodeOnly = "repository_code_only"

// blockRepositories takes out of a due batch every repository (by its
// stored type, or a name in the path form) when the capability's stage
// takes network kinds, and blocks those pairs with the reason. The policy
// gives repositories no network capability; this keeps a stray ledger row
// from ever sending one to a network tool.
func (s *Service) blockRepositories(ctx context.Context, tenantID shared.ID, capability string, due []covdom.DueTarget) ([]covdom.DueTarget, error) {
	st, ok := stage.Lookup(stage.Key(capability))
	if !ok || !st.TakesNetworkKinds() || len(due) == 0 {
		return due, nil
	}
	kept := make([]covdom.DueTarget, 0, len(due))
	blocked := map[shared.ID]string{}
	for _, d := range due {
		if stage.IsRepositoryType(asset.TypeRef{Type: d.Type, SubType: d.SubType}) || stage.ClassifyTarget(d.Target()) == stage.KindPath {
			blocked[d.AssetID] = ReasonRepositoryCodeOnly
			continue
		}
		kept = append(kept, d)
	}
	if len(blocked) == 0 {
		return due, nil
	}
	if err := s.planner.MarkBlocked(ctx, tenantID, capability, blocked, BlockedRecheck); err != nil {
		return nil, err
	}
	s.logger.Warn("SECURITY: repositories left out of a network coverage batch", "tenant_id", tenantID.String(),
		"capability", capability, "count", len(blocked))
	return kept, nil
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
		if due, err = s.blockRepositories(ctx, tenantID, capability, due); err != nil {
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
			// A refusal of the whole batch (zone coverage, approval, a scan
			// that may not be triggered) blocks its pairs with the code and
			// rechecks later; retrying it every pass changes nothing. Any
			// other error (the database) leaves them due.
			var de *shared.DomainError
			if errors.As(err, &de) && de.Code != "" {
				blocked := make(map[shared.ID]string, len(due))
				for _, d := range due {
					blocked[d.AssetID] = strings.ToLower(de.Code)
				}
				if err := s.planner.MarkBlocked(ctx, tenantID, capability, blocked, BlockedRecheck); err != nil {
					return total, err
				}
				s.logger.Info("coverage batch refused, pairs blocked", "tenant_id", tenantID.String(),
					"capability", capability, "targets", len(targets), "code", de.Code)
				continue
			}
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
