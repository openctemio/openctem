package coverage

// Path discovery in the coverage loop (docs/architecture/web-discovery.md).
// enumerate.web_paths is an ordinary coverage capability of web services
// (30-day cadence, an origin scope entry, new inventory since the last run,
// no edge challenge: asset-types.yaml), with three things on top that this
// file decides before a batch starts:
//
//   - the organization's switch (scope settings path_discovery, default on);
//     off pauses the pairs (switched_off), never covers them;
//   - the daily request budget: a batch holds at most as many origins as the
//     budget left allows at the per-origin cap; the rest is paused as
//     deferred (budget) and resumes when the budget allows;
//   - per target refusals: a bug bounty program that forbids brute force or
//     automated scanning, or an address origin on a shared edge network, is
//     blocked with the reason (labeled, rechecked later), never dispatched.
//
// Fail closed: without the gate wired the capability is never planned.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/edgeaddr"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Refusal reasons of a path discovery pair.
const (
	ReasonProgramForbidsEnumeration = "program_forbids_enumeration"
	ReasonSharedEdgeAddress         = "shared_edge_address"
	ReasonProgramRulesConflict      = "program_rules_conflict"
)

// Defaults of path discovery's budgets (the platform default layer; the
// server may set others from its configuration).
const (
	DefaultPathRequestsPerOrigin = 300
	DefaultPathDailyRequests     = 50_000
	// pathBudgetRetry is when deferred pairs are offered again.
	pathBudgetRetry = time.Hour
)

// PathBudget is path discovery's request budget for one organization.
type PathBudget struct {
	// PerOrigin is the request cap of one origin's job (signed into its web
	// scope); one run per origin per cadence.
	PerOrigin int
	// Daily is the organization's request budget per rolling day.
	Daily int
}

// PathDiscoveryGate answers what path discovery may do for a tenant.
type PathDiscoveryGate interface {
	PathDiscoveryEnabled(ctx context.Context, tenantID shared.ID) (bool, error)
	PathDiscoveryBudget(ctx context.Context, tenantID shared.ID) (PathBudget, error)
	// PathDiscoveryRefusals maps the targets that may not be dispatched to
	// the reason (the rest are absent).
	PathDiscoveryRefusals(ctx context.Context, tenantID shared.ID, targets []string) (map[string]string, error)
}

// AttemptCounter counts a capability's pairs attempted since t.
type AttemptCounter interface {
	CapabilityAttemptsSince(ctx context.Context, tenantID shared.ID, capability string, t time.Time) (int, error)
}

// SetPathDiscovery wires path discovery's gate and the attempt counter its
// daily budget reads. Unwired, path discovery is never planned.
func (s *Service) SetPathDiscovery(g PathDiscoveryGate, attempts AttemptCounter) {
	s.pathGate, s.pathAttempts = g, attempts
}

// pathDiscoveryLimit is how many origins the next path discovery batch may
// hold (stop: none this pass; the pairs were paused with the reason when
// that applies).
func (s *Service) pathDiscoveryLimit(ctx context.Context, tenantID shared.ID, limit int) (int, bool, error) {
	if s.pathGate == nil || s.pathAttempts == nil {
		return 0, true, nil
	}
	on, err := s.pathGate.PathDiscoveryEnabled(ctx, tenantID)
	if err != nil {
		return 0, true, err
	}
	if !on {
		return 0, true, s.pauseCapability(ctx, tenantID, covdom.CapabilityEnumerateWebPaths, covdom.ReadySwitchedOff, 0)
	}
	b, err := s.pathGate.PathDiscoveryBudget(ctx, tenantID)
	if err != nil {
		return 0, true, err
	}
	if b.PerOrigin <= 0 || b.Daily <= 0 {
		return 0, true, s.pauseCapability(ctx, tenantID, covdom.CapabilityEnumerateWebPaths, covdom.ReadyBudgetSpent, pathBudgetRetry)
	}
	used, err := s.pathAttempts.CapabilityAttemptsSince(ctx, tenantID, covdom.CapabilityEnumerateWebPaths, s.now().Add(-24*time.Hour))
	if err != nil {
		return 0, true, err
	}
	fit := (b.Daily - used*b.PerOrigin) / b.PerOrigin
	if fit <= 0 {
		return 0, true, s.pauseCapability(ctx, tenantID, covdom.CapabilityEnumerateWebPaths, covdom.ReadyBudgetSpent, pathBudgetRetry)
	}
	return min(limit, fit), false, nil
}

// pathDiscoveryRefuse blocks the due pairs the gate refuses and returns the
// rest. A gate error refuses the whole batch (fail closed).
func (s *Service) pathDiscoveryRefuse(ctx context.Context, tenantID shared.ID, due []covdom.DueTarget) ([]covdom.DueTarget, error) {
	targets := make([]string, 0, len(due))
	for _, d := range due {
		targets = append(targets, d.Target())
	}
	refused, err := s.pathGate.PathDiscoveryRefusals(ctx, tenantID, targets)
	if err != nil {
		return nil, err
	}
	if len(refused) == 0 {
		return due, nil
	}
	kept := make([]covdom.DueTarget, 0, len(due))
	blocked := map[shared.ID]string{}
	for _, d := range due {
		if why, ok := refused[d.Target()]; ok {
			blocked[d.AssetID] = why
			continue
		}
		kept = append(kept, d)
	}
	if err := s.planner.MarkBlocked(ctx, tenantID, covdom.CapabilityEnumerateWebPaths, blocked, BlockedRecheck); err != nil {
		return nil, err
	}
	s.logger.Info("path discovery targets refused", "tenant_id", tenantID.String(), "refused", len(blocked), "remaining", len(kept))
	return kept, nil
}

// ProgramRuleSource answers the bug bounty program rules a job on targets
// carries (*bountyprogram.Service).
type ProgramRuleSource interface {
	JobRules(ctx context.Context, tenantID shared.ID, targets []string, now time.Time) (*bp.JobRules, error)
}

// PathDiscoveryPolicy is the server's PathDiscoveryGate: the switch from the
// organization's scope settings, the budget from the platform default, the
// program rules and the shared edge classification.
type PathDiscoveryPolicy struct {
	Settings ScopeSettingsReader
	Programs ProgramRuleSource // nil: no program applies
	Edge     *edgeaddr.Classifier
	Budget   PathBudget
	Log      *logger.Logger
}

// PathDiscoveryEnabled reads the organization's switch (default on). A read
// error is off (fail closed).
func (p PathDiscoveryPolicy) PathDiscoveryEnabled(ctx context.Context, tenantID shared.ID) (bool, error) {
	if p.Settings == nil {
		return false, nil
	}
	ss, err := p.Settings.GetScopeSettings(ctx, tenantID.String())
	if err != nil {
		return false, err
	}
	if ss == nil {
		return true, nil
	}
	return ss.PathDiscoveryOn(), nil
}

// PathDiscoveryBudget returns the platform budget, defaulted.
func (p PathDiscoveryPolicy) PathDiscoveryBudget(context.Context, shared.ID) (PathBudget, error) {
	b := p.Budget
	if b.PerOrigin <= 0 {
		b.PerOrigin = DefaultPathRequestsPerOrigin
	}
	if b.Daily <= 0 {
		b.Daily = DefaultPathDailyRequests
	}
	return b, nil
}

// PathDiscoveryRefusals refuses a target a covering program forbids
// enumeration on, and an address origin on a shared edge network.
func (p PathDiscoveryPolicy) PathDiscoveryRefusals(ctx context.Context, tenantID shared.ID, targets []string) (map[string]string, error) {
	out := map[string]string{}
	edge := p.Edge
	if edge == nil {
		edge = edgeaddr.Default()
	}
	for _, t := range targets {
		if addr, ok := addressHost(t); ok {
			if _, shared := edge.SharedFrontEnd(addr.String()); shared {
				out[t] = ReasonSharedEdgeAddress
				continue
			}
		}
		if p.Programs == nil {
			continue
		}
		r, err := p.Programs.JobRules(ctx, tenantID, []string{t}, time.Now())
		if errors.Is(err, bp.ErrRulesConflict) {
			out[t] = ReasonProgramRulesConflict
			continue
		}
		if err != nil {
			// A conflict or a read error: not dispatched now.
			return nil, fmt.Errorf("program rules: %w", err)
		}
		if r.EnumerationRefusal() != "" {
			out[t] = ReasonProgramForbidsEnumeration
		}
	}
	return out, nil
}

// addressHost is the host of a URL target when it is an IP address.
func addressHost(target string) (netip.Addr, bool) {
	u, err := url.Parse(strings.TrimSpace(target))
	if err != nil {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(u.Hostname())
	return a, err == nil
}
