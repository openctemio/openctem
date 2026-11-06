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
// The same gate (PathDiscoveryPolicy) serves every caller of path discovery:
// the planner here, a workflow's paths step (scanrun) and the web job guard
// every job passes before it is stored (scope.WebJobGuard), which is also
// where the dispatch is claimed in the path discovery ledger. The checks are
// the switch, the daily request budget, an active scope entry naming the
// origin's host, the shared edge and program refusals, an edge that did not
// challenge the last probe, new inventory, and the per-origin 30 day floor of
// the ledger, so the request cap per origin holds whoever asks.
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
	// PathDiscoveryFit is how many more origins the organization's daily
	// request budget holds at the per-origin cap.
	PathDiscoveryFit(ctx context.Context, tenantID shared.ID) (int, error)
	// PathDiscoveryRefusals maps the targets that may not be dispatched to
	// the reason (the rest are absent).
	PathDiscoveryRefusals(ctx context.Context, tenantID shared.ID, targets []string) (map[string]string, error)
}

// SetPathDiscovery wires path discovery's gate. Unwired, path discovery is
// never planned.
func (s *Service) SetPathDiscovery(g PathDiscoveryGate) { s.pathGate = g }

// pathDiscoveryLimit is how many origins the next path discovery batch may
// hold (stop: none this pass; the pairs were paused with the reason when
// that applies).
func (s *Service) pathDiscoveryLimit(ctx context.Context, tenantID shared.ID, limit int) (int, bool, error) {
	if s.pathGate == nil {
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
	fit, err := s.pathGate.PathDiscoveryFit(ctx, tenantID)
	if err != nil {
		return 0, true, err
	}
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
// program rules, the shared edge classification and the ledger with the
// origin facts. It is also the web job guard's dispatch gate
// (AdmitPathDispatch) and the workflow step's (PathDiscoveryRefusals).
type PathDiscoveryPolicy struct {
	Settings ScopeSettingsReader
	Programs ProgramRuleSource // nil: no program applies
	Edge     *edgeaddr.Classifier
	Budget   PathBudget
	// Ledger holds the origin facts and the dispatch record; nil refuses
	// every origin (fail closed).
	Ledger covdom.PathLedger
	Log    *logger.Logger
	Now    func() time.Time // nil: time.Now
}

func (p PathDiscoveryPolicy) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
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

// PathDiscoveryFit is how many more origins the daily request budget holds
// at the per-origin cap.
func (p PathDiscoveryPolicy) PathDiscoveryFit(ctx context.Context, tenantID shared.ID) (int, error) {
	if p.Ledger == nil {
		return 0, nil
	}
	b, _ := p.PathDiscoveryBudget(ctx, tenantID)
	granted, err := p.Ledger.PathRequestsGrantedSince(ctx, tenantID, p.now().Add(-24*time.Hour))
	if err != nil {
		return 0, err
	}
	return max((b.Daily-granted)/b.PerOrigin, 0), nil
}

// PathDiscoveryRefusals maps each target path discovery may not run on now
// to the reason: no live web service of the organization, no active scope
// entry naming its host, an edge that challenged the last probe, nothing new
// in the inventory, a run within the last 30 days (from any caller), a
// covering program that forbids enumeration, an address on a shared edge
// network. A read error refuses the whole call (fail closed).
func (p PathDiscoveryPolicy) PathDiscoveryRefusals(ctx context.Context, tenantID shared.ID, targets []string) (map[string]string, error) {
	if p.Ledger == nil {
		return nil, errors.New("path discovery ledger is not configured")
	}
	out := map[string]string{}
	origins := make([]string, 0, len(targets))
	keyOf := make(map[string]string, len(targets))
	for _, t := range targets {
		o, _, ok := covdom.PathOrigin(t)
		if !ok {
			out[t] = covdom.ReasonNotAnOrigin
			continue
		}
		keyOf[t] = o
		origins = append(origins, o)
	}
	facts, err := p.Ledger.PathOriginFacts(ctx, tenantID, origins)
	if err != nil {
		return nil, err
	}
	now := p.now()
	var rest []string
	for _, t := range targets {
		o, ok := keyOf[t]
		if !ok {
			continue
		}
		f, known := facts[o]
		switch {
		case !known:
			out[t] = covdom.ReasonNotAnOrigin
		case !f.ScopeEntry:
			out[t] = covdom.ReasonNoOriginScopeEntry
		case !f.EdgeClear:
			out[t] = covdom.ReasonEdgeChallenged
		case !f.LastDispatch.IsZero() && now.Sub(f.LastDispatch) < covdom.PathEvery:
			out[t] = covdom.ReasonPathRanRecently
		case !f.InventoryChanged:
			out[t] = covdom.ReasonInventoryUnchanged
		default:
			rest = append(rest, t)
		}
	}
	targetsRefused, err := p.targetRefusals(ctx, tenantID, rest)
	if err != nil {
		return nil, err
	}
	for t, why := range targetsRefused {
		out[t] = why
	}
	return out, nil
}

// targetRefusals refuses a target a covering program forbids enumeration on,
// and an address origin on a shared edge network.
func (p PathDiscoveryPolicy) targetRefusals(ctx context.Context, tenantID shared.ID, targets []string) (map[string]string, error) {
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

// Codes of a refused path discovery dispatch (the web job guard's refusals).
const (
	CodePathDiscoveryOff     = "PATH_DISCOVERY_OFF"
	CodePathDiscoveryRefused = "PATH_DISCOVERY_REFUSED"
)

// CheckPathDispatch is the first half of the dispatch gate of every path
// discovery job (scope.WebJobGuard, which every command passes before it is
// stored): the organization's switch, then every refusal of
// PathDiscoveryRefusals. It records nothing.
func (p PathDiscoveryPolicy) CheckPathDispatch(ctx context.Context, tenantID shared.ID, targets []string) error {
	on, err := p.PathDiscoveryEnabled(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("path discovery switch: %w", err)
	}
	if !on {
		return shared.NewDomainError(CodePathDiscoveryOff, "Path discovery is turned off for the organization (scope settings).", shared.ErrValidation)
	}
	refused, err := p.PathDiscoveryRefusals(ctx, tenantID, targets)
	if err != nil {
		return fmt.Errorf("path discovery gate: %w", err)
	}
	for _, t := range targets {
		if why, ok := refused[t]; ok {
			return shared.NewDomainError(CodePathDiscoveryRefused,
				"Path discovery does not run on this origin now: "+why+".", shared.ErrValidation)
		}
	}
	return nil
}

// ClaimPathDispatch is the second half, run LAST by the guard (after the
// refusals that follow the checks, the confined sensor and the scope build):
// the claim in the ledger (the per-origin 30 day floor, the daily request
// budget, the run's per-host budget). It returns the request cap the job
// carries: the requested one (0: the per-origin budget), at most the
// per-origin budget and at most what the budgets left. It is all or nothing:
// when an origin of the job is refused, or the claim fails, the origins
// already claimed for the command are given back before the error returns.
func (p PathDiscoveryPolicy) ClaimPathDispatch(ctx context.Context, tenantID, commandID shared.ID, runID *shared.ID, targets []string, requested int) (int, error) {
	if p.Ledger == nil {
		return 0, shared.NewDomainError(CodePathDiscoveryRefused, "Path discovery is not configured on this server.", shared.ErrValidation)
	}
	b, _ := p.PathDiscoveryBudget(ctx, tenantID)
	if requested <= 0 {
		requested = b.PerOrigin
	}
	requested = min(requested, b.PerOrigin)
	granted := requested
	for _, t := range targets {
		got, why, err := p.Ledger.ClaimPathOrigin(ctx, covdom.PathClaim{TenantID: tenantID, Origin: t, CommandID: commandID, RunID: runID,
			Requested: requested, PerHost: b.PerOrigin, Daily: b.Daily})
		if err == nil && why == "" {
			granted = min(granted, got)
			continue
		}
		// Not the origins claimed so far (the context may be the reason).
		p.releaseAfterRefusal(tenantID, commandID)
		if err != nil {
			return 0, fmt.Errorf("path discovery claim: %w", err)
		}
		return 0, shared.NewDomainError(CodePathDiscoveryRefused,
			"Path discovery does not run on this origin now: "+why+".", shared.ErrValidation)
	}
	return granted, nil
}

// ReleasePathDispatch gives back the origins a command claimed (all of them
// when origins is nil): the job was refused after the claim, or it sent no
// request.
func (p PathDiscoveryPolicy) ReleasePathDispatch(ctx context.Context, tenantID, commandID shared.ID, origins []string) error {
	if p.Ledger == nil {
		return nil
	}
	return p.Ledger.ReleasePathClaim(ctx, tenantID, commandID, origins)
}

// ReleaseEmptyPathDispatch gives back the origins a job that sent no request
// claimed, at most once per origin per PathEvery: the sensor's report of an
// empty job cannot reset the origin's floor and daily budget repeatedly.
func (p PathDiscoveryPolicy) ReleaseEmptyPathDispatch(ctx context.Context, tenantID, commandID shared.ID, origins []string) error {
	if p.Ledger == nil || len(origins) == 0 {
		return nil
	}
	return p.Ledger.ReleaseEmptyPathClaim(ctx, tenantID, commandID, origins)
}

// releaseAfterRefusal releases on a context that survives the caller's
// cancellation (the claim that failed may have been cut short by it).
func (p PathDiscoveryPolicy) releaseAfterRefusal(tenantID, commandID shared.ID) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), releaseTimeout)
	defer cancel()
	if err := p.ReleasePathDispatch(ctx, tenantID, commandID, nil); err != nil && p.Log != nil {
		p.Log.Warn("path discovery: claims of a refused job not released", "command_id", commandID.String(), "error", logger.SanitizeError(err))
	}
}

// releaseTimeout bounds a release after a refusal.
const releaseTimeout = 10 * time.Second
