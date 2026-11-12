package exploration

// The frontier controller (docs/architecture/exploration.md, "Scoring and
// dispatch"). One pass per tenant: the rules open leads, blocked leads whose
// recheck time came are reopened, running leads settle from their run, and
// the best open leads are dispatched.
//
// Dispatch goes only through the coverage planner's run path
// (scan.Service.StartCoverage): the dispatch gate (ResolveDispatchTargets,
// fail closed), scope entries and exclusions, zone routing, the signed job
// and the sensor's local policy all apply, exactly as for a coverage batch,
// and every dispatch counts against the tenant's coverage daily budget. The
// target is always the subject asset's own stored name, never anything a
// lead carries; a target the gate refuses blocks the lead with the gate's
// code and nothing runs. Intrusive steps are never dispatched this way.

import (
	"context"
	"errors"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	scanapp "github.com/openctemio/openctem/server/internal/app/scan"
	"github.com/openctemio/openctem/server/pkg/domain/audit"
	covdom "github.com/openctemio/openctem/server/pkg/domain/coverage"
	"github.com/openctemio/openctem/server/pkg/domain/exploration"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/stage"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// Controller defaults.
const (
	DefaultMaxRunning     = 4
	DefaultDailyBudget    = 5000
	DefaultStallAfter     = 24 * time.Hour
	DefaultBlockedRecheck = 6 * time.Hour
	DefaultRefusalRetry   = 30 * time.Minute
	// frontierRead bounds the leads one pass reads per state.
	frontierRead = exploration.MaxListLimit
)

// metaReason is the audit metadata key of a state change's reason.
const metaReason = "reason"

// Blocked reasons the controller writes itself (the gate's own codes are
// kept as they are).
const (
	BlockedIntrusive = "intrusive_needs_person"
	BlockedNoAction  = "no_action_for_subject"
	BlockedRefused   = "refused"
)

// RunStarter starts one capability on targets through the coverage run path
// (scan.Service).
type RunStarter interface {
	StartCoverage(ctx context.Context, in scanapp.CoverageInput) (*scanapp.CoverageResult, error)
}

// Ledger is the part of the coverage ledger a dispatch uses: the daily
// budget's attempts, and marking the subject's pair queued on the run so the
// ledger settles it too (a pair the ledger does not hold is left alone).
type Ledger interface {
	AttemptsSince(ctx context.Context, tenantID shared.ID, t time.Time) (int, error)
	MarkQueued(ctx context.Context, tenantID shared.ID, capability string, assetIDs []shared.ID, runID shared.ID, tool string) error
}

// ControllerConfig bounds the controller.
type ControllerConfig struct {
	// DailyBudget is the coverage daily budget the dispatches share.
	DailyBudget    int
	MaxRunning     int
	StallAfter     time.Duration
	BlockedRecheck time.Duration
	RefusalRetry   time.Duration
}

func (c *ControllerConfig) defaults() {
	if c.DailyBudget <= 0 {
		c.DailyBudget = DefaultDailyBudget
	}
	if c.MaxRunning <= 0 {
		c.MaxRunning = DefaultMaxRunning
	}
	if c.StallAfter <= 0 {
		c.StallAfter = DefaultStallAfter
	}
	if c.BlockedRecheck <= 0 {
		c.BlockedRecheck = DefaultBlockedRecheck
	}
	if c.RefusalRetry <= 0 {
		c.RefusalRetry = DefaultRefusalRetry
	}
}

// Controller runs the exploration loop.
type Controller struct {
	repo    exploration.Repository
	store   exploration.ControllerStore
	rules   *Rules
	starter RunStarter
	ledger  Ledger
	sw      ActiveSwitch
	audit   Auditor
	logger  *logger.Logger
	cfg     ControllerConfig
	now     func() time.Time
	rollups exploration.RollupStore
}

// NewController wires the controller.
func NewController(repo exploration.Repository, store exploration.ControllerStore, rules *Rules, starter RunStarter,
	ledger Ledger, sw ActiveSwitch, audit Auditor, log *logger.Logger, cfg ControllerConfig) *Controller {
	cfg.defaults()
	return &Controller{repo: repo, store: store, rules: rules, starter: starter, ledger: ledger, sw: sw, audit: audit,
		logger: log.With("component", "exploration"), cfg: cfg, now: time.Now}
}

// SetRollups precomputes the exploration's figures after every pass.
func (c *Controller) SetRollups(r exploration.RollupStore) { c.rollups = r }

// Run runs one pass for every tenant with assets. One tenant's failure does
// not stop the others. It returns how many leads changed.
func (c *Controller) Run(ctx context.Context) (int, error) {
	tenants, err := c.store.Tenants(ctx)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, t := range tenants {
		if ctx.Err() != nil {
			return total, ctx.Err()
		}
		n, err := c.RunTenant(ctx, t)
		total += n
		if err != nil {
			c.logger.Warn("exploration pass of a tenant failed", "tenant_id", t.String(), "error", logger.SanitizeError(err))
		}
	}
	return total, nil
}

// RunTenant runs one pass for one tenant.
func (c *Controller) RunTenant(ctx context.Context, tenantID shared.ID) (int, error) {
	n := 0
	if c.rules != nil {
		opened, err := c.rules.RunTenant(ctx, tenantID)
		n += opened
		if err != nil {
			c.logger.Warn("exploration rules failed", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		}
	}
	explorationID, err := c.repo.EnsureContinuous(ctx, tenantID)
	if err != nil {
		return n, err
	}
	k, err := c.recheckBlocked(ctx, tenantID)
	n += k
	if err != nil {
		return n, err
	}
	k, err = c.settle(ctx, tenantID)
	n += k
	if err != nil {
		return n, err
	}
	k, err = c.dispatch(ctx, tenantID, explorationID)
	n += k
	if err != nil {
		return n, err
	}
	if c.rollups != nil {
		if err := c.rollups.RefreshRollup(ctx, tenantID, explorationID); err != nil {
			return n, err
		}
	}
	return n, nil
}

func (c *Controller) systemCtx(tenantID shared.ID) auditapp.AuditContext {
	return auditapp.AuditContext{TenantID: tenantID.String(), ActorEmail: "exploration-controller"}
}

// move changes a lead's state, saves it (compare and set) and audits it.
func (c *Controller) move(ctx context.Context, l *exploration.Lead, to exploration.LeadState, meta map[string]any) error {
	from := l.State
	if err := l.Move(to, c.now()); err != nil {
		return err
	}
	if err := c.repo.SaveLead(ctx, l); err != nil {
		return err
	}
	if meta == nil {
		meta = map[string]any{}
	}
	meta["from"] = string(from)
	meta["to"] = string(to)
	recordLead(ctx, c.audit, c.logger, l, audit.ActionExplorationLeadState, c.systemCtx(l.TenantID), meta)
	return nil
}

// block moves a lead to blocked with a reason; recheck 0 leaves it blocked
// until a person acts.
func (c *Controller) block(ctx context.Context, l *exploration.Lead, reason string, recheck time.Duration) error {
	l.BlockedReason = covdom.Clip(reason, exploration.MaxBlocked)
	l.NextAttemptAt = nil
	if recheck > 0 {
		t := c.now().Add(recheck)
		l.NextAttemptAt = &t
	}
	return c.move(ctx, l, exploration.StateBlocked, map[string]any{metaReason: l.BlockedReason})
}

func (c *Controller) recheckBlocked(ctx context.Context, tenantID shared.ID) (int, error) {
	leads, err := c.repo.ListLeads(ctx, tenantID, exploration.LeadFilter{States: []exploration.LeadState{exploration.StateBlocked}, Limit: frontierRead})
	if err != nil {
		return 0, err
	}
	n := 0
	now := c.now()
	for _, l := range leads {
		if l.NextAttemptAt == nil || l.NextAttemptAt.After(now) {
			continue
		}
		l.NextAttemptAt, l.BlockedReason = nil, ""
		if err := c.move(ctx, l, exploration.StateOpen, map[string]any{metaReason: "recheck"}); err != nil && !errors.Is(err, exploration.ErrStale) {
			return n, err
		}
		n++
	}
	return n, nil
}

// autoActive reads the tenant's automatic coverage switch (fail closed).
func (c *Controller) autoActive(ctx context.Context, tenantID shared.ID) bool {
	if c.sw == nil {
		return false
	}
	on, err := c.sw.CoverageEnabled(ctx, tenantID)
	return err == nil && on
}

// budgetLeft is what the tenant's coverage daily budget leaves for leads:
// the ledger's attempts and the leads' own dispatches both count.
func (c *Controller) budgetLeft(ctx context.Context, tenantID shared.ID) (int, error) {
	since := c.now().Add(-24 * time.Hour)
	used := 0
	if c.ledger != nil {
		n, err := c.ledger.AttemptsSince(ctx, tenantID, since)
		if err != nil {
			return 0, err
		}
		used += n
	}
	n, err := c.store.DispatchesSince(ctx, tenantID, since)
	if err != nil {
		return 0, err
	}
	return c.cfg.DailyBudget - used - n, nil
}

//nolint:cyclop,gocognit // one pass over the frontier: supersede, score, select, dispatch
func (c *Controller) dispatch(ctx context.Context, tenantID, explorationID shared.ID) (int, error) {
	if c.starter == nil {
		return 0, nil
	}
	running, err := c.repo.ListLeads(ctx, tenantID, exploration.LeadFilter{States: []exploration.LeadState{exploration.StateRunning}, Limit: frontierRead})
	if err != nil {
		return 0, err
	}
	slots := c.cfg.MaxRunning - len(running)
	left, err := c.budgetLeft(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	slots = min(slots, left)
	open, err := c.repo.ListLeads(ctx, tenantID, exploration.LeadFilter{States: []exploration.LeadState{exploration.StateOpen}, Limit: frontierRead})
	if err != nil || len(open) == 0 {
		return 0, err
	}
	ids := make([]shared.ID, 0, len(open))
	tools := map[string]bool{}
	for _, l := range open {
		if l.SubjectAssetID != nil {
			ids = append(ids, *l.SubjectAssetID)
		}
		if st, ok := stage.Lookup(stage.Key(l.Action.Capability)); ok {
			tools[st.DefaultTool()] = true
		}
	}
	subjects, err := c.store.Subjects(ctx, tenantID, ids)
	if err != nil {
		return 0, err
	}
	cells, err := c.store.Cells(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	toolList := make([]string, 0, len(tools))
	for t := range tools {
		toolList = append(toolList, t)
	}
	costs, err := c.store.ToolMeanMs(ctx, tenantID, toolList)
	if err != nil {
		return 0, err
	}
	n := 0
	var frontier []*exploration.Lead
	for _, l := range open {
		if l.ExplorationID != explorationID {
			continue
		}
		subj, ok := exploration.LeadSubject{}, false
		if l.SubjectAssetID != nil {
			subj, ok = subjects[*l.SubjectAssetID]
		}
		if !ok || subj.Archived {
			// The subject was removed or archived: the question no longer holds.
			if err := c.move(ctx, l, exploration.StateSuperseded, map[string]any{metaReason: "subject_gone"}); err != nil && !errors.Is(err, exploration.ErrStale) {
				return n, err
			}
			n++
			continue
		}
		lt, _ := exploration.LookupLeadType(l.Type)
		tool := ""
		if st, ok := stage.Lookup(stage.Key(l.Action.Capability)); ok {
			tool = st.DefaultTool()
		}
		score, inputs := exploration.Score(exploration.ScoreInput{
			Likelihood: l.Likelihood, Cell: cells[exploration.CellKey(l.Type, l.Action.Capability)],
			ValueWeight: lt.ValueWeight, Subject: subj.Value, MeanMs: costs[tool],
		})
		if score != l.Score {
			l.Score, l.ScoreInputs = score, inputs
			if err := c.repo.SaveLead(ctx, l); err != nil {
				if errors.Is(err, exploration.ErrStale) {
					continue
				}
				return n, err
			}
		}
		frontier = append(frontier, l)
	}
	busy := map[string]bool{}
	for _, l := range running {
		if l.SubjectAssetID != nil {
			busy[exploration.BusyKey(l.SubjectAssetID.String(), l.Action.Capability)] = true
		}
	}
	auto := c.autoActive(ctx, tenantID)
	for _, l := range exploration.Select(frontier, cells, busy, slots) {
		done, err := c.dispatchOne(ctx, l, subjects[*l.SubjectAssetID], auto)
		if done {
			n++
		}
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// dispatchOne starts one lead's step. done is true when the lead changed.
//
//nolint:cyclop // each outcome of the gate is one branch
func (c *Controller) dispatchOne(ctx context.Context, l *exploration.Lead, subj exploration.LeadSubject, auto bool) (bool, error) {
	lt, ok := exploration.LookupLeadType(l.Type)
	if !ok {
		return true, c.block(ctx, l, BlockedNoAction, 0)
	}
	if l.Attempts >= lt.MaxAttempts {
		return true, c.move(ctx, l, exploration.StateExhausted, map[string]any{metaReason: "attempts"})
	}
	// Intrusive steps always need a person and never run as the system.
	if l.Tier >= stage.TierIntrusive {
		return true, c.block(ctx, l, BlockedIntrusive, 0)
	}
	// An active step follows the tenant's automatic coverage now, unless a
	// person approved it.
	if l.Tier == stage.TierActive && l.ApprovedBy == nil && !auto {
		return true, c.move(ctx, l, exploration.StateAwaitingApproval, map[string]any{metaReason: "auto_coverage_off"})
	}
	// The catalog's action must still apply to the subject as it is now.
	if a, ok := lt.ActionFor(subj.Type, subj.SubType); !ok || a.Capability != l.Action.Capability {
		return true, c.block(ctx, l, BlockedNoAction, 0)
	}
	target := covdom.DueTarget{AssetID: subj.ID, Name: subj.Name, Type: subj.Type, SubType: subj.SubType}.Target()
	res, err := c.starter.StartCoverage(ctx, scanapp.CoverageInput{
		TenantID: l.TenantID, Capability: l.Action.Capability, Targets: []string{target},
	})
	switch {
	case errors.Is(err, scanapp.ErrCoverageBusy):
		return false, nil // the capability's run is still active: next pass
	case err != nil:
		if reason := scanapp.CoverageReadinessForRefusal(err); reason != "" {
			return true, c.block(ctx, l, reason, c.cfg.RefusalRetry)
		}
		var de *shared.DomainError
		if errors.As(err, &de) && de.Code != "" {
			return true, c.block(ctx, l, de.Code, c.cfg.BlockedRecheck)
		}
		c.logger.Warn("exploration: step not started", "tenant_id", l.TenantID.String(),
			"lead_id", l.ID.String(), "error", logger.SanitizeError(err))
		return false, nil
	}
	if res.RunID == nil {
		if len(res.Refused) > 0 {
			code := res.Refused[0].Code
			if code == "" {
				code = BlockedRefused
			}
			return true, c.block(ctx, l, code, c.cfg.BlockedRecheck)
		}
		return false, nil // deferred to a later batch
	}
	runID := *res.RunID
	if _, err := c.repo.AddLinks(ctx, []exploration.Link{{TenantID: l.TenantID, LeadID: l.ID,
		Rel: exploration.RelDispatchedAs, EndKind: exploration.EndScanRun, EndID: &runID}}); err != nil {
		return false, err
	}
	if c.ledger != nil {
		if err := c.ledger.MarkQueued(ctx, l.TenantID, l.Action.Capability, []shared.ID{subj.ID}, runID, res.Tool); err != nil {
			c.logger.Warn("exploration: ledger pair not marked", "error", logger.SanitizeError(err))
		}
	}
	l.Attempts++
	l.BlockedReason, l.NextAttemptAt = "", nil
	return true, c.move(ctx, l, exploration.StateRunning, map[string]any{"run_id": runID.String(), "target": target})
}

// lastRun is the run a running lead was last dispatched as.
func lastRun(links []exploration.Link) *shared.ID {
	var out *shared.ID
	for _, k := range links {
		if k.Rel == exploration.RelDispatchedAs && k.EndID != nil {
			out = k.EndID
		}
	}
	return out
}

// settle answers running leads whose run finished.
//
//nolint:cyclop // one pass: run state, then the type's settle mode
func (c *Controller) settle(ctx context.Context, tenantID shared.ID) (int, error) {
	running, err := c.repo.ListLeads(ctx, tenantID, exploration.LeadFilter{States: []exploration.LeadState{exploration.StateRunning}, Limit: frontierRead})
	if err != nil || len(running) == 0 {
		return 0, err
	}
	links := map[shared.ID][]exploration.Link{}
	var runIDs []shared.ID
	for _, l := range running {
		ls, err := c.repo.Links(ctx, tenantID, l.ID)
		if err != nil {
			return 0, err
		}
		links[l.ID] = ls
		if r := lastRun(ls); r != nil {
			runIDs = append(runIDs, *r)
		}
	}
	runs, err := c.store.Runs(ctx, tenantID, runIDs)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, l := range running {
		runID := lastRun(links[l.ID])
		var facts exploration.RunFacts
		known := false
		if runID != nil {
			facts, known = runs[*runID]
		}
		var o outcome
		switch {
		case !known:
			o = outcome{verdict: exploration.VerdictInconclusive, reason: "run_missing", effect: exploration.EffectFailed}
		case !facts.Terminal():
			if c.now().Sub(facts.CreatedAt) < c.cfg.StallAfter {
				continue
			}
			o = outcome{verdict: exploration.VerdictInconclusive, reason: "stalled", effect: exploration.EffectFailed}
		case !facts.Succeeded():
			o = outcome{verdict: exploration.VerdictInconclusive, reason: "run_" + facts.Status, effect: exploration.EffectFailed}
		default:
			if o, err = c.answer(ctx, l, *runID, facts, links[l.ID]); err != nil {
				return n, err
			}
		}
		if err := c.apply(ctx, l, runID, o); err != nil && !errors.Is(err, exploration.ErrStale) {
			return n, err
		}
		n++
	}
	return n, nil
}

// outcome is a settled step's answer.
type outcome struct {
	verdict  exploration.VerdictKind
	reason   string
	effect   exploration.Effect
	findings []exploration.FindingYield
}

// answer reads the subject after a finished run, by the type's settle mode.
func (c *Controller) answer(ctx context.Context, l *exploration.Lead, runID shared.ID, run exploration.RunFacts, links []exploration.Link) (outcome, error) {
	lt, _ := exploration.LookupLeadType(l.Type)
	if l.SubjectAssetID == nil {
		return outcome{verdict: exploration.VerdictInconclusive, reason: "subject_gone", effect: exploration.EffectFailed}, nil
	}
	subject := *l.SubjectAssetID
	switch lt.Settle {
	case exploration.SettleFinding:
		ys, err := c.store.RunFindings(ctx, l.TenantID, runID, subject)
		if err != nil {
			return outcome{}, err
		}
		if len(ys) > 0 {
			return outcome{verdict: exploration.VerdictProven, reason: "finding_reported", effect: exploration.EffectCreated, findings: ys}, nil
		}
		return outcome{verdict: exploration.VerdictRefuted, reason: "nothing_found", effect: exploration.EffectNotFound}, nil
	case exploration.SettleLiveness:
		state, checked, err := c.store.Liveness(ctx, l.TenantID, subject)
		if err != nil {
			return outcome{}, err
		}
		if checked == nil || checked.Before(run.CreatedAt) {
			return outcome{verdict: exploration.VerdictInconclusive, reason: "liveness_not_checked", effect: exploration.EffectNotFound}, nil
		}
		switch state {
		case "alive":
			return outcome{verdict: exploration.VerdictRefuted, reason: "answered", effect: exploration.EffectChanged}, nil
		case "gone", "unreachable", "unresolvable":
			return outcome{verdict: exploration.VerdictProven, reason: "confirmed_" + state, effect: exploration.EffectConfirmed}, nil
		}
		return outcome{verdict: exploration.VerdictInconclusive, reason: "liveness_" + state, effect: exploration.EffectNotFound}, nil
	case exploration.SettleMatch:
		var cited []shared.ID
		for _, k := range links {
			if k.Rel == exploration.RelDerivedFrom && k.EndKind == exploration.EndFinding && k.EndID != nil {
				cited = append(cited, *k.EndID)
			}
		}
		m, err := c.store.MatchState(ctx, l.TenantID, cited)
		if err != nil {
			return outcome{}, err
		}
		switch {
		case m.Confirmed > 0:
			return outcome{verdict: exploration.VerdictProven, reason: "version_confirmed", effect: exploration.EffectConfirmed}, nil
		case m.Total > 0 && m.Closed == m.Total:
			return outcome{verdict: exploration.VerdictRefuted, reason: "match_closed", effect: exploration.EffectChanged}, nil
		}
		return outcome{verdict: exploration.VerdictInconclusive, reason: "match_unchanged", effect: exploration.EffectNotFound}, nil
	}
	return outcome{verdict: exploration.VerdictInconclusive, reason: "unknown_settle_mode", effect: exploration.EffectFailed}, fmt.Errorf("%w: settle mode %q", exploration.ErrNotInCatalog, lt.Settle)
}

// apply writes the yields, the verdict and the lead's next state.
func (c *Controller) apply(ctx context.Context, l *exploration.Lead, runID *shared.ID, o outcome) error {
	var yields []exploration.Link
	for _, f := range o.findings {
		id := f.ID
		eff := exploration.EffectConfirmed
		if f.Created {
			eff = exploration.EffectCreated
		}
		yields = append(yields, exploration.Link{TenantID: l.TenantID, LeadID: l.ID, Rel: exploration.RelYields,
			EndKind: exploration.EndFinding, EndID: &id, Effect: eff, OutcomeReason: o.reason})
	}
	if len(yields) == 0 && l.SubjectAssetID != nil {
		yields = append(yields, exploration.Link{TenantID: l.TenantID, LeadID: l.ID, Rel: exploration.RelYields,
			EndKind: exploration.EndAsset, EndID: l.SubjectAssetID, Effect: o.effect, OutcomeReason: o.reason})
	}
	if _, err := c.repo.AddLinks(ctx, yields); err != nil {
		return err
	}
	checker := "scan_run"
	evidence := []exploration.EvidenceRef{}
	if runID != nil {
		checker = "scan_run:" + runID.String()
		evidence = append(evidence, exploration.EvidenceRef{Kind: "scan_run", ID: runID.String()})
	}
	for _, f := range o.findings {
		evidence = append(evidence, exploration.EvidenceRef{Kind: "finding", ID: f.ID.String()})
	}
	if err := c.repo.AddVerdict(ctx, exploration.Verdict{TenantID: l.TenantID, LeadID: l.ID, Verdict: o.verdict,
		Tier: exploration.TierDeterministic, Checker: checker, Evidence: evidence, Reason: o.reason}); err != nil {
		return err
	}
	recordLead(ctx, c.audit, c.logger, l, audit.ActionExplorationLeadVerdict, c.systemCtx(l.TenantID),
		map[string]any{"verdict": string(o.verdict), metaReason: o.reason})
	lt, _ := exploration.LookupLeadType(l.Type)
	switch {
	case o.verdict == exploration.VerdictProven:
		return c.move(ctx, l, exploration.StateDone, map[string]any{metaReason: o.reason})
	case o.verdict == exploration.VerdictRefuted:
		return c.move(ctx, l, exploration.StateRefuted, map[string]any{metaReason: o.reason})
	case l.Attempts >= lt.MaxAttempts:
		return c.move(ctx, l, exploration.StateExhausted, map[string]any{metaReason: o.reason})
	}
	// Inconclusive with attempts left: back on the frontier after the
	// refusal retry, so the step is not repeated at once.
	t := c.now().Add(c.cfg.RefusalRetry)
	l.NextAttemptAt, l.BlockedReason = &t, covdom.Clip(o.reason, exploration.MaxBlocked)
	return c.move(ctx, l, exploration.StateBlocked, map[string]any{metaReason: o.reason})
}
