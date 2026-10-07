package pipeline

// The hop router: chaining scan stages through the inventory with a gate at
// every hop. Design: research/27 §5 (owner decisions G3-G5) and
// research/22 P0-5 (E6); architecture: docs/architecture/scan-stages.md.
//
// A step used to receive the run's seed targets whatever came before it, so
// "subfinder -> dnsx" resolved the seed domains, not what subfinder found.
// Now, when a step's predecessors produce asset types its stage takes, the
// step is planned only after those predecessors finished and every report
// of theirs was ingested, from what ingest recorded for them
// (scan_step_outputs; never a sensor's raw output). Every derived target
// goes through:
//
//   - the type contract: the stage must take the asset's stored pair;
//   - a strict parse of the name (hostile output: length, control and bidi
//     characters, host and URL shape);
//   - the hop limit (G5): at most stage.MaxHops discovery hops from a seed;
//   - fan-out caps: per parent and per stage (never above the run cap);
//   - the one target gate of every active-scan path (scan.ResolveDispatchTargets):
//     the target validator, scope exclusions, act scope, zone routing and
//     the ownership gate. A passive (T0) stage may take a name nobody
//     confirmed yet (but never a rejected or tombstoned one); an active (T1)
//     stage takes only what easm.ActiveGate allows. An intrusive (T2) stage
//     is never fed derived targets.
//
// Planning is exactly once per (run, stage): scan_run_stage_plans is the
// key, so a duplicate completion or ingest event plans nothing. Every
// decision is recorded in scan_run_targets (seed or derived, parent, hop,
// the rule that allowed it or the reason it was skipped). Every read and
// write is scoped to the run's tenant.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// WithHopStore wires stage chaining. Without it every step keeps receiving
// the run's seed targets (the behavior before chaining).
func WithHopStore(h pipeline.HopRepository) Option {
	return func(s *Service) { s.hops = h }
}

// Planning outcomes the scheduler acts on.
var (
	// errStageDeferred: a predecessor's report is still being ingested; the
	// step stays pending and is planned when the ingest commits.
	errStageDeferred = errors.New("stage waits for its predecessors' results to be ingested")
	// errStageAlreadyPlanned: another planner planned this stage of the run.
	errStageAlreadyPlanned = errors.New("stage already planned")
)

// noInputsError: the stage was planned and nothing passed; the step is
// settled without a command.
type noInputsError struct{ summary string }

func (e *noInputsError) Error() string { return "no inputs: " + e.summary }

// codeStageNotChainable: an intrusive stage downstream of another stage.
const codeStageNotChainable = "STAGE_NOT_CHAINABLE"

// outputReadLimit bounds how many outputs one planning reads; the rest are
// counted as over the cap.
const outputReadLimit = 2 * stage.RunFanoutCap

// planStage decides the targets of one step and records the decision. seeds
// are the run's targets after the type gate. It returns the step's targets,
// or errStageDeferred, errStageAlreadyPlanned, *noInputsError or a failure.
func (s *Service) planStage(ctx context.Context, run *pipeline.Run, step *pipeline.Step, resolved scanapp.StepTool,
	preds []*pipeline.Step, seeds *scanapp.StepTargets,
) (*scanapp.StepTargets, error) {
	if s.hops == nil || !resolved.HasStage {
		return seeds, nil
	}
	st := resolved.Stage
	plan := &pipeline.StagePlan{
		TenantID: run.TenantID, RunID: run.ID, StageKey: step.StepKey,
		Stage: string(st.Key), Tool: resolved.Name, Tier: int(st.Tier), Skipped: map[string]int{},
	}
	seedList := seedTargets(run, seeds)
	rows := make([]pipeline.RunTarget, 0, len(seedList))
	seen := make(map[string]bool, len(seedList))
	for _, t := range seedList {
		key := strings.ToLower(strings.TrimSpace(t))
		if key == "" || len(key) > maxTargetKey || seen[key] {
			continue
		}
		seen[key] = true
		rows = append(rows, pipeline.RunTarget{TargetKey: key, Origin: pipeline.TargetOriginSeed,
			Decision: pipeline.TargetPlanned, Reason: pipeline.ReasonSeed})
	}
	plan.Inputs, plan.Planned = len(seedList), len(seedList)
	if seeds != nil && seeds.Refused > 0 {
		plan.Inputs += seeds.Refused
		plan.Skipped["incompatible_type"] = seeds.Refused
	}

	feeding := feedingPredecessors(run, st, preds)
	if len(feeding) == 0 {
		return s.savePlan(ctx, plan, rows, seeds)
	}
	if st.Tier >= stage.TierIntrusive {
		return nil, shared.NewDomainError(codeStageNotChainable,
			fmt.Sprintf("Step '%s' runs an intrusive stage (%s); intrusive stages never take targets an earlier stage found.", step.StepKey, st.Key),
			shared.ErrValidation)
	}
	plan.Chained = true

	predRuns := make([]shared.ID, 0, len(feeding))
	predKeys := make([]string, 0, len(feeding))
	for _, p := range feeding {
		predRuns = append(predRuns, p.run)
		predKeys = append(predKeys, p.key)
	}
	pending, err := s.hops.PendingStepIngest(ctx, run.TenantID, predRuns)
	if err != nil {
		return nil, err
	}
	if pending {
		return nil, errStageDeferred
	}
	outputs, total, err := s.hops.ListStepOutputs(ctx, run.TenantID, run.ID, predRuns, outputReadLimit)
	if err != nil {
		return nil, err
	}
	parents, err := s.hops.PlannedTargets(ctx, run.TenantID, run.ID, predKeys)
	if err != nil {
		return nil, err
	}
	stageOf := make(map[shared.ID]string, len(feeding))
	for _, p := range feeding {
		stageOf[p.run] = p.key
	}

	cands, inputs := deriveCandidates(st, outputs, parents, stageOf, seen, plan.Skipped, len(seedList))
	if cands, err = s.expandEndpoints(ctx, run, st, step, cands, plan.Skipped); err != nil {
		return nil, err
	}
	if total > len(outputs) {
		plan.Skipped[pipeline.ReasonOverCap] += total - len(outputs)
		inputs += total - len(outputs)
		s.logger.Warn("chained stage: more outputs than one plan reads; the rest are over the cap",
			"run_id", run.ID.String(), "step_key", step.StepKey, "outputs", total, "read", len(outputs))
	}
	plan.Inputs += inputs

	planned, skipped, err := s.gateCandidates(ctx, run, st, cands)
	if err != nil {
		return nil, err
	}
	targets := append([]string{}, seedList...)
	for _, c := range planned {
		targets = append(targets, c.key)
		rows = append(rows, c.row(pipeline.TargetPlanned, plannedReason(st)))
		plan.MaxHop = max(plan.MaxHop, c.hop)
	}
	for _, c := range skipped {
		rows = append(rows, c.row(pipeline.TargetSkipped, c.reason))
		plan.Skipped[c.reason]++
	}
	for _, c := range cands.dropped {
		rows = append(rows, c.row(pipeline.TargetSkipped, c.reason))
	}
	plan.Planned = len(targets)
	if over := plan.Skipped[pipeline.ReasonOverCap]; over > 0 {
		s.logger.Warn("chained stage fan-out capped",
			"run_id", run.ID.String(), "step_key", step.StepKey, "planned", len(planned), "over_cap", over)
	}

	out := &scanapp.StepTargets{Targets: targets}
	if seeds != nil {
		out.Refused, out.Reason = seeds.Refused, seeds.Reason
	}
	if _, err := s.savePlan(ctx, plan, rows, out); err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, &noInputsError{summary: skipSummary(plan.Skipped)}
	}
	return out, nil
}

func (s *Service) savePlan(ctx context.Context, plan *pipeline.StagePlan, rows []pipeline.RunTarget, out *scanapp.StepTargets) (*scanapp.StepTargets, error) {
	ok, err := s.hops.SaveStagePlan(ctx, plan, rows)
	if err != nil {
		return nil, fmt.Errorf("record stage plan: %w", err)
	}
	if !ok {
		return nil, errStageAlreadyPlanned
	}
	return out, nil
}

func plannedReason(st stage.Stage) string {
	if st.Tier.Passive() {
		return pipeline.ReasonPassiveAllowed
	}
	return pipeline.ReasonGateAllowed
}

// seedTargets are the run's targets the step takes (after the type gate).
func seedTargets(run *pipeline.Run, seeds *scanapp.StepTargets) []string {
	if seeds != nil && seeds.Targets != nil {
		return seeds.Targets
	}
	switch ts := run.Context["targets"].(type) {
	case []string:
		return ts
	case []any:
		out := make([]string, 0, len(ts))
		for _, v := range ts {
			if str, ok := v.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

// feedingPred is a predecessor whose outputs the stage takes.
type feedingPred struct {
	key string
	run shared.ID
}

// feedingPredecessors are the step's direct predecessors that produced
// results (completed or partial: a partial predecessor still feeds) and
// whose stage produces a type this stage takes.
func feedingPredecessors(run *pipeline.Run, st stage.Stage, preds []*pipeline.Step) []feedingPred {
	out := make([]feedingPred, 0, len(preds))
	for _, p := range preds {
		ps, ok := stage.ForStep(p.Tool, p.Capabilities)
		if !ok || !stage.Feeds(ps, st) {
			continue
		}
		sr := run.GetStepRun(p.StepKey)
		if sr == nil || !sr.Status.ProducedResults() {
			continue
		}
		out = append(out, feedingPred{key: p.StepKey, run: sr.ID})
	}
	return out
}

// hopCandidate is one derived target before the gate.
type hopCandidate struct {
	key         string
	assetID     shared.ID
	parentAsset *shared.ID
	parentStage string
	relation    string
	hop         int
	reason      string
}

func (c hopCandidate) row(decision, reason string) pipeline.RunTarget {
	id := c.assetID
	return pipeline.RunTarget{TargetKey: c.key, AssetID: &id, Origin: pipeline.TargetOriginDerived,
		ParentAssetID: c.parentAsset, ParentStageKey: c.parentStage, Relation: c.relation,
		Hop: c.hop, Decision: decision, Reason: reason}
}

// candidates are the derived targets that reach the gate, and the ones
// dropped before it (recorded with their reason).
type candidates struct {
	gate    []hopCandidate
	dropped []hopCandidate
}

// deriveCandidates turns a stage's predecessors' outputs into candidate
// targets: only types the stage takes, well-formed names, within the hop
// limit, deduplicated against the seeds and each other, under the per-parent
// and per-stage caps. It returns them and how many outputs were inputs of
// the stage (outputs of a type the stage does not take are not).
func deriveCandidates(st stage.Stage, outputs []pipeline.StepOutput, parents []pipeline.RunTarget,
	stageOf map[shared.ID]string, seen map[string]bool, skipped map[string]int, seedCount int,
) (candidates, int) {
	var out candidates
	inputs := 0
	perParent := map[string]int{}
	budget := min(st.MaxFanout, stage.RunFanoutCap) - seedCount
	// Deterministic: by name, so a cap keeps the same targets run to run.
	sorted := append([]pipeline.StepOutput{}, outputs...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, o := range sorted {
		if !st.Accepts(asset.TypeRef{Type: asset.AssetType(o.Type), SubType: o.SubType}) {
			continue
		}
		inputs++
		key, ok := hopTargetKey(o.Name)
		c := hopCandidate{key: key, assetID: o.AssetID}
		if !ok {
			skipped[pipeline.ReasonInvalid]++ // not recorded: the name is not safe to store as a key
			continue
		}
		if seen[key] {
			skipped[pipeline.ReasonDuplicate]++
			continue
		}
		seen[key] = true
		parent, hop, relation := traceParent(key, parents)
		c.hop, c.relation = hop, relation
		if parent != nil {
			c.parentAsset, c.parentStage = parent.AssetID, parent.StageKey
		} else {
			c.parentStage = stageOf[o.StepRunID]
		}
		switch {
		case hop > stage.MaxHops:
			c.reason = pipeline.ReasonHopLimit
		case parent != nil && perParent[parent.TargetKey] >= st.PerParentCap():
			c.reason = pipeline.ReasonOverCap
		case len(out.gate) >= budget:
			c.reason = pipeline.ReasonOverCap
		}
		if c.reason != "" {
			skipped[c.reason]++
			out.dropped = append(out.dropped, c)
			continue
		}
		if parent != nil {
			perParent[parent.TargetKey]++
		}
		out.gate = append(out.gate, c)
	}
	return out, inputs
}

// gateCandidates passes the candidates through the one target gate and the
// run's zone. It returns the planned and the refused candidates (with their
// reason). A gate that cannot decide fails the step (fail closed).
func (s *Service) gateCandidates(ctx context.Context, run *pipeline.Run, st stage.Stage, cands candidates) ([]hopCandidate, []hopCandidate, error) {
	if len(cands.gate) == 0 {
		return nil, nil, nil
	}
	if s.targetGate == nil {
		return nil, nil, errors.New("target gate is not configured; derived targets not dispatched")
	}
	byKey := make(map[string]hopCandidate, len(cands.gate))
	in := scanapp.DispatchTargetsInput{
		TenantID: run.TenantID, ActScope: true, FallbackUser: runActor(run),
		PassiveOnly: st.Tier.Passive(),
		Targets:     make([]string, 0, len(cands.gate)),
		Assets:      make(map[string]scanapp.DispatchAsset, len(cands.gate)),
	}
	for _, c := range cands.gate {
		byKey[c.key] = c
		in.Targets = append(in.Targets, c.key)
		in.Assets[c.key] = scanapp.DispatchAsset{IDs: []string{c.assetID.String()}}
	}
	d, err := s.targetGate.ResolveDispatchTargets(ctx, in)
	if err != nil {
		return nil, nil, fmt.Errorf("gate derived targets: %w", err)
	}
	lookup := func(t string) (hopCandidate, bool) {
		c, ok := byKey[t]
		if !ok {
			c, ok = byKey[strings.ToLower(t)]
		}
		return c, ok
	}
	runZone := pipeline.ScanZoneFromContext(run.Context)
	planned := make([]hopCandidate, 0, len(d.Allowed))
	refused := make([]hopCandidate, 0, len(d.Excluded)+len(d.Refused))
	for _, t := range d.Allowed {
		c, ok := lookup(t)
		if !ok {
			continue
		}
		if !sameZone(runZone, d.Zone(t)) {
			c.reason = pipeline.ReasonOtherZone
			refused = append(refused, c)
			continue
		}
		planned = append(planned, c)
	}
	for _, t := range d.Excluded {
		if c, ok := lookup(t); ok {
			c.reason = pipeline.ReasonExcluded
			refused = append(refused, c)
		}
	}
	for _, r := range d.Refused {
		c, ok := lookup(r.Target)
		if !ok {
			continue
		}
		c.reason = pipeline.ReasonRefused
		if r.Reason == scanapp.ReasonOwnershipNotConfirmed {
			c.reason = pipeline.ReasonUnconfirmed
		}
		refused = append(refused, c)
	}
	return planned, refused, nil
}

// sameZone reports whether a derived target routes to the run's zone (both
// unzoned, or the same zone): a chained step never leaves its run's zone.
func sameZone(runZone *shared.ID, z *scanzone.Zone) bool {
	if z == nil {
		return runZone == nil
	}
	return runZone != nil && z.ID.Equals(*runZone)
}

// runActor is who a chained stage acts for (act scope): the user recorded
// on the run (the person who triggered it, else the scan's owner), else the
// run's triggered_by user, else nobody (a system run).
func runActor(run *pipeline.Run) *shared.ID {
	if v, ok := run.Context[scanapp.RunContextKeyActor].(string); ok {
		if id, err := shared.IDFromString(v); err == nil && !id.IsZero() {
			return &id
		}
	}
	return userIDOf(run.TriggeredBy)
}

// maxTargetKey bounds a target key (scan_run_targets.target_key).
const maxTargetKey = 2048

// hopTargetKey parses an output's name as a target a sensor may be handed:
// a host name, an IP address, host:port, or an http(s) URL without
// credentials. Anything else (control or bidi characters, oversize, other
// schemes, malformed hosts) is refused. The key is lower-case for hosts.
func hopTargetKey(name string) (string, bool) {
	s := strings.TrimSpace(name)
	if s == "" || len(s) > maxTargetKey || !utf8.ValidString(s) || hasUnsafeRune(s) {
		return "", false
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Host == "" {
			return "", false
		}
		if !validHost(u.Hostname()) || !validPort(u.Port()) {
			return "", false
		}
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		u.Fragment = ""
		return u.String(), true
	}
	host, port := s, ""
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
		if port == "" {
			return "", false
		}
	}
	if !validHost(host) || !validPort(port) {
		return "", false
	}
	return strings.ToLower(s), true
}

func hasUnsafeRune(s string) bool {
	for _, r := range s {
		switch {
		case r <= 0x20 || r == 0x7f:
			return true
		case r >= 0x200b && r <= 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0xfeff:
			return true
		}
	}
	return false
}

func validPort(p string) bool {
	if p == "" {
		return true
	}
	n, err := strconv.Atoi(p)
	return err == nil && n >= 1 && n <= 65535
}

// validHost: an IP address or a DNS name of LDH (and underscore) labels.
func validHost(h string) bool {
	h = strings.TrimSuffix(strings.Trim(h, "[]"), ".")
	if h == "" {
		return false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	if len(h) > 253 || !strings.Contains(h, ".") {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
				return false
			}
		}
	}
	return true
}

// keyHost is the host a target key points at ("" if none).
func keyHost(key string) string {
	if strings.Contains(key, "://") {
		if u, err := url.Parse(key); err == nil {
			return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		}
		return ""
	}
	h := key
	if host, _, err := net.SplitHostPort(key); err == nil {
		h = host
	}
	h = strings.ToLower(strings.TrimSuffix(strings.Trim(h, "[]"), "."))
	if !validHost(h) {
		return ""
	}
	return h
}

// traceParent finds the planned target of a predecessor a derived target
// came from, and its hop: the same host keeps the parent's hop (a port,
// service or URL on a host the run already reached); a name under a parent
// name is one hop further (a subdomain); anything else (a resolved
// address, an alias) is one hop beyond the furthest parent.
func traceParent(key string, parents []pipeline.RunTarget) (*pipeline.RunTarget, int, string) {
	h := keyHost(key)
	maxHop := 0
	var under *pipeline.RunTarget
	underLen := 0
	for i := range parents {
		p := &parents[i]
		maxHop = max(maxHop, p.Hop)
		ph := keyHost(p.TargetKey)
		if h == "" || ph == "" {
			continue
		}
		if ph == h {
			return p, p.Hop, "same_host"
		}
		if strings.HasSuffix(h, "."+ph) && len(ph) > underLen {
			under, underLen = p, len(ph)
		}
	}
	if under != nil {
		return under, under.Hop + 1, "subdomain_of"
	}
	return nil, maxHop + 1, "derived"
}

func skipSummary(skipped map[string]int) string {
	if len(skipped) == 0 {
		return "no target to scan"
	}
	keys := make([]string, 0, len(skipped))
	for k := range skipped {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", skipped[k], k))
	}
	return "nothing passed the gate (" + strings.Join(parts, ", ") + ")"
}

// OnCommandIngested is called when every segment of a sensor report bound
// to a command has been ingested. A chained step waiting for that ingest
// (errStageDeferred) is planned now. Tenant-scoped: a command of another
// tenant resolves to nothing. Best-effort: a failure is logged and the run
// timeout still ends a run that never advances.
func (s *Service) OnCommandIngested(ctx context.Context, tenantID, commandID shared.ID) {
	if s.hops == nil {
		return
	}
	runID, _, err := s.hops.StepRunOfCommand(ctx, tenantID, commandID)
	if err != nil {
		if !errors.Is(err, shared.ErrNotFound) {
			s.logger.Warn("chained stages: resolve an ingested command", "command_id", commandID.String(), "error", err)
		}
		return
	}
	run, err := s.runRepo.GetWithStepRuns(ctx, runID)
	if err != nil || run == nil || run.TenantID != tenantID || run.IsComplete() {
		return
	}
	template, err := s.templateRepo.GetWithSteps(ctx, run.PipelineID)
	if err != nil {
		s.logger.Warn("chained stages: load the run template", "run_id", runID.String(), "error", err)
		return
	}
	if err := s.advanceRun(ctx, run, template); err != nil {
		s.logger.Warn("chained stages: advance after ingest", "run_id", runID.String(), "error", err)
	}
}

// RunStepShares is how the run's step commands (chunks) are spread over
// sensors, per step. Empty when the command store cannot tell.
func (s *Service) RunStepShares(ctx context.Context, tenantID, runID string) ([]command.StepSensorShare, error) {
	run, err := s.GetRun(ctx, tenantID, runID)
	if err != nil {
		return nil, err
	}
	reader, ok := s.commandRepo.(command.StepShareReader)
	if !ok {
		return []command.StepSensorShare{}, nil
	}
	shares, err := reader.StepSensorShares(ctx, run.TenantID, run.ID)
	if err != nil {
		return nil, err
	}
	if shares == nil {
		shares = []command.StepSensorShare{}
	}
	return shares, nil
}

// ListRunStages returns how each stage of a run was planned (inputs,
// planned and skipped targets by reason). A run of another tenant is
// shared.ErrNotFound.
func (s *Service) ListRunStages(ctx context.Context, tenantID, runID string) ([]pipeline.StagePlan, error) {
	run, err := s.GetRun(ctx, tenantID, runID)
	if err != nil {
		return nil, err
	}
	if s.hops == nil {
		return []pipeline.StagePlan{}, nil
	}
	plans, err := s.hops.ListStagePlans(ctx, run.TenantID, run.ID)
	if err != nil {
		return nil, err
	}
	if plans == nil {
		plans = []pipeline.StagePlan{}
	}
	return plans, nil
}
