package scanrun

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

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/scope/ipset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// WithHopStore wires stage chaining. Without it every step keeps receiving
// the run's seed targets (the behavior before chaining).
func WithHopStore(h scanrun.HopRepository) Option {
	return func(s *Service) { s.hops = h }
}

// Planning outcomes the scheduler acts on.
var (
	// errStageDeferred: a predecessor's report is still being ingested; the
	// step stays pending and is planned when the ingest commits.
	errStageDeferred = errors.New("stage waits for its predecessors' results to be ingested")
	// errStageAlreadyPlanned: another planner planned this stage of the run.
	errStageAlreadyPlanned = errors.New("stage already planned")
	// errStreamWaiting: a streamed stage's first wave had nothing to
	// dispatch; the step stays pending and a later wave dispatches it
	// (or the closing wave settles it).
	errStreamWaiting = errors.New("streamed stage waits for its predecessor's results")
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
// are the run's targets after the type gate. With delta (the workflow's
// delta gating) a heavy stage keeps only the derived targets that are new,
// changed or due since the previous run of the scan. With stream the step
// starts while its feeding predecessor still runs (RFC-137): the plan is
// recorded as an open stream (later waves add targets, stream.go), and a
// first wave with nothing to dispatch leaves the step waiting
// (errStreamWaiting) instead of settling it. It returns the step's targets,
// or errStageDeferred, errStageAlreadyPlanned, errStreamWaiting,
// *noInputsError or a failure.
func (s *Service) planStage(ctx context.Context, run *scanrun.Run, step *scanworkflow.Step, resolved scanapp.StepTool,
	preds []*scanworkflow.Step, seeds *scanapp.StepTargets, delta, stream bool,
) (*scanapp.StepTargets, error) {
	if s.hops == nil || !resolved.HasStage {
		return seeds, nil
	}
	st := resolved.Stage
	plan := &scanrun.StagePlan{
		TenantID: run.TenantID, RunID: run.ID, StageKey: step.StepKey,
		Stage: string(st.Key), Tool: resolved.Name, Tier: int(st.Tier), Skipped: map[string]int{},
	}
	seedList := seedTargets(run, seeds)
	rows := make([]scanrun.RunTarget, 0, len(seedList))
	seen := make(map[string]bool, len(seedList))
	for _, t := range seedList {
		key := strings.ToLower(strings.TrimSpace(t))
		if key == "" || len(key) > maxTargetKey || seen[key] {
			continue
		}
		seen[key] = true
		rows = append(rows, scanrun.RunTarget{TargetKey: key, Origin: scanrun.TargetOriginSeed,
			Decision: scanrun.TargetPlanned, Reason: scanrun.ReasonSeed})
	}
	plan.Inputs, plan.Planned = len(seedList), len(seedList)
	if seeds != nil && seeds.Refused > 0 {
		plan.Inputs += seeds.Refused
		plan.Skipped["incompatible_type"] = seeds.Refused
	}

	feeding := feedingPredecessors(run, st, preds, stream)
	if len(feeding) == 0 {
		return s.savePlan(ctx, plan, rows, seeds)
	}
	if st.Tier >= stage.TierIntrusive {
		return nil, shared.NewDomainError(codeStageNotChainable,
			fmt.Sprintf("Step '%s' runs an intrusive stage (%s); intrusive stages never take targets an earlier stage found.", step.StepKey, st.Key),
			shared.ErrValidation)
	}
	plan.Chained = true
	plan.Streamed = stream

	d, err := s.deriveStage(ctx, run, step, st, feeding, seen, nil, seedList, delta, plan.Skipped, false)
	if err != nil {
		return nil, err
	}
	plan.Inputs += d.inputs
	rows = append(rows, d.rows...)
	targets := append(append([]string{}, seedList...), d.targets...)
	plan.MaxHop = d.maxHop
	plan.Planned = len(targets)

	out := &scanapp.StepTargets{Targets: targets}
	if seeds != nil {
		out.Refused, out.Reason = seeds.Refused, seeds.Reason
	}
	if _, err := s.savePlan(ctx, plan, rows, out); err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		if stream {
			return nil, errStreamWaiting
		}
		if n := plan.Skipped[scanrun.ReasonUnchanged]; n > 0 {
			return nil, &noInputsError{summary: fmt.Sprintf("nothing new since the last run: %d unchanged", n)}
		}
		return nil, &noInputsError{summary: skipSummary(plan.Skipped)}
	}
	return out, nil
}

// derivedPlan is what one planning derived from the predecessors' outputs:
// the targets to dispatch, every decision as a row, how many outputs were
// inputs of the stage, and the furthest hop planned.
type derivedPlan struct {
	targets []string
	rows    []scanrun.RunTarget
	inputs  int
	maxHop  int
}

// deriveStage reads what the feeding predecessors produced and passes it
// through every gate of a hop: the type contract, the strict parse, the hop
// limit and fan-out caps, the one target gate and the zone, delta gating
// and the step's range seeds. seen holds the keys already taken (the seeds,
// and in a later wave every key the stage decided); prior holds the
// stage's earlier decisions (nil for a first planning): a prior key is never
// decided again, and its earlier decision counts against the caps. skipped
// gets the counts by reason. A predecessor report still being ingested
// defers the planning (errStageDeferred); wave plans the outputs it reads
// without the over-the-read-limit count (the closing wave counts it).
func (s *Service) deriveStage(ctx context.Context, run *scanrun.Run, step *scanworkflow.Step, st stage.Stage,
	feeding []feedingPred, seen map[string]bool, prior map[string]scanrun.RunTarget, seedList []string, delta bool,
	skipped map[string]int, wave bool,
) (derivedPlan, error) {
	var d derivedPlan
	predRuns := make([]shared.ID, 0, len(feeding))
	predKeys := make([]string, 0, len(feeding))
	for _, p := range feeding {
		predRuns = append(predRuns, p.run)
		predKeys = append(predKeys, p.key)
	}
	pending, err := s.hops.PendingStepIngest(ctx, run.TenantID, predRuns)
	if err != nil {
		return d, err
	}
	if pending {
		return d, errStageDeferred
	}
	outputs, total, err := s.hops.ListStepOutputs(ctx, run.TenantID, run.ID, predRuns, outputReadLimit)
	if err != nil {
		return d, err
	}
	parents, err := s.hops.PlannedTargets(ctx, run.TenantID, run.ID, predKeys)
	if err != nil {
		return d, err
	}
	stageOf := make(map[shared.ID]string, len(feeding))
	for _, p := range feeding {
		stageOf[p.run] = p.key
	}

	outputs = canonicalWebInputs(st, outputs, skipped)
	outputs = s.namedPortOutputs(ctx, run.TenantID, st, outputs, parents)
	cands, inputs := deriveCandidatesPrior(st, outputs, parents, stageOf, seen, prior, skipped, len(seedList), stepTargetCap(run, step))
	if cands, err = s.expandEndpoints(ctx, run, st, step, cands, skipped); err != nil {
		return d, err
	}
	if total > len(outputs) && !wave {
		skipped[scanrun.ReasonOverCap] += total - len(outputs)
		inputs += total - len(outputs)
		s.logger.Warn("chained stage: more outputs than one plan reads; the rest are over the cap",
			"run_id", run.ID.String(), "step_key", step.StepKey, "outputs", total, "read", len(outputs))
	}
	d.inputs = inputs

	planned, refused, err := s.gateCandidates(ctx, run, st, cands)
	if err != nil {
		return d, err
	}
	if delta && stage.Heavy(st.Key) {
		var unchanged []hopCandidate
		planned, unchanged = s.deltaGate(ctx, run, step, st, planned)
		for _, c := range unchanged {
			d.rows = append(d.rows, c.row(scanrun.TargetSkipped, scanrun.ReasonUnchanged))
			skipped[scanrun.ReasonUnchanged]++
		}
	}
	inRange := seedRanges(seedList)
	for _, c := range planned {
		if coveredByRange(inRange, c.key) {
			// The step scans the range this address is in already (a range
			// swept and also found live): once is enough.
			d.rows = append(d.rows, c.row(scanrun.TargetSkipped, reasonCoveredByRange))
			skipped[reasonCoveredByRange]++
			continue
		}
		d.targets = append(d.targets, c.key)
		d.rows = append(d.rows, c.row(scanrun.TargetPlanned, plannedReason(st)))
		d.maxHop = max(d.maxHop, c.hop)
	}
	for _, c := range refused {
		d.rows = append(d.rows, c.row(scanrun.TargetSkipped, c.reason))
		skipped[c.reason]++
	}
	for _, c := range cands.dropped {
		d.rows = append(d.rows, c.row(scanrun.TargetSkipped, c.reason))
	}
	var hopLimited, overCap int
	for _, c := range cands.dropped {
		switch c.reason {
		case scanrun.ReasonHopLimit:
			hopLimited++
		case scanrun.ReasonOverCap:
			overCap++
		}
	}
	if n := overCap + max(total-len(outputs), 0)*boolInt(!wave); n > 0 {
		metrics.ScanStageTargetsSkipped.WithLabelValues(scanrun.ReasonOverCap).Add(float64(n))
		s.logger.Warn("chained stage fan-out capped",
			"run_id", run.ID.String(), "step_key", step.StepKey, "planned", len(planned), "over_cap", n)
	}
	if hopLimited > 0 {
		metrics.ScanStageTargetsSkipped.WithLabelValues(scanrun.ReasonHopLimit).Add(float64(hopLimited))
	}
	return d, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// deltaGate splits a heavy stage's planned candidates into those it runs on
// and those that are done since the previous run of the scan (unchanged).
// Without a previous run, a store that can decide, or a decision (an error
// is logged), every candidate runs: gating only ever saves work, it never
// hides an asset that needs it.
func (s *Service) deltaGate(ctx context.Context, run *scanrun.Run, step *scanworkflow.Step, st stage.Stage,
	cands []hopCandidate,
) (keep, unchanged []hopCandidate) {
	baseline, ok := s.hops.(scanrun.DeltaBaseline)
	if !ok || len(cands) == 0 {
		return cands, nil
	}
	prev, err := s.hops.PreviousRun(ctx, run.TenantID, run.ID)
	if err != nil {
		s.logger.Warn("delta gating: previous run unreadable; the stage runs on every target",
			"run_id", run.ID.String(), "step_key", step.StepKey, "error", err)
		return cands, nil
	}
	if prev.IsZero() {
		return cands, nil // first run of the scan: everything is new
	}
	ids := make([]shared.ID, 0, len(cands))
	for _, c := range cands {
		ids = append(ids, c.assetID)
	}
	done, err := baseline.UnchangedSince(ctx, run.TenantID, prev, step.StepKey, string(st.Key), ids, stage.HeavyMaxAge(st.Key))
	if err != nil {
		s.logger.Warn("delta gating: baseline unreadable; the stage runs on every target",
			"run_id", run.ID.String(), "step_key", step.StepKey, "error", err)
		return cands, nil
	}
	keep = make([]hopCandidate, 0, len(cands))
	for _, c := range cands {
		if done[c.assetID] {
			unchanged = append(unchanged, c)
			continue
		}
		keep = append(keep, c)
	}
	return keep, unchanged
}

// reasonCoveredByRange: a derived address a range seed of the same step
// already covers.
const reasonCoveredByRange = "covered_by_range"

// seedRanges is the address set of a step's range seeds.
func seedRanges(seeds []string) ipset.Set {
	var rs []ipset.Range
	for _, t := range seeds {
		t = strings.TrimSpace(t)
		if !strings.ContainsAny(t, "/-") {
			continue
		}
		if r, ok := ipset.Parse(t); ok {
			rs = append(rs, r)
		}
	}
	return ipset.Of(rs...)
}

// coveredByRange reports whether key is an address inside the set.
func coveredByRange(set ipset.Set, key string) bool {
	if set.Empty() {
		return false
	}
	a, err := netip.ParseAddr(strings.TrimSpace(key))
	return err == nil && set.Contains(a.Unmap())
}

func (s *Service) savePlan(ctx context.Context, plan *scanrun.StagePlan, rows []scanrun.RunTarget, out *scanapp.StepTargets) (*scanapp.StepTargets, error) {
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
		return scanrun.ReasonPassiveAllowed
	}
	return scanrun.ReasonGateAllowed
}

// seedTargets are the run's targets the step takes (after the type gate).
func seedTargets(run *scanrun.Run, seeds *scanapp.StepTargets) []string {
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
// whose stage produces a type this stage takes. With active, a predecessor
// that is still queued or running feeds too (a streamed stage takes what
// its finished tasks produced).
func feedingPredecessors(run *scanrun.Run, st stage.Stage, preds []*scanworkflow.Step, active bool) []feedingPred {
	out := make([]feedingPred, 0, len(preds))
	for _, p := range preds {
		ps, ok := stage.ForStep(p.Tool, p.Capabilities)
		if !ok || !stage.Feeds(ps, st) {
			continue
		}
		sr := run.GetStepRun(p.StepKey)
		if sr == nil || !(sr.Status.ProducedResults() || (active && (sr.IsQueued() || sr.IsRunning()))) {
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

func (c hopCandidate) row(decision, reason string) scanrun.RunTarget {
	var assetID *shared.ID
	if !c.assetID.IsZero() {
		id := c.assetID
		assetID = &id
	}
	return scanrun.RunTarget{TargetKey: c.key, AssetID: assetID, Origin: scanrun.TargetOriginDerived,
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
func deriveCandidates(st stage.Stage, outputs []scanrun.StepOutput, parents []scanrun.RunTarget,
	stageOf map[shared.ID]string, seen map[string]bool, skipped map[string]int, seedCount, stepCap int,
) (candidates, int) {
	return deriveCandidatesPrior(st, outputs, parents, stageOf, seen, nil, skipped, seedCount, stepCap)
}

// deriveCandidatesPrior is deriveCandidates for a later wave of a streamed
// stage: a key in prior was decided by an earlier wave. It is not decided
// again and not counted as an input or a duplicate; when it reached the
// gate then, it still counts against the per-parent and per-stage caps.
func deriveCandidatesPrior(st stage.Stage, outputs []scanrun.StepOutput, parents []scanrun.RunTarget,
	stageOf map[shared.ID]string, seen map[string]bool, prior map[string]scanrun.RunTarget, skipped map[string]int, seedCount, stepCap int,
) (candidates, int) {
	var out candidates
	inputs := 0
	perParent := map[string]int{}
	gated := 0 // prior keys that reached the gate
	budget := min(st.MaxFanout, stage.RunFanoutCap)
	if stepCap > 0 && stepCap < budget {
		// The step's own cap at the run's depth: lower-only.
		budget = stepCap
	}
	budget -= seedCount
	// Deterministic: by name, so a cap keeps the same targets run to run.
	sorted := append([]scanrun.StepOutput{}, outputs...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, o := range sorted {
		if !st.Accepts(asset.TypeRef{Type: asset.AssetType(o.Type), SubType: o.SubType}) {
			continue
		}
		inputs++
		key, ok := hopTargetKey(o.Name)
		c := hopCandidate{key: key, assetID: o.AssetID}
		if !ok {
			skipped[scanrun.ReasonInvalid]++ // not recorded: the name is not safe to store as a key
			continue
		}
		if p, decided := prior[key]; decided && !seen[key] {
			seen[key] = true
			inputs--
			if p.Reason != scanrun.ReasonHopLimit && p.Reason != scanrun.ReasonOverCap {
				gated++
				if parent, _, _ := traceParent(key, parents); parent != nil {
					perParent[parent.TargetKey]++
				}
			}
			continue
		}
		if seen[key] {
			skipped[scanrun.ReasonDuplicate]++
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
			c.reason = scanrun.ReasonHopLimit
		case parent != nil && perParent[parent.TargetKey] >= st.PerParentCap():
			c.reason = scanrun.ReasonOverCap
		case len(out.gate)+gated >= budget:
			c.reason = scanrun.ReasonOverCap
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
func (s *Service) gateCandidates(ctx context.Context, run *scanrun.Run, st stage.Stage, cands candidates) ([]hopCandidate, []hopCandidate, error) {
	if len(cands.gate) == 0 {
		return nil, nil, nil
	}
	if s.targetGate == nil {
		return nil, nil, errors.New("target gate is not configured; derived targets not dispatched")
	}
	byKey := make(map[string]hopCandidate, len(cands.gate))
	in := scanapp.DispatchTargetsInput{
		TenantID: run.TenantID, ActScope: true, FallbackUser: runActor(run),
		SystemPolicy: scanapp.RunSystemPolicy(run),
		PassiveOnly:  st.Tier.Passive(),
		Tier:         stageTier(st),
		// A lookup-only stage (resolve.dns) runs on names with no DNS
		// answer: finding out whether they resolve is its work.
		Capability: string(st.Key),
		Targets:    make([]string, 0, len(cands.gate)),
		Assets:     make(map[string]scanapp.DispatchAsset, len(cands.gate)),
	}
	for _, c := range cands.gate {
		byKey[c.key] = c
		in.Targets = append(in.Targets, c.key)
		if c.assetID.IsZero() {
			// A named open port (hop_named_ports.go) names no asset: it is
			// checked by name, as a seed is.
			continue
		}
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
	runZone := scanrun.ScanZoneFromContext(run.Context)
	planned := make([]hopCandidate, 0, len(d.Allowed))
	refused := make([]hopCandidate, 0, len(d.Excluded)+len(d.Refused))
	for _, t := range d.Allowed {
		c, ok := lookup(t)
		if !ok {
			continue
		}
		if !sameZone(runZone, d.Zone(t)) {
			c.reason = scanrun.ReasonOtherZone
			refused = append(refused, c)
			continue
		}
		planned = append(planned, c)
	}
	for _, t := range d.Excluded {
		if c, ok := lookup(t); ok {
			c.reason = scanrun.ReasonExcluded
			refused = append(refused, c)
		}
	}
	for _, r := range d.Refused {
		c, ok := lookup(r.Target)
		if !ok {
			continue
		}
		c.reason = scanrun.ReasonRefused
		if r.Reason == scanapp.ReasonOwnershipNotConfirmed {
			c.reason = scanrun.ReasonUnconfirmed
			if r.Code == scopedom.RefusalWildcardOnly {
				c.reason = scanrun.ReasonWildcardOnly
			}
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
func runActor(run *scanrun.Run) *shared.ID {
	// A platform policy's run acts as its policy, never as a person.
	if scanapp.RunSystemPolicy(run) != "" {
		return nil
	}
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
	if h, p, _, ok := asset.SplitServiceName(s); ok {
		// A service in any name form keys as host:port.
		if !validHost(h) || !validPort(strconv.Itoa(p)) {
			return "", false
		}
		return net.JoinHostPort(h, strconv.Itoa(p)), true
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
	if host, _, _, ok := asset.SplitServiceName(key); ok {
		h = host
	} else if host, _, err := net.SplitHostPort(key); err == nil {
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
func traceParent(key string, parents []scanrun.RunTarget) (*scanrun.RunTarget, int, string) {
	h := keyHost(key)
	maxHop := 0
	var under *scanrun.RunTarget
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
	template, err := s.runWorkflow(ctx, run)
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
func (s *Service) ListRunStages(ctx context.Context, tenantID, runID string) ([]scanrun.StagePlan, error) {
	run, err := s.GetRun(ctx, tenantID, runID)
	if err != nil {
		return nil, err
	}
	if s.hops == nil {
		return []scanrun.StagePlan{}, nil
	}
	plans, err := s.hops.ListStagePlans(ctx, run.TenantID, run.ID)
	if err != nil {
		return nil, err
	}
	if plans == nil {
		plans = []scanrun.StagePlan{}
	}
	return plans, nil
}

// stageTier is the stage's tier as the target gate's ceiling check reads it.
func stageTier(st stage.Stage) *scopedom.Tier {
	t := scopedom.Tier(st.Tier)
	return &t
}
