package scanrun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// memHops is an in-memory HopRepository.
type memHops struct {
	outputs   map[shared.ID][]scanrun.StepOutput
	pending   bool
	plans     map[string]scanrun.StagePlan
	targets   []scanrun.RunTarget
	cmdRun    map[shared.ID]shared.ID
	saveCalls int
	previous  shared.ID                 // PreviousRun
	deltas    []scanrun.StepOutputDelta // CompareStepOutputs
	preview   []scanrun.StepOutput      // PreviewStepOutputs
}

func (m *memHops) PreviousRun(context.Context, shared.ID, shared.ID) (shared.ID, error) {
	return m.previous, nil
}

func (m *memHops) CompareStepOutputs(_ context.Context, _, _, prev shared.ID, _ *shared.DataScope) ([]scanrun.StepOutputDelta, error) {
	if prev.IsZero() {
		return nil, nil
	}
	return m.deltas, nil
}

func (m *memHops) PreviewStepOutputs(_ context.Context, _, _, _ shared.ID, _ string, _ *shared.DataScope, limit int) ([]scanrun.StepOutput, int, error) {
	if len(m.preview) > limit {
		return m.preview[:limit], len(m.preview), nil
	}
	return m.preview, len(m.preview), nil
}

func newMemHops() *memHops {
	return &memHops{outputs: map[shared.ID][]scanrun.StepOutput{}, plans: map[string]scanrun.StagePlan{},
		cmdRun: map[shared.ID]shared.ID{}}
}

func (m *memHops) RecordStepOutputs(context.Context, shared.ID, shared.ID, []shared.ID) (int, error) {
	return 0, nil
}

func (m *memHops) ListStepOutputs(_ context.Context, _, _ shared.ID, srs []shared.ID, limit int) ([]scanrun.StepOutput, int, error) {
	var all []scanrun.StepOutput
	for _, sr := range srs {
		all = append(all, m.outputs[sr]...)
	}
	total := len(all)
	if len(all) > limit {
		all = all[:limit]
	}
	return all, total, nil
}

func (m *memHops) PendingStepIngest(context.Context, shared.ID, []shared.ID) (bool, error) {
	return m.pending, nil
}

func (m *memHops) SaveStagePlan(_ context.Context, p *scanrun.StagePlan, rows []scanrun.RunTarget) (bool, error) {
	m.saveCalls++
	k := p.RunID.String() + "/" + p.StageKey
	if _, dup := m.plans[k]; dup {
		return false, nil
	}
	m.plans[k] = *p
	for _, r := range rows {
		r.StageKey = p.StageKey
		m.targets = append(m.targets, r)
	}
	return true, nil
}

func (m *memHops) PlannedTargets(_ context.Context, _, _ shared.ID, keys []string) ([]scanrun.RunTarget, error) {
	var out []scanrun.RunTarget
	for _, t := range m.targets {
		for _, k := range keys {
			if t.StageKey == k && t.Decision == scanrun.TargetPlanned {
				out = append(out, t)
			}
		}
	}
	return out, nil
}

func (m *memHops) CountStepOutputs(context.Context, shared.ID, shared.ID, *shared.DataScope) ([]scanrun.StepOutputCount, error) {
	return nil, nil
}

func (m *memHops) ListStagePlans(_ context.Context, _, runID shared.ID) ([]scanrun.StagePlan, error) {
	var out []scanrun.StagePlan
	for _, p := range m.plans {
		if p.RunID == runID {
			out = append(out, p)
		}
	}
	return out, nil
}

func (m *memHops) StepRunOfCommand(_ context.Context, _, cmd shared.ID) (shared.ID, string, error) {
	if r, ok := m.cmdRun[cmd]; ok {
		return r, "", nil
	}
	return shared.ID{}, "", shared.ErrNotFound
}

func (m *memHops) plan(t *testing.T, run shared.ID, key string) scanrun.StagePlan {
	t.Helper()
	p, ok := m.plans[run.String()+"/"+key]
	if !ok {
		t.Fatalf("stage %s was not planned", key)
	}
	return p
}

// attrTable is an ownership gate: asset id -> state, typed name -> state.
type attrTable struct {
	byID   map[string]attribution.State
	byName map[string]attribution.State
	// ceiling: name -> max_tier of the entry covering it (absent: any).
	ceiling map[string]scopedom.Tier
	// uncovered: names no scope authority covers (passive stages).
	uncovered map[string]bool
}

func (a attrTable) ActiveCheckBlocked(_ context.Context, _ shared.ID, ids []string) (map[string]attribution.State, error) {
	out := map[string]attribution.State{}
	for _, id := range ids {
		if s, ok := a.byID[id]; ok {
			out[id] = s
		}
	}
	return out, nil
}

func (a attrTable) TierExceeded(_ context.Context, _ shared.ID, ts []string, tier scopedom.Tier) (map[string]*scopedom.RuleRef, error) {
	out := map[string]*scopedom.RuleRef{}
	for _, t := range ts {
		if c, ok := a.ceiling[t]; ok && c < tier {
			out[t] = nil
		}
	}
	return out, nil
}

func (a attrTable) BlockedTargets(_ context.Context, _ shared.ID, ts []string) (map[string]attribution.State, error) {
	out := map[string]attribution.State{}
	for _, t := range ts {
		if s, ok := a.byName[t]; ok {
			out[t] = s
		}
	}
	return out, nil
}

// excludeNames is a scope-exclusion filter on exact names.
type excludeNames map[string]bool

func (e excludeNames) ExcludedTargets(_ context.Context, _ string, cs []scope.ExclusionCandidate) (map[shared.ID]bool, error) {
	out := map[shared.ID]bool{}
	for _, c := range cs {
		for _, v := range c.Values {
			if e[v] {
				out[c.ID] = true
			}
		}
	}
	return out, nil
}

// allowActs lets the actor scan everything.
type allowActs struct{ asked []actscope.Input }

func (a *allowActs) Check(_ context.Context, in actscope.Input) (*actscope.Decision, error) {
	a.asked = append(a.asked, in)
	return &actscope.Decision{RefusedTargets: map[string]string{}, RefusedAssets: map[shared.ID]bool{}}, nil
}

type zoneList struct{ zones []*scanzone.Zone }

func (z zoneList) List(context.Context, shared.ID) ([]*scanzone.Zone, error) { return z.zones, nil }
func (z zoneList) RoutableSensors(context.Context, shared.ID, []shared.ID, string) (map[shared.ID][]scanzone.SensorCandidate, error) {
	return nil, nil
}

// chainFixture: subs (subfinder) -> dns (dnsx) -> ports (naabu), run seeded
// with acme.com, the real target gate (scan.ResolveDispatchTargets) over a
// fake ownership table and exclusions.
type chainFixture struct {
	s     *Service
	run   *scanrun.Run
	tpl   *scanworkflow.Workflow
	store *memStepRuns
	cmds  *countingCommands
	hops  *memHops
	attr  attrTable
	acts  *allowActs
	excl  excludeNames
	sr    map[string]shared.ID
}

func newChainFixture(t *testing.T, zones ...*scanzone.Zone) *chainFixture {
	t.Helper()
	f := &chainFixture{hops: newMemHops(), cmds: &countingCommands{}, acts: &allowActs{}, excl: excludeNames{},
		attr: attrTable{byID: map[string]attribution.State{}, byName: map[string]attribution.State{}, ceiling: map[string]scopedom.Tier{}}, sr: map[string]shared.ID{}}
	f.run = &scanrun.Run{ID: shared.NewID(), TenantID: shared.NewID(), ScanWorkflowID: shared.NewID(),
		Status: scanrun.RunStatusRunning, Context: map[string]any{"targets": []string{"acme.com"}}}
	f.tpl = &scanworkflow.Workflow{}
	f.store = &memStepRuns{rows: map[string]scanrun.StepRun{}}
	steps := []struct {
		key, tool string
		deps      []string
	}{{"subs", "subfinder", nil}, {"dns", "dnsx", []string{"subs"}}, {"ports", "naabu", []string{"dns"}}, {"http", "httpx", []string{"ports"}}}
	for i, st := range steps {
		step := &scanworkflow.Step{ID: shared.NewID(), StepKey: st.key, Tool: st.tool, StepOrder: i + 1,
			DependsOn: st.deps, Condition: scanworkflow.AlwaysCondition()}
		f.tpl.Steps = append(f.tpl.Steps, step)
		sr := scanrun.NewStepRun(f.run.ID, step.ID, st.key, step.StepOrder, 0)
		f.sr[st.key] = sr.ID
		f.store.rows[st.key] = *sr
		cp := *sr
		f.run.StepRuns = append(f.run.StepRuns, &cp)
	}
	f.run.TotalSteps = len(steps)
	gate := scanapp.NewTargetGate(f.excl, f.attr, zoneList{zones: zones}, nil, logger.NewNop())
	scanapp.WithActScope(f.acts)(gate)
	f.s = &Service{stepRunRepo: f.store, runRepo: &statusRuns{run: f.run}, templateRepo: fixedTemplate{tpl: f.tpl},
		commandRepo: f.cmds, toolRepo: platformTools{names: map[string]bool{"subfinder": true, "dnsx": true, "naabu": true, "httpx": true}},
		targetGate: gate, hops: f.hops, sensorRepo: tenantSensors{id: shared.NewID()}, logger: logger.NewNop()}
	return f
}

// settle marks a step finished with the given status in the store and in
// the run copy the scheduler reads.
func (f *chainFixture) settle(key string, status scanrun.StepRunStatus) {
	r := f.store.rows[key]
	r.Status = status
	f.store.rows[key] = r
	if sr := f.run.GetStepRun(key); sr != nil {
		sr.Status = status
	}
}

// seed records a planned target of a stage (what an earlier planning wrote).
func (f *chainFixture) seed(stageKey, target string, hop int, asset *shared.ID) {
	f.hops.targets = append(f.hops.targets, scanrun.RunTarget{StageKey: stageKey, TargetKey: target, Hop: hop,
		AssetID: asset, Decision: scanrun.TargetPlanned, Origin: scanrun.TargetOriginSeed})
}

// output records an asset a stage produced and returns its id.
func (f *chainFixture) output(stageKey, name, typ, sub string, state attribution.State) shared.ID {
	id := shared.NewID()
	f.hops.outputs[f.sr[stageKey]] = append(f.hops.outputs[f.sr[stageKey]],
		scanrun.StepOutput{StepRunID: f.sr[stageKey], AssetID: id, Name: name, Type: typ, SubType: sub})
	if state != "" {
		f.attr.byID[id.String()] = state
	}
	return id
}

func (f *chainFixture) schedule(t *testing.T) {
	t.Helper()
	if err := f.s.scheduleRunnableSteps(context.Background(), f.run, f.tpl); err != nil {
		t.Fatal(err)
	}
}

// lastTargets decodes the targets of the n-th command created.
func (f *chainFixture) commandTargets(t *testing.T, n int) []string {
	t.Helper()
	if len(f.cmds.created) <= n {
		t.Fatalf("only %d command(s) created; step rows: %+v", len(f.cmds.created), f.store.rows)
	}
	var p struct {
		Targets []string `json:"targets"`
		Scanner string   `json:"scanner"`
	}
	if err := json.Unmarshal([]byte(f.cmds.created[n]), &p); err != nil {
		t.Fatal(err)
	}
	sort.Strings(p.Targets)
	return p.Targets
}

// allCommandTargets is the union of the targets of every created command,
// sorted; it fails on a target carried by two commands.
func (f *chainFixture) allCommandTargets(t *testing.T) []string {
	t.Helper()
	var all []string
	seen := map[string]bool{}
	for i := range f.cmds.created {
		for _, x := range f.commandTargets(t, i) {
			if seen[x] {
				t.Fatalf("target %s is in two commands", x)
			}
			seen[x] = true
			all = append(all, x)
		}
	}
	sort.Strings(all)
	return all
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// E6 + the tier rule (research/22 P0-5, research/27 §5.7): subfinder's
// output feeds dnsx; a needs_review name reaches dnsx (T0) but not naabu
// (T1). The seed stays a target of every stage.
func TestHopRouter_NeedsReviewReachesPassiveStageOnly(t *testing.T) {
	f := newChainFixture(t)
	f.seed("subs", "acme.com", 0, nil)
	f.settle("subs", scanrun.StepRunStatusCompleted)
	review := f.output("subs", "new.acme.com", "subdomain", "", attribution.StateNeedsReview)
	f.output("subs", "www.acme.com", "subdomain", "", "")

	f.schedule(t)
	dns := f.commandTargets(t, 0)
	if !contains(dns, "acme.com") || !contains(dns, "www.acme.com") || !contains(dns, "new.acme.com") {
		t.Fatalf("dnsx targets = %v: the seed and subfinder's names (needs_review too) must reach a T0 stage", dns)
	}
	p := f.hops.plan(t, f.run.ID, "dns")
	if !p.Chained || p.Planned != 3 || p.MaxHop != 1 || p.Tier != 0 {
		t.Fatalf("dns plan = %+v", p)
	}

	// dnsx re-observes the names and resolves an address.
	f.settle("dns", scanrun.StepRunStatusCompleted)
	f.hops.outputs[f.sr["dns"]] = []scanrun.StepOutput{
		{StepRunID: f.sr["dns"], AssetID: review, Name: "new.acme.com", Type: "subdomain"},
		{StepRunID: f.sr["dns"], AssetID: shared.NewID(), Name: "www.acme.com", Type: "subdomain"},
		{StepRunID: f.sr["dns"], AssetID: shared.NewID(), Name: "203.0.113.7", Type: "ip_address"},
	}
	f.schedule(t)
	ports := f.commandTargets(t, 1)
	if contains(ports, "new.acme.com") {
		t.Fatalf("naabu targets = %v: a needs_review name reached an active (T1) stage", ports)
	}
	if !contains(ports, "www.acme.com") || !contains(ports, "203.0.113.7") || !contains(ports, "acme.com") {
		t.Fatalf("naabu targets = %v", ports)
	}
	pp := f.hops.plan(t, f.run.ID, "ports")
	if pp.Skipped[scanrun.ReasonUnconfirmed] != 1 || pp.MaxHop != 2 {
		t.Fatalf("ports plan = %+v", pp)
	}
	// The refused name is recorded with its reason.
	found := false
	for _, r := range f.hops.targets {
		if r.StageKey == "ports" && r.TargetKey == "new.acme.com" {
			found = r.Decision == scanrun.TargetSkipped && r.Reason == scanrun.ReasonUnconfirmed &&
				r.Origin == scanrun.TargetOriginDerived && r.Relation == "same_host" && r.ParentStageKey == "dns"
		}
	}
	if !found {
		t.Fatal("the refused name has no provenance row with its reason")
	}
	if len(f.acts.asked) == 0 {
		t.Fatal("derived targets did not go through the act-scope check")
	}
}

// RFC-054 §4.2 step 6 on a chained hop: a name whose scope entry allows t0
// only reaches the passive stage (dnsx), never the active one (naabu).
func TestHopRouter_TierCeiling(t *testing.T) {
	f := newChainFixture(t)
	f.seed("subs", "acme.com", 0, nil)
	f.settle("subs", scanrun.StepRunStatusCompleted)
	f.attr.ceiling["passive.acme.com"] = scopedom.TierPassive
	f.output("subs", "passive.acme.com", "subdomain", "", "")
	f.output("subs", "www.acme.com", "subdomain", "", "")

	f.schedule(t)
	if dns := f.commandTargets(t, 0); !contains(dns, "passive.acme.com") {
		t.Fatalf("dnsx targets = %v: a t0 entry authorizes a passive stage", dns)
	}
	f.settle("dns", scanrun.StepRunStatusCompleted)
	f.hops.outputs[f.sr["dns"]] = []scanrun.StepOutput{
		{StepRunID: f.sr["dns"], AssetID: shared.NewID(), Name: "passive.acme.com", Type: "subdomain"},
		{StepRunID: f.sr["dns"], AssetID: shared.NewID(), Name: "www.acme.com", Type: "subdomain"},
	}
	f.schedule(t)
	ports := f.commandTargets(t, 1)
	if contains(ports, "passive.acme.com") || !contains(ports, "www.acme.com") {
		t.Fatalf("naabu targets = %v: a name covered only at t0 reached a t1 stage", ports)
	}
}

// An excluded name and a rejected (tombstoned) name are never dispatched,
// not even to a passive stage.
func TestHopRouter_ExcludedAndRejectedNeverDispatched(t *testing.T) {
	f := newChainFixture(t)
	f.seed("subs", "acme.com", 0, nil)
	f.settle("subs", scanrun.StepRunStatusCompleted)
	f.excl["legacy.acme.com"] = true
	f.output("subs", "legacy.acme.com", "subdomain", "", "")
	f.output("subs", "old.acme.com", "subdomain", "", attribution.StateRejected)
	f.output("subs", "ok.acme.com", "subdomain", "", "")

	f.schedule(t)
	dns := f.commandTargets(t, 0)
	if contains(dns, "legacy.acme.com") || contains(dns, "old.acme.com") || !contains(dns, "ok.acme.com") {
		t.Fatalf("dnsx targets = %v", dns)
	}
	p := f.hops.plan(t, f.run.ID, "dns")
	if p.Skipped[scanrun.ReasonExcluded] != 1 || p.Skipped[scanrun.ReasonUnconfirmed] != 1 {
		t.Fatalf("skipped = %v", p.Skipped)
	}
}

// A 20k fan-out is capped: one parent gives at most its per-parent cap, the
// stage never takes more than its cap, outputs beyond what one plan reads
// are counted, and the step is still dispatched with what fits.
func TestHopRouter_FanOutCapped(t *testing.T) {
	f := newChainFixture(t)
	f.seed("subs", "acme.com", 0, nil)
	f.settle("subs", scanrun.StepRunStatusCompleted)
	for i := 0; i < 20001; i++ {
		f.output("subs", fmt.Sprintf("h%05d.acme.com", i), "subdomain", "", "")
	}
	f.schedule(t)
	dns := f.allCommandTargets(t)
	if len(dns) != 5001 {
		t.Fatalf("dnsx got %d targets, want 5000 derived + the seed", len(dns))
	}
	// Cut into chunks of the capability's size (resolve.dns: 200), one
	// unpinned command each, so every eligible sensor takes a share.
	if len(f.cmds.created) != 26 {
		t.Fatalf("commands = %d, want 26 chunks of at most 200", len(f.cmds.created))
	}
	for i := range f.cmds.created {
		if n := len(f.commandTargets(t, i)); n > 200 {
			t.Fatalf("chunk %d has %d targets", i, n)
		}
	}
	p := f.hops.plan(t, f.run.ID, "dns")
	if p.Planned != 5001 || p.Skipped[scanrun.ReasonOverCap] != 15001 || p.Inputs != 20002 {
		t.Fatalf("plan = planned %d inputs %d skipped %v", p.Planned, p.Inputs, p.Skipped)
	}
}

// A derived target more than MaxHops discovery hops from the seeds is
// skipped with hop_limit.
func TestHopRouter_HopLimit(t *testing.T) {
	f := newChainFixture(t)
	f.seed("dns", "deep.acme.com", 3, nil)
	f.settle("subs", scanrun.StepRunStatusCompleted)
	f.settle("dns", scanrun.StepRunStatusCompleted)
	f.run.Context["targets"] = []string{}
	f.output("dns", "deep.acme.com", "subdomain", "", "") // same host: hop 3, allowed
	f.output("dns", "203.0.113.9", "ip_address", "", "")  // a resolved address: hop 4
	f.schedule(t)
	ports := f.commandTargets(t, 0)
	if contains(ports, "203.0.113.9") || !contains(ports, "deep.acme.com") {
		t.Fatalf("naabu targets = %v", ports)
	}
	if p := f.hops.plan(t, f.run.ID, "ports"); p.Skipped[scanrun.ReasonHopLimit] != 1 || p.MaxHop != 3 {
		t.Fatalf("plan = %+v", p)
	}
}

// Hostile names in a report never become targets: control and bidi
// characters, oversize names, other URL schemes, credentials in URLs; the
// metadata address is refused by the target validator.
func TestHopRouter_HostileOutputsBounded(t *testing.T) {
	f := newChainFixture(t)
	f.seed("subs", "acme.com", 0, nil)
	f.settle("subs", scanrun.StepRunStatusCompleted)
	for _, n := range []string{
		"evil\u202egnp.acme.com", "a\x00b.acme.com", "tab\tx.acme.com",
		strings.Repeat("a", 3000) + ".acme.com", "-bad.acme.com", "fine.acme.com",
	} {
		f.output("subs", n, "subdomain", "", "")
	}
	f.schedule(t)
	dns := f.commandTargets(t, 0)
	if len(dns) != 2 || !contains(dns, "fine.acme.com") {
		t.Fatalf("dnsx targets = %v", dns)
	}
	if p := f.hops.plan(t, f.run.ID, "dns"); p.Skipped[scanrun.ReasonInvalid] != 5 {
		t.Fatalf("skipped = %v", p.Skipped)
	}

	// The probe stage refuses URLs it must not touch and the metadata address.
	g := newChainFixture(t)
	g.seed("ports", "acme.com", 0, nil)
	g.settle("subs", scanrun.StepRunStatusCompleted)
	g.settle("dns", scanrun.StepRunStatusCompleted)
	g.settle("ports", scanrun.StepRunStatusCompleted)
	g.run.Context["targets"] = []string{}
	g.output("ports", "169.254.169.254:80", "service", "open_port", "")
	g.output("ports", "acme.com:443", "service", "open_port", "")
	g.schedule(t)
	http := g.commandTargets(t, 0)
	if len(http) != 1 || http[0] != "acme.com:443" {
		t.Fatalf("httpx targets = %v", http)
	}
	if p := g.hops.plan(t, g.run.ID, "http"); p.Skipped[scanrun.ReasonRefused] != 1 {
		t.Fatalf("skipped = %v", p.Skipped)
	}
	for _, k := range []string{"javascript:alert(1)", "http://user:pw@acme.com/", "ftp://acme.com/", "https://acme.com:99999/"} {
		if _, ok := hopTargetKey(k); ok {
			t.Errorf("%q accepted as a target", k)
		}
	}
}

// Exactly once per (run, stage): a second planning of the same stage (a
// duplicate completion or ingest event racing the first) creates nothing.
func TestHopRouter_PlansAStageOnce(t *testing.T) {
	f := newChainFixture(t)
	f.seed("subs", "acme.com", 0, nil)
	f.settle("subs", scanrun.StepRunStatusCompleted)
	f.output("subs", "www.acme.com", "subdomain", "", "")
	dns := f.tpl.Steps[1]
	stale := f.store.rows["dns"] // both callers read the step while pending
	for i := 0; i < 2; i++ {
		sr := stale
		err := f.s.queueStepForExecutionWithSettings(context.Background(), f.run, dns, &sr, f.tpl.Settings, predecessorsOf(f.tpl, dns))
		if i == 0 && err != nil {
			t.Fatal(err)
		}
		if i == 1 && !errors.Is(err, errStageAlreadyPlanned) {
			t.Fatalf("second planning: err = %v", err)
		}
	}
	if len(f.cmds.created) != 1 {
		t.Fatalf("commands = %d, want 1", len(f.cmds.created))
	}
}

// A predecessor whose report is still being ingested defers the stage; the
// ingest commit plans it. A partial predecessor still feeds its successor.
func TestHopRouter_WaitsForIngestThenPlans(t *testing.T) {
	f := newChainFixture(t)
	f.seed("subs", "acme.com", 0, nil)
	f.settle("subs", scanrun.StepRunStatusPartial)
	f.output("subs", "www.acme.com", "subdomain", "", "")
	f.hops.pending = true

	f.schedule(t)
	if len(f.cmds.created) != 0 || f.store.rows["dns"].Status != scanrun.StepRunStatusPending {
		t.Fatalf("planned before ingest committed: commands %d, dns %s", len(f.cmds.created), f.store.rows["dns"].Status)
	}

	f.hops.pending = false
	cmd := shared.NewID()
	f.hops.cmdRun[cmd] = f.run.ID
	f.s.OnCommandIngested(context.Background(), f.run.TenantID, cmd)
	dns := f.commandTargets(t, 0)
	if !contains(dns, "www.acme.com") {
		t.Fatalf("dnsx targets = %v: a partial predecessor must still feed", dns)
	}
	// The same event again plans nothing.
	f.s.OnCommandIngested(context.Background(), f.run.TenantID, cmd)
	if len(f.cmds.created) != 1 {
		t.Fatalf("commands = %d after a duplicate ingest event", len(f.cmds.created))
	}
	// Another tenant's command resolves to nothing here.
	f.s.OnCommandIngested(context.Background(), shared.NewID(), cmd)
	if len(f.cmds.created) != 1 {
		t.Fatal("another tenant's event advanced the run")
	}
}

// A chained step that ends with nothing to scan is settled without a
// command, with the reason, and the run moves on.
func TestHopRouter_NoInputsSettlesTheStep(t *testing.T) {
	f := newChainFixture(t)
	f.seed("subs", "acme.com", 0, nil)
	f.run.Context["targets"] = []string{}
	f.settle("subs", scanrun.StepRunStatusCompleted)
	f.output("subs", "old.acme.com", "subdomain", "", attribution.StateRejected)
	f.schedule(t)
	dns := f.store.rows["dns"]
	if dns.Status != scanrun.StepRunStatusCompleted || !strings.Contains(dns.SkipReason, "no inputs") {
		t.Fatalf("dns = %s %q", dns.Status, dns.SkipReason)
	}
	if len(f.cmds.created) != 0 {
		t.Fatalf("a command was created for a stage with nothing to scan: %v", f.cmds.created)
	}
}

// A derived target in another scan zone than the run is never handed to the
// run's stage: a chained step stays in its run's zone.
func TestHopRouter_StaysInTheRunZone(t *testing.T) {
	tenant := shared.NewID()
	sensor := shared.NewID()
	z1, err := scanzone.NewZone(tenant, "dc1", "", false, []string{"10.1.0.0/16"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	z2, err := scanzone.NewZone(tenant, "dc2", "", false, []string{"10.2.0.0/16"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	z1.SensorIDs, z2.SensorIDs = []shared.ID{sensor}, []shared.ID{sensor}
	f := newChainFixture(t, z1, z2)
	f.run.TenantID = tenant
	f.run.Context = map[string]any{"targets": []string{}, scanrun.RunContextKeyScanZoneID: z1.ID.String()}
	f.seed("dns", "10.1.0.1", 0, nil)
	f.settle("subs", scanrun.StepRunStatusCompleted)
	f.settle("dns", scanrun.StepRunStatusCompleted)
	f.output("dns", "10.1.0.5", "ip_address", "", "")
	f.output("dns", "10.2.0.5", "ip_address", "", "")
	f.schedule(t)
	ports := f.commandTargets(t, 0)
	if len(ports) != 1 || ports[0] != "10.1.0.5" {
		t.Fatalf("naabu targets = %v", ports)
	}
	if p := f.hops.plan(t, f.run.ID, "ports"); p.Skipped[scanrun.ReasonOtherZone] != 1 {
		t.Fatalf("skipped = %v", p.Skipped)
	}
}

// An intrusive (T2) stage after another stage is refused: intrusive stages
// never take derived targets.
func TestHopRouter_IntrusiveStageIsNotChained(t *testing.T) {
	f := newChainFixture(t)
	f.tpl.Steps[3].Tool = "zap"
	f.s.toolRepo = platformTools{names: map[string]bool{"zap": true}}
	f.seed("ports", "acme.com", 0, nil)
	f.settle("subs", scanrun.StepRunStatusCompleted)
	f.settle("dns", scanrun.StepRunStatusCompleted)
	f.settle("ports", scanrun.StepRunStatusCompleted)
	f.output("ports", "acme.com:443", "service", "open_port", "")
	// zap takes http services; feed it one from the step before.
	f.tpl.Steps[2].Tool = "httpx"
	f.output("ports", "https://acme.com", "service", "http", "")
	f.schedule(t)
	if r := f.store.rows["http"]; r.Status != scanrun.StepRunStatusFailed || r.ErrorCode != codeStageNotChainable {
		t.Fatalf("zap step = %s/%s", r.Status, r.ErrorCode)
	}
}

// A root step records its seeds once, so later stages can trace their
// parents, and the run's lanes read back.
func TestHopRouter_RootStageRecordsSeedsAndLanes(t *testing.T) {
	f := newChainFixture(t)
	f.schedule(t)
	if got := f.commandTargets(t, 0); len(got) != 1 || got[0] != "acme.com" {
		t.Fatalf("subfinder targets = %v", got)
	}
	p := f.hops.plan(t, f.run.ID, "subs")
	if p.Chained || p.Planned != 1 || p.Stage != "discover.subdomains" || p.Tool != "subfinder" {
		t.Fatalf("subs plan = %+v", p)
	}
	parents, _ := f.hops.PlannedTargets(context.Background(), f.run.TenantID, f.run.ID, []string{"subs"})
	if len(parents) != 1 || parents[0].Origin != scanrun.TargetOriginSeed || parents[0].Hop != 0 {
		t.Fatalf("seed rows = %+v", parents)
	}
}

// tenantRuns answers GetByTenantAndID for its own tenant only.
type tenantRuns struct {
	statusRuns
}

func (r *tenantRuns) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*scanrun.Run, error) {
	if r.run == nil || r.run.TenantID != tenantID || r.run.ID != id {
		return nil, shared.ErrNotFound
	}
	return r.run, nil
}

// A run of another tenant has no stage lanes: not found.
func TestListRunStages_CrossTenantNotFound(t *testing.T) {
	f := newChainFixture(t)
	f.s.runRepo = &tenantRuns{statusRuns{run: f.run}}
	f.schedule(t)
	plans, err := f.s.ListRunStages(context.Background(), f.run.TenantID.String(), f.run.ID.String())
	if err != nil || len(plans) != 1 || plans[0].StageKey != "subs" {
		t.Fatalf("own run: %v %v", plans, err)
	}
	if _, err := f.s.ListRunStages(context.Background(), shared.NewID().String(), f.run.ID.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another tenant read the lanes: %v", err)
	}
}

// A service in every name form is a hop target keyed as host:port
// (research/63 PR0); a bad port is still refused.
func TestHopTargetKey_ServiceNames(t *testing.T) {
	for in, want := range map[string]string{
		"example.co.uk:443:tcp": "example.co.uk:443",
		"example.co.uk:443/tcp": "example.co.uk:443",
		"[2001:db8::1]:443/tcp": "[2001:db8::1]:443",
		"203.0.113.5:22:tcp":    "203.0.113.5:22",
	} {
		got, ok := hopTargetKey(in)
		if !ok || got != want {
			t.Errorf("hopTargetKey(%q) = %q, %v; want %q", in, got, ok, want)
		}
		if h := keyHost(in); h == "" {
			t.Errorf("keyHost(%q) is empty", in)
		}
	}
	if _, ok := hopTargetKey("example.co.uk:70000:tcp"); ok {
		t.Error("an out-of-range port was accepted")
	}
}

func (a attrTable) UncoveredTargets(_ context.Context, _ shared.ID, ts []string) ([]string, error) {
	var out []string
	for _, t := range ts {
		if a.uncovered[t] {
			out = append(out, t)
		}
	}
	return out, nil
}
