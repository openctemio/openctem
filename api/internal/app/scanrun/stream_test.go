package scanrun

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// --- memHops as a stream store ---------------------------------------------

func (m *memHops) LockStageStream(context.Context, shared.ID, shared.ID, string) (func(), error) {
	return func() {}, nil
}

func (m *memHops) StageStream(_ context.Context, _, runID shared.ID, key string) (scanrun.StagePlan, bool, error) {
	p, ok := m.plans[runID.String()+"/"+key]
	return p, ok, nil
}

func (m *memHops) StageTargets(_ context.Context, _, _ shared.ID, key string) ([]scanrun.RunTarget, error) {
	var out []scanrun.RunTarget
	for _, t := range m.targets {
		if t.StageKey == key {
			out = append(out, t)
		}
	}
	return out, nil
}

func (m *memHops) SaveStageWave(_ context.Context, p *scanrun.StagePlan, rows []scanrun.RunTarget) ([]string, error) {
	k := p.RunID.String() + "/" + p.StageKey
	plan, ok := m.plans[k]
	if !ok || !plan.StreamOpen {
		return nil, nil
	}
	have := map[string]bool{}
	for _, t := range m.targets {
		if t.StageKey == p.StageKey {
			have[t.TargetKey] = true
		}
	}
	var added []string
	for _, r := range rows {
		if have[r.TargetKey] {
			continue
		}
		have[r.TargetKey] = true
		r.StageKey = p.StageKey
		m.targets = append(m.targets, r)
		if r.Decision == scanrun.TargetPlanned {
			added = append(added, r.TargetKey)
		}
	}
	planned := 0
	skipped := map[string]int{}
	for kk, v := range p.Skipped {
		skipped[kk] += v
	}
	for _, t := range m.targets {
		if t.StageKey != p.StageKey {
			continue
		}
		if t.Decision == scanrun.TargetPlanned {
			planned++
		} else {
			skipped[t.Reason]++
		}
	}
	plan.Inputs, plan.Planned, plan.Skipped = p.Inputs, planned, skipped
	if len(added) > 0 {
		plan.Waves++
	}
	m.plans[k] = plan
	return added, nil
}

func (m *memHops) CloseStageStream(_ context.Context, _, runID shared.ID, key string) (bool, error) {
	k := runID.String() + "/" + key
	p, ok := m.plans[k]
	if !ok || !p.StreamOpen {
		return false, nil
	}
	p.StreamOpen = false
	m.plans[k] = p
	return true, nil
}

// --- commands with states ---------------------------------------------------

// streamCmds keeps every command with its state and answers the batch gate.
type streamCmds struct {
	command.Repository
	mu        sync.Mutex
	cmds      []*command.Command
	finalized map[shared.ID]bool
}

func (c *streamCmds) Create(_ context.Context, cmd *command.Command) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	cmd.Status = command.CommandStatusPending
	c.cmds = append(c.cmds, cmd)
	return nil
}

func (c *streamCmds) StepBatchState(_ context.Context, _, stepRunID shared.ID) (command.StepBatch, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var b command.StepBatch
	for _, cmd := range c.cmds {
		if cmd.StepRunID == nil || *cmd.StepRunID != stepRunID {
			continue
		}
		b.Total++
		switch cmd.Status {
		case command.CommandStatusPending, command.CommandStatusAcknowledged, command.CommandStatusRunning:
			b.Active++
		case command.CommandStatusFailed, command.CommandStatusExpired, command.CommandStatusCanceled:
			b.Failed++
			if b.FirstError == "" {
				b.FirstError = "tool crashed"
			}
		}
	}
	return b, nil
}

func (c *streamCmds) ClaimStepFinalization(_ context.Context, stepRunID shared.ID) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.finalized[stepRunID] {
		return false, nil
	}
	c.finalized[stepRunID] = true
	return true, nil
}

// of returns the commands of a step run.
func (c *streamCmds) of(stepRunID shared.ID) []*command.Command {
	var out []*command.Command
	for _, cmd := range c.cmds {
		if cmd.StepRunID != nil && *cmd.StepRunID == stepRunID {
			out = append(out, cmd)
		}
	}
	return out
}

func cmdTargets(t *testing.T, cmd *command.Command) []string {
	t.Helper()
	var p struct {
		Targets []string `json:"targets"`
	}
	if err := json.Unmarshal(cmd.Payload, &p); err != nil {
		t.Fatal(err)
	}
	sort.Strings(p.Targets)
	return p.Targets
}

// streamFixture: the chain fixture (subs -> dns -> ports -> http) with
// streaming on, subfinder done, and dnsx running as two tasks (a and b)
// that ports (naabu) may stream from.
type streamFixture struct {
	*chainFixture
	cmds *streamCmds
	a, b *command.Command
}

func newStreamFixture(t *testing.T) *streamFixture {
	t.Helper()
	f := &streamFixture{chainFixture: newChainFixture(t), cmds: &streamCmds{finalized: map[shared.ID]bool{}}}
	f.s.commandRepo = f.cmds
	f.s.streaming = true
	f.seed("subs", "acme.com", 0, nil)
	f.settle("subs", scanrun.StepRunStatusCompleted)
	f.seed("dns", "acme.com", 0, nil)
	dnsSR := f.sr["dns"]
	for _, name := range []string{"a", "b"} {
		cmd := &command.Command{ID: shared.NewID(), TenantID: f.run.TenantID, StepRunID: &dnsSR, Status: command.CommandStatusRunning}
		f.cmds.cmds = append(f.cmds.cmds, cmd)
		f.hops.cmdRun[cmd.ID] = f.run.ID
		if name == "a" {
			f.a = cmd
		} else {
			f.b = cmd
		}
	}
	f.hops.plans[f.run.ID.String()+"/dns"] = scanrun.StagePlan{RunID: f.run.ID, StageKey: "dns", Chained: true}
	f.settle("dns", scanrun.StepRunStatusRunning)
	return f
}

// finish marks a dnsx task done (or failed) and tells the service, the way
// the command handler does.
func (f *streamFixture) finish(t *testing.T, cmd *command.Command, status command.CommandStatus) {
	t.Helper()
	cmd.Status = status
	var err error
	if status == command.CommandStatusCompleted {
		err = f.s.OnStepCompleted(context.Background(), f.run.TenantID, f.run.ID.String(), "dns", 0, nil)
	} else {
		err = f.s.OnStepFailed(context.Background(), f.run.TenantID, f.run.ID.String(), "dns", "tool crashed", "COMMAND_FAILED")
	}
	if err != nil {
		t.Fatal(err)
	}
}

// finishPorts completes every active command of the ports step.
func (f *streamFixture) finishPorts(t *testing.T) {
	t.Helper()
	for _, cmd := range f.cmds.of(f.sr["ports"]) {
		if cmd.Status != command.CommandStatusPending {
			continue
		}
		cmd.Status = command.CommandStatusCompleted
		if err := f.s.OnStepCompleted(context.Background(), f.run.TenantID, f.run.ID.String(), "ports", 0, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *streamFixture) portsTargets(t *testing.T) [][]string {
	t.Helper()
	var out [][]string
	for _, cmd := range f.cmds.of(f.sr["ports"]) {
		out = append(out, cmdTargets(t, cmd))
	}
	return out
}

func flatten(xs [][]string) []string {
	var out []string
	for _, x := range xs {
		out = append(out, x...)
	}
	sort.Strings(out)
	return out
}

// The live fault: a slow predecessor task no longer holds back its
// successor. Task a finished, task b still runs: ports gets the seed and
// what a found at once; b's results follow in their own wave, without the
// targets a already handed on.
func TestStageStreaming_SlowTaskDoesNotBlockFinishedOnes(t *testing.T) {
	f := newStreamFixture(t)
	f.output("dns", "www.acme.com", "subdomain", "", "")
	f.output("dns", "203.0.113.7", "ip_address", "", "")
	f.finish(t, f.a, command.CommandStatusCompleted)

	first := f.portsTargets(t)
	if len(first) != 1 {
		t.Fatalf("ports commands after task a = %v, want one (dnsx task b still runs)", first)
	}
	if got := first[0]; !contains(got, "acme.com") || !contains(got, "www.acme.com") || !contains(got, "203.0.113.7") {
		t.Fatalf("first wave = %v, want the seed and task a's results", got)
	}
	if st := f.store.rows["ports"].Status; st != scanrun.StepRunStatusQueued {
		t.Fatalf("ports step = %s, want queued while dnsx runs", st)
	}
	p := f.hops.plan(t, f.run.ID, "ports")
	if !p.Streamed || !p.StreamOpen || p.Waves != 1 {
		t.Fatalf("ports plan = %+v, want an open stream with one wave", p)
	}

	// ports finishes its first wave while dnsx still runs: the step waits.
	f.finishPorts(t)
	if st := f.store.rows["ports"].Status; st != scanrun.StepRunStatusQueued {
		t.Fatalf("ports step = %s after its first wave, want still queued (its stream is open)", st)
	}

	// Task b reports a duplicate of a's name and a new one.
	f.output("dns", "www.acme.com", "subdomain", "", "")
	f.output("dns", "api.acme.com", "subdomain", "", "")
	f.finish(t, f.b, command.CommandStatusCompleted)

	all := f.portsTargets(t)
	if len(all) != 2 {
		t.Fatalf("ports commands = %v, want a second wave", all)
	}
	if got := all[1]; len(got) != 1 || got[0] != "api.acme.com" {
		t.Fatalf("second wave = %v, want only the new name (dedupe across waves)", got)
	}
	seen := map[string]bool{}
	for _, x := range flatten(all) {
		if seen[x] {
			t.Fatalf("target %s dispatched twice", x)
		}
		seen[x] = true
	}
	p = f.hops.plan(t, f.run.ID, "ports")
	if p.StreamOpen || p.Planned != 4 {
		t.Fatalf("ports plan after dnsx = %+v, want the stream closed with 4 planned", p)
	}
	if st := f.store.rows["ports"].Status; st != scanrun.StepRunStatusQueued {
		t.Fatalf("ports step = %s, want queued while its last wave runs", st)
	}
	f.finishPorts(t)
	if st := f.store.rows["ports"].Status; st != scanrun.StepRunStatusCompleted {
		t.Fatalf("ports step = %s after its last command, want completed", st)
	}
}

// One predecessor task failing loses nothing of the others: the finished
// task's results still reach the successor, the predecessor ends partial.
func TestStageStreaming_FailedTaskDoesNotLoseOthers(t *testing.T) {
	f := newStreamFixture(t)
	f.finish(t, f.a, command.CommandStatusFailed)
	if n := len(f.cmds.of(f.sr["ports"])); n != 0 {
		t.Fatalf("ports commands after a failed task = %d, want none (nothing finished yet)", n)
	}
	f.output("dns", "www.acme.com", "subdomain", "", "")
	f.finish(t, f.b, command.CommandStatusCompleted)

	if st := f.store.rows["dns"].Status; st != scanrun.StepRunStatusPartial {
		t.Fatalf("dns step = %s, want partial", st)
	}
	got := flatten(f.portsTargets(t))
	if !contains(got, "www.acme.com") || !contains(got, "acme.com") {
		t.Fatalf("ports targets = %v, want task b's result and the seed", got)
	}
	f.finishPorts(t)
	if st := f.store.rows["ports"].Status; st != scanrun.StepRunStatusCompleted {
		t.Fatalf("ports step = %s, want completed", st)
	}
}

// Every gate still runs on every wave: a later wave never hands on an
// excluded name or one the ownership gate refuses for an active stage.
func TestStageStreaming_GatesApplyToEveryWave(t *testing.T) {
	f := newStreamFixture(t)
	f.output("dns", "www.acme.com", "subdomain", "", "")
	f.finish(t, f.a, command.CommandStatusCompleted)

	f.excl["evil.acme.com"] = true
	f.output("dns", "evil.acme.com", "subdomain", "", "")
	f.output("dns", "review.acme.com", "subdomain", "", attribution.StateNeedsReview)
	f.output("dns", "ok.acme.com", "subdomain", "", "")
	f.finish(t, f.b, command.CommandStatusCompleted)

	got := flatten(f.portsTargets(t))
	if contains(got, "evil.acme.com") || contains(got, "review.acme.com") {
		t.Fatalf("ports targets = %v: a refused name was dispatched by a later wave", got)
	}
	if !contains(got, "ok.acme.com") {
		t.Fatalf("ports targets = %v, want ok.acme.com", got)
	}
	reasons := map[string]string{}
	for _, r := range f.hops.targets {
		if r.StageKey == "ports" {
			reasons[r.TargetKey] = r.Reason
		}
	}
	if reasons["evil.acme.com"] != scanrun.ReasonExcluded || reasons["review.acme.com"] != scanrun.ReasonUnconfirmed {
		t.Fatalf("decisions = %v, want the refusals recorded with their reasons", reasons)
	}
}

// Off (the platform switch, or the workflow's barrier setting), the
// successor waits for the whole predecessor, as before.
func TestStageStreaming_OffKeepsTheBarrier(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(f *streamFixture)
	}{
		{"platform switch off", func(f *streamFixture) { f.s.streaming = false }},
		{"workflow barrier", func(f *streamFixture) { f.tpl.Settings.StageBarrier = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newStreamFixture(t)
			tc.set(f)
			f.output("dns", "www.acme.com", "subdomain", "", "")
			f.finish(t, f.a, command.CommandStatusCompleted)
			if n := len(f.cmds.of(f.sr["ports"])); n != 0 {
				t.Fatalf("ports commands = %d while dnsx runs, want none", n)
			}
			f.finish(t, f.b, command.CommandStatusCompleted)
			if n := len(f.cmds.of(f.sr["ports"])); n != 1 {
				t.Fatalf("ports commands = %d after dnsx, want one", n)
			}
			if p := f.hops.plan(t, f.run.ID, "ports"); p.Streamed {
				t.Fatalf("ports plan = %+v, want a barrier plan", p)
			}
		})
	}
}

// A streamed stage whose predecessor produced nothing it takes settles
// with no inputs once the predecessor finished, never earlier.
func TestStageStreaming_NothingToStreamSettlesAtTheEnd(t *testing.T) {
	f := newStreamFixture(t)
	f.run.Context["targets"] = []string{} // no seed for ports either
	f.finish(t, f.a, command.CommandStatusCompleted)
	if st := f.store.rows["ports"].Status; st != scanrun.StepRunStatusPending {
		t.Fatalf("ports step = %s while dnsx runs, want pending", st)
	}
	f.finish(t, f.b, command.CommandStatusCompleted)
	if st := f.store.rows["ports"].Status; st != scanrun.StepRunStatusCompleted {
		t.Fatalf("ports step = %s after dnsx, want settled with no inputs", st)
	}
	if n := len(f.cmds.of(f.sr["ports"])); n != 0 {
		t.Fatalf("ports commands = %d, want none", n)
	}
}

func TestStreamChunkSize(t *testing.T) {
	for _, tc := range []struct{ size, n, want int }{
		{200, 72, 18},    // httpx: 72 hosts in 4 tasks instead of 1
		{200, 1000, 200}, // never above the capability's size
		{200, 30, 10},    // never below the floor
		{200, 8, 200},    // small steps stay one task
		{1, 50, 1},       // one root per task stays one root per task
		{25, 100, 25},
	} {
		if got := streamChunkSize(tc.size, tc.n); got != tc.want {
			t.Errorf("streamChunkSize(%d, %d) = %d, want %d", tc.size, tc.n, got, tc.want)
		}
	}
}

// A step a successor streams from is cut into smaller tasks; with the
// barrier it stays one task.
func TestStageStreaming_SourceIsSplit(t *testing.T) {
	for _, barrier := range []bool{false, true} {
		f := newChainFixture(t)
		f.s.streaming = true
		cmds := &streamCmds{finalized: map[shared.ID]bool{}}
		f.s.commandRepo = cmds
		f.tpl.Settings.StageBarrier = barrier
		targets := make([]string, 0, 72)
		for i := range 72 {
			targets = append(targets, "h"+string(rune('a'+i%26))+string(rune('a'+i/26))+".acme.com")
		}
		f.run.Context["targets"] = targets
		f.seed("subs", "acme.com", 0, nil)
		f.settle("subs", scanrun.StepRunStatusCompleted)
		f.schedule(t)
		n := len(cmds.of(f.sr["dns"]))
		want := 1
		if !barrier {
			want = 4
		}
		if n != want {
			t.Fatalf("barrier=%v: dnsx commands = %d, want %d", barrier, n, want)
		}
	}
}

func TestStreamStage_IntrusiveAndEndpointSelectionNeverStream(t *testing.T) {
	if _, ok := streamStage(&scanworkflow.Step{Tool: "naabu"}); !ok {
		t.Fatal("a port scan should stream")
	}
	nuclei := &scanworkflow.Step{Tool: "nuclei", Config: map[string]any{scanworkflow.StepKeyEndpointSelector: scanworkflow.EndpointSelectorChanged}}
	if _, ok := streamStage(nuclei); ok {
		t.Fatal("a template stage that selects endpoints since the run started streamed")
	}
	for _, st := range stage.All() {
		if st.Tier < stage.TierIntrusive {
			continue
		}
		for _, impl := range st.Implementations {
			if _, ok := streamStage(&scanworkflow.Step{Tool: impl.Tool, Capabilities: []string{string(st.Key)}}); ok {
				t.Fatalf("intrusive stage %s (%s) may stream", st.Key, impl.Tool)
			}
		}
	}
}
