package scanrun

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// unreached marks a task as completed having reached none of its n targets
// (a host discovery chunk whose probes never left the sensor).
func (f *streamFixture) unreached(cmd *command.Command, n int) {
	if f.cmds.reach == nil {
		f.cmds.reach = map[shared.ID]command.StepBatch{}
	}
	f.cmds.reach[cmd.ID] = command.StepBatch{ReachTargets: n, Unreached: n}
}

// The incident: a source task that completed having reached nothing does
// not start its successor. The successor would otherwise take its seeds
// (the whole range of a swept scan) at once and keep running when the
// source then fails. When every source task reached nothing, the source
// fails as unreachable and the successor is skipped before it ever runs.
func TestStageStreaming_UnreachedSourceTaskDoesNotStartSuccessor(t *testing.T) {
	f := newStreamFixture(t)
	f.unreached(f.a, 4096)
	f.finish(t, f.a, command.CommandStatusCompleted)
	if n := len(f.cmds.of(f.sr["ports"])); n != 0 {
		t.Fatalf("ports commands after a task that reached nothing = %d, want none", n)
	}

	f.unreached(f.b, 4096)
	f.finish(t, f.b, command.CommandStatusCompleted)
	if st := f.store.rows["dns"]; st.Status != scanrun.StepRunStatusFailed || st.ErrorCode != scanrun.FailureTargetUnreachable {
		t.Fatalf("dns step = %s/%s, want failed TARGET_UNREACHABLE", st.Status, st.ErrorCode)
	}
	if n := len(f.cmds.of(f.sr["ports"])); n != 0 {
		t.Fatalf("ports commands after dns failed = %d, want none", n)
	}
	if st := f.store.rows["ports"].Status; st != scanrun.StepRunStatusSkipped {
		t.Fatalf("ports step = %s, want skipped (its dependency did not succeed)", st)
	}
}

// One unreached task does not hold the stream back once another task of
// the source reached something.
func TestStageStreaming_ReachedTaskStillStarts(t *testing.T) {
	f := newStreamFixture(t)
	f.unreached(f.a, 16)
	f.finish(t, f.a, command.CommandStatusCompleted)
	f.output("dns", "203.0.113.7", "ip_address", "", "")
	f.cmds.reach[f.b.ID] = command.StepBatch{ReachTargets: 16, Reached: 1, Unreached: 15}
	f.finish(t, f.b, command.CommandStatusCompleted)
	if got := flatten(f.portsTargets(t)); !contains(got, "203.0.113.7") {
		t.Fatalf("ports targets = %v, want the address b reached", got)
	}
}

func TestSourceHasResults(t *testing.T) {
	cases := []struct {
		name string
		b    command.StepBatch
		want bool
	}{
		{"nothing finished", command.StepBatch{Total: 2, Active: 2}, false},
		{"only failures", command.StepBatch{Total: 2, Failed: 2}, false},
		{"completed without reach summary", command.StepBatch{Total: 2, Active: 1}, true},
		{"completed and reached", command.StepBatch{Total: 2, Active: 1, ReachBatches: 1, ReachTargets: 4, Reached: 1, Unreached: 3}, true},
		{"completed, reached nothing", command.StepBatch{Total: 2, Active: 1, ReachBatches: 1, ReachTargets: 4, Unreached: 4}, false},
		{"one batch without summary", command.StepBatch{Total: 3, Active: 1, ReachBatches: 1, ReachTargets: 4, Unreached: 4}, true},
		{"reached nothing but found something", command.StepBatch{Total: 1, Findings: 1, ReachBatches: 1, ReachTargets: 4, Unreached: 4}, true},
	}
	for _, c := range cases {
		if got := sourceHasResults(c.b); got != c.want {
			t.Errorf("%s: sourceHasResults = %v, want %v", c.name, got, c.want)
		}
	}
}

// A step that already streamed from its source stops when the source then
// fails: its open tasks are canceled and it settles DEPENDENCY_FAILED,
// never scanning the rest of its input on its own.
func TestStageStreaming_SourceFailureStopsStreamedSuccessor(t *testing.T) {
	f := newStreamFixture(t)
	f.output("dns", "www.acme.com", "subdomain", "", "")
	f.finish(t, f.a, command.CommandStatusCompleted)
	ports := f.cmds.of(f.sr["ports"])
	if len(ports) == 0 {
		t.Fatal("ports did not start streaming from task a")
	}

	// The source fails (its step timeout, a fail-fast elsewhere): b is
	// still running when the step is settled failed.
	f.settle("dns", scanrun.StepRunStatusFailed)
	if err := f.s.advanceRun(context.Background(), f.run, f.tpl); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range f.cmds.of(f.sr["ports"]) {
		if cmd.Status != command.CommandStatusCanceled {
			t.Fatalf("ports command %s = %s, want canceled", cmd.ID, cmd.Status)
		}
	}
	st := f.store.rows["ports"]
	if st.Status != scanrun.StepRunStatusSkipped || st.ErrorCode != scanrun.FailureDependencyFailed {
		t.Fatalf("ports step = %s/%s, want skipped DEPENDENCY_FAILED", st.Status, st.ErrorCode)
	}
	if !strings.Contains(st.SkipReason, `"dns"`) {
		t.Fatalf("skip reason = %q, want it to name the source step", st.SkipReason)
	}
	if p := f.hops.plan(t, f.run.ID, "ports"); p.StreamOpen {
		t.Fatalf("ports stream still open: %+v", p)
	}
	if st := f.store.rows["http"].Status; st != scanrun.StepRunStatusSkipped {
		t.Fatalf("http step = %s, want skipped after ports stopped", st)
	}
}

// Finished tasks of a stopped step keep their results: the step ends
// partial, not skipped.
func TestStageStreaming_StoppedStepKeepsFinishedTasks(t *testing.T) {
	f := newStreamFixture(t)
	f.output("dns", "www.acme.com", "subdomain", "", "")
	f.finish(t, f.a, command.CommandStatusCompleted)
	ports := f.cmds.of(f.sr["ports"])
	if len(ports) == 0 {
		t.Fatal("ports did not start streaming from task a")
	}
	ports[0].Status = command.CommandStatusCompleted

	f.settle("dns", scanrun.StepRunStatusFailed)
	if err := f.s.advanceRun(context.Background(), f.run, f.tpl); err != nil {
		t.Fatal(err)
	}
	if st := f.store.rows["ports"]; st.Status != scanrun.StepRunStatusPartial || st.ErrorCode != scanrun.FailureDependencyFailed {
		t.Fatalf("ports step = %s/%s, want partial DEPENDENCY_FAILED", st.Status, st.ErrorCode)
	}
}

// Continue on failure keeps the streamed step running.
func TestStageStreaming_ContinueOnFailureKeepsStream(t *testing.T) {
	f := newStreamFixture(t)
	f.tpl.Settings.ContinueOnFailedDependency = true
	f.output("dns", "www.acme.com", "subdomain", "", "")
	f.finish(t, f.a, command.CommandStatusCompleted)
	f.settle("dns", scanrun.StepRunStatusFailed)
	if err := f.s.advanceRun(context.Background(), f.run, f.tpl); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range f.cmds.of(f.sr["ports"]) {
		if cmd.Status == command.CommandStatusCanceled {
			t.Fatal("a ports command was canceled although the workflow continues on failure")
		}
	}
}
