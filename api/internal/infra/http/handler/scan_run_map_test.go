package handler

import (
	"strings"
	"testing"

	scanrunapp "github.com/openctemio/openctem/api/internal/app/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func mapStepRun(key string, order int, status scanrundom.StepRunStatus) *scanrundom.StepRun {
	return &scanrundom.StepRun{ID: shared.NewID(), StepKey: key, StepOrder: order, Status: status}
}

// The map draws the run's workflow version: subfinder fed httpx and nuclei.
// subfinder finished with 12 outputs in scope, httpx runs, nuclei is queued
// with no chunk taken (waiting for a sensor) and the edges carry what
// subfinder produced.
func TestRunMap_StatesEdgesAndOutputs(t *testing.T) {
	sub := mapStepRun("subdomains", 1, scanrundom.StepRunStatusCompleted)
	sub.FindingsCount = 2
	probe := mapStepRun("probe", 2, scanrundom.StepRunStatusRunning)
	vuln := mapStepRun("vulns", 3, scanrundom.StepRunStatusQueued)
	run := &scanrundom.Run{ID: shared.NewID(), Status: scanrundom.RunStatusRunning, ScanWorkflowVersion: 3,
		StepRuns: []*scanrundom.StepRun{vuln, sub, probe}}
	wf := &scanworkflow.Workflow{Steps: []*scanworkflow.Step{
		{StepKey: "vulns", Name: "Vulnerabilities", Tool: "nuclei", StepOrder: 3, DependsOn: []string{"probe"}, TimeoutSeconds: 600},
		{StepKey: "subdomains", Name: "Subdomains", Tool: "subfinder", StepOrder: 1},
		{StepKey: "probe", Name: "Probe", Tool: "httpx", StepOrder: 2, DependsOn: []string{"subdomains"}},
	}}
	m := &scanrunapp.RunMap{
		Run: run, Workflow: wf,
		Shares: []command.StepSensorShare{
			{StepKey: "subdomains", Total: 1, Completed: 1},
			{StepKey: "probe", Total: 4, Running: 1, Completed: 2, Queued: 1},
			{StepKey: "vulns", Total: 2, Queued: 2},
		},
		Plans: []scanrundom.StagePlan{{StageKey: "probe", Inputs: 12, Planned: 10}},
		Outputs: []scanrundom.StepOutputCount{
			{StepRunID: sub.ID, AssetType: "domain", Count: 9},
			{StepRunID: sub.ID, AssetType: "ip_address", Count: 3},
			{StepRunID: shared.NewID(), AssetType: "domain", Count: 99}, // another run's step: ignored
		},
	}

	got := toRunMapResponse(m)
	if got.ScanWorkflowVersion != 3 || len(got.Nodes) != 3 {
		t.Fatalf("map = %+v", got)
	}
	want := []struct{ key, state, reason string }{
		{"subdomains", mapStateSucceeded, ""},
		{"probe", mapStateRunning, ""},
		{"vulns", mapStateWaiting, "waiting_for_sensor"},
	}
	for i, w := range want {
		n := got.Nodes[i]
		if n.StepKey != w.key || n.State != w.state || n.Reason != w.reason {
			t.Errorf("node %d = %s %s %q, want %s %s %q", i, n.StepKey, n.State, n.Reason, w.key, w.state, w.reason)
		}
	}
	if s := got.Nodes[0]; s.Outputs.Total != 12 || s.Outputs.ByType["domain"] != 9 || s.Findings != 2 {
		t.Errorf("subdomains outputs = %+v findings %d", s.Outputs, s.Findings)
	}
	if p := got.Nodes[1]; p.Chunks.Total != 4 || p.Chunks.Running != 1 || p.Inputs == nil || *p.Planned != 10 {
		t.Errorf("probe chunks/plan = %+v %v %v", p.Chunks, p.Inputs, p.Planned)
	}
	if v := got.Nodes[2]; v.TimeoutSeconds != 600 || v.Inputs != nil || v.Outputs.ByType == nil {
		t.Errorf("vulns = %+v", v)
	}
	if len(got.Edges) != 2 || got.Edges[0] != (RunMapEdge{From: "subdomains", To: "probe", Count: 12}) ||
		got.Edges[1] != (RunMapEdge{From: "probe", To: "vulns", Count: 0}) {
		t.Errorf("edges = %+v", got.Edges)
	}
}

// Failed, partial, skipped and canceled steps carry their reason and error
// class; a platform job's message never names the platform sensor.
func TestRunMap_FailureReasonsAndPlatformRedaction(t *testing.T) {
	failed := mapStepRun("scan", 1, scanrundom.StepRunStatusFailed)
	failed.ErrorCode = "NO_SENSOR_AVAILABLE"
	failed.ErrorMessage = "dial tcp 10.9.8.7:443 on /opt/platform/work: refused"
	skipped := mapStepRun("after", 2, scanrundom.StepRunStatusSkipped)
	skipped.ErrorCode = "DEPENDENCY_FAILED"
	run := &scanrundom.Run{ID: shared.NewID(), StepRuns: []*scanrundom.StepRun{failed, skipped}}
	m := &scanrunapp.RunMap{Run: run, Workflow: &scanworkflow.Workflow{Steps: []*scanworkflow.Step{
		{StepKey: "scan", StepOrder: 1}, {StepKey: "after", StepOrder: 2, DependsOn: []string{"scan"}},
	}}, Shares: []command.StepSensorShare{{StepKey: "scan", Platform: true, Total: 1, Failed: 1}}}

	got := toRunMapResponse(m)
	f, s := got.Nodes[0], got.Nodes[1]
	if f.State != mapStateFailed || f.Reason != "NO_SENSOR_AVAILABLE" || f.ErrorClass == "" {
		t.Errorf("failed node = %+v", f)
	}
	if strings.Contains(f.ErrorMessage, "10.9.8.7") || strings.Contains(f.ErrorMessage, "/opt/platform") {
		t.Errorf("platform job message not redacted: %q", f.ErrorMessage)
	}
	if s.State != mapStateSkipped || s.Reason != "DEPENDENCY_FAILED" {
		t.Errorf("skipped node = %+v", s)
	}
}

// A run without a workflow version (a retest) is drawn from its step runs.
func TestRunMap_RunWithoutWorkflow(t *testing.T) {
	sr := mapStepRun("retest", 1, scanrundom.StepRunStatusCompleted)
	sr.StepName, sr.Tool = "Retest", "nuclei"
	got := toRunMapResponse(&scanrunapp.RunMap{Run: &scanrundom.Run{ID: shared.NewID(), StepRuns: []*scanrundom.StepRun{sr}}})
	if len(got.Nodes) != 1 || got.Nodes[0].Tool != "nuclei" || got.Nodes[0].State != mapStateSucceeded || len(got.Edges) != 0 {
		t.Fatalf("map = %+v", got)
	}
}

// With a previous run of the scan every step compares its outputs with it
// (a step that produced nothing either time as 0/0/0); without one the
// comparison is absent.
func TestRunMap_ComparesWithThePreviousRun(t *testing.T) {
	sub := mapStepRun("subdomains", 1, scanrundom.StepRunStatusCompleted)
	quiet := mapStepRun("quiet", 2, scanrundom.StepRunStatusCompleted)
	run := &scanrundom.Run{ID: shared.NewID(), Status: scanrundom.RunStatusCompleted,
		StepRuns: []*scanrundom.StepRun{sub, quiet}}
	prev := shared.NewID()
	m := &scanrunapp.RunMap{
		Run:           run,
		Outputs:       []scanrundom.StepOutputCount{{StepRunID: sub.ID, AssetType: "domain", Count: 10}},
		PreviousRunID: prev,
		Deltas:        []scanrundom.StepOutputDelta{{StepKey: "subdomains", Previous: 8, Added: 3, Gone: 1}},
	}
	got := toRunMapResponse(m)
	if got.PreviousRunID != prev.String() {
		t.Fatalf("previous_run_id = %q", got.PreviousRunID)
	}
	o := got.Nodes[0].Outputs
	if o.Total != 10 || o.Previous == nil || *o.Previous != 8 || *o.Added != 3 || *o.Gone != 1 {
		t.Fatalf("subdomains outputs = %+v", o)
	}
	q := got.Nodes[1].Outputs
	if q.Previous == nil || *q.Previous != 0 || *q.Added != 0 || *q.Gone != 0 {
		t.Fatalf("a step without outputs compares as 0/0/0, got %+v", q)
	}

	m.PreviousRunID, m.Deltas = shared.ID{}, nil
	got = toRunMapResponse(m)
	if got.PreviousRunID != "" || got.Nodes[0].Outputs.Previous != nil {
		t.Fatalf("without a previous run the comparison must be absent: %+v", got.Nodes[0].Outputs)
	}
}
