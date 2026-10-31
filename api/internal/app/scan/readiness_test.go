package scan

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func readinessService(statuses map[string]sensordom.ToolStatus, pfOffered, pfOnline bool, pfTools []string) *Service {
	s := &Service{logger: logger.NewNop()}
	WithReadinessSources(
		func(context.Context, shared.ID) (map[string]sensordom.ToolStatus, error) { return statuses, nil },
		func(context.Context, shared.ID) (bool, bool, []string, error) {
			return pfOffered, pfOnline, pfTools, nil
		},
	)(s)
	return s
}

func rwf(pref scanworkflow.SensorPreference, steps ...*scanworkflow.Step) *scanworkflow.Workflow {
	return &scanworkflow.Workflow{ID: shared.NewID(), Name: "wf", Settings: scanworkflow.Settings{SensorPreference: pref}, Steps: steps}
}

func rstep(key, tool string, caps ...string) *scanworkflow.Step {
	return &scanworkflow.Step{StepKey: key, Name: key, Tool: tool, Capabilities: caps}
}

func readinessOf(t *testing.T, s *Service, w *scanworkflow.Workflow) *WorkflowReadiness {
	t.Helper()
	m, err := s.WorkflowReadiness(context.Background(), shared.NewID(), []*scanworkflow.Workflow{w})
	if err != nil {
		t.Fatal(err)
	}
	return m[w.ID]
}

func TestWorkflowReadiness_States(t *testing.T) {
	statuses := map[string]sensordom.ToolStatus{
		"dnsx": sensordom.ToolReady, "naabu": sensordom.ToolOfflineOnly, "subfinder": sensordom.ToolNoSensor,
		"httpx": sensordom.ToolDisabled, "semgrep": sensordom.ToolNoSensor, "codeql": sensordom.ToolNoSensor,
	}
	s := readinessService(statuses, false, false, nil)

	cases := []struct {
		name  string
		w     *scanworkflow.Workflow
		state string
		fix   string
	}{
		{"capability with an online tool", rwf("", rstep("dns", "", "resolve.dns")), ReadinessReady, ""},
		{"only offline sensors", rwf("", rstep("ports", "", "scan.ports")), ReadinessWaiting, "Start a sensor"},
		{"no sensor has connected yet", rwf("", rstep("subs", "", "discover.subdomains")), ReadinessWaiting, "Add a sensor with subfinder"},
		{"tool switched off", rwf("", rstep("http", "", "probe.http")), ReadinessBlocked, "Enable httpx"},
		{"pinned tool not installed", rwf("", rstep("shots", "gowitness", "scan")), ReadinessBlocked, "Any tool"},
		{"code analysis runs in CI", rwf("", rstep("sast", "", "sast.code")), ReadinessCIOnly, "CI pipeline"},
		{"the worst step decides", rwf("", rstep("dns", "", "resolve.dns"), rstep("ports", "", "scan.ports"), rstep("http", "", "probe.http")), ReadinessBlocked, ""},
		{"no steps", rwf(""), ReadinessBlocked, ""},
	}
	for _, tc := range cases {
		r := readinessOf(t, s, tc.w)
		if r.State != tc.state {
			t.Errorf("%s: state %s, want %s (%+v)", tc.name, r.State, tc.state, r.Steps)
			continue
		}
		if tc.fix != "" {
			last := r.Steps[len(r.Steps)-1]
			if !strings.Contains(last.Fix, tc.fix) || last.Reason == "" {
				t.Errorf("%s: fix %q / reason %q, want %q", tc.name, last.Fix, last.Reason, tc.fix)
			}
		}
	}
}

// Platform scanning counts as a tool's runner when the organization is
// offered it and the workflow does not keep to its own sensors. It is never
// named per sensor: the reason speaks of tools and capabilities only.
func TestWorkflowReadiness_PlatformScanning(t *testing.T) {
	statuses := map[string]sensordom.ToolStatus{"subfinder": sensordom.ToolNoSensor}
	w := func(pref scanworkflow.SensorPreference) *scanworkflow.Workflow {
		return rwf(pref, rstep("subs", "", "discover.subdomains"))
	}
	if r := readinessOf(t, readinessService(statuses, true, true, []string{"subfinder"}), w("")); r.State != ReadinessReady {
		t.Fatalf("platform online: %s", r.State)
	}
	if r := readinessOf(t, readinessService(statuses, true, false, []string{"subfinder"}), w("")); r.State != ReadinessWaiting {
		t.Fatalf("platform offline: %s", r.State)
	}
	if r := readinessOf(t, readinessService(statuses, true, true, []string{"subfinder"}), w(scanworkflow.SensorPreferenceTenant)); r.State != ReadinessWaiting {
		t.Fatalf("own sensors only, none connected yet: %s", r.State)
	}
	if r := readinessOf(t, readinessService(statuses, false, true, []string{"subfinder"}), w("")); r.State != ReadinessWaiting {
		t.Fatalf("platform not offered, no sensor yet: %s", r.State)
	}
	// A platform-only workflow does not count the tenant's sensors.
	own := map[string]sensordom.ToolStatus{"subfinder": sensordom.ToolReady}
	if r := readinessOf(t, readinessService(own, false, false, nil), w(scanworkflow.SensorPreferencePlatform)); r.State != ReadinessBlocked {
		t.Fatalf("platform-only with own sensors: %s", r.State)
	}
}

func TestRequireWorkflowRunnable(t *testing.T) {
	s := readinessService(map[string]sensordom.ToolStatus{"dnsx": sensordom.ToolOfflineOnly}, false, false, nil)
	ctx := context.Background()
	tenant := shared.NewID()
	// Waiting may be scheduled.
	if err := s.requireWorkflowRunnable(ctx, tenant, rwf("", rstep("dns", "", "resolve.dns"))); err != nil {
		t.Fatalf("waiting refused: %v", err)
	}
	err := s.requireWorkflowRunnable(ctx, tenant, rwf("", rstep("dns", "", "resolve.dns"), rstep("ports", "", "scan.ports")))
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != CodeWorkflowNotRunnable || !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "ports") {
		t.Fatalf("blocked workflow: %v", err)
	}
	// Without the sources nothing is refused (the trigger checks still apply).
	if err := (&Service{logger: logger.NewNop()}).requireWorkflowRunnable(ctx, tenant, rwf("")); err != nil {
		t.Fatalf("no sources: %v", err)
	}
}

// Each organization reads its own sources: the per-tenant cache never
// answers one organization with another one's sensors.
func TestWorkflowReadiness_TenantIsolatedCache(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	s := &Service{logger: logger.NewNop()}
	WithReadinessSources(
		func(_ context.Context, tenant shared.ID) (map[string]sensordom.ToolStatus, error) {
			if tenant == a {
				return map[string]sensordom.ToolStatus{"dnsx": sensordom.ToolReady}, nil
			}
			return map[string]sensordom.ToolStatus{"dnsx": sensordom.ToolDisabled}, nil
		}, nil)(s)
	w := rwf("", rstep("dns", "", "resolve.dns"))
	ra, _ := s.WorkflowReadiness(context.Background(), a, []*scanworkflow.Workflow{w})
	rb, _ := s.WorkflowReadiness(context.Background(), b, []*scanworkflow.Workflow{w})
	ra2, _ := s.WorkflowReadiness(context.Background(), a, []*scanworkflow.Workflow{w})
	if ra[w.ID].State != ReadinessReady || rb[w.ID].State != ReadinessBlocked || ra2[w.ID].State != ReadinessReady {
		t.Fatalf("cross-tenant readiness: a=%s b=%s a again=%s", ra[w.ID].State, rb[w.ID].State, ra2[w.ID].State)
	}
}

// A new organization has no sensor yet: the probing scan of continuous
// discovery (port scan, HTTP probe) is saved waiting, becomes ready when a
// sensor with the tools registers, and is still refused when a tool is off.
func TestRequireWorkflowRunnable_NoSensorYetThenReady(t *testing.T) {
	ctx := context.Background()
	tenant := shared.NewID()
	probe := func() *scanworkflow.Workflow {
		return rwf("", rstep("ports", "", "scan.ports"), rstep("http", "", "probe.http"))
	}
	empty := map[string]sensordom.ToolStatus{"naabu": sensordom.ToolNoSensor, "httpx": sensordom.ToolNoSensor}
	s := readinessService(empty, false, false, nil)
	if err := s.requireWorkflowRunnable(ctx, tenant, probe()); err != nil {
		t.Fatalf("no sensor yet must be saved: %v", err)
	}
	r := readinessOf(t, s, probe())
	if r.State != ReadinessWaiting || !strings.Contains(r.Steps[0].Reason, "Waits for a sensor with") {
		t.Fatalf("want waiting: %+v", r)
	}
	online := readinessService(map[string]sensordom.ToolStatus{"naabu": sensordom.ToolReady, "httpx": sensordom.ToolReady}, false, false, nil)
	if r := readinessOf(t, online, probe()); r.State != ReadinessReady {
		t.Fatalf("sensor registered: %s", r.State)
	}
	off := readinessService(map[string]sensordom.ToolStatus{"naabu": sensordom.ToolNoSensor, "httpx": sensordom.ToolDisabled}, false, false, nil)
	if err := off.requireWorkflowRunnable(ctx, tenant, probe()); err == nil {
		t.Fatal("a disabled tool must still be refused")
	}
}

func optStep(key, tool string, caps ...string) *scanworkflow.Step {
	s := rstep(key, tool, caps...)
	s.RunPolicy.Optional = true
	return s
}

// An optional step that no installed tool implements is skipped (the run
// skips it with the reason): it is reported with its capability and reason
// and never blocks the workflow. A required step in the same situation
// still blocks, and a workflow of only skipped steps is blocked.
func TestWorkflowReadiness_OptionalStepSkipped(t *testing.T) {
	s := readinessService(map[string]sensordom.ToolStatus{
		"httpx": sensordom.ToolReady, "naabu": sensordom.ToolDisabled, "nuclei": sensordom.ToolNoSensor,
	}, false, false, nil)

	r := readinessOf(t, s, rwf("", rstep("http", "", "probe.http"), optStep("shots", "", "capture.screenshot")))
	if r.State != ReadinessReady || !r.Runnable() {
		t.Fatalf("optional planned step must not block: %+v", r)
	}
	shot := r.Steps[1]
	if shot.State != ReadinessSkipped || !shot.Optional || shot.Capability != "capture.screenshot" ||
		shot.Code != ReasonNoTool || !strings.HasPrefix(shot.Reason, "Skipped: ") || !strings.Contains(shot.Reason, "capture.screenshot") {
		t.Fatalf("skipped step: %+v", shot)
	}

	// An optional step whose only tool is turned off is skipped too (the
	// run's tool lookup refuses it the same way).
	if r := readinessOf(t, s, rwf("", rstep("http", "", "probe.http"), optStep("ports", "", "scan.ports"))); r.State != ReadinessReady || r.Steps[1].State != ReadinessSkipped || r.Steps[1].Code != ReasonToolDisabled {
		t.Fatalf("optional disabled tool: %+v", r)
	}

	// The same step, required, blocks as before.
	if r := readinessOf(t, s, rwf("", rstep("http", "", "probe.http"), rstep("shots", "", "capture.screenshot"))); r.State != ReadinessBlocked || r.Steps[1].Code != ReasonNoTool {
		t.Fatalf("required planned step: %+v", r)
	}

	// An optional step whose tool is installed and enabled is not skipped:
	// the run dispatches it, so its sensor state counts.
	if r := readinessOf(t, s, rwf("", rstep("http", "", "probe.http"), optStep("tpl", "", "vuln.templates"))); r.Steps[1].State != ReadinessWaiting || r.State != ReadinessWaiting {
		t.Fatalf("optional step with an installed tool: %+v", r)
	}

	// Only skipped steps: nothing would run.
	only := rwf("", optStep("shots", "", "capture.screenshot"))
	if r := readinessOf(t, s, only); r.State != ReadinessBlocked {
		t.Fatalf("only optional steps: %s", r.State)
	}
	err := s.requireWorkflowRunnable(context.Background(), shared.NewID(), only)
	if err == nil || !strings.Contains(err.Error(), "every step is optional") {
		t.Fatalf("refusal of a workflow of skipped steps: %v", err)
	}
}

// Every reason carries a stable code and the tools it names.
func TestWorkflowReadiness_ReasonCodes(t *testing.T) {
	s := readinessService(map[string]sensordom.ToolStatus{
		"naabu": sensordom.ToolOfflineOnly, "subfinder": sensordom.ToolNoSensor, "httpx": sensordom.ToolDisabled,
	}, false, false, nil)
	cases := map[*scanworkflow.Step]string{
		rstep("ports", "", "scan.ports"):         ReasonSensorOffline,
		rstep("subs", "", "discover.subdomains"): ReasonNoSensorYet,
		rstep("http", "", "probe.http"):          ReasonToolDisabled,
		rstep("sast", "", "sast.code"):           ReasonCIOnly,
		rstep("x", "gowitness", "scan"):          ReasonToolNotInstalled,
		rstep("shots", "", "capture.screenshot"): ReasonNoTool,
	}
	for step, want := range cases {
		r := readinessOf(t, s, rwf("", step))
		if got := r.Steps[0]; got.Code != want {
			t.Errorf("%s: code %q, want %q (%+v)", step.StepKey, got.Code, want, got)
		}
	}
}
