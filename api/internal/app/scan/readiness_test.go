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
