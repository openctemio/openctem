package scan

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// fakeToolLookup is a tool registry: platform tools by name and the
// capability fallback's answer, recording what was asked.
type fakeToolLookup struct {
	platform map[string]*tool.Tool
	byCaps   *tool.Tool
	capsErr  error
	asked    []string
	capsWith shared.ID
}

func (f *fakeToolLookup) GetPlatformToolByName(_ context.Context, name string) (*tool.Tool, error) {
	f.asked = append(f.asked, name)
	if t, ok := f.platform[name]; ok {
		return t, nil
	}
	return nil, shared.ErrNotFound
}

func (f *fakeToolLookup) FindByCapabilities(_ context.Context, tenantID shared.ID, _ []string) (*tool.Tool, error) {
	f.capsWith = tenantID
	return f.byCaps, f.capsErr
}

func activeTool(name string) *tool.Tool { return &tool.Tool{Name: name, IsActive: true} }

func domainCode(err error) string {
	var de *shared.DomainError
	if errors.As(err, &de) {
		return de.Code
	}
	return ""
}

// F1: a step that names only a capability runs the catalog default of its
// stage, and the command names that tool in `scanner`.
func TestResolveStepTool_CapabilityOnlyStepGetsAScanner(t *testing.T) {
	tools := &fakeToolLookup{platform: map[string]*tool.Tool{"naabu": activeTool("naabu")}}
	step := &scanworkflow.Step{ID: shared.NewID(), StepKey: "ports", Capabilities: []string{"recon", "portscan"}}
	got, err := ResolveStepTool(context.Background(), tools, shared.NewID(), step)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "naabu" || got.Pinned || !got.HasStage || got.Stage.Key != stage.ScanPorts {
		t.Fatalf("resolved = %+v", got)
	}
	run := &scanrun.Run{ID: shared.NewID(), Context: map[string]any{"targets": []string{"a.example.com"}}}
	p, err := StepCommandPayload(run, got.WithTool(step), got.Name, "sr", nil)
	if err != nil {
		t.Fatal(err)
	}
	if p["scanner"] != "naabu" || p["preferred_tool"] != "naabu" {
		t.Fatalf("scanner = %v preferred_tool = %v", p["scanner"], p["preferred_tool"])
	}
	if step.Tool != "" {
		t.Fatal("resolving changed the stored step")
	}
}

// G10: a pinned tool is strict; the planner does not swap it, even when the
// catalog default of its stage is another tool.
func TestResolveStepTool_PinnedToolIsStrict(t *testing.T) {
	tools := &fakeToolLookup{}
	step := &scanworkflow.Step{StepKey: "secrets", Tool: "trufflehog", Capabilities: []string{"secrets"}}
	got, err := ResolveStepTool(context.Background(), tools, shared.NewID(), step)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "trufflehog" || !got.Pinned || got.Stage.Key != stage.SecretsCode {
		t.Fatalf("resolved = %+v", got)
	}
	if len(tools.asked) != 0 {
		t.Fatalf("a pinned step looked up %v", tools.asked)
	}
}

// G10: `auto` may substitute: the default is disabled, the next active
// implementation runs. A collector or connector is never picked.
func TestResolveStepTool_SubstitutesAnActiveImplementation(t *testing.T) {
	collector := &tool.Tool{Name: "trufflehog", IsActive: true, Metadata: map[string]any{"kind": tool.KindCollector}}
	tools := &fakeToolLookup{platform: map[string]*tool.Tool{
		"betterleaks": {Name: "betterleaks", IsActive: false},
		"trufflehog":  collector,
		"gitleaks":    activeTool("gitleaks"),
	}}
	step := &scanworkflow.Step{StepKey: "secrets", Capabilities: []string{"secrets"}}
	got, err := ResolveStepTool(context.Background(), tools, shared.NewID(), step)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "gitleaks" {
		t.Fatalf("resolved %s, want gitleaks (betterleaks disabled, trufflehog a collector)", got.Name)
	}
	if !reflect.DeepEqual(tools.asked, []string{"betterleaks", "trufflehog", "gitleaks"}) {
		t.Fatalf("asked %v: the default must be tried first", tools.asked)
	}
}

// No active implementation, an ambiguous capability list, and an empty
// step are refused with a code, before any command exists.
func TestResolveStepTool_Refusals(t *testing.T) {
	ctx := context.Background()
	none := &fakeToolLookup{platform: map[string]*tool.Tool{}}
	if _, err := ResolveStepTool(ctx, none, shared.NewID(), &scanworkflow.Step{StepKey: "p", Capabilities: []string{"portscan"}}); domainCode(err) != codeNoMatchingTool {
		t.Errorf("no implementation: %v", err)
	}
	if _, err := ResolveStepTool(ctx, none, shared.NewID(), &scanworkflow.Step{StepKey: "x", Capabilities: []string{"portscan", "dns"}}); domainCode(err) != codeStepCapabilityUnsure {
		t.Errorf("ambiguous: %v", err)
	}
	if _, err := ResolveStepTool(ctx, none, shared.NewID(), &scanworkflow.Step{StepKey: "e"}); domainCode(err) != codeStepInvalid {
		t.Errorf("empty step: %v", err)
	}
	if _, err := ResolveStepTool(ctx, nil, shared.NewID(), &scanworkflow.Step{StepKey: "p", Capabilities: []string{"portscan"}}); err == nil {
		t.Error("no registry: resolved anyway (must fail closed)")
	}
	broken := &fakeToolLookup{platform: map[string]*tool.Tool{}, capsErr: errors.New("db down")}
	if _, err := ResolveStepTool(ctx, broken, shared.NewID(), &scanworkflow.Step{StepKey: "c", Capabilities: []string{"custom-cap"}}); err == nil {
		t.Error("a failed lookup resolved a tool")
	}
}

// Capabilities the catalog does not know fall back to the tenant's tool
// lookup, scoped by the caller's tenant; a disabled match is refused.
func TestResolveStepTool_FallbackIsTenantScoped(t *testing.T) {
	tenant := shared.NewID()
	tools := &fakeToolLookup{byCaps: activeTool("acme-scanner")}
	got, err := ResolveStepTool(context.Background(), tools, tenant, &scanworkflow.Step{StepKey: "c", Capabilities: []string{"acme-cap"}})
	if err != nil || got.Name != "acme-scanner" || got.HasStage {
		t.Fatalf("got %+v, %v", got, err)
	}
	if tools.capsWith != tenant {
		t.Fatal("the fallback lookup is not scoped to the caller's tenant")
	}
	tools.byCaps = &tool.Tool{Name: "acme-scanner", IsActive: false}
	if _, err := ResolveStepTool(context.Background(), tools, tenant, &scanworkflow.Step{StepKey: "c", Capabilities: []string{"acme-cap"}}); domainCode(err) != codeNoMatchingTool {
		t.Fatalf("a disabled tool was picked: %v", err)
	}
}

// Golden: the payload of a pinned-tool step has exactly the keys and values
// both former builders sent (scan trigger and scan run service), so moving
// to one builder changes no command a sensor receives.
func TestStepCommandPayload_Golden(t *testing.T) {
	asset := shared.NewID()
	run := &scanrun.Run{ID: shared.NewID(), AssetID: &asset, Context: map[string]any{
		"targets":                []string{"a.example.com"},
		"scan_id":                "s-1",
		RunContextKeyTargetTypes: map[string]string{"a.example.com": "domain"},
	}}
	step := &scanworkflow.Step{ID: shared.NewID(), StepKey: "subs", Tool: "subfinder",
		Capabilities: []string{"recon", "subdomain"}, TimeoutSeconds: 600}
	p, err := StepCommandPayload(run, step, "subfinder", "sr-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"scan_run_id":           run.ID.String(),
		"scan_run_step_id":      "sr-1",
		"step_key":              "subs",
		"step_id":               step.ID.String(),
		"config":                map[string]any{},
		"required_capabilities": []string{"recon", "subdomain"},
		"preferred_tool":        "subfinder",
		"scanner":               "subfinder",
		"timeout_seconds":       600,
		"context":               map[string]any{"targets": []string{"a.example.com"}, "scan_id": "s-1"},
		"targets":               []string{"a.example.com"},
		"asset_id":              asset.String(),
		// A capability job (RFC-055): subfinder runs them on the sensor.
		"capability": "discover.subdomains@1",
	}
	if len(p) != len(want) {
		t.Errorf("keys = %d, want %d: %v", len(p), len(want), p)
	}
	for k, v := range want {
		got := p[k]
		if m, ok := got.(map[string]any); ok && len(m) == 0 {
			got = map[string]any{}
		}
		if !reflect.DeepEqual(got, v) {
			t.Errorf("%s = %#v, want %#v", k, p[k], v)
		}
	}
	// The selection mode stays on the platform: no sensor reads it.
	p, _ = StepCommandPayload(&scanrun.Run{ID: shared.NewID()}, step, "subfinder", "sr", nil)
	if _, ok := p["agent_preference"]; ok {
		t.Error("retired agent_preference key sent")
	}
	if _, ok := p["targets"]; ok {
		t.Error("targets appeared from nowhere")
	}
}

// The step's settings go under `config`, normalized for the resolved tool;
// a value the sensor would refuse fails before any command exists; a step
// with no tool cannot build a payload.
func TestStepCommandPayload_SettingsAndRefusals(t *testing.T) {
	run := &scanrun.Run{ID: shared.NewID()}
	step := &scanworkflow.Step{ID: shared.NewID(), StepKey: "ports", Config: map[string]any{"top_ports": "1000", "rate": float64(500)}}
	p, err := StepCommandPayload(run, step, "naabu", "sr", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, ok := p[scanworkflow.PayloadKeyConfig].(map[string]any)
	if !ok || cfg["top_ports"] != int64(1000) || cfg["rate"] != int64(500) {
		t.Fatalf("config = %#v", p[scanworkflow.PayloadKeyConfig])
	}
	step.Config = map[string]any{"ports": "80 -nmap-cli id"}
	if _, err := StepCommandPayload(run, step, "naabu", "sr", nil); err == nil {
		t.Fatal("flag injection in ports reached a command payload")
	}
	step.Config = map[string]any{"tags": []any{"cve", "-code"}}
	if _, err := StepCommandPayload(run, step, "nuclei", "sr", nil); err == nil {
		t.Fatal("a flag as a nuclei tag reached a command payload")
	}
	if _, err := StepCommandPayload(run, &scanworkflow.Step{StepKey: "x"}, " ", "sr", nil); domainCode(err) != codeNoMatchingTool {
		t.Fatalf("tool-less payload: %v", err)
	}
}

// recordingQueuer is a StepQueuer that records the steps it was handed.
type recordingQueuer struct{ steps []string }

func (q *recordingQueuer) QueueRunStep(_ context.Context, _ *scanrun.Run, step *scanworkflow.Step) error {
	q.steps = append(q.steps, step.StepKey)
	return nil
}

// The scan trigger hands its first workflow steps to the one dispatcher;
// without it nothing is queued (fail closed).
func TestScheduleWorkflowSteps_DelegatesToTheOneDispatcher(t *testing.T) {
	steps := []*scanworkflow.Step{
		{ID: shared.NewID(), StepKey: "a", Tool: "subfinder", Condition: scanworkflow.AlwaysCondition()},
		{ID: shared.NewID(), StepKey: "b", Tool: "dnsx", DependsOn: []string{"a"}, Condition: scanworkflow.AlwaysCondition()},
		{ID: shared.NewID(), StepKey: "c", Tool: "httpx", Condition: scanworkflow.AlwaysCondition()},
	}
	run := &scanrun.Run{ID: shared.NewID(), TenantID: shared.NewID(), StartedAt: ptrTime(time.Now())}
	q := &recordingQueuer{}
	s := &Service{logger: logger.NewNop(), stepQueuer: q}
	if err := s.scheduleWorkflowSteps(context.Background(), run, steps, 3); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(q.steps, []string{"a", "c"}) {
		t.Fatalf("queued %v, want the steps without dependencies [a c]", q.steps)
	}
	s.stepQueuer = nil
	if err := s.scheduleWorkflowSteps(context.Background(), run, steps, 3); !errors.Is(err, ErrStepQueuerUnavailable) {
		t.Fatalf("no dispatcher: %v", err)
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

// prefer_tools: the step tries its own order, among the capability's
// implementations, not the catalog order.
func TestResolveStepTool_PreferOrder(t *testing.T) {
	tools := &fakeToolLookup{platform: map[string]*tool.Tool{
		"betterleaks": activeTool("betterleaks"),
		"gitleaks":    activeTool("gitleaks"),
	}}
	step := &scanworkflow.Step{StepKey: "secrets", Capabilities: []string{"secrets.code"}, PreferTools: []string{"gitleaks", "betterleaks"}}
	got, err := ResolveStepTool(context.Background(), tools, shared.NewID(), step)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "gitleaks" || got.Pinned || got.Capability() != "secrets.code@1" {
		t.Fatalf("resolved = %+v", got)
	}
	if !reflect.DeepEqual(got.Candidates, []string{"gitleaks", "betterleaks"}) {
		t.Fatalf("candidates = %v", got.Candidates)
	}
}

// A tool that does not take a standard param the step sets is never picked:
// the value would otherwise be dropped silently.
func TestResolveStepTool_SkipsToolsThatDoNotTakeTheParams(t *testing.T) {
	tools := &fakeToolLookup{platform: map[string]*tool.Tool{
		"betterleaks": activeTool("betterleaks"),
		"trufflehog":  activeTool("trufflehog"),
		"gitleaks":    activeTool("gitleaks"),
	}}
	step := &scanworkflow.Step{StepKey: "secrets", Capabilities: []string{"secrets.code"}, Config: map[string]any{"history": true}}
	_, err := ResolveStepTool(context.Background(), tools, shared.NewID(), step)
	if domainCode(err) != codeNoMatchingTool {
		t.Fatalf("err = %v, want NO_MATCHING_TOOL", err)
	}
	if de := err.Error(); !strings.Contains(de, "does not take history") {
		t.Fatalf("the reason is missing: %v", err)
	}
	if len(tools.asked) != 0 {
		t.Fatalf("looked up %v though none takes the params", tools.asked)
	}
}

// The resolved step carries the config the tool receives: standard params
// under the tool's own keys, and the extras for that tool only.
func TestStepTool_WithToolMapsTheConfig(t *testing.T) {
	tools := &fakeToolLookup{platform: map[string]*tool.Tool{"naabu": activeTool("naabu")}}
	step := &scanworkflow.Step{StepKey: "ports", Capabilities: []string{"scan.ports"},
		Config: map[string]any{"top_n": float64(100)}}
	got, err := ResolveStepTool(context.Background(), tools, shared.NewID(), step)
	if err != nil {
		t.Fatal(err)
	}
	run := &scanrun.Run{ID: shared.NewID(), Context: map[string]any{}}
	p, err := StepCommandPayload(run, got.WithTool(step), got.Name, "sr", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := p[scanworkflow.PayloadKeyConfig].(map[string]any)
	if _, std := cfg["top_n"]; std || cfg["top_ports"] == nil {
		t.Fatalf("sensor config = %v, want top_ports", cfg)
	}
	if _, ok := step.Config["top_n"]; !ok {
		t.Fatal("resolving changed the stored step config")
	}
}

// A step names its capability only for a tool that runs capability jobs on
// the sensor and implements the step's stage; every other command is
// unchanged, so an older sensor or another tool runs as before.
func TestStepCommandPayload_Capability(t *testing.T) {
	run := &scanrun.Run{ID: shared.NewID()}
	cases := []struct {
		tool string
		caps []string
		want string
	}{
		{"naabu", nil, "scan.ports@1"},
		{"nuclei", nil, "vuln.templates@1"},
		{"trivy", []string{"sca"}, "sca.deps@1"},
		{"zap", nil, ""},          // no capability jobs on the sensor
		{"acme-scanner", nil, ""}, // not in the catalog
		{"tenable_sc", nil, ""},   // a connector
	}
	for _, tc := range cases {
		step := &scanworkflow.Step{ID: shared.NewID(), StepKey: "s", Tool: tc.tool, Capabilities: tc.caps}
		p, err := StepCommandPayload(run, step, tc.tool, "sr", nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.tool, err)
		}
		got, _ := p[PayloadKeyCapability].(string)
		if got != tc.want {
			t.Errorf("%s: capability %q, want %q", tc.tool, got, tc.want)
		}
	}
}
