package scan

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
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
	step := &pipeline.Step{ID: shared.NewID(), StepKey: "ports", Capabilities: []string{"recon", "portscan"}}
	got, err := ResolveStepTool(context.Background(), tools, shared.NewID(), step)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "naabu" || got.Pinned || !got.HasStage || got.Stage.Key != stage.ScanPorts {
		t.Fatalf("resolved = %+v", got)
	}
	run := &pipeline.Run{ID: shared.NewID(), Context: map[string]any{"targets": []string{"a.example.com"}}}
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
	step := &pipeline.Step{StepKey: "secrets", Tool: "trufflehog", Capabilities: []string{"secrets"}}
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
	step := &pipeline.Step{StepKey: "secrets", Capabilities: []string{"secrets"}}
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
	if _, err := ResolveStepTool(ctx, none, shared.NewID(), &pipeline.Step{StepKey: "p", Capabilities: []string{"portscan"}}); domainCode(err) != codeNoMatchingTool {
		t.Errorf("no implementation: %v", err)
	}
	if _, err := ResolveStepTool(ctx, none, shared.NewID(), &pipeline.Step{StepKey: "x", Capabilities: []string{"portscan", "dns"}}); domainCode(err) != codeStepCapabilityUnsure {
		t.Errorf("ambiguous: %v", err)
	}
	if _, err := ResolveStepTool(ctx, none, shared.NewID(), &pipeline.Step{StepKey: "e"}); domainCode(err) != codeStepInvalid {
		t.Errorf("empty step: %v", err)
	}
	if _, err := ResolveStepTool(ctx, nil, shared.NewID(), &pipeline.Step{StepKey: "p", Capabilities: []string{"portscan"}}); err == nil {
		t.Error("no registry: resolved anyway (must fail closed)")
	}
	broken := &fakeToolLookup{platform: map[string]*tool.Tool{}, capsErr: errors.New("db down")}
	if _, err := ResolveStepTool(ctx, broken, shared.NewID(), &pipeline.Step{StepKey: "c", Capabilities: []string{"custom-cap"}}); err == nil {
		t.Error("a failed lookup resolved a tool")
	}
}

// Capabilities the catalog does not know fall back to the tenant's tool
// lookup, scoped by the caller's tenant; a disabled match is refused.
func TestResolveStepTool_FallbackIsTenantScoped(t *testing.T) {
	tenant := shared.NewID()
	tools := &fakeToolLookup{byCaps: activeTool("acme-scanner")}
	got, err := ResolveStepTool(context.Background(), tools, tenant, &pipeline.Step{StepKey: "c", Capabilities: []string{"acme-cap"}})
	if err != nil || got.Name != "acme-scanner" || got.HasStage {
		t.Fatalf("got %+v, %v", got, err)
	}
	if tools.capsWith != tenant {
		t.Fatal("the fallback lookup is not scoped to the caller's tenant")
	}
	tools.byCaps = &tool.Tool{Name: "acme-scanner", IsActive: false}
	if _, err := ResolveStepTool(context.Background(), tools, tenant, &pipeline.Step{StepKey: "c", Capabilities: []string{"acme-cap"}}); domainCode(err) != codeNoMatchingTool {
		t.Fatalf("a disabled tool was picked: %v", err)
	}
}

// Golden: the payload of a pinned-tool step has exactly the keys and values
// both former builders sent (scan trigger and pipeline service), so moving
// to one builder changes no command a sensor receives.
func TestStepCommandPayload_Golden(t *testing.T) {
	asset := shared.NewID()
	run := &pipeline.Run{ID: shared.NewID(), AssetID: &asset, Context: map[string]any{
		"targets":                []string{"a.example.com"},
		"scan_id":                "s-1",
		RunContextKeyTargetTypes: map[string]string{"a.example.com": "domain"},
	}}
	step := &pipeline.Step{ID: shared.NewID(), StepKey: "subs", Tool: "subfinder",
		Capabilities: []string{"recon", "subdomain"}, TimeoutSeconds: 600}
	p, err := StepCommandPayload(run, step, "subfinder", "sr-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"pipeline_run_id":       run.ID.String(),
		"step_run_id":           "sr-1",
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
	p, _ = StepCommandPayload(&pipeline.Run{ID: shared.NewID()}, step, "subfinder", "sr", nil)
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
	run := &pipeline.Run{ID: shared.NewID()}
	step := &pipeline.Step{ID: shared.NewID(), StepKey: "ports", Config: map[string]any{"top_ports": "1000", "rate": float64(500)}}
	p, err := StepCommandPayload(run, step, "naabu", "sr", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, ok := p[pipeline.PayloadKeyConfig].(map[string]any)
	if !ok || cfg["top_ports"] != int64(1000) || cfg["rate"] != int64(500) {
		t.Fatalf("config = %#v", p[pipeline.PayloadKeyConfig])
	}
	step.Config = map[string]any{"ports": "80 -nmap-cli id"}
	if _, err := StepCommandPayload(run, step, "naabu", "sr", nil); err == nil {
		t.Fatal("flag injection in ports reached a command payload")
	}
	step.Config = map[string]any{"tags": []any{"cve", "-code"}}
	if _, err := StepCommandPayload(run, step, "nuclei", "sr", nil); err == nil {
		t.Fatal("a flag as a nuclei tag reached a command payload")
	}
	if _, err := StepCommandPayload(run, &pipeline.Step{StepKey: "x"}, " ", "sr", nil); domainCode(err) != codeNoMatchingTool {
		t.Fatalf("tool-less payload: %v", err)
	}
}

// recordingQueuer is a StepQueuer that records the steps it was handed.
type recordingQueuer struct{ steps []string }

func (q *recordingQueuer) QueueRunStep(_ context.Context, _ *pipeline.Run, step *pipeline.Step) error {
	q.steps = append(q.steps, step.StepKey)
	return nil
}

// The scan trigger hands its first workflow steps to the one dispatcher;
// without it nothing is queued (fail closed).
func TestScheduleWorkflowSteps_DelegatesToTheOneDispatcher(t *testing.T) {
	steps := []*pipeline.Step{
		{ID: shared.NewID(), StepKey: "a", Tool: "subfinder", Condition: pipeline.AlwaysCondition()},
		{ID: shared.NewID(), StepKey: "b", Tool: "dnsx", DependsOn: []string{"a"}, Condition: pipeline.AlwaysCondition()},
		{ID: shared.NewID(), StepKey: "c", Tool: "httpx", Condition: pipeline.AlwaysCondition()},
	}
	run := &pipeline.Run{ID: shared.NewID(), TenantID: shared.NewID(), StartedAt: ptrTime(time.Now())}
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
