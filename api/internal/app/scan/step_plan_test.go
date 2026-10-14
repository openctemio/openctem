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
	"github.com/openctemio/openctem/api/pkg/domain/stage/stagetest"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/domain/toolbudget"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// fakeToolLookup is a tool registry: platform tools by name and the
// capability fallback's answer, recording what was asked.
type fakeToolLookup struct {
	platform map[string]*tool.Tool
	// own are the tenants' own tools (tools their sensors declare).
	own      map[shared.ID]map[string]*tool.Tool
	byCaps   *tool.Tool
	capsErr  error
	asked    []string
	capsWith shared.ID
}

func (f *fakeToolLookup) GetByName(_ context.Context, tenantID shared.ID, name string) (*tool.Tool, error) {
	f.asked = append(f.asked, name)
	if t, ok := f.platform[name]; ok {
		return t, nil
	}
	if t, ok := f.own[tenantID][name]; ok {
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
	got, err := ResolveStepTool(context.Background(), tools, testCat, shared.NewID(), step)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "naabu" || got.Pinned || !got.HasStage || got.Stage.Key != stage.ScanPorts {
		t.Fatalf("resolved = %+v", got)
	}
	run := &scanrun.Run{ID: shared.NewID(), Context: map[string]any{"targets": []string{"a.example.com"}}}
	p, err := StepCommandPayload(testCat, run, got.WithTool(step), got.Name, "sr", nil)
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
	step := &scanworkflow.Step{StepKey: "sast", Tool: "opengrep", Capabilities: []string{"sast"}}
	got, err := ResolveStepTool(context.Background(), tools, testCat, shared.NewID(), step)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "opengrep" || !got.Pinned || got.Stage.Key != stage.SASTCode {
		t.Fatalf("resolved = %+v", got)
	}
	if len(tools.asked) != 0 {
		t.Fatalf("a pinned step looked up %v", tools.asked)
	}
}

// G10: `auto` may substitute: the default is disabled, the next active
// implementation runs. A collector or connector is never picked.
func TestResolveStepTool_SubstitutesAnActiveImplementation(t *testing.T) {
	collector := &tool.Tool{Name: "opengrep", IsActive: true, Metadata: map[string]any{"kind": tool.KindCollector}}
	tools := &fakeToolLookup{platform: map[string]*tool.Tool{
		"semgrep":  {Name: "semgrep", IsActive: false},
		"opengrep": collector,
		"codeql":   activeTool("codeql"),
	}}
	step := &scanworkflow.Step{StepKey: "sast", Capabilities: []string{"sast"}}
	got, err := ResolveStepTool(context.Background(), tools, testCat, shared.NewID(), step)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "codeql" {
		t.Fatalf("resolved %s, want codeql (semgrep disabled, opengrep a collector)", got.Name)
	}
	if !reflect.DeepEqual(tools.asked, []string{"semgrep", "opengrep", "codeql"}) {
		t.Fatalf("asked %v: the default must be tried first", tools.asked)
	}
}

// No active implementation, an ambiguous capability list, and an empty
// step are refused with a code, before any command exists.
func TestResolveStepTool_Refusals(t *testing.T) {
	ctx := context.Background()
	none := &fakeToolLookup{platform: map[string]*tool.Tool{}}
	if _, err := ResolveStepTool(ctx, none, testCat, shared.NewID(), &scanworkflow.Step{StepKey: "p", Capabilities: []string{"portscan"}}); domainCode(err) != codeNoMatchingTool {
		t.Errorf("no implementation: %v", err)
	}
	if _, err := ResolveStepTool(ctx, none, testCat, shared.NewID(), &scanworkflow.Step{StepKey: "x", Capabilities: []string{"portscan", "dns"}}); domainCode(err) != codeStepCapabilityUnsure {
		t.Errorf("ambiguous: %v", err)
	}
	if _, err := ResolveStepTool(ctx, none, testCat, shared.NewID(), &scanworkflow.Step{StepKey: "e"}); domainCode(err) != codeStepInvalid {
		t.Errorf("empty step: %v", err)
	}
	if _, err := ResolveStepTool(ctx, nil, testCat, shared.NewID(), &scanworkflow.Step{StepKey: "p", Capabilities: []string{"portscan"}}); err == nil {
		t.Error("no registry: resolved anyway (must fail closed)")
	}
	broken := &fakeToolLookup{platform: map[string]*tool.Tool{}, capsErr: errors.New("db down")}
	if _, err := ResolveStepTool(ctx, broken, testCat, shared.NewID(), &scanworkflow.Step{StepKey: "c", Capabilities: []string{"custom-cap"}}); err == nil {
		t.Error("a failed lookup resolved a tool")
	}
}

// Capabilities the catalog does not know fall back to the tenant's tool
// lookup, scoped by the caller's tenant; a disabled match is refused.
func TestResolveStepTool_FallbackIsTenantScoped(t *testing.T) {
	tenant := shared.NewID()
	tools := &fakeToolLookup{byCaps: activeTool("acme-scanner")}
	got, err := ResolveStepTool(context.Background(), tools, testCat, tenant, &scanworkflow.Step{StepKey: "c", Capabilities: []string{"acme-cap"}})
	if err != nil || got.Name != "acme-scanner" || got.HasStage {
		t.Fatalf("got %+v, %v", got, err)
	}
	if tools.capsWith != tenant {
		t.Fatal("the fallback lookup is not scoped to the caller's tenant")
	}
	tools.byCaps = &tool.Tool{Name: "acme-scanner", IsActive: false}
	if _, err := ResolveStepTool(context.Background(), tools, testCat, tenant, &scanworkflow.Step{StepKey: "c", Capabilities: []string{"acme-cap"}}); domainCode(err) != codeNoMatchingTool {
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
	p, err := StepCommandPayload(testCat, run, step, "subfinder", "sr-1", nil)
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
		// The task's layered budget (research/122): one subfinder target.
		"budget": toolbudget.ForTask("subfinder", 1),
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
	p, _ = StepCommandPayload(testCat, &scanrun.Run{ID: shared.NewID()}, step, "subfinder", "sr", nil)
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
	p, err := StepCommandPayload(testCat, run, step, "naabu", "sr", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, ok := p[scanworkflow.PayloadKeyConfig].(map[string]any)
	if !ok || cfg["top_ports"] != int64(1000) || cfg["rate"] != int64(500) {
		t.Fatalf("config = %#v", p[scanworkflow.PayloadKeyConfig])
	}
	step.Config = map[string]any{"ports": "80 -nmap-cli id"}
	if _, err := StepCommandPayload(testCat, run, step, "naabu", "sr", nil); err == nil {
		t.Fatal("flag injection in ports reached a command payload")
	}
	step.Config = map[string]any{"tags": []any{"cve", "-code"}}
	if _, err := StepCommandPayload(testCat, run, step, "nuclei", "sr", nil); err == nil {
		t.Fatal("a flag as a nuclei tag reached a command payload")
	}
	if _, err := StepCommandPayload(testCat, run, &scanworkflow.Step{StepKey: "x"}, " ", "sr", nil); domainCode(err) != codeNoMatchingTool {
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
	s := &Service{tools: testTools, logger: logger.NewNop(), stepQueuer: q}
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
		"semgrep": activeTool("semgrep"),
		"codeql":  activeTool("codeql"),
	}}
	step := &scanworkflow.Step{StepKey: "sast", Capabilities: []string{"sast.code"}, PreferTools: []string{"codeql", "semgrep", "gitleaks"}}
	got, err := ResolveStepTool(context.Background(), tools, testCat, shared.NewID(), step)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "codeql" || got.Pinned || got.Capability() != "sast.code@1" {
		t.Fatalf("resolved = %+v", got)
	}
	// gitleaks reports no contract: it implements nothing.
	if !reflect.DeepEqual(got.Candidates, []string{"codeql", "semgrep"}) {
		t.Fatalf("candidates = %v", got.Candidates)
	}
}

// A tool that does not take a standard param the step sets is never picked:
// the value would otherwise be dropped silently.
func TestResolveStepTool_SkipsToolsThatDoNotTakeTheParams(t *testing.T) {
	tools := &fakeToolLookup{platform: map[string]*tool.Tool{
		"semgrep":  activeTool("semgrep"),
		"opengrep": activeTool("opengrep"),
		"codeql":   activeTool("codeql"),
	}}
	step := &scanworkflow.Step{StepKey: "sast", Capabilities: []string{"sast.code"}, Config: map[string]any{"languages": []any{"go"}}}
	got, err := ResolveStepTool(context.Background(), tools, testCat, shared.NewID(), step)
	if err != nil || got.Name != "codeql" {
		t.Fatalf("resolved %s, %v; want codeql, the one whose contract maps languages", got.Name, err)
	}
	if !reflect.DeepEqual(tools.asked, []string{"codeql"}) {
		t.Fatalf("looked up %v; semgrep and opengrep do not take languages", tools.asked)
	}
	tools.platform["codeql"] = &tool.Tool{Name: "codeql", IsActive: false}
	tools.asked = nil
	_, err = ResolveStepTool(context.Background(), tools, testCat, shared.NewID(), step)
	if domainCode(err) != codeNoMatchingTool {
		t.Fatalf("err = %v, want NO_MATCHING_TOOL", err)
	}
	if de := err.Error(); !strings.Contains(de, "semgrep does not take languages") {
		t.Fatalf("the reason is missing: %v", err)
	}
}

// The resolved step carries the config the tool receives: standard params
// under the tool's own keys, and the extras for that tool only.
func TestStepTool_WithToolMapsTheConfig(t *testing.T) {
	tools := &fakeToolLookup{platform: map[string]*tool.Tool{"naabu": activeTool("naabu")}}
	step := &scanworkflow.Step{StepKey: "ports", Capabilities: []string{"scan.ports"},
		Config: map[string]any{"top_n": float64(100)}}
	got, err := ResolveStepTool(context.Background(), tools, testCat, shared.NewID(), step)
	if err != nil {
		t.Fatal(err)
	}
	run := &scanrun.Run{ID: shared.NewID(), Context: map[string]any{}}
	p, err := StepCommandPayload(testCat, run, got.WithTool(step), got.Name, "sr", nil)
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
		{"zap", nil, "dast.web@1"}, // its reported contract implements dast.web
		{"acme-scanner", nil, ""},  // not in the catalog
		{"tenable_sc", nil, ""},    // a connector
	}
	for _, tc := range cases {
		step := &scanworkflow.Step{ID: shared.NewID(), StepKey: "s", Tool: tc.tool, Capabilities: tc.caps}
		p, err := StepCommandPayload(testCat, run, step, tc.tool, "sr", nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.tool, err)
		}
		got, _ := p[PayloadKeyCapability].(string)
		if got != tc.want {
			t.Errorf("%s: capability %q, want %q", tc.tool, got, tc.want)
		}
	}
}

// A capability step runs a tool that only its organization's sensor
// reports: the contract says it implements dast.web@1, maps the standard
// max_duration_minutes to its own max_minutes and takes one target per
// task. The tool row is the organization's own (a declared tool), read
// with the tenant's id; another organization neither sees the tool in its
// catalog nor reads the row.
func TestResolveStepTool_ToolFromAReportedContract(t *testing.T) {
	tenantA, tenantB := shared.NewID(), shared.NewID()
	toyweb := stage.ToolFacts{Name: "toyweb", Implements: []stage.Key{stage.DASTWeb},
		Params: map[stage.Key]map[string]string{stage.DASTWeb: {"max_duration_minutes": "max_minutes"}}}
	catA, catB := stagetest.Catalog(toyweb), stagetest.Catalog()
	tools := &fakeToolLookup{own: map[shared.ID]map[string]*tool.Tool{tenantA: {"toyweb": activeTool("toyweb")}}}
	step := &scanworkflow.Step{ID: shared.NewID(), StepKey: "web", Capabilities: []string{"dast.web"},
		Config: map[string]any{"max_duration_minutes": 30}}

	got, err := ResolveStepTool(context.Background(), tools, catA, tenantA, step)
	if err != nil {
		t.Fatalf("tenant A: %v", err)
	}
	if got.Name != "toyweb" || got.Capability() != "dast.web@1" || got.Stage.ChunkSizeFor("toyweb") != 0 {
		t.Fatalf("resolved = %s %s", got.Name, got.Capability())
	}
	run := &scanrun.Run{ID: shared.NewID(), TenantID: tenantA, Context: map[string]any{"targets": []string{"https://app.example.com"}}}
	p, err := StepCommandPayload(catA, run, got.WithTool(step), got.Name, "sr", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := p["config"].(map[string]any)
	if p[PayloadKeyCapability] != "dast.web@1" || p["scanner"] != "toyweb" || cfg["max_minutes"] != 30 || cfg["max_duration_minutes"] != nil {
		t.Fatalf("payload capability %v scanner %v config %v", p[PayloadKeyCapability], p["scanner"], cfg)
	}

	// SECURITY: tenant B's catalog has no dast.web tool, and its lookup
	// never reaches tenant A's row.
	if _, err := ResolveStepTool(context.Background(), tools, catB, tenantB, step); domainCode(err) != codeNoMatchingTool {
		t.Fatalf("tenant B: err = %v, want NO_MATCHING_TOOL", err)
	}
	tools.asked = nil
	if _, err := ResolveStepTool(context.Background(), tools, catA, tenantB, step); domainCode(err) != codeNoMatchingTool {
		t.Fatalf("tenant B with A's facts: err = %v, want NO_MATCHING_TOOL (A's tool row is not B's)", err)
	}
}

// A tool whose contract names only capabilities the platform does not
// route is never picked for a capability; pinned, it runs as a tenant tool
// that never chains.
func TestResolveStepTool_UnknownCapabilityNotRouted(t *testing.T) {
	cat := stagetest.Catalog(stage.ToolFacts{Name: "odd", Implements: []stage.Key{"made.up"}})
	tools := &fakeToolLookup{platform: map[string]*tool.Tool{"odd": activeTool("odd")}}
	if _, err := ResolveStepTool(context.Background(), tools, cat, shared.NewID(),
		&scanworkflow.Step{StepKey: "x", Capabilities: []string{"made.up"}}); err == nil {
		t.Fatal("a capability the platform does not route was resolved")
	}
	got, err := ResolveStepTool(context.Background(), tools, cat, shared.NewID(), &scanworkflow.Step{StepKey: "x", Tool: "odd"})
	if err != nil || got.HasStage || got.Capability() != "" {
		t.Fatalf("pinned odd = %+v %v", got.Name, err)
	}
}

// naabu pinned without a capability runs its primary capability (port
// scan); it runs host discovery only when the step names it.
func TestStepCommandPayload_NaabuPrimaryCapability(t *testing.T) {
	run := &scanrun.Run{ID: shared.NewID(), Context: map[string]any{"targets": []string{"192.0.2.0/28"}}}
	for _, tc := range []struct {
		caps []string
		want string
	}{{nil, "scan.ports@1"}, {[]string{"recon"}, "scan.ports@1"}, {[]string{"discover.hosts"}, "discover.hosts@1"}} {
		step := &scanworkflow.Step{ID: shared.NewID(), StepKey: "n", Tool: "naabu", Capabilities: tc.caps}
		p, err := StepCommandPayload(testCat, run, step, "naabu", "sr", nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := p[PayloadKeyCapability]; got != tc.want {
			t.Errorf("naabu %v: capability %v, want %s", tc.caps, got, tc.want)
		}
	}
}
