package scan

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
)

// declaredTool is a tool an organization's sensor declares for
// vuln.templates@1, taking the standard param rate under its own key rps.
func declaredTool(t *testing.T, tenantID shared.ID, name string, implements ...string) *tool.Tool {
	t.Helper()
	if len(implements) == 0 {
		implements = []string{"vuln.templates@1"}
	}
	params := map[string]map[string]string{}
	for _, ref := range implements {
		params[ref] = map[string]string{"rate": "rps"}
	}
	dt, err := tool.NewDeclaredTool(tenantID, tool.Declaration{
		Name: name, Version: "1.0.0", Implements: implements, Params: params,
		Consumes: []string{"http_service"}, Digest: "sha256:" + name,
	})
	if err != nil {
		t.Fatal(err)
	}
	return dt
}

func templatesStep(config map[string]any, prefer ...string) *scanworkflow.Step {
	return &scanworkflow.Step{ID: shared.NewID(), StepKey: "vulns", Capabilities: []string{"vuln.templates"}, Config: config, PreferTools: prefer}
}

// A capability step whose catalog implementations are all unavailable runs
// the organization's declared implementation: its standard params are
// mapped through its descriptor and its command names the capability.
func TestResolveStepTool_DeclaredToolRunsTheCapability(t *testing.T) {
	tenant := shared.NewID()
	tools := &fakeToolLookup{custom: []*tool.Tool{declaredTool(t, tenant, "acme-headers")}}
	step := templatesStep(map[string]any{"rate": 10})

	got, err := ResolveStepTool(context.Background(), tools, tenant, step)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "acme-headers" || !got.Declared || !got.HasStage || got.Stage.Key != stage.VulnTemplates || got.Pinned {
		t.Fatalf("resolved = %+v", got)
	}
	if got.Capability() != "vuln.templates@1" {
		t.Fatalf("capability = %q", got.Capability())
	}
	run := &scanrun.Run{ID: shared.NewID(), Context: map[string]any{"targets": []string{"https://app.example.com"}}}
	p, err := got.CommandPayload(run, got.WithTool(step), "sr", nil)
	if err != nil {
		t.Fatal(err)
	}
	if p["scanner"] != "acme-headers" || p[PayloadKeyCapability] != "vuln.templates@1" {
		t.Fatalf("scanner = %v capability = %v", p["scanner"], p[PayloadKeyCapability])
	}
	cfg, _ := p[scanworkflow.PayloadKeyConfig].(map[string]any)
	if !reflect.DeepEqual(cfg, map[string]any{"rps": 10}) {
		t.Fatalf("config = %v, want the standard param under the tool's key", cfg)
	}
	if !slices.Equal(tools.listedFor, []shared.ID{tenant}) {
		t.Fatalf("declared tools listed for %v, want only the step's organization", tools.listedFor)
	}
}

// The catalog's implementation comes first: existing workflows keep the
// tool they ran before a declared tool appeared.
func TestResolveStepTool_CatalogImplementationFirst(t *testing.T) {
	tenant := shared.NewID()
	tools := &fakeToolLookup{
		platform: map[string]*tool.Tool{"nuclei": activeTool("nuclei")},
		custom:   []*tool.Tool{declaredTool(t, tenant, "acme-headers")},
	}
	got, err := ResolveStepTool(context.Background(), tools, tenant, templatesStep(nil))
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "nuclei" || got.Declared {
		t.Fatalf("resolved = %+v, want the catalog default", got)
	}
	if want := []string{"nuclei", "acme-headers"}; !slices.Equal(got.Candidates, want) {
		t.Fatalf("candidates = %v, want %v", got.Candidates, want)
	}
}

// prefer_tools may name a declared tool, ahead of the catalog's.
func TestResolveStepTool_PreferToolsNamesADeclaredTool(t *testing.T) {
	tenant := shared.NewID()
	tools := &fakeToolLookup{
		platform: map[string]*tool.Tool{"nuclei": activeTool("nuclei")},
		custom:   []*tool.Tool{declaredTool(t, tenant, "acme-headers")},
	}
	got, err := ResolveStepTool(context.Background(), tools, tenant, templatesStep(nil, "acme-headers", "nuclei"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "acme-headers" || !got.Declared {
		t.Fatalf("resolved = %+v, want the preferred declared tool", got)
	}
}

// Tenant isolation: another organization's declared tool is never a
// candidate, whatever it implements or is called.
func TestResolveStepTool_AnotherOrganizationsDeclaredToolIsNeverPicked(t *testing.T) {
	tenant, other := shared.NewID(), shared.NewID()
	tools := &fakeToolLookup{custom: []*tool.Tool{declaredTool(t, other, "acme-headers")}}

	_, err := ResolveStepTool(context.Background(), tools, tenant, templatesStep(nil))
	if domainCode(err) != codeNoMatchingTool {
		t.Fatalf("err = %v, want %s", err, codeNoMatchingTool)
	}
	// Named in prefer_tools or pinned, it is still not this organization's.
	if _, err := ResolveStepTool(context.Background(), tools, tenant, templatesStep(nil, "acme-headers")); domainCode(err) != codeNoMatchingTool {
		t.Fatalf("prefer_tools: err = %v, want %s", err, codeNoMatchingTool)
	}
	pinned := templatesStep(nil)
	pinned.Tool = "acme-headers"
	got, err := ResolveStepTool(context.Background(), tools, tenant, pinned)
	if err != nil {
		t.Fatal(err)
	}
	if got.Declared || got.HasStage {
		t.Fatalf("a pin of another organization's tool resolved as its declared tool: %+v", got)
	}
}

// Only a declared tool that implements the stage's capability@major,
// active and a scanner, is a candidate; a tool a member created with a
// matching capability word is not (nothing vouches for what it runs).
func TestResolveStepTool_DeclaredCandidatesAreFiltered(t *testing.T) {
	tenant := shared.NewID()
	inactive := declaredTool(t, tenant, "acme-off")
	inactive.IsActive = false
	otherCapability := declaredTool(t, tenant, "acme-dast", "dast.web@1")
	otherCapability.Capabilities = append(otherCapability.Capabilities, "vuln.templates") // a word, not the reference
	member := &tool.Tool{Name: "member-tool", TenantID: &tenant, IsActive: true, Capabilities: []string{"vuln.templates"}, Metadata: map[string]any{}}
	tools := &fakeToolLookup{custom: []*tool.Tool{inactive, otherCapability, member}}

	_, err := ResolveStepTool(context.Background(), tools, tenant, templatesStep(nil))
	if domainCode(err) != codeNoMatchingTool {
		t.Fatalf("err = %v, want %s", err, codeNoMatchingTool)
	}
}

// A declared tool that does not take a standard param the step sets is
// skipped with the reason, never handed the step with the value dropped.
func TestResolveStepTool_DeclaredToolWithoutTheParamIsSkipped(t *testing.T) {
	tenant := shared.NewID()
	tools := &fakeToolLookup{custom: []*tool.Tool{declaredTool(t, tenant, "acme-headers")}}

	_, err := ResolveStepTool(context.Background(), tools, tenant, templatesStep(map[string]any{"severity": []any{"high"}}))
	if domainCode(err) != codeNoMatchingTool {
		t.Fatalf("err = %v, want %s", err, codeNoMatchingTool)
	}
	if err == nil || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err = %v", err)
	}
}

// A pinned declared tool runs its step's capability (params mapped, the
// capability in the command), so its output is checked against it.
func TestResolveStepTool_PinnedDeclaredToolRunsItsCapability(t *testing.T) {
	tenant := shared.NewID()
	tools := &fakeToolLookup{custom: []*tool.Tool{declaredTool(t, tenant, "acme-headers")}}
	step := templatesStep(map[string]any{"rate": 5, "x_extra": true})
	step.Tool = "acme-headers"

	got, err := ResolveStepTool(context.Background(), tools, tenant, step)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Pinned || !got.Declared || !got.HasStage || got.Name != "acme-headers" {
		t.Fatalf("resolved = %+v", got)
	}
	run := &scanrun.Run{ID: shared.NewID(), Context: map[string]any{"targets": []string{"https://app.example.com"}}}
	p, err := got.CommandPayload(run, got.WithTool(step), "sr", nil)
	if err != nil {
		t.Fatal(err)
	}
	if p[PayloadKeyCapability] != "vuln.templates@1" {
		t.Fatalf("capability = %v", p[PayloadKeyCapability])
	}
	cfg, _ := p[scanworkflow.PayloadKeyConfig].(map[string]any)
	if cfg["rps"] != 5 || cfg["x_extra"] != true {
		t.Fatalf("config = %v, want rps mapped and the tool's own setting kept", cfg)
	}
}

// A failed lookup of declared tools fails the step (fail closed): it is
// never read as "the organization has none".
func TestResolveStepTool_DeclaredLookupFailureFailsTheStep(t *testing.T) {
	tools := &fakeToolLookup{listErr: errors.New("db down")}
	if _, err := ResolveStepTool(context.Background(), tools, shared.NewID(), templatesStep(nil)); err == nil || domainCode(err) == codeNoMatchingTool {
		t.Fatalf("err = %v, want the lookup failure", err)
	}
}

// A catalog tool's command is unchanged by CommandPayload.
func TestStepTool_CommandPayloadOfACatalogTool(t *testing.T) {
	tools := &fakeToolLookup{platform: map[string]*tool.Tool{"nuclei": activeTool("nuclei")}}
	step := templatesStep(nil)
	got, err := ResolveStepTool(context.Background(), tools, shared.NewID(), step)
	if err != nil {
		t.Fatal(err)
	}
	run := &scanrun.Run{ID: shared.NewID(), Context: map[string]any{"targets": []string{"https://app.example.com"}}}
	a, err := got.CommandPayload(run, got.WithTool(step), "sr", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := StepCommandPayload(run, got.WithTool(step), got.Name, "sr", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("CommandPayload = %v, StepCommandPayload = %v", a, b)
	}
}
