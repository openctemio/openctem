package handler

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
)

// fakeModuleGate turns modules off per tenant.
type fakeModuleGate struct{ off map[string]map[string]bool }

func (g fakeModuleGate) IsEnabled(_ context.Context, tenantID, moduleID string) bool {
	return !g.off[tenantID][moduleID]
}

// Every MCP tool and prompt names the module of its REST route ("" = core),
// so a new tool cannot be added without deciding it.
func TestMCP_EveryToolAndPromptIsClassified(t *testing.T) {
	want := map[string]string{
		"list_findings":            "",
		"get_finding":              "",
		"finding_stats":            "",
		"list_active_cves":         "",
		"explain_finding_priority": "",
		"list_remediation_groups":  "", // /findings/remediation-groups is core
		"list_assets":              "",
		"get_exposure_chains":      moduledom.ModuleAttackSurface,
		"compliance_posture":       moduledom.ModuleCompliance,
		"get_campaign":             moduledom.ModulePentest,
		"list_campaign_findings":   moduledom.ModulePentest,
		"get_pentest_finding":      moduledom.ModulePentest,
		"list_retests":             moduledom.ModulePentest,
		"list_finding_templates":   moduledom.ModulePentest,
		"campaign_report_stats":    moduledom.ModulePentest,
		// prompts
		"exec_summary":         moduledom.ModulePentest,
		"finding_writeup":      moduledom.ModulePentest,
		"remediation_guidance": moduledom.ModulePentest,
		"attack_narrative":     moduledom.ModulePentest,
	}
	h := newTestMCPWithPentest(&fakeFindingReader{}, &fakePentestReader{})
	seen := 0
	check := func(name, module string) {
		seen++
		m, ok := want[name]
		if !ok {
			t.Errorf("MCP %q is not classified: add it to this test with the module of its REST route", name)
			return
		}
		if m != module {
			t.Errorf("MCP %q: module %q, want %q", name, module, m)
		}
	}
	for _, tool := range h.tools {
		check(tool.Name, tool.Module)
	}
	for _, p := range h.prompts {
		check(p.Name, p.Module)
	}
	if seen != len(want) {
		t.Errorf("classified %d names, registry has %d: drop the retired ones", len(want), seen)
	}
}

func TestMCP_ModuleOffHidesAndRefuses(t *testing.T) {
	const tenantOff, tenantOn = testTenantUUID, "018f5a1e-0000-7000-8000-00000000beef"
	pr := &fakePentestReader{campaign: newTestCampaign(t)}
	h := newTestMCPWithPentest(&fakeFindingReader{}, pr)
	h.SetModuleGate(fakeModuleGate{off: map[string]map[string]bool{
		tenantOff: {moduledom.ModulePentest: true, moduledom.ModuleAttackSurface: true},
	}})
	scopes := append([]string{"pentest:campaigns:read", "pentest:findings:read"}, allReadScopes...)

	listed := func(tenant, method, key string) map[string]bool {
		t.Helper()
		_, resp := doRPCScoped(t, h, tenant, "user-1", scopes, `{"jsonrpc":"2.0","id":1,"method":"`+method+`"}`)
		if resp.Error != nil {
			t.Fatalf("%s: %+v", method, resp.Error)
		}
		var r map[string][]struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(resp.Result, &r); err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, x := range r[key] {
			out[x.Name] = true
		}
		return out
	}

	// Off: not listed. Core tools stay.
	tools := listed(tenantOff, "tools/list", "tools")
	for _, hidden := range []string{"get_campaign", "campaign_report_stats", "get_exposure_chains"} {
		if tools[hidden] {
			t.Errorf("tool %q listed with its module off", hidden)
		}
	}
	if !tools["list_findings"] || !tools["compliance_posture"] {
		t.Errorf("core or enabled tools missing: %v", tools)
	}
	if p := listed(tenantOff, "prompts/list", "prompts"); len(p) != 0 {
		t.Errorf("pentest prompts listed with pentest off: %v", p)
	}

	// Another organization is unaffected.
	if !listed(tenantOn, "tools/list", "tools")["get_campaign"] {
		t.Error("the module state of one organization changed another's tool list")
	}

	// Off: a direct call is refused without reaching the data.
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_campaign","arguments":{"id":"018f5a1e-0000-7000-8000-0000000000cc"}}}`
	_, resp := doRPCScoped(t, h, tenantOff, "user-1", scopes, body)
	if resp.Error != nil {
		t.Fatalf("tools/call: %+v", resp.Error)
	}
	if !strings.Contains(string(resp.Result), `"isError":true`) || !strings.Contains(string(resp.Result), "not enabled") {
		t.Errorf("tools/call with module off: %s", resp.Result)
	}
	if pr.gotTenant != "" {
		t.Errorf("pentest reader reached with the module off (tenant %q)", pr.gotTenant)
	}

	_, resp = doRPCScoped(t, h, tenantOff, "user-1", scopes,
		`{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"exec_summary","arguments":{"campaign_id":"018f5a1e-0000-7000-8000-0000000000cc"}}}`)
	if resp.Error == nil || !strings.Contains(resp.Error.Message, "not enabled") {
		t.Errorf("prompts/get with module off: %+v %s", resp.Error, resp.Result)
	}

	// On: the same call runs.
	_, resp = doRPCScoped(t, h, tenantOn, "user-1", scopes, body)
	if resp.Error != nil || strings.Contains(string(resp.Result), `"isError":true`) {
		t.Errorf("tools/call with module on: %+v %s", resp.Error, resp.Result)
	}
}
