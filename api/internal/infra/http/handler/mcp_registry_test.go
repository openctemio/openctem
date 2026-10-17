package handler

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// mcpWriteToolAllowlist is the complete set of tools that change data. Adding
// a tool with Write: true fails TestMCPWriteToolAllowlist until it is listed
// here WITH the security review that approved it. Rules a new tool must meet:
//   - runs only through the web confirmation (the person approves the exact
//     arguments, in the web console, never in the assistant);
//   - uses the scoped service path (tenant from context, acting user, data
//     scope), never an admin path;
//   - returns tenant text only through untrustedResult;
//   - any fetch goes through pkg/httpsec;
//   - it must NEVER approve, accept a risk, approve a false positive, delete,
//     launch a scan or change integration configuration. MCP may create an
//     approval request through the transition engine; it never decides one.
var mcpWriteToolAllowlist = map[string]string{
	"add_finding_comment": "findings:comment; OAuth person only; exact text confirmed in the web page; " +
		"hidden characters rejected; client visibility needs lead or reviewer",
}

func TestMCPWriteToolAllowlist(t *testing.T) {
	h := newTestMCPWithPentest(&fakeFindingReader{}, &fakePentestReader{})
	h.SetWriteTools(&fakeConfirmer{approved: map[string]string{}}, &fakeCommenter{})
	var got []string
	for _, tool := range h.tools {
		if tool.Write {
			got = append(got, tool.Name)
			if note := mcpWriteToolAllowlist[tool.Name]; strings.TrimSpace(note) == "" {
				t.Errorf("write tool %q is not in mcpWriteToolAllowlist: add it with its security review note (see the rules above it)", tool.Name)
			}
			if tool.prepare == nil {
				t.Errorf("write tool %q has no confirmation step (prepare)", tool.Name)
			}
		}
	}
	sort.Strings(got)
	if len(got) != len(mcpWriteToolAllowlist) {
		t.Errorf("write tools %v differ from the allowlist", got)
	}
}

// TestMCPCanRequestButNeverApprove: no tool, listed or not, can decide an
// approval, accept a risk or perform another privileged decision. Approving
// stays in the web console.
func TestMCPCanRequestButNeverApprove(t *testing.T) {
	h := newTestMCPWithPentest(&fakeFindingReader{}, &fakePentestReader{})
	h.SetWriteTools(&fakeConfirmer{approved: map[string]string{}}, &fakeCommenter{})
	banned := []string{"approve", "reject", "decide", "accept", "false_positive", "fp_", "delete", "remove",
		"launch", "scan_start", "run_scan", "integration", "confirm", "grant", "revoke", "role"}
	for _, tool := range h.tools {
		name := strings.ToLower(tool.Name)
		for _, b := range banned {
			if strings.Contains(name, b) {
				t.Errorf("tool %q looks like a privileged decision (%q); MCP never decides approvals", tool.Name, b)
			}
		}
		if tool.Write && tool.RequiredPerm != "findings:comment" {
			t.Errorf("write tool %q needs a reviewed permission list", tool.Name)
		}
	}
	for _, p := range h.prompts {
		if strings.Contains(strings.ToLower(p.Name), "approve") {
			t.Errorf("prompt %q must not approve anything", p.Name)
		}
	}
}

// TestMCPToolsListStatic: tools/list never carries tenant data. Two tenants
// whose stores differ get byte-identical definitions, so tool-description
// poisoning from tenant data is impossible.
func TestMCPToolsListStatic(t *testing.T) {
	list := func(tenant string, fr *fakeFindingReader) string {
		h := newTestMCPWithPentest(fr, &fakePentestReader{})
		h.SetWriteTools(&fakeConfirmer{approved: map[string]string{}}, &fakeCommenter{})
		out := wtRequest(t, h, true, allToolPerms(h), `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
		b, _ := json.Marshal(out["result"])
		_ = tenant
		return string(b)
	}
	f1 := makePentestFinding(t)
	a := list("tenant-a", &fakeFindingReader{finding: f1})
	b := list("tenant-b", &fakeFindingReader{})
	if a != b {
		t.Fatal("tools/list differs between tenants")
	}
	if strings.Contains(a, f1.Title()) {
		t.Fatal("tenant data in a tool definition")
	}
	// prompts/list likewise
	p := func() string {
		h := newTestMCPWithPentest(&fakeFindingReader{finding: f1}, &fakePentestReader{})
		out := wtRequest(t, h, true, allToolPerms(h), `{"jsonrpc":"2.0","id":1,"method":"prompts/list"}`)
		bb, _ := json.Marshal(out["result"])
		return string(bb)
	}
	first, second := p(), p()
	if first != second || strings.Contains(first, f1.Title()) {
		t.Fatal("prompts/list carries tenant data")
	}
}

func allToolPerms(h *MCPHandler) []string {
	var perms []string
	for _, tool := range h.tools {
		perms = append(perms, tool.RequiredPerm)
	}
	for _, p := range h.prompts {
		perms = append(perms, p.RequiredPerm)
	}
	return perms
}
