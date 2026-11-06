package handler

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// scopeFake is the scope data of tenants: entries per tenant, program
// exclusions and memberships, and an injectable failure.
type scopeFake struct {
	targets  map[string][]*scopedom.Target
	excl     []bountyprogram.Exclusion
	members  map[string][]shared.ID
	failList error
	failProg error
}

func (f *scopeFake) ListActiveTargets(_ context.Context, tenant string) ([]*scopedom.Target, error) {
	if f.failList != nil {
		return nil, f.failList
	}
	return f.targets[tenant], nil
}

func (f *scopeFake) ListProgramExclusions(_ context.Context, _ shared.ID) ([]bountyprogram.Exclusion, error) {
	return f.excl, f.failProg
}

func (f *scopeFake) VerifiedDomainNames(context.Context, shared.ID) ([]string, error) {
	return nil, nil
}

func (f *scopeFake) MemberProgramIDs(_ context.Context, _, user shared.ID) ([]shared.ID, error) {
	if f.failProg != nil {
		return nil, f.failProg
	}
	return f.members[user.String()], nil
}

func scopeEntry(t *testing.T, tenant, pattern string, tier scopedom.Tier, program *shared.ID) *scopedom.Target {
	t.Helper()
	tid, _ := shared.IDFromString(tenant)
	e, err := scopedom.NewTarget(tid, scopedom.TargetTypeDomain, pattern, "", "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetMaxTier(tier, e.CreatedAt())
	if program != nil {
		if err := e.SetAuthorization(scopedom.AuthProgram, program); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

const otherTenant = "018f5a1e-0000-7000-8000-0000000000ee"

func newScopeHandler(t *testing.T, f *scopeFake) *MCPHandler {
	t.Helper()
	h := newTestMCPWithPentest(&fakeFindingReader{}, &fakePentestReader{})
	h.SetScopeCheck(f, f, f)
	return h
}

var scopePerms = []string{"attack_surface:scope:read"}

func checkScope(t *testing.T, h *MCPHandler, perms []string, args string) (scopeDecision, string, bool) {
	t.Helper()
	text, isErr := resultText(wtRequest(t, h, true, perms,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"check_scope","arguments":`+args+`}}`))
	var d scopeDecision
	_ = json.Unmarshal([]byte(text), &d)
	return d, text, isErr
}

func TestCheckScope_ListedOnlyWithScopeRead(t *testing.T) {
	h := newScopeHandler(t, &scopeFake{})
	list := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	if !toolNames(wtRequest(t, h, true, scopePerms, list))["check_scope"] {
		t.Fatal("not listed with attack_surface:scope:read")
	}
	if toolNames(wtRequest(t, h, true, []string{"findings:read"}, list))["check_scope"] {
		t.Fatal("listed without the permission")
	}
	if _, text, _ := checkScope(t, h, []string{"findings:read"}, `{"target":"a.example.com"}`); !strings.Contains(text, "permission_denied") {
		t.Fatalf("called without the permission: %s", text)
	}
	// No widening or proposing counterpart exists.
	for name := range toolNames(wtRequest(t, h, true, append(scopePerms, "findings:write", "findings:comment"), list)) {
		if strings.Contains(name, "scope") && name != "check_scope" {
			t.Fatalf("unexpected scope tool %q", name)
		}
	}
}

func TestCheckScope_Decisions(t *testing.T) {
	f := &scopeFake{targets: map[string][]*scopedom.Target{}}
	f.targets[wtTenant] = []*scopedom.Target{
		scopeEntry(t, wtTenant, "*.acme.example", scopedom.TierActive, nil),
	}
	f.targets[otherTenant] = []*scopedom.Target{
		scopeEntry(t, otherTenant, "*.victim.example", scopedom.TierIntrusive, nil),
	}
	h := newScopeHandler(t, f)

	d, _, isErr := checkScope(t, h, scopePerms, `{"target":"app.acme.example"}`)
	if isErr || d.Decision != scopeAllowed || d.Via == nil || d.Via.Kind == "" {
		t.Fatalf("covered target: %+v", d)
	}
	// Above the entry's tier: passive only.
	if d, _, _ := checkScope(t, h, scopePerms, `{"target":"app.acme.example","intensity":"intrusive"}`); d.Decision != scopePassiveOnly {
		t.Fatalf("intrusive on an active entry: %+v", d)
	}
	// Another tenant's entry never matches.
	d, text, _ := checkScope(t, h, scopePerms, `{"target":"www.victim.example","intensity":"passive"}`)
	if d.Decision != scopeRefused || strings.Contains(text, "victim") {
		t.Fatalf("cross-tenant: %s", text)
	}
	// An uncovered target is refused and the answer lists no entries.
	d, text, _ = checkScope(t, h, scopePerms, `{"target":"other.example.org"}`)
	if d.Decision != scopeRefused || strings.Contains(text, "acme") || !strings.Contains(text, "platform's scope decision") {
		t.Fatalf("uncovered: %s", text)
	}
	// The platform deny list answers with a code, never its contents.
	d, text, _ = checkScope(t, h, scopePerms, `{"target":"169.254.169.254"}`)
	if d.Decision != scopeRefused || len(d.Reasons) != 1 || d.Reasons[0] != scopeReasonDenied {
		t.Fatalf("deny list: %s", text)
	}
	if _, _, isErr := checkScope(t, h, scopePerms, `{"target":"x.example.com","intensity":"loud"}`); !isErr {
		t.Fatal("bad intensity accepted")
	}
	if _, _, isErr := checkScope(t, h, scopePerms, `{}`); !isErr {
		t.Fatal("missing target accepted")
	}
}

func TestCheckScope_ProgramRules(t *testing.T) {
	prog := shared.NewID()
	f := &scopeFake{targets: map[string][]*scopedom.Target{}, members: map[string][]shared.ID{}}
	f.targets[wtTenant] = []*scopedom.Target{
		scopeEntry(t, wtTenant, "*.bounty.example", scopedom.TierActive, &prog),
		scopeEntry(t, wtTenant, "*.acme.example", scopedom.TierActive, nil),
	}
	f.excl = []bountyprogram.Exclusion{{TargetType: scopedom.TargetTypeDomain, Pattern: "admin.bounty.example"}}
	h := newScopeHandler(t, f)

	// Program-only: refused without the program, even though an entry covers it.
	d, _, _ := checkScope(t, h, scopePerms, `{"target":"app.bounty.example"}`)
	if d.Decision != scopeRefused || d.Reasons[0] != scopeReasonProgramOnly {
		t.Fatalf("program-only without program: %+v", d)
	}
	args := `{"target":"app.bounty.example","program_id":"` + prog.String() + `"}`
	// Not a member: refused.
	if d, _, _ := checkScope(t, h, scopePerms, args); d.Decision != scopeRefused {
		t.Fatalf("non-member: %+v", d)
	}
	user, _ := shared.IDFromString(wtUser)
	f.members[user.String()] = []shared.ID{prog}
	if d, _, _ := checkScope(t, h, scopePerms, args); d.Decision != scopeAllowed || d.Via.Kind != "program" {
		t.Fatalf("member: %+v", d)
	}
	// A program exclusion carves a child out of the wildcard.
	ex := `{"target":"admin.bounty.example","program_id":"` + prog.String() + `"}`
	if d, _, _ := checkScope(t, h, scopePerms, ex); d.Decision != scopeRefused {
		t.Fatalf("excluded child: %+v", d)
	}
	// Another program's id does not unlock it.
	other := `{"target":"app.bounty.example","program_id":"` + shared.NewID().String() + `"}`
	if d, _, _ := checkScope(t, h, scopePerms, other); d.Decision != scopeRefused {
		t.Fatalf("other program: %+v", d)
	}
	// An ownership entry is not program-only and needs no program.
	if d, _, _ := checkScope(t, h, scopePerms, `{"target":"x.acme.example"}`); d.Decision != scopeAllowed {
		t.Fatalf("ownership entry: %+v", d)
	}
}

func TestCheckScope_LookupErrorRefuses(t *testing.T) {
	f := &scopeFake{targets: map[string][]*scopedom.Target{wtTenant: {scopeEntry(t, wtTenant, "*.acme.example", scopedom.TierActive, nil)}}}
	h := newScopeHandler(t, f)
	f.failList = errors.New("db down")
	d, text, isErr := checkScope(t, h, scopePerms, `{"target":"app.acme.example"}`)
	if isErr || d.Decision != scopeRefused || d.Reasons[0] != scopeReasonLookupFailed {
		t.Fatalf("lookup error must refuse: %s", text)
	}
	if strings.Contains(text, "db down") {
		t.Fatalf("internal error leaked: %s", text)
	}
	f.failList = nil

	// A failing program lookup refuses a program-only answer too.
	prog := shared.NewID()
	f.targets[wtTenant] = []*scopedom.Target{scopeEntry(t, wtTenant, "*.bounty.example", scopedom.TierActive, &prog)}
	f.failProg = errors.New("db down")
	if d, _, _ := checkScope(t, h, scopePerms, `{"target":"a.bounty.example","program_id":"`+prog.String()+`"}`); d.Decision != scopeRefused {
		t.Fatalf("program lookup error must refuse: %+v", d)
	}
}

func TestCheckScope_RateLimitedPerConnection(t *testing.T) {
	f := &scopeFake{targets: map[string][]*scopedom.Target{wtTenant: {scopeEntry(t, wtTenant, "*.acme.example", scopedom.TierActive, nil)}}}
	h := newScopeHandler(t, f)
	var limited scopeDecision
	for i := 0; i < mcpScopeLimitBurst+5; i++ {
		d, _, _ := checkScope(t, h, scopePerms, `{"target":"app.acme.example"}`)
		if d.Decision == scopeRefused && len(d.Reasons) > 0 && d.Reasons[0] == scopeReasonRateLimited {
			limited = d
			break
		}
		if d.Decision != scopeAllowed {
			t.Fatalf("call %d: %+v", i, d)
		}
	}
	if limited.RetryAfterSeconds < 1 {
		t.Fatal("burst was never limited")
	}
}

func TestCheckScope_AuditStoresHashedTarget(t *testing.T) {
	args := sanitizeMCPArgs(json.RawMessage(`{"target":"Secret.Acme.example","intensity":"active","program_id":"p"}`))
	got, _ := args["target"].(string)
	if !strings.HasPrefix(got, "sha256:") || strings.Contains(got, "acme") {
		t.Fatalf("target = %q", got)
	}
	if got != hashAuditTarget("secret.acme.example ") {
		t.Fatal("hash is not stable across case and spacing")
	}
	if args["intensity"] != "active" {
		t.Fatalf("intensity = %v", args["intensity"])
	}
}
