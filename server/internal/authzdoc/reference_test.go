package authzdoc

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func buildRef(t *testing.T) *Reference {
	t.Helper()
	ref, err := Build(apiRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

// Every route belongs to exactly one feature, every listed register function
// still registers routes, and every route says how it is authorized: a gate,
// or the coverage allowlist's reason for having none. CI runs this, so a new
// route without a classification fails the build.
func TestEveryRouteIsClassified(t *testing.T) {
	ref := buildRef(t) // Build fails on a route in no feature.
	routes, err := ParseRoutes(apiRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{}
	for _, r := range routes {
		used[r.Register] = true
	}
	listed := map[string]string{}
	for _, f := range Features {
		for _, reg := range f.Registers {
			if prev, dup := listed[reg]; dup {
				t.Errorf("%s is listed in features %s and %s", reg, prev, f.ID)
			}
			listed[reg] = f.ID
			if !used[reg] {
				t.Errorf("feature %s lists %s, which registers no route (remove it)", f.ID, reg)
			}
		}
	}
	for _, f := range ref.Features {
		if len(f.Routes) == 0 {
			t.Errorf("feature %s has no route", f.ID)
		}
		for _, r := range f.Routes {
			if !r.Gate.Gated() && r.Ungated == "" {
				t.Errorf("%s %s has no permission gate and no allowlist reason", r.Method, r.Path)
			}
			if r.DataSurface.Class == "" {
				t.Errorf("%s %s has no data-scope class", r.Method, r.Path)
			}
			if r.Gate.Gated() && len(r.Gate.Other) == 0 && !slices.Contains(r.Roles, "owner") {
				t.Errorf("%s %s: not even the owner passes the gate %+v", r.Method, r.Path, r.Gate)
			}
		}
	}
}

// Personas and teams name roles and teams that exist.
func TestPersonasAndTeamsAreConsistent(t *testing.T) {
	ref := buildRef(t)
	roles := map[string]bool{}
	for _, r := range ref.Roles {
		roles[r.ID] = true
	}
	known := func(id string) bool { _, pending := pendingRoles[id]; return roles[id] || pending }
	teams := map[string]bool{}
	for _, tp := range TeamPatterns {
		if teams[tp.ID] {
			t.Errorf("duplicate team pattern %s", tp.ID)
		}
		teams[tp.ID] = true
		for _, r := range tp.Roles {
			if !known(r) {
				t.Errorf("team %s names unknown role %s", tp.ID, r)
			}
		}
	}
	seen := map[string]bool{}
	for _, p := range Personas {
		if seen[p.ID] {
			t.Errorf("duplicate persona %s", p.ID)
		}
		seen[p.ID] = true
		for _, r := range p.Roles {
			if !known(r) {
				t.Errorf("persona %s names unknown role %s", p.ID, r)
			}
		}
		if p.Team != "" && !teams[p.Team] {
			t.Errorf("persona %s names unknown team %s", p.ID, p.Team)
		}
		if p.DataScope == "" || p.Access == "" || p.Goal == "" {
			t.Errorf("persona %s needs a goal, a data scope and an access rule", p.ID)
		}
	}
}

// A pending role disappears from pendingRoles once it is a real built-in role.
func TestPendingRolesAreNotYetBuiltIn(t *testing.T) {
	for _, r := range Roles() {
		if _, ok := pendingRoles[r.ID]; ok {
			t.Errorf("%s is now a built-in role: remove it from pendingRoles", r.ID)
		}
	}
}

// Who passes a gate follows the permissions, with the admin bypass.
func TestRolePasses(t *testing.T) {
	ref := buildRef(t)
	role := func(id string) RoleInfo {
		for _, r := range ref.Roles {
			if r.ID == id {
				return r
			}
		}
		t.Fatalf("no role %s", id)
		return RoleInfo{}
	}
	fix := Gate{Permissions: []string{"findings:fix_apply"}}
	verify := Gate{Permissions: []string{"findings:verify"}}
	if !role("remediation-owner").Passes(fix) || role("remediation-owner").Passes(verify) {
		t.Error("remediation owner: fix yes, verify no")
	}
	if role("viewer").Passes(Gate{Permissions: []string{"findings:write"}}) {
		t.Error("viewer passes findings:write")
	}
	if !role("admin").Passes(Gate{Permissions: []string{"team:delete"}}) {
		t.Error("admin bypass")
	}
	if role("admin").Passes(Gate{Permissions: []string{"team:delete"}, MinRole: "owner"}) {
		t.Error("admin passes an owner-only route")
	}
	if role("program-lead").Passes(Gate{MinRole: "admin"}) {
		t.Error("a template passes a team-admin route")
	}
	if !role("auditor").Passes(Gate{AnyOf: [][]string{{"audit:read", "settings:write"}}}) {
		t.Error("any-of")
	}
}

// The outputs render: valid JSON, one page per feature plus the index, the
// matrix and the personas page, front matter only when asked.
func TestRender(t *testing.T) {
	ref := buildRef(t)
	b, err := ref.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var back Reference
	if err := json.Unmarshal(b, &back); err != nil || len(back.Features) != len(Features) {
		t.Fatalf("JSON round trip: %v", err)
	}
	plain := ref.Markdown(MarkdownOptions{})
	if len(plain) != len(Features)+3 {
		t.Fatalf("%d pages", len(plain))
	}
	for _, p := range plain {
		if strings.HasPrefix(string(p.Content), "---") {
			t.Errorf("%s has front matter without the option", p.Path)
		}
	}
	for _, p := range ref.Markdown(MarkdownOptions{FrontMatter: true}) {
		if !strings.HasPrefix(string(p.Content), "---\ntitle: ") {
			t.Errorf("%s lacks front matter", p.Path)
		}
	}
}
