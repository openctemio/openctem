package actscope

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// programTargets adds program exclusions to tenantTargets.
type programTargets struct {
	tenantTargets
	excl []bountyprogram.Exclusion
}

func (p programTargets) ListProgramExclusions(context.Context, shared.ID) ([]bountyprogram.Exclusion, error) {
	return p.excl, nil
}

type members map[shared.ID][]shared.ID // user -> programs

func (m members) MemberProgramIDs(_ context.Context, _ shared.ID, user shared.ID) ([]shared.ID, error) {
	return m[user], nil
}

type actingAs string

func (a actingAs) CallerUserID(context.Context) string { return string(a) }

type failingMembers struct{}

func (failingMembers) MemberProgramIDs(context.Context, shared.ID, shared.ID) ([]shared.ID, error) {
	return nil, errors.New("db down")
}

// A restricted member may scan typed targets their own programs cover
// (RFC-065 §7), never another program's, never the organization's own
// scope, never a program exclusion.
func TestCheck_ProgramMembers(t *testing.T) {
	ctx := context.Background()
	tenant := shared.NewID()
	acme, beta := shared.NewID(), shared.NewID()
	entry := func(pattern string, program *shared.ID) *scopedom.Target {
		e, err := scopedom.NewTarget(tenant, scopedom.TargetTypeDomain, pattern, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if program != nil {
			if err := e.SetAuthorization(scopedom.AuthProgram, program); err != nil {
				t.Fatal(err)
			}
		}
		return e
	}
	targets := programTargets{
		tenantTargets: tenantTargets{tenant.String(): {
			entry("*.acme.example", &acme), entry("*.beta.example", &beta), entry("*.corp.example", nil),
		}},
		excl: []bountyprogram.Exclusion{{TenantID: tenant, ProgramID: acme, TargetType: scopedom.TargetTypeDomain, Pattern: "admin.acme.example"}},
	}
	alice := shared.NewID()
	c := New(&fakeEnforcer{}, tenantAssets{}, targets, tenantRoots{}).
		SetPrograms(members{alice: {acme}}, actingAs(alice.String()))

	d, err := c.Check(ctx, Input{TenantID: tenant, Targets: []string{
		"www.acme.example", "https://shop.acme.example/x", "admin.acme.example", "www.beta.example", "intranet.corp.example",
	}})
	if err != nil {
		t.Fatal(err)
	}
	for target, refused := range map[string]bool{
		"www.acme.example":            false,
		"https://shop.acme.example/x": false,
		"admin.acme.example":          true, // out of scope for the program
		"www.beta.example":            true, // another program
		"intranet.corp.example":       true, // the organization's own scope
	} {
		if _, got := d.RefusedTargets[target]; got != refused {
			t.Errorf("%s: refused=%v, want %v", target, got, refused)
		}
	}

	// Someone in no program, or a checker without programs, gets nothing.
	bob := shared.NewID()
	for _, chk := range []*Checker{
		New(&fakeEnforcer{}, tenantAssets{}, targets, tenantRoots{}).SetPrograms(members{alice: {acme}}, actingAs(bob.String())),
		New(&fakeEnforcer{}, tenantAssets{}, targets, tenantRoots{}),
	} {
		d, err := chk.Check(ctx, Input{TenantID: tenant, Targets: []string{"www.acme.example"}})
		if err != nil || d.RefusedTargets["www.acme.example"] != ReasonNotAnAsset {
			t.Errorf("not a member: %v %v", d, err)
		}
	}

	// A scheduled run acts as its owner.
	d, err = New(&fakeEnforcer{}, tenantAssets{}, targets, tenantRoots{}).
		SetPrograms(members{alice: {acme}}, actingAs("")).
		Check(ctx, Input{TenantID: tenant, FallbackUser: &alice, Targets: []string{"www.acme.example"}})
	if err != nil || d.Refused() {
		t.Errorf("fallback user: %v %v", d, err)
	}

	// A failed membership lookup refuses the check.
	if _, err := New(&fakeEnforcer{}, tenantAssets{}, targets, tenantRoots{}).
		SetPrograms(failingMembers{}, actingAs(alice.String())).
		Check(ctx, Input{TenantID: tenant, Targets: []string{"www.acme.example"}}); err == nil {
		t.Error("a failed lookup must refuse")
	}
}
