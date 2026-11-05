package taggov

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/accesscontrol"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tag"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

var (
	reqApproval = Requirement{Rule: RuleScanApproval, AdminOnly: true}
	reqScope    = Requirement{Rule: RuleAccessScope, Permission: "team:groups:write"}
)

func TestSetRequirements(t *testing.T) {
	s := NewSet([]Ref{{"Production", reqApproval}, {"env:prod", reqScope}, {" ", reqScope}})
	if !s.Protected("production") || !s.Protected("PRODUCTION") {
		t.Error("an exact governing tag is protected without case")
	}
	if s.Protected("prod") {
		t.Error("a different tag is not protected")
	}
	if !s.Protected("env:staging") {
		t.Error("a governing key:value tag governs its whole key")
	}
	if s.Protected("envx:prod") || s.Protected("team:payments") {
		t.Error("another key is not protected")
	}
}

func TestChangesAndAllowed(t *testing.T) {
	s := NewSet([]Ref{{"production", reqApproval}, {"team:pay", reqScope}})
	added, removed := Diff([]string{"production", "x"}, []string{"x", "team:pay", "y"})
	ch := s.Changes(added, removed)
	if len(ch) != 2 {
		t.Fatalf("removing production and adding team:pay are governed: %+v", ch)
	}
	none := func(string) bool { return false }
	groups := func(p string) bool { return p == "team:groups:write" }
	if Allowed(ch, none, false) {
		t.Error("assets:write alone must not change a governing tag")
	}
	if Allowed(ch, groups, false) {
		t.Error("the approval rule tag needs an administrator")
	}
	if !Allowed(ch, groups, true) {
		t.Error("an administrator holding the permission may")
	}
	if !Allowed(s.Changes([]string{"free"}, nil), none, false) {
		t.Error("an ungoverned tag needs nothing more")
	}
}

type src struct {
	refs  []Ref
	err   error
	calls *int
}

func (s src) Refs(context.Context, shared.ID) ([]Ref, error) {
	*s.calls++
	return s.refs, s.err
}

func TestGovernorCachesPerTenantAndFailsClosed(t *testing.T) {
	calls := 0
	g := NewGovernor(time.Minute, src{refs: []Ref{{"a", reqScope}}, calls: &calls})
	t1, t2 := shared.NewID(), shared.NewID()
	for i := 0; i < 3; i++ {
		if s, err := g.For(context.Background(), t1); err != nil || !s.Protected("a") {
			t.Fatal("tenant 1 set", err)
		}
	}
	if calls != 1 {
		t.Errorf("cached: calls=%d", calls)
	}
	g.For(context.Background(), t2)
	if calls != 2 {
		t.Error("the cache is per tenant")
	}
	g.Invalidate(t1)
	g.For(context.Background(), t1)
	if calls != 3 {
		t.Error("invalidate refreshes")
	}

	boom := errors.New("db down")
	bad := NewGovernor(time.Minute, src{err: boom, calls: &calls})
	s, err := bad.For(context.Background(), t1)
	allow := ImportAllow(s, err)
	if r, ok := allow("harmless"); ok || r != tag.ReasonProtected {
		t.Error("an import fails closed when the governing set is unknown")
	}
}

func TestImportAllowDropsGoverningTags(t *testing.T) {
	s := NewSet([]Ref{{"env:prod", reqScope}, {"production", reqApproval}})
	in := []string{"env:prod", "env:dev", "Production", "team:ok", "free"}
	kept, dropped := tag.FilterImport(in, ImportAllow(s, nil))
	if len(kept) != 2 || kept[0] != "team:ok" || kept[1] != "free" || dropped[tag.ReasonProtected] != 3 {
		t.Fatalf("kept %v dropped %v", kept, dropped)
	}
}

type fakeAC struct {
	scope  []*accesscontrol.ScopeRule
	assign []*accesscontrol.AssignmentRule
}

func (f fakeAC) ListActiveScopeRulesByTenant(context.Context, shared.ID) ([]*accesscontrol.ScopeRule, error) {
	return f.scope, nil
}
func (f fakeAC) ListActiveRulesByPriority(context.Context, shared.ID) ([]*accesscontrol.AssignmentRule, error) {
	return f.assign, nil
}

type fakeSettings struct {
	st *tenant.ScanGovernanceSettings
}

func (f fakeSettings) GetScanGovernanceSettings(context.Context, string) (*tenant.ScanGovernanceSettings, error) {
	return f.st, nil
}

// Every kind of rule that reads an asset tag feeds the governing set with
// the permission that edits that kind of rule.
func TestSourcesCoverEveryRuleKind(t *testing.T) {
	tid, gid := shared.NewID(), shared.NewID()
	ar, err := accesscontrol.NewAssignmentRule(tid, "r", accesscontrol.AssignmentConditions{AssetTags: []string{"team:routing"}}, gid, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tagRule := accesscontrol.ReconstituteScopeRule(shared.NewID(), tid, gid, "s", "", accesscontrol.ScopeRuleTagMatch,
		[]string{"team:access"}, accesscontrol.MatchLogicAny, nil, accesscontrol.OwnershipSecondary, 10, true, now, now, nil)
	groupRule := accesscontrol.ReconstituteScopeRule(shared.NewID(), tid, gid, "g", "", accesscontrol.ScopeRuleAssetGroupMatch,
		nil, accesscontrol.MatchLogicAny, []shared.ID{shared.NewID()}, accesscontrol.OwnershipSecondary, 10, true, now, now, nil)
	st := &tenant.ScanGovernanceSettings{Rules: []scangov.Rule{
		{Name: "on", Enabled: true, Conditions: scangov.Conditions{AssetTags: []string{"production"}}},
		{Name: "off", Enabled: false, Conditions: scangov.Conditions{AssetTags: []string{"disabled-rule-tag"}}},
	}}
	ac := fakeAC{scope: []*accesscontrol.ScopeRule{tagRule, groupRule}, assign: []*accesscontrol.AssignmentRule{ar}}
	g := NewGovernor(time.Minute, ScopeRuleSource(ac), AssignmentRuleSource(ac), ApprovalRuleSource(fakeSettings{st}))
	set, err := g.For(context.Background(), tid)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Requirement{
		"team:access":  {Rule: RuleAccessScope, Permission: "team:groups:write"},
		"team:routing": {Rule: RuleAssignmentRule, Permission: "team:assignment_rules:write"},
		"production":   {Rule: RuleScanApproval, AdminOnly: true},
	}
	for tg, r := range want {
		got := set.exact[tg]
		if len(got) != 1 || got[0] != r {
			t.Errorf("%s: got %+v want %+v", tg, got, r)
		}
	}
	if set.Protected("disabled-rule-tag") {
		t.Error("a disabled rule governs nothing")
	}
}

// A change of case is a remove plus an add: "Env:Prod" for "env:prod" is not
// "no change" (a rule matches the exact string), so it is checked like any
// other change of a governing tag.
func TestDiffIsExact(t *testing.T) {
	added, removed := Diff([]string{"env:prod", "keep"}, []string{"Env:Prod", "keep"})
	if len(added) != 1 || added[0] != "Env:Prod" || len(removed) != 1 || removed[0] != "env:prod" {
		t.Fatalf("added %v removed %v", added, removed)
	}
	if a, r := Diff([]string{"a", "b"}, []string{"b", "a"}); len(a)+len(r) != 0 {
		t.Fatalf("order is not a change: %v %v", a, r)
	}
}
