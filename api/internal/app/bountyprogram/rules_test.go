package bountyprogram

import (
	"context"
	"errors"
	"testing"
	"time"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ruleTargets is the tenant's scope as scopeauth reads it: active entries
// and every program exclusion, from the fake repository.
type ruleTargets struct{ repo *fakeRepo }

func (r ruleTargets) ListActiveTargets(_ context.Context, tenantID string) ([]*scopedom.Target, error) {
	var out []*scopedom.Target
	for _, e := range r.repo.entries {
		if e.TenantID().String() == tenantID && e.IsActive() {
			out = append(out, e)
		}
	}
	return out, nil
}

func (r ruleTargets) ListProgramExclusions(ctx context.Context, tenantID shared.ID) ([]bp.Exclusion, error) {
	return r.repo.Exclusions(ctx, tenantID, nil)
}

func importProgram(t *testing.T, svc *Service, tenant, user shared.ID, name, paste string, rules bp.Rules) *bp.Program {
	t.Helper()
	ctx := context.Background()
	in := Input{Name: name, Platform: "self", Handle: "jdoe", ProgramURL: "https://" + name + ".example/security",
		ScopeText: paste, Rules: rules}
	pv, err := svc.Preview(ctx, tenant, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	in.AcceptTermsSHA256 = pv.TermsSHA256
	p, _, err := svc.Import(ctx, tenant, user, in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestJobRules(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	tenant, other, user := shared.NewID(), shared.NewID(), shared.NewID()
	svc := NewService(repo, fullData(true), nil)
	svc.SetRuleScope(ruleTargets{repo})

	mon10, _ := time.Parse(time.RFC3339, "2026-10-05T10:00:00Z")
	importProgram(t, svc, tenant, user, "acme", "*.acme.example\n-admin.acme.example\n", bp.Rules{RateLimitRPS: 5,
		RequiredHeaders: []bp.Header{{Name: "X-Bug-Bounty", Value: "jdoe"}}, UserAgent: "jdoe-research",
		TestingWindows: []bp.TestingWindow{{Days: []string{"mon"}, Start: "08:00", End: "12:00", Timezone: "UTC"}}})
	importProgram(t, svc, tenant, user, "shop", "shop.acme.example\nstore.example\n", bp.Rules{RateLimitRPS: 2,
		RequiredHeaders: []bp.Header{{Name: "X-Bug-Bounty", Value: "jdoe"}}})
	importProgram(t, svc, tenant, user, "rival", "rival.example\n", bp.Rules{UserAgent: "someone-else"})

	// No program covers the target: no rule.
	if r, err := svc.JobRules(ctx, tenant, []string{"owned.example.org"}, mon10); r != nil || err != nil {
		t.Fatalf("uncovered: %+v %v", r, err)
	}
	// A program exclusion keeps its name out of the program.
	if r, err := svc.JobRules(ctx, tenant, []string{"admin.acme.example"}, mon10); r != nil || err != nil {
		t.Fatalf("excluded: %+v %v", r, err)
	}
	// One program, a URL target.
	r, err := svc.JobRules(ctx, tenant, []string{"https://app.acme.example/login"}, mon10)
	if err != nil || r == nil || r.RateLimit != 5 || r.UserAgent != "jdoe-research" || r.Headers["X-Bug-Bounty"] != "jdoe" {
		t.Fatalf("acme: %+v %v", r, err)
	}
	// Two programs cover one name: compatible rules merge, the lower rate wins.
	r, err = svc.JobRules(ctx, tenant, []string{"shop.acme.example"}, mon10)
	if err != nil || r.RateLimit != 2 || len(r.Programs) != 2 {
		t.Fatalf("acme+shop: %+v %v", r, err)
	}
	// Outside acme's window.
	if _, err := svc.JobRules(ctx, tenant, []string{"app.acme.example"}, mon10.Add(4*time.Hour)); !errors.Is(err, bp.ErrOutsideWindow) {
		t.Fatalf("outside window: %v", err)
	}
	// shop has no window: any time.
	if _, err := svc.JobRules(ctx, tenant, []string{"store.example"}, mon10.Add(4*time.Hour)); err != nil {
		t.Fatalf("no window: %v", err)
	}
	// Two User-Agents in one job.
	if _, err := svc.JobRules(ctx, tenant, []string{"app.acme.example", "rival.example"}, mon10); !errors.Is(err, bp.ErrRulesConflict) {
		t.Fatalf("conflict: %v", err)
	}
	// Another tenant's programs never apply.
	if r, err := svc.JobRules(ctx, other, []string{"app.acme.example"}, mon10); r != nil || err != nil {
		t.Fatalf("other tenant: %+v %v", r, err)
	}
	// A suspended program's entries are not in effect.
	for _, p := range repo.programs {
		if p.Name == "rival" {
			_ = repo.SetStatus(ctx, p, scopedom.StatusInactive)
		}
	}
	if r, err := svc.JobRules(ctx, tenant, []string{"rival.example"}, mon10); r != nil || err != nil {
		t.Fatalf("suspended: %+v %v", r, err)
	}
	// Not wired: fail closed.
	if _, err := NewService(repo, fullData(true), nil).JobRules(ctx, tenant, []string{"x"}, mon10); err == nil {
		t.Fatal("an unwired rule scope must not answer no rules")
	}
}
