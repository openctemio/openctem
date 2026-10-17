package handler

// Suppression rules and the caller's data scope: an organization-wide rule
// acts on every asset of the tenant, and an asset-bound rule on that asset's
// findings, so a restricted member neither creates, approves nor sees what
// lies outside their scope.

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestSuppressionRule_MemberScope_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer raw.Close()
	ctx := context.Background()
	if err := raw.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := raw.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	tenant := shared.NewID().String()
	admin, scoped := shared.NewID().String(), shared.NewID().String()
	inScope, outScope := shared.NewID().String(), shared.NewID().String()
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'sup', $2)`, tenant, "sup-"+tenant)
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = raw.ExecContext(bg, `DELETE FROM suppression_rules WHERE tenant_id = $1`, tenant)
		_, _ = raw.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, tenant)
		for _, u := range []string{admin, scoped} {
			_, _ = raw.ExecContext(bg, `DELETE FROM users WHERE id = $1`, u)
		}
	})
	for _, u := range []string{admin, scoped} {
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'sup')`, u, u+"@sup.test")
	}
	for _, id := range []string{inScope, outScope} {
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'public', 'high')`,
			id, tenant, "sup-"+id+".example.com")
	}
	exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		scoped, tenant, inScope)

	db := &postgres.DB{DB: raw}
	enforcer := datascope.New(postgres.NewDataScopeRepository(db),
		func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, logger.NewNop())
	svc := suppression.NewService(postgres.NewSuppressionRepository(db), logger.NewNop())
	svc.SetAssetRefChecker(enforcer)
	svc.SetScopeFilter(enforcer.FilterForCaller)
	svc.SetScopeResolver(enforcer.Resolve)

	tid := shared.MustIDFromString(tenant)
	as := func(user string, isAdmin bool) context.Context {
		c := context.WithValue(ctx, middleware.UserIDKey, user)
		return context.WithValue(c, middleware.IsAdminKey, isAdmin)
	}
	create := func(c context.Context, user, asset string) (*suppression.Rule, error) {
		in := suppression.CreateRuleInput{
			TenantID: tid, Name: "sup " + shared.NewID().String(), SuppressionType: suppression.SuppressionTypeFalsePositive,
			ReasonCode: "detection_error", Description: "fixture rule used by tests", ToolName: "semgrep", RuleID: "go.lang.test-rule",
			RequestedBy: shared.MustIDFromString(user),
		}
		if asset != "" {
			aid := shared.MustIDFromString(asset)
			in.AssetID = &aid
		}
		return svc.CreateRule(c, in)
	}

	// Creating: an organization-wide rule needs full data access.
	if _, err := create(as(scoped, false), scoped, ""); !errors.Is(err, suppression.ErrOrgWideRuleNeedsFullScope) {
		t.Fatalf("restricted member created an organization-wide rule: %v", err)
	}
	if _, err := create(as(admin, true), admin, ""); err != nil {
		t.Fatalf("admin, organization-wide rule: %v", err)
	}
	bound, err := create(as(scoped, false), scoped, inScope)
	if err != nil {
		t.Fatalf("restricted member, in-scope rule: %v", err)
	}
	outRule, err := create(as(admin, true), admin, outScope)
	if err != nil {
		t.Fatalf("admin, out-of-scope-for-member rule: %v", err)
	}
	orgRules, err := svc.ListRules(as(admin, true), tid, suppression.RuleFilter{})
	if err != nil || len(orgRules) != 3 {
		t.Fatalf("admin lists %d rules, err %v, want 3", len(orgRules), err)
	}
	var orgRule *suppression.Rule
	for _, r := range orgRules {
		if r.AssetID() == nil {
			orgRule = r
		}
	}

	// Listing: the member does not see the rule bound to an asset outside their scope.
	all, err := svc.ListRules(as(scoped, false), tid, suppression.RuleFilter{})
	if err != nil {
		t.Fatal(err)
	}
	visible, err := svc.VisibleRules(as(scoped, false), tid, all)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[shared.ID]bool{}
	for _, r := range visible {
		seen[r.ID()] = true
	}
	if seen[outRule.ID()] || !seen[bound.ID()] || !seen[orgRule.ID()] {
		t.Errorf("member sees out-of-scope=%v in-scope=%v org-wide=%v, want false true true", seen[outRule.ID()], seen[bound.ID()], seen[orgRule.ID()])
	}

	// By id: the out-of-scope rule does not exist for the member; the
	// organization-wide rule is readable but cannot be approved or changed.
	if _, err := svc.GetRule(as(scoped, false), tid, outRule.ID()); !errors.Is(err, suppression.ErrRuleNotFound) {
		t.Errorf("member read an out-of-scope rule: %v", err)
	}
	if _, err := svc.GetRule(as(scoped, false), tid, orgRule.ID()); err != nil {
		t.Errorf("member cannot read an organization-wide rule: %v", err)
	}
	approve := func(c context.Context, user string, r *suppression.Rule) error {
		fresh, err := svc.GetRule(as(admin, true), tid, r.ID())
		if err != nil {
			t.Fatal(err)
		}
		at := fresh.UpdatedAt()
		_, err = svc.ApproveRule(c, suppression.ApproveRuleInput{TenantID: tid, RuleID: r.ID(), ApprovedBy: shared.MustIDFromString(user), ReviewedUpdatedAt: &at})
		return err
	}
	if err := approve(as(scoped, false), scoped, outRule); !errors.Is(err, suppression.ErrRuleNotFound) {
		t.Errorf("member approved a rule bound to an asset outside their scope: %v", err)
	}
	if err := approve(as(scoped, false), scoped, orgRule); !errors.Is(err, suppression.ErrOrgWideRuleNeedsFullScope) {
		t.Errorf("member approved an organization-wide rule: %v", err)
	}
	name := "renamed"
	if _, err := svc.UpdateRule(as(scoped, false), suppression.UpdateRuleInput{TenantID: tid, RuleID: orgRule.ID(), Name: &name, UpdatedBy: shared.MustIDFromString(scoped)}); !errors.Is(err, suppression.ErrOrgWideRuleNeedsFullScope) {
		t.Errorf("member edited an organization-wide rule: %v", err)
	}
	if err := svc.DeleteRule(as(scoped, false), tid, orgRule.ID(), shared.MustIDFromString(scoped)); !errors.Is(err, suppression.ErrOrgWideRuleNeedsFullScope) {
		t.Errorf("member deleted an organization-wide rule: %v", err)
	}
	// A different person with full access approves both.
	if err := approve(as(admin, true), admin, bound); err != nil {
		t.Errorf("admin approves the member's in-scope rule: %v", err)
	}
	if err := approve(as(admin, true), admin, outRule); err != nil {
		// requested by the same admin: the four-eyes rule decides, not the scope
		if !errors.Is(err, suppression.ErrSelfApproval) {
			t.Errorf("admin approves an out-of-scope-for-member rule: %v", err)
		}
	}
}
