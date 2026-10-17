package integration

// The dry run for CI trusts and scope on a real database: it writes nothing
// (even on a read-only connection), counts what turning "Trust and add to
// scope" on would do for trusts saved before it existed, and what trusts
// that manage scope would change. Nothing is applied automatically: an
// administrator turns it on per trust, through the audited trust change.

import (
	"context"
	"database/sql"
	"net/url"
	"testing"
	"time"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// legacyTrust saves a trust the way it was before trusts managed scope:
// manage_scope off, no links, no entries.
func (r *ciScopeRig) legacyTrust(tenantID shared.ID, owners ...string) *cirun.TrustConfig {
	r.t.Helper()
	now := time.Now().UTC()
	c := &cirun.TrustConfig{ID: shared.NewID(), TenantID: tenantID, Name: "legacy-" + shared.NewID().String()[28:],
		Provider: cirun.ProviderGitLab, Issuer: r.idp.srv.URL, Rules: cirun.Rules{Owners: owners}, Enabled: true,
		CreatedAt: now, UpdatedAt: now}
	c.Normalize()
	if err := c.Validate(); err != nil {
		r.t.Fatal(err)
	}
	if err := r.repo.CreateTrustConfig(context.Background(), c); err != nil {
		r.t.Fatal(err)
	}
	return c
}

func (r *ciScopeRig) scopeRows(tenantID shared.ID) int {
	r.t.Helper()
	var n int
	if err := r.db.QueryRowContext(context.Background(), `SELECT
		(SELECT count(*) FROM scope_targets WHERE tenant_id = $1) + (SELECT count(*) FROM scope_target_ci_trusts WHERE tenant_id = $1)`,
		tenantID.String()).Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

func planFor(reps []cirunapp.ScopePlanTenant, id shared.ID) *cirunapp.ScopePlanTenant {
	for i := range reps {
		if reps[i].TenantID.Equals(id) {
			return &reps[i]
		}
	}
	return nil
}

func TestCITrustScopePlan(t *testing.T) {
	r := newCIScopeRig(t)
	ctx := context.Background()
	// Tenant A: one trust that manages scope, two legacy trusts, one of
	// whose namespaces is already in scope by hand.
	r.scopeTrust(r.tenant, cirun.Rules{Owners: []string{"gamma"}})
	if _, err := r.scope.CreateTarget(ctx, scopeapp.CreateTargetInput{TenantID: r.tenant.String(), TargetType: "repository",
		Pattern: r.host + "/beta/*"}); err != nil {
		t.Fatal(err)
	}
	acme := r.legacyTrust(r.tenant, "acme")
	r.legacyTrust(r.tenant, "beta")
	// Tenant B: one legacy trust.
	r.legacyTrust(r.other, "acme")
	beforeA, beforeB := r.scopeRows(r.tenant), r.scopeRows(r.other)

	// Nothing is created for a legacy trust on its own: no start-up job, and
	// a run links but never creates.
	if code, _ := r.exchange(r.tenant, r.idp.token(t, acme.Audience, "acme/api", "main", "3333333333333333333333333333333333333333", nil)); code != 201 {
		t.Fatalf("exchange: %d", code)
	}
	if r.entry(r.tenant, r.host+"/acme/*") != nil {
		t.Fatal("a legacy trust got an entry without an administrator")
	}

	// The dry run, on a read-only connection like the command's.
	ro := readOnlyDB(t)
	planner := cirunapp.NewService(cirunapp.Deps{Repo: postgres.NewCIRunRepository(ro)}, cirunapp.Config{}, logger.NewNop())
	roScope := scopeapp.NewService(postgres.NewScopeTargetRepository(ro), postgres.NewScopeExclusionRepository(ro),
		postgres.NewAssetRepository(ro), logger.NewNop())
	roScope.SetCITrustLinks(postgres.NewScopeCITrustLinkRepository(ro))
	planner.SetScopeLinker(roScope)
	plan, err := planner.PlanScope(ctx, []shared.ID{r.tenant, r.other})
	if err != nil {
		t.Fatal(err)
	}
	a, b := planFor(plan, r.tenant), planFor(plan, r.other)
	if a == nil || a.Trusts != 3 || a.ManagedTrusts != 1 || a.AdoptableTrust != 2 || a.Managed[scopedom.CITrustKept] != 1 ||
		a.Adoptable[scopedom.CITrustCreated] != 1 || a.Adoptable[scopedom.CITrustLinked] != 1 {
		t.Fatalf("plan for A: %+v", a)
	}
	if b == nil || b.AdoptableTrust != 1 || b.Adoptable[scopedom.CITrustCreated] != 1 {
		t.Fatalf("plan for B: %+v", b)
	}
	if r.scopeRows(r.tenant) != beforeA || r.scopeRows(r.other) != beforeB {
		t.Fatal("the dry run wrote")
	}

	// An administrator turns it on for one trust: audited, as them.
	on := true
	if _, err := r.svc.UpdateTrustConfig(ctx, r.tenant, acme.ID, cirunapp.TrustConfigInput{Name: acme.Name, Provider: "gitlab",
		Issuer: acme.Issuer, Audience: acme.Audience, Rules: acme.Rules, ManageScope: &on}, r.admin); err != nil {
		t.Fatal(err)
	}
	if e := r.entry(r.tenant, r.host+"/acme/*"); e == nil || e.Status() != scopedom.StatusActive {
		t.Fatalf("after turning it on: %+v", e)
	}
	if r.scopeRows(r.other) != beforeB {
		t.Fatal("turning it on in A touched B")
	}
	plan, err = planner.PlanScope(ctx, []shared.ID{r.tenant})
	if err != nil {
		t.Fatal(err)
	}
	if pa := planFor(plan, r.tenant); pa == nil || pa.ManagedTrusts != 2 || pa.Managed[scopedom.CITrustKept] != 2 || pa.AdoptableTrust != 1 {
		t.Fatalf("plan after turning it on: %+v", plan)
	}
}

// readOnlyDB opens the test database with every transaction read-only.
func readOnlyDB(t *testing.T) *postgres.DB {
	t.Helper()
	u, err := url.Parse(testdb.URL())
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("default_transaction_read_only", "on")
	u.RawQuery = q.Encode()
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &postgres.DB{DB: db}
}
