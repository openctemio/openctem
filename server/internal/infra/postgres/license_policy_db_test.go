package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/lib/pq"

	licapp "github.com/openctemio/openctem/api/internal/app/licensepolicy"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/licensepolicy"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type licenseFixture struct {
	t      *testing.T
	db     *sql.DB
	tenant shared.ID
	other  shared.ID
	a1, a2 shared.ID
	b1     shared.ID
	suffix string
}

func newLicenseFixture(t *testing.T) *licenseFixture {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		testdb.Skipf(t, "DATABASE_URL not set; skipping license policy DB test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	f := &licenseFixture{t: t, db: db, tenant: shared.NewID(), other: shared.NewID(), a1: shared.NewID(), a2: shared.NewID(),
		b1: shared.NewID(), suffix: shared.NewID().String()[:8]}
	for _, tid := range []shared.ID{f.tenant, f.other} {
		mustExec(t, db, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tid.String(), "lic-"+tid.String())
		tid := tid
		t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, tid.String()) })
	}
	for asset, tenant := range map[shared.ID]shared.ID{f.a1: f.tenant, f.a2: f.tenant, f.b1: f.other} {
		mustExec(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'repository')`,
			asset.String(), tenant.String(), "lic-"+asset.String())
	}
	return f
}

// link records that asset uses a package with these licenses in a scope.
func (f *licenseFixture) link(tenant, asset shared.ID, name, version, scope string, licenses ...string) string {
	f.t.Helper()
	product, ver := testdb.SeedPackageVersion(f.t, f.db, tenant.String(), "pkg:npm/"+name+f.suffix+"@"+version)
	id := testdb.SeedPackageLink(f.t, f.db, tenant.String(), asset.String(), product, ver, "package-lock.json", "direct")
	var dep any
	if scope != "" {
		dep = scope
	}
	if licenses == nil {
		licenses = []string{}
	}
	mustExec(f.t, f.db, `UPDATE asset_software SET licenses = $2, dep_scope = $3 WHERE id = $1`, id, pq.Array(licenses), dep)
	return id
}

func (f *licenseFixture) setPolicy(tenant shared.ID, p licensepolicy.Policy) {
	f.t.Helper()
	raw, _ := json.Marshal(p)
	mustExec(f.t, f.db, `UPDATE tenants SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), '{license_policy}', $2::jsonb) WHERE id = $1`,
		tenant.String(), string(raw))
}

func (f *licenseFixture) verdict(linkID string) (string, string) {
	f.t.Helper()
	var v, r sql.NullString
	if err := f.db.QueryRow(`SELECT license_verdict, license_rule FROM asset_software WHERE id = $1`, linkID).Scan(&v, &r); err != nil {
		f.t.Fatal(err)
	}
	return v.String, r.String
}

// findings returns status and severity of the license findings on an asset.
func (f *licenseFixture) findings(tenant, asset shared.ID) map[string][2]string {
	f.t.Helper()
	rows, err := f.db.Query(`SELECT title, status, severity FROM findings
		WHERE tenant_id = $1 AND asset_id = $2 AND finding_type = 'license' AND tool_name = 'license-policy'`, tenant.String(), asset.String())
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string][2]string{}
	for rows.Next() {
		var title, status, sev string
		if err := rows.Scan(&title, &status, &sev); err != nil {
			f.t.Fatal(err)
		}
		out[title] = [2]string{status, sev}
	}
	if err := rows.Err(); err != nil {
		f.t.Fatal(err)
	}
	return out
}

func TestLicensePolicy_DB(t *testing.T) {
	f := newLicenseFixture(t)
	ctx := context.Background()
	db := &DB{DB: f.db}
	svc := licapp.NewService(NewLicensePolicyRepository(db), NewFindingRepository(db), NewTenantRepository(db), nil)

	mit := f.link(f.tenant, f.a1, "lp-mit", "1.0.0", "", "MIT")
	gpl := f.link(f.tenant, f.a1, "lp-gpl", "2.0.0", "runtime", "GPL-3.0-only")
	gplTest := f.link(f.tenant, f.a2, "lp-gpl", "2.0.0", "test", "GPL-3.0-only")
	dual := f.link(f.tenant, f.a1, "lp-dual", "3.0.0", "", "MIT OR GPL-3.0-only")
	custom := f.link(f.tenant, f.a2, "lp-custom", "1.0.0", "", "Custom License")
	foreign := f.link(f.other, f.b1, "lp-gpl", "2.0.0", "", "GPL-3.0-only")

	policy := licensepolicy.Policy{Enabled: true, Unknown: licensepolicy.ActionReview, Rules: []licensepolicy.Rule{
		{Match: "category:copyleft", Action: licensepolicy.ActionAllow, Scopes: []string{"test"}},
		{Match: "category:copyleft", Action: licensepolicy.ActionDeny},
	}}
	f.setPolicy(f.tenant, policy)
	// The other tenant denies nothing; its links must stay untouched anyway.
	res, err := svc.EvaluateTenant(ctx, f.tenant)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	for link, want := range map[string][2]string{
		mit: {"allow", "default"}, gpl: {"deny", "category:copyleft"}, gplTest: {"allow", "category:copyleft"},
		dual: {"allow", "default"}, custom: {"review", "unknown"},
	} {
		if v, r := f.verdict(link); v != want[0] || r != want[1] {
			t.Errorf("link %s: %s by %s, want %s by %s", link, v, r, want[0], want[1])
		}
	}
	if v, _ := f.verdict(foreign); v != "" {
		t.Errorf("another tenant's link was evaluated: %q", v)
	}
	if res.Created != 1 {
		t.Errorf("one deny finding expected: %+v", res)
	}
	a1 := f.findings(f.tenant, f.a1)
	if len(a1) != 1 {
		t.Fatalf("a1 findings: %v", a1)
	}
	for _, st := range a1 {
		if st[0] != "new" || st[1] != "high" {
			t.Errorf("deny finding: %v", st)
		}
	}
	if len(f.findings(f.tenant, f.a2)) != 0 || len(f.findings(f.other, f.b1)) != 0 {
		t.Error("review without opt-in, allowed test scope and other tenant open nothing")
	}
	// Re-evaluating changes nothing.
	if res, err := svc.EvaluateTenant(ctx, f.tenant); err != nil || res.Created != 0 || res.LinksUpdated != 0 {
		t.Errorf("idempotent: %+v %v", res, err)
	}

	// Review findings opt-in: the unknown license opens a medium finding.
	policy.ReviewFindings = true
	f.setPolicy(f.tenant, policy)
	if _, err := svc.EvaluateTenant(ctx, f.tenant); err != nil {
		t.Fatal(err)
	}
	a2 := f.findings(f.tenant, f.a2)
	if len(a2) != 1 {
		t.Fatalf("a2 review finding: %v", a2)
	}
	for _, st := range a2 {
		if st[1] != "medium" {
			t.Errorf("review severity: %v", st)
		}
	}

	// The policy allows GPL-3.0-only: the deny finding resolves; denied
	// again, it reopens.
	allowGPL := policy
	allowGPL.Rules = append([]licensepolicy.Rule{{Match: "GPL-3.0-only", Action: licensepolicy.ActionAllow}}, policy.Rules...)
	f.setPolicy(f.tenant, allowGPL)
	if res, err := svc.EvaluateTenant(ctx, f.tenant); err != nil || res.Resolved != 1 {
		t.Fatalf("resolve on allow: %+v %v", res, err)
	}
	for _, st := range f.findings(f.tenant, f.a1) {
		if st[0] != "resolved" {
			t.Errorf("after allow: %v", st)
		}
	}
	f.setPolicy(f.tenant, policy)
	if res, err := svc.EvaluateTenant(ctx, f.tenant); err != nil || res.Reopened != 1 {
		t.Fatalf("reopen on deny: %+v %v", res, err)
	}
	for _, st := range f.findings(f.tenant, f.a1) {
		if st[0] != "confirmed" {
			t.Errorf("after deny again: %v", st)
		}
	}

	// The package goes away from the asset (a new snapshot): evaluating
	// that asset resolves its finding.
	mustExec(t, f.db, `DELETE FROM asset_software WHERE id = $1`, gpl)
	if res, err := svc.EvaluateAssets(ctx, f.tenant, []shared.ID{f.a1}); err != nil || res.Resolved != 1 {
		t.Fatalf("link removed: %+v %v", res, err)
	}
	// Evaluating another tenant's asset id under this tenant touches nothing.
	if res, err := svc.EvaluateAssets(ctx, f.tenant, []shared.ID{f.b1}); err != nil || res.LinksUpdated != 0 || res.Created != 0 {
		t.Fatalf("cross-tenant asset: %+v %v", res, err)
	}

	// Policy off: verdicts cleared, open findings resolved.
	policy.Enabled = false
	f.setPolicy(f.tenant, policy)
	if _, err := svc.EvaluateTenant(ctx, f.tenant); err != nil {
		t.Fatal(err)
	}
	if v, _ := f.verdict(custom); v != "" {
		t.Errorf("verdict kept with the policy off: %q", v)
	}
	for _, st := range f.findings(f.tenant, f.a2) {
		if st[0] != "resolved" {
			t.Errorf("policy off resolves: %v", st)
		}
	}
}
