package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// VEX documents imported by a person: matched by vulnerability id AND
// package, within the caller's tenant only; a subcomponent statement only
// on the named product's asset; a not_affected statement closes only open,
// non-human findings, and only when asked to.
func TestFindingVEXDocument_DB(t *testing.T) {
	f := newCoverageFixture(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: f.db})

	// Global package versions (the feed's): findings of two tenants name them.
	comp := func(purl, _ string) shared.ID {
		product, id := testdb.SeedPackageVersion(t, f.db, "", purl)
		t.Cleanup(func() { _, _ = f.db.ExecContext(ctx, `DELETE FROM software_products WHERE id = $1`, product) })
		return shared.MustIDFromString(id)
	}
	lodash20 := comp("pkg:npm/lodash@4.17.20-"+shared.NewID().String()[28:], "4.17.20")
	// The base of the component purl above is pkg:npm/lodash; its version is
	// unique per run so runs do not share a version.
	var ver string
	if err := f.db.QueryRowContext(ctx, `SELECT split_part(purl, '@', 2) FROM software_versions WHERE id = $1`, lodash20.String()).Scan(&ver); err != nil {
		t.Fatal(err)
	}
	other := comp("pkg:npm/express@4.0.0-"+shared.NewID().String()[28:], "4.0.0")

	insert := func(tenant, asset, component shared.ID, cve, status, source string) shared.ID {
		id := shared.NewID()
		f.exec(t, `INSERT INTO findings (id, tenant_id, asset_id, component_id, source, tool_name, message, severity, fingerprint, status, cve_id)
			VALUES ($1, $2, $3, $4, $5, 'trivy', 'm', 'high', $6, $7, $8)`, id, tenant, asset, component, source, "fp-"+id.String(), status, cve)
		return id
	}
	onHost := insert(f.tenant, f.host, lodash20, "CVE-2024-0001", "new", "sca")
	onOther := insert(f.tenant, f.otherHost, lodash20, "CVE-2024-0001", "new", "sca")
	pentest := insert(f.tenant, f.host, lodash20, "CVE-2024-0001", "new", "pentest")
	resolved := insert(f.tenant, f.host, lodash20, "CVE-2024-0001", "resolved", "sca")
	otherCVE := insert(f.tenant, f.host, lodash20, "CVE-2024-9999", "new", "sca")
	otherPkg := insert(f.tenant, f.host, other, "CVE-2024-0001", "new", "sca")

	otherTenant := shared.NewID()
	f.exec(t, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, otherTenant, "vexdoc-o-"+otherTenant.String())
	t.Cleanup(func() { _, _ = f.db.ExecContext(ctx, "DELETE FROM tenants WHERE id = $1", otherTenant.String()) })
	otherAsset := shared.NewID()
	f.exec(t, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'h-o', 'host')`, otherAsset, otherTenant)
	foreign := insert(otherTenant, otherAsset, lodash20, "CVE-2024-0001", "new", "sca")

	ids := func(cs []vulnerability.VEXCandidate) map[shared.ID]bool {
		m := map[shared.ID]bool{}
		for _, c := range cs {
			m[c.ID] = true
		}
		return m
	}
	q := vulnerability.VEXDocumentQuery{IDs: []string{"CVE-2024-0001"}, Products: []vulnerability.VEXProduct{{Base: "pkg:npm/lodash"}}}
	got, err := repo.MatchVEXDocument(ctx, f.tenant, q, 0)
	if err != nil {
		t.Fatal(err)
	}
	m := ids(got)
	for _, want := range []shared.ID{onHost, onOther, pentest, resolved} {
		if !m[want] {
			t.Errorf("finding %s not matched", want)
		}
	}
	for _, not := range []shared.ID{otherCVE, otherPkg, foreign} {
		if m[not] {
			t.Errorf("finding %s matched (other cve, other package or other tenant)", not)
		}
	}

	// A version names one version only.
	q.Products = []vulnerability.VEXProduct{{Base: "pkg:npm/lodash", Version: "9.9.9"}}
	if got, _ := repo.MatchVEXDocument(ctx, f.tenant, q, 0); len(got) != 0 {
		t.Errorf("another version matched %d findings", len(got))
	}
	q.Products = []vulnerability.VEXProduct{{Base: "pkg:npm/lodash", Version: ver}}
	if got, _ := repo.MatchVEXDocument(ctx, f.tenant, q, 0); len(got) != 4 {
		t.Errorf("the exact version matched %d findings, want 4", len(got))
	}

	// A subcomponent statement: only the product's asset.
	var hostName string
	if err := f.db.QueryRowContext(ctx, `SELECT name FROM assets WHERE id = $1`, f.host.String()).Scan(&hostName); err != nil {
		t.Fatal(err)
	}
	q.Products = []vulnerability.VEXProduct{{Base: "pkg:npm/lodash"}}
	q.AssetNames = []string{hostName}
	got, err = repo.MatchVEXDocument(ctx, f.tenant, q, 0)
	if err != nil {
		t.Fatal(err)
	}
	if m := ids(got); m[onOther] || !m[onHost] {
		t.Errorf("subcomponent match left the product: %v", m)
	}
	q.AssetNames = nil

	// Apply with close: only the open, non-human finding closes; all get the
	// statement; the other tenant's finding is untouched even when its id is
	// passed.
	v := vulnerability.InteropVEX{Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path", Source: "doc-1"}
	stored, closed, err := repo.ApplyVEXDocument(ctx, f.tenant, []shared.ID{onHost, pentest, resolved, foreign}, v, true, "VEX not_affected: test")
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 3 || len(closed) != 1 || closed[0] != onHost {
		t.Fatalf("stored %v closed %v", stored, closed)
	}
	var status, method string
	var vexStatus *string
	if err := f.db.QueryRowContext(ctx, `SELECT status, COALESCE(resolution_method, ''), vex_status FROM findings WHERE id = $1`, onHost.String()).Scan(&status, &method, &vexStatus); err != nil {
		t.Fatal(err)
	}
	if status != "false_positive" || method != "vex_not_affected" || vexStatus == nil || *vexStatus != "not_affected" {
		t.Errorf("closed finding = %s %s %v", status, method, vexStatus)
	}
	if err := f.db.QueryRowContext(ctx, `SELECT status FROM findings WHERE id = $1`, pentest.String()).Scan(&status); err != nil || status != "new" {
		t.Errorf("pentest finding = %s %v", status, err)
	}
	if err := f.db.QueryRowContext(ctx, `SELECT status, vex_status FROM findings WHERE id = $1`, foreign.String()).Scan(&status, &vexStatus); err != nil || status != "new" || vexStatus != nil {
		t.Errorf("another tenant's finding changed: %s %v %v", status, vexStatus, err)
	}

	// Without close: stored, not closed.
	_, closed, err = repo.ApplyVEXDocument(ctx, f.tenant, []shared.ID{onOther}, v, false, "r")
	if err != nil || len(closed) != 0 {
		t.Fatalf("closed %v %v", closed, err)
	}
	if err := f.db.QueryRowContext(ctx, `SELECT status, vex_status FROM findings WHERE id = $1`, onOther.String()).Scan(&status, &vexStatus); err != nil || status != "new" || vexStatus == nil {
		t.Errorf("unclosed finding = %s %v %v", status, vexStatus, err)
	}

	// An affected statement never closes, even when asked.
	_, closed, err = repo.ApplyVEXDocument(ctx, f.tenant, []shared.ID{otherCVE}, vulnerability.InteropVEX{Status: "affected", Source: "d"}, true, "r")
	if err != nil || len(closed) != 0 {
		t.Fatalf("affected closed %v %v", closed, err)
	}
}
