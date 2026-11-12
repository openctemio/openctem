package integration

import (
	"context"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/finding"
	vexapp "github.com/openctemio/openctem/api/internal/app/vex"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// TestVEXStatementRequest: a not_affected statement (findings:approve, always
// on) never sets false_positive. It opens a pending request by the actor
// "vex" for the findings it covers, the ones reported later included, and the
// person who created the statement cannot complete that request alone: it
// needs one more sign-off than the tier from a second distinct approver.
func TestVEXStatementRequest(t *testing.T) {
	db := setupTestDB(t)
	pdb := &postgres.DB{DB: db}
	ctx := context.Background()
	tenant := createTestTenant(t, db, "vex-stmt-req")
	uploader, second := shared.NewID(), shared.NewID()
	asset := shared.NewID()
	suffix := shared.NewID().String()[:8]
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, tenant.String())
		for _, id := range []shared.ID{uploader, second} {
			_, _ = db.Exec(`DELETE FROM users WHERE id = $1`, id.String())
		}
		_ = db.Close()
	})
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	for _, id := range []shared.ID{uploader, second} {
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'approver')`, id.String(), id.String()+"@example.com")
	}
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'vex-req-asset', 'repository')`, asset.String(), tenant.String())
	product, version := testdb.SeedPackageVersion(t, db, "", "pkg:npm/vexreq"+suffix+"@1.0.0")
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM software_products WHERE id = $1`, product) })
	testdb.SeedPackageLink(t, db, tenant.String(), asset.String(), product, version, "package-lock.json", "direct")
	newFinding := func() shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO findings (id, tenant_id, asset_id, component_id, source, tool_name, message, severity, fingerprint, status, cve_id)
			VALUES ($1::uuid, $2, $3, $4, 'sca', 'trivy', 'm', 'high', $1::text, 'new', 'CVE-2030-0001')`,
			id.String(), tenant.String(), asset.String(), version)
		return id
	}
	status := func(id shared.ID) string {
		var s string
		if err := db.QueryRow(`SELECT status FROM findings WHERE id = $1`, id.String()).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}

	vexSvc := vexapp.NewService(postgres.NewVEXStatementRepository(pdb), nil, nil, nil)
	actx := auditapp.AuditContext{TenantID: tenant.String(), ActorID: uploader.String()}
	early := newFinding()
	if _, res, err := vexSvc.Create(ctx, tenant, vexapp.Input{VulnID: "CVE-2030-0001", ProductID: product,
		Versions: []string{"1.0.0"}, Status: "not_affected", Justification: "vulnerable_code_not_present"}, actx); err != nil {
		t.Fatal(err)
	} else if res.Closed != 0 || res.Requested != 1 {
		t.Fatalf("applied %+v, want 0 closed and 1 requested", res)
	}
	late := newFinding()
	if _, err := vexSvc.ApplyToFingerprints(ctx, tenant, []string{late.String()}); err != nil {
		t.Fatal(err)
	}

	approvals := postgres.NewFindingApprovalRepository(pdb)
	svc := finding.NewVulnerabilityService(nil, postgres.NewFindingRepository(pdb), logger.NewNop())
	svc.SetApprovalRepository(approvals)
	svc.SetApprovalNotifier(staticApprovers{uploader, second}, nil, nil, "")

	for name, id := range map[string]shared.ID{"existing": early, "later": late} {
		if s := status(id); s != "new" {
			t.Fatalf("%s finding is %s, a statement must not set false_positive", name, s)
		}
		list, err := approvals.ListByFinding(ctx, tenant, id)
		if err != nil || len(list) != 1 || list[0].RequestedByActor != "vex" || list[0].RequestedStatus != "false_positive" {
			t.Fatalf("%s finding: want one pending vex request, got %+v %v", name, list, err)
		}
	}

	// The uploader alone cannot complete the request: their sign-off is one
	// of at least two, a repeat is refused, and only a second person applies it.
	list, _ := approvals.ListByFinding(ctx, tenant, early)
	requireTwoSignoffs(t, svc, tenant, list[0].ID.String(), uploader, second,
		func() string { return status(early) }, "new", "false_positive")
}
