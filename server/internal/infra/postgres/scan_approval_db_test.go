package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/scangov"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Scan approval requests are tenant-scoped (RFC-073): a request is created
// only for the tenant's own scan; get, list, decide, consume and remind
// never reach another tenant's request; one pending request per scan; the
// target facts read only the tenant's assets.
func TestScanApprovals_TenantScoped_DB(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	tenant := seedScanTriggerTenant(ctx, t, db)
	other := seedScanTriggerTenant(ctx, t, db)
	repo := NewScanApprovalRepository(&DB{DB: db})

	newScan := func(tid shared.ID) shared.ID {
		t.Helper()
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, targets) VALUES ($1, $2, $3, 'single', 'zap', ARRAY['app.acme.vn'])`,
			id.String(), tid.String(), "approval "+id.String()); err != nil {
			t.Fatal(err)
		}
		return id
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	mine, theirs := newScan(tenant), newScan(other)
	def := scangov.Definition{Targets: []string{"app.acme.vn"}, ScanType: "single", ScannerName: "zap", Intensity: "intrusive"}
	ev := scangov.Evaluation{Mode: scangov.ModeOn, Required: true, Approvals: 1, Validity: scangov.ValidityRun,
		Matched: []scangov.MatchedRule{{ID: "r", Name: "Intrusive scans"}}}
	req := scangov.NewRequest(tenant, mine, def, ev, "", "pentest", "CHG-1", true, 14, now)

	if err := repo.Create(ctx, scangov.NewRequest(tenant, theirs, def, ev, "", "x", "", false, 14, now)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("a request for another tenant's scan: %v, want not found", err)
	}
	if err := repo.Create(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, scangov.NewRequest(tenant, mine, def, ev, "", "x", "", false, 14, now)); err == nil {
		t.Fatal("a second pending request for the same scan")
	}

	got, err := repo.Get(ctx, tenant, req.ID)
	if err != nil || got.ScanName == "" || got.Digest != def.Digest() || got.Evaluation.Matched[0].Name != "Intrusive scans" || got.Ticket != "CHG-1" {
		t.Fatalf("get: %v %+v", err, got)
	}
	if _, err := repo.Get(ctx, other, req.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another tenant reads the request: %v", err)
	}
	if list, n, _ := repo.List(ctx, scangov.ListFilter{TenantID: other, Limit: 10}); n != 0 || len(list) != 0 {
		t.Fatalf("another tenant lists %d requests", n)
	}
	if list, n, _ := repo.List(ctx, scangov.ListFilter{TenantID: tenant, Statuses: []scangov.Status{scangov.StatusPending}, Limit: 10}); n != 1 || len(list) != 1 {
		t.Fatalf("list pending: %d", n)
	}

	// Reminders: once per interval, never across tenants.
	if ok, _ := repo.MarkReminded(ctx, other, req.ID, now, time.Hour); ok {
		t.Fatal("another tenant reminded")
	}
	if ok, _ := repo.MarkReminded(ctx, tenant, req.ID, now, time.Hour); !ok {
		t.Fatal("first reminder")
	}
	if ok, _ := repo.MarkReminded(ctx, tenant, req.ID, now.Add(time.Minute), time.Hour); ok {
		t.Fatal("second reminder within the hour")
	}

	// A decision is a compare-and-swap on the pending status.
	got.Approvals = append(got.Approvals, scangov.Approval{UserID: shared.NewID().String(), ApprovedAt: now})
	got.Status = scangov.StatusApproved
	foreign := *got
	foreign.TenantID = other
	if ok, _ := repo.Update(ctx, &foreign, scangov.StatusPending); ok {
		t.Fatal("another tenant decided the request")
	}
	if ok, err := repo.Update(ctx, got, scangov.StatusPending); !ok || err != nil {
		t.Fatalf("approve: %v %v", ok, err)
	}
	if ok, _ := repo.Update(ctx, got, scangov.StatusPending); ok {
		t.Fatal("a decided request was decided again")
	}
	if a, _ := repo.ApprovedFor(ctx, tenant, mine, def.Digest()); a == nil || len(a.Approvals) != 1 {
		t.Fatalf("approved for digest: %+v", a)
	}
	if a, _ := repo.ApprovedFor(ctx, other, mine, def.Digest()); a != nil {
		t.Fatal("another tenant sees the approval")
	}
	if ok, _ := repo.Consume(ctx, other, req.ID, now); ok {
		t.Fatal("another tenant consumed the approval")
	}
	if ok, _ := repo.Consume(ctx, tenant, req.ID, now); !ok {
		t.Fatal("consume")
	}
	if ok, _ := repo.Consume(ctx, tenant, req.ID, now); ok {
		t.Fatal("a run-only approval used twice")
	}
	latest, err := repo.LatestByScans(ctx, tenant, []shared.ID{mine, theirs})
	if err != nil || len(latest) != 1 || latest[mine] == nil {
		t.Fatalf("latest by scans: %v %v", err, latest)
	}

	// Target facts: only the tenant's assets count.
	for _, a := range []struct {
		tid  shared.ID
		name string
	}{{tenant, "app.acme.vn"}, {tenant, "db.acme.vn"}, {other, "api.acme.vn"}} {
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status, tags, is_crown_jewel)
			VALUES ($1, $2, $3, 'domain', 'critical', 'active', ARRAY['production'], true)`, shared.NewID().String(), a.tid.String(), a.name); err != nil {
			t.Fatal(err)
		}
	}
	f, err := repo.TargetAssetFacts(ctx, tenant, []string{"app.acme.vn"}, nil, []string{"acme.vn"})
	if err != nil || f.Expanded != 1 || f.MaxCriticality != "critical" || !f.CrownJewel || len(f.Tags) != 1 {
		t.Fatalf("facts: %v %+v", err, f)
	}
	if f, _ := repo.TargetAssetFacts(ctx, other, nil, nil, []string{"other.example"}); f.Expanded != 0 || f.CrownJewel {
		t.Fatalf("facts of an unrelated root: %+v", f)
	}
}

// The approval rules read each target's effective criticality: an asset whose
// own criticality is low but whose business unit (through its parent) is
// critical counts as critical, the same value finding priority uses. Deleted
// assets are not targets, and another tenant never reads the asset.
func TestScanApprovals_TargetFactsUseEffectiveCriticality_DB(t *testing.T) {
	db := openScanDB(t)
	ctx := context.Background()
	repo := NewScanApprovalRepository(&DB{DB: db})
	tenant := seedScanTriggerTenant(ctx, t, db)
	other := seedScanTriggerTenant(ctx, t, db)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	low, gone := shared.NewID().String(), shared.NewID().String()
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status) VALUES ($1, $2, 'pay.acme.vn', 'domain', 'low', 'active')`, low, tenant.String())
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status, deleted_at) VALUES ($1, $2, 'old.acme.vn', 'domain', 'critical', 'active', now())`, gone, tenant.String())

	f, err := repo.TargetAssetFacts(ctx, tenant, []string{"pay.acme.vn", "old.acme.vn"}, nil, nil)
	if err != nil || f.MaxCriticality != "low" {
		t.Fatalf("own criticality, deleted asset ignored: %v %+v", err, f)
	}

	// Another tenant's critical unit raises nothing (a cross-tenant
	// membership is refused by the (tenant, asset) foreign key, and the
	// lookup filters on the tenant).
	exec(`INSERT INTO business_units (id, tenant_id, name, criticality) VALUES ($1, $2, 'Foreign', 'critical')`, shared.NewID().String(), other.String())
	if f, err := repo.TargetAssetFacts(ctx, other, []string{"pay.acme.vn"}, nil, nil); err != nil || f.MaxCriticality != "none" {
		t.Fatalf("another tenant sees the asset: %v %+v", err, f)
	}

	// A child unit under a critical parent raises the asset to critical.
	parent, child := shared.NewID().String(), shared.NewID().String()
	exec(`INSERT INTO business_units (id, tenant_id, name, criticality) VALUES ($1, $2, 'Payments', 'critical')`, parent, tenant.String())
	exec(`INSERT INTO business_units (id, tenant_id, name, criticality, parent_id) VALUES ($1, $2, 'Checkout', 'low', $3)`, child, tenant.String(), parent)
	exec(`INSERT INTO business_unit_assets (id, tenant_id, business_unit_id, asset_id) VALUES ($1, $2, $3, $4)`, shared.NewID().String(), tenant.String(), child, low)
	if f, err := repo.TargetAssetFacts(ctx, tenant, []string{"pay.acme.vn"}, nil, nil); err != nil || f.MaxCriticality != "critical" {
		t.Fatalf("unit-raised asset: %v %+v", err, f)
	}
}
