package postgres

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Every intake figure equals the receipt list it opens: for the whole
// window and for each source (origin and tool), the sums OrgIntake returns
// are the totals the receipt list computes for the same filter, so the
// dashboard's received, new, reopened and suppressed figures can never
// disagree with the list's totals. Another tenant's receipts never count.
func TestOrgIntake_EqualsReceiptListTotals_DB(t *testing.T) {
	f := newReceiptFixture(t)
	other := seedTestTenant(f.ctx, t, f.db)
	otherAsset := seedTestAsset(f.ctx, t, f.db, other)

	rec := func(tenant, asset shared.ID, kind ingestreceipt.SourceKind, tool string, received, created, reopened, suppressed int) {
		var cr, ro []shared.ID
		for i := 0; i < created; i++ {
			cr = append(cr, f.finding(tenant, asset, "fp-c-"+shared.NewID().String(), "new"))
		}
		for i := 0; i < reopened; i++ {
			ro = append(ro, f.finding(tenant, asset, "fp-r-"+shared.NewID().String(), "new"))
		}
		f.record(&ingestreceipt.Delta{TenantID: tenant, Source: ingestreceipt.Source{Kind: kind, Ref: shared.NewID().String()},
			Tool: tool, Reports: 1, Received: received, Created: cr, Reopened: ro, Suppressed: suppressed})
	}
	rec(f.tenant, f.asset, ingestreceipt.SourceCIRun, "nuclei", 40, 10, 2, 3)
	rec(f.tenant, f.asset, ingestreceipt.SourceCIRun, "nuclei", 20, 4, 0, 1)
	rec(f.tenant, f.asset, ingestreceipt.SourceConnector, "cloud", 30, 6, 1, 0)
	rec(other, otherAsset, ingestreceipt.SourceCIRun, "nuclei", 999, 5, 5, 5)

	since := time.Now().Add(-24 * time.Hour).UTC()
	repo := NewDashboardWidgetRepository(&DB{DB: f.db})
	rows, err := repo.OrgIntake(f.ctx, f.tenant, since)
	if err != nil {
		t.Fatalf("intake: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("%d sources, want 2: %+v", len(rows), rows)
	}
	check := func(label string, flt ingestreceipt.Filter, got ingestreceipt.Totals) {
		t.Helper()
		want, err := f.repo.Totals(f.ctx, f.tenant, flt)
		if err != nil {
			t.Fatalf("%s totals: %v", label, err)
		}
		if got != want {
			t.Errorf("%s: dashboard %+v, receipt list %+v", label, got, want)
		}
	}
	var all ingestreceipt.Totals
	for _, r := range rows {
		got := ingestreceipt.Totals{Receipts: r.Receipts, Received: r.Received, Created: r.Created,
			StillDetected: r.StillDetected, Reopened: r.Reopened, Closed: r.Closed, Skipped: r.Skipped,
			Failed: r.Failed, Suppressed: r.Suppressed}
		check(r.Origin+"/"+r.Tool, ingestreceipt.Filter{Origin: r.Origin, Tool: r.Tool, Since: &since}, got)
		all.Receipts += got.Receipts
		all.Received += got.Received
		all.Created += got.Created
		all.StillDetected += got.StillDetected
		all.Reopened += got.Reopened
		all.Closed += got.Closed
		all.Skipped += got.Skipped
		all.Failed += got.Failed
		all.Suppressed += got.Suppressed
	}
	check("window", ingestreceipt.Filter{Since: &since}, all)
	if all.Received != 90 || all.Created != 20 || all.Reopened != 3 || all.Suppressed != 4 {
		t.Errorf("seeded sums %+v", all)
	}
}
