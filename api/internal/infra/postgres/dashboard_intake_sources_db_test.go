package postgres

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// A run that carries reports of several tools on one receipt is counted
// per tool: a discovery tool that reported first keeps only its assets, the
// detection tool after it keeps its findings, and the receipt list filtered
// by either tool has the same totals as the dashboard row. Findings the
// platform derived (the version matcher) are a source of their own. Each
// source lists its senders, whose figures sum to the source; only the
// tenant's own sensors are named. Another tenant's receipts, tool rows and
// sensors never count.
func TestOrgIntake_PerToolAndInstances_DB(t *testing.T) {
	f := newReceiptFixture(t)
	other := seedTestTenant(f.ctx, t, f.db)
	otherAsset := seedTestAsset(f.ctx, t, f.db, other)

	sensor := func(tenant shared.ID, name string) shared.ID {
		t.Helper()
		id := shared.NewID()
		if _, err := f.db.ExecContext(f.ctx, `INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status)
			VALUES ($1, $2, $3, $4, 'p', 'active')`, id.String(), tenant.String(), name, "h-"+id.String()); err != nil {
			t.Fatalf("seed sensor: %v", err)
		}
		return id
	}
	edge := sensor(f.tenant, "edge-sensor")
	core := sensor(f.tenant, "core-sensor")
	foreign := sensor(other, "other-tenant-sensor")
	inst := func(id shared.ID) ingestreceipt.Instance {
		return ingestreceipt.Instance{Kind: ingestreceipt.InstanceSensor, ID: id.String()}
	}
	created := func(tenant, asset shared.ID, n int) []shared.ID {
		var ids []shared.ID
		for i := 0; i < n; i++ {
			ids = append(ids, f.finding(tenant, asset, "fp-"+shared.NewID().String(), "new"))
		}
		return ids
	}

	// One connector run (one receipt): subfinder first with assets only,
	// then nuclei from two sensors with findings.
	run := ingestreceipt.Source{Kind: ingestreceipt.SourceConnector, Ref: "run-" + shared.NewID().String()}
	f.record(&ingestreceipt.Delta{TenantID: f.tenant, Source: run, Tool: "subfinder", Instance: inst(edge),
		Reports: 1, AssetsCreated: 40, AssetsUpdated: 10})
	f.record(&ingestreceipt.Delta{TenantID: f.tenant, Source: run, Tool: "nuclei", Instance: inst(edge),
		Reports: 1, Received: 7, Created: created(f.tenant, f.asset, 3)})
	f.record(&ingestreceipt.Delta{TenantID: f.tenant, Source: run, Tool: "nuclei", Instance: inst(core),
		Reports: 1, Received: 5, Created: created(f.tenant, f.asset, 2)})
	// A sensor id of another tenant on this tenant's receipt stays unnamed.
	f.record(&ingestreceipt.Delta{TenantID: f.tenant, Source: run, Tool: "nuclei", Instance: inst(foreign),
		Reports: 1, Received: 1})
	// The platform's version matches.
	f.record(&ingestreceipt.Delta{TenantID: f.tenant,
		Source:   ingestreceipt.Source{Kind: ingestreceipt.SourcePlatform, Ref: "version-match:2026-10-31"},
		Tool:     "version-match",
		Instance: ingestreceipt.Instance{Kind: ingestreceipt.InstancePlatform, ID: ingestreceipt.InstancePlatform},
		Reports:  1, Received: 4, Created: created(f.tenant, f.asset, 4)})
	// Another tenant: same tools, never counted.
	f.record(&ingestreceipt.Delta{TenantID: other, Source: run, Tool: "nuclei", Instance: inst(foreign),
		Reports: 1, Received: 999, AssetsCreated: 999, Created: created(other, otherAsset, 2)})

	// The receipt's own counts are the sum of its tool rows.
	var receiptReceived, toolReceived int
	if err := f.db.QueryRowContext(f.ctx, `SELECT r.findings_received, (SELECT sum(received) FROM ingest_receipt_tools t WHERE t.receipt_id = r.id)
		FROM ingest_receipts r WHERE r.tenant_id = $1 AND r.source_ref = $2`, f.tenant.String(), run.Ref).Scan(&receiptReceived, &toolReceived); err != nil {
		t.Fatalf("receipt sums: %v", err)
	}
	if receiptReceived != 13 || toolReceived != 13 {
		t.Errorf("receipt received %d, tool rows %d, want 13", receiptReceived, toolReceived)
	}

	since := time.Now().Add(-24 * time.Hour).UTC()
	repo := NewDashboardWidgetRepository(&DB{DB: f.db})
	rows, err := repo.OrgIntake(f.ctx, f.tenant, since)
	if err != nil {
		t.Fatalf("intake: %v", err)
	}
	by := map[string]dashboard.IntakeRow{}
	for _, r := range rows {
		by[r.Origin+"/"+r.Tool] = r
	}
	if len(by) != 3 {
		t.Fatalf("sources %+v, want connector/subfinder, connector/nuclei, platform/version-match", rows)
	}
	sub, nuc, vm := by["connector/subfinder"], by["connector/nuclei"], by["platform/version-match"]
	if sub.Received != 0 || sub.Created != 0 || sub.Assets != 50 {
		t.Errorf("subfinder: received %d created %d assets %d, want 0/0/50", sub.Received, sub.Created, sub.Assets)
	}
	if nuc.Received != 13 || nuc.Created != 5 || nuc.Assets != 0 || nuc.Receipts != 1 {
		t.Errorf("nuclei: %+v, want 13 received, 5 created, 1 receipt", nuc)
	}
	if vm.Received != 4 || vm.Created != 4 {
		t.Errorf("version-match: %+v", vm)
	}

	// Every source equals its receipt list (tool filter), the window too.
	for _, r := range rows {
		want, err := f.repo.Totals(f.ctx, f.tenant, ingestreceipt.Filter{Origin: r.Origin, Tool: r.Tool, Since: &since})
		if err != nil {
			t.Fatalf("totals: %v", err)
		}
		got := ingestreceipt.Totals{Receipts: r.Receipts, Received: r.Received, Created: r.Created,
			StillDetected: r.StillDetected, Reopened: r.Reopened, Closed: r.Closed, Skipped: r.Skipped,
			Failed: r.Failed, Suppressed: r.Suppressed}
		if got != want {
			t.Errorf("%s/%s: dashboard %+v, receipt list %+v", r.Origin, r.Tool, got, want)
		}
		list, total, err := f.repo.List(f.ctx, f.tenant, ingestreceipt.Filter{Origin: r.Origin, Tool: r.Tool, Since: &since}, pagination.New(1, 50))
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if total != r.Receipts || int64(len(list)) != r.Receipts {
			t.Errorf("%s/%s: list has %d receipts (%d rows), source %d", r.Origin, r.Tool, total, len(list), r.Receipts)
		}
	}
	window, err := f.repo.Totals(f.ctx, f.tenant, ingestreceipt.Filter{Since: &since})
	if err != nil {
		t.Fatalf("window totals: %v", err)
	}
	if window.Received != sub.Received+nuc.Received+vm.Received || window.Created != sub.Created+nuc.Created+vm.Created {
		t.Errorf("window %+v does not sum the sources", window)
	}

	// Senders: nuclei has three, summing to the source; only the tenant's
	// sensors are named and owned.
	if len(nuc.Instances) != 3 {
		t.Fatalf("nuclei instances %+v, want 3", nuc.Instances)
	}
	var sum int64
	for _, in := range nuc.Instances {
		sum += in.Received
		switch in.ID {
		case edge.String():
			if !in.Owned || in.Name != "edge-sensor" || in.Received != 7 {
				t.Errorf("edge instance %+v", in)
			}
		case core.String():
			if !in.Owned || in.Name != "core-sensor" || in.Received != 5 {
				t.Errorf("core instance %+v", in)
			}
		case foreign.String():
			if in.Owned || in.Name != "" {
				t.Errorf("another tenant's sensor is named or owned: %+v", in)
			}
		default:
			t.Errorf("unexpected instance %+v", in)
		}
	}
	if sum != nuc.Received {
		t.Errorf("nuclei instances sum %d, source %d", sum, nuc.Received)
	}
	if len(sub.Instances) != 1 || sub.Instances[0].Assets != 50 || sub.Instances[0].ID != edge.String() {
		t.Errorf("subfinder instances %+v", sub.Instances)
	}
	if len(vm.Instances) != 1 || vm.Instances[0].Kind != ingestreceipt.InstancePlatform {
		t.Errorf("version-match instances %+v", vm.Instances)
	}

	// The other tenant sees only its own row.
	otherRows, err := repo.OrgIntake(f.ctx, other, since)
	if err != nil {
		t.Fatalf("other intake: %v", err)
	}
	if len(otherRows) != 1 || otherRows[0].Received != 999 || len(otherRows[0].Instances) != 1 || !otherRows[0].Instances[0].Owned {
		t.Errorf("other tenant intake %+v", otherRows)
	}
}

// A coverage decision names no sender: its closed findings join the row of
// the sender that last reported the tool on the receipt, so the receipt and
// its tool rows still agree.
func TestReceiptTools_CoverageJoinsLastSender_DB(t *testing.T) {
	f := newReceiptFixture(t)
	src := ingestreceipt.Source{Kind: ingestreceipt.SourceConnector, Ref: "cov-" + shared.NewID().String()}
	sid := shared.NewID().String()
	f.record(&ingestreceipt.Delta{TenantID: f.tenant, Source: src, Tool: "nuclei", Reports: 1, Received: 2,
		Instance: ingestreceipt.Instance{Kind: ingestreceipt.InstanceSensor, ID: sid}})
	closed := f.finding(f.tenant, f.asset, "fp-closed-"+shared.NewID().String(), "resolved")
	f.record(&ingestreceipt.Delta{TenantID: f.tenant, Source: src, Tool: "nuclei", Closed: []shared.ID{closed}})
	n := f.count(`SELECT count(*) FROM ingest_receipt_tools t JOIN ingest_receipts r ON r.id = t.receipt_id
		WHERE r.tenant_id = $1 AND r.source_ref = $2`, f.tenant.String(), src.Ref)
	if n != 1 {
		t.Errorf("%d tool rows, want 1 (the decision joins the sender's row)", n)
	}
	c := f.count(`SELECT t.closed FROM ingest_receipt_tools t JOIN ingest_receipts r ON r.id = t.receipt_id
		WHERE r.tenant_id = $1 AND r.source_ref = $2 AND t.instance_id = $3`, f.tenant.String(), src.Ref, sid)
	if c != 1 {
		t.Errorf("closed on the sender's row = %d, want 1", c)
	}
}
