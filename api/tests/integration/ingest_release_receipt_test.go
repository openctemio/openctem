package integration

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/tools/receiptreattribute"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func releaseRig(t *testing.T, tool string) (*v2Rig, v2Tenant, *ingest.Service, *postgres.SensorResultRepository, *sensor.Sensor) {
	t.Helper()
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant(tool)
	db := &postgres.DB{DB: r.db}
	results := postgres.NewSensorResultRepository(db)
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	svc.SetResultQuarantine(results, sensorresult.DefaultLimits())
	svc.SetReceiptRecorder(postgres.NewIngestReceiptRepository(db))
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	return r, tn, svc, results, agt
}

type receiptRow struct {
	kind, ref, tool        string
	released               bool
	received, created      int
	still, reopened        int
	suppressed, skipped    int
	failed                 int
	reports                int
	toolInstKind, toolInst string
	toolReleased           int
}

func readReceipts(t *testing.T, r *v2Rig, tenant shared.ID) []receiptRow {
	t.Helper()
	rows, err := r.db.QueryContext(context.Background(), `
		SELECT r.source_kind, r.source_ref, COALESCE(r.tool_name, ''), r.released_from_quarantine, r.findings_received,
			r.findings_created, r.findings_updated, r.findings_reopened, r.findings_suppressed, r.skipped,
			r.findings_failed, r.reports,
			COALESCE(max(t.instance_kind), ''), COALESCE(max(t.instance_id), ''), COALESCE(sum(t.released_reports), 0)
		FROM ingest_receipts r LEFT JOIN ingest_receipt_tools t ON t.receipt_id = r.id
		WHERE r.tenant_id = $1 GROUP BY r.id ORDER BY r.created_at`, tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []receiptRow
	for rows.Next() {
		var x receiptRow
		if err := rows.Scan(&x.kind, &x.ref, &x.tool, &x.released, &x.received, &x.created, &x.still, &x.reopened,
			&x.suppressed, &x.skipped, &x.failed, &x.reports, &x.toolInstKind, &x.toolInst, &x.toolReleased); err != nil {
			t.Fatal(err)
		}
		out = append(out, x)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// A report released from the quarantine is recorded under the sensor that
// sent it, never under a connector: the receipt is a sensor receipt, its
// sender is that sensor, it carries the release marker, and no connector
// receipt appears. The ingest itself still applies the whole report.
func TestIngest_ReleasedItemReceiptNamesTheSensor(t *testing.T) {
	r, tn, svc, results, agt := releaseRig(t, "dnsx")
	ctx := context.Background()
	cmd := shared.NewID()
	rep := &ctis.Report{Version: ctis.SchemaVersion, Tool: &ctis.Tool{Name: "dnsx"},
		Metadata: ctis.ReportMetadata{ID: ctis.NewReportID(), GeneratedAt: time.Now().UTC()},
		Assets: []ctis.Asset{
			{ID: "d", Type: ctis.AssetTypeDomainName, Value: "rel.example.org"},
			{ID: "r", Type: ctis.AssetTypeRepository, Value: "github.com/acme/released"},
		}}
	bind := ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd, Tool: "dnsx", Targets: []string{"rel.example.org"}}
	if _, err := svc.Ingest(ctx, agt, ingest.Input{Report: rep, Options: ingest.Options{Binding: bind, Route: "ctis"}}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	items, _, err := results.List(ctx, tn.tenant, sensorresult.ListFilter{})
	if err != nil || len(items) != 1 {
		t.Fatalf("held items = %d, %v", len(items), err)
	}
	if _, err := svc.AcceptQuarantined(ctx, auditapp.AuditContext{}, tn.tenant, items[0].ID, shared.NewID()); err != nil {
		t.Fatalf("release: %v", err)
	}
	var released *receiptRow
	all := readReceipts(t, r, tn.tenant)
	// The hold and the release are one receipt, and the report's findings
	// are received once (the hold's count moved to the release's outcomes).
	if len(all) != 1 || all[0].reports != 1 {
		t.Fatalf("hold and release made %d receipts: %+v", len(all), all)
	}
	var heldOutcome int
	if err := r.db.QueryRowContext(context.Background(), `SELECT COALESCE((outcomes->>'quarantined')::int, 0) FROM ingest_receipts WHERE tenant_id = $1`,
		tn.tenant.String()).Scan(&heldOutcome); err != nil || heldOutcome != 0 {
		t.Fatalf("a released receipt keeps a quarantined outcome: %d, %v", heldOutcome, err)
	}
	for _, rc := range all {
		if rc.kind == "connector" {
			t.Fatalf("a connector receipt appeared for a sensor's report: %+v", rc)
		}
		if rc.released {
			c := rc
			released = &c
		}
	}
	if released == nil {
		t.Fatal("no receipt carries the release marker")
	}
	if released.kind != "sensor" || released.tool != "dnsx" || released.toolInstKind != "sensor" ||
		released.toolInst != tn.sensor.String() || released.toolReleased != 1 {
		t.Fatalf("released receipt = %+v, want a sensor receipt of dnsx from sensor %s", *released, tn.sensor)
	}
	var n int
	if err := r.db.QueryRowContext(context.Background(), `SELECT count(*) FROM assets WHERE tenant_id = $1 AND name = 'github.com/acme/released'`,
		tn.tenant.String()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("the release did not apply the whole report: %d, %v", n, err)
	}
}

// receipt-reattribute moves the receipts an auto-released item wrote before
// the fix (a connector receipt named after the tool) back to the sensor, from
// the quarantine's own record of the release. A dry run changes nothing; a
// connector receipt with no auto-released item behind it, and another
// tenant's, are left alone.
func TestReceiptReattribute(t *testing.T) {
	r, tn, svc, results, agt := releaseRig(t, "dnsx")
	ctx := context.Background()
	cmd := shared.NewID()
	rep := &ctis.Report{Version: ctis.SchemaVersion, Tool: &ctis.Tool{Name: "dnsx"},
		Metadata: ctis.ReportMetadata{ID: ctis.NewReportID(), GeneratedAt: time.Now().UTC()},
		Assets: []ctis.Asset{
			{ID: "d", Type: ctis.AssetTypeDomainName, Value: "old.example.org"},
			{ID: "r", Type: ctis.AssetTypeRepository, Value: "github.com/acme/old"},
		}}
	bind := ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd, Tool: "dnsx", Targets: []string{"old.example.org"}}
	if _, err := svc.Ingest(ctx, agt, ingest.Input{Report: rep, Options: ingest.Options{Binding: bind, Route: "ctis"}}); err != nil {
		t.Fatal(err)
	}
	items, _, err := results.List(ctx, tn.tenant, sensorresult.ListFilter{})
	if err != nil || len(items) != 1 {
		t.Fatalf("held = %d, %v", len(items), err)
	}
	// The platform releases it (the auto-release stores auto_accepted).
	if _, err := svc.AcceptQuarantined(ctx, auditapp.AuditContext{}, tn.tenant, items[0].ID, shared.NewID()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.db.ExecContext(context.Background(), `UPDATE sensor_result_quarantine SET result = '{"auto_accepted": true}'::jsonb WHERE id = $1`,
		items[0].ID.String()); err != nil {
		t.Fatal(err)
	}
	// Put the receipt back as the old release wrote it.
	tid := tn.tenant.String()
	if _, err := r.db.ExecContext(context.Background(), `UPDATE ingest_receipts SET source_kind = 'connector', source_ref = $2, released_from_quarantine = false
		WHERE tenant_id = $1 AND released_from_quarantine`, tid, items[0].ReportID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.db.ExecContext(context.Background(), `UPDATE ingest_receipt_tools SET instance_kind = 'connector', instance_id = 'dnsx', instance_name = 'dnsx',
		released_reports = 0 WHERE tenant_id = $1`, tid); err != nil {
		t.Fatal(err)
	}
	// A connector receipt with no released item behind it.
	if _, err := r.db.ExecContext(context.Background(), `INSERT INTO ingest_receipts (id, tenant_id, source_kind, source_ref, tool_name, status)
		VALUES ($1, $2, 'connector', 'real-sync-1', 'dnsx', 'completed')`, shared.NewID().String(), tid); err != nil {
		t.Fatal(err)
	}

	got, err := receiptreattribute.Run(ctx, r.db, &tn.tenant, false)
	if err != nil || got.Receipts != 1 || got.Moved != 0 || got.Conflicts != 0 {
		t.Fatalf("dry run = %+v, %v", got, err)
	}
	var kind string
	if err := r.db.QueryRowContext(context.Background(), `SELECT source_kind FROM ingest_receipts WHERE tenant_id = $1 AND source_ref = $2`, tid, items[0].ReportID).Scan(&kind); err != nil || kind != "connector" {
		t.Fatalf("the dry run changed the receipt: %q, %v", kind, err)
	}
	other := shared.NewID()
	if res, err := receiptreattribute.Run(ctx, r.db, &other, true); err != nil || res.Receipts != 0 {
		t.Fatalf("another tenant's run touched this tenant: %+v, %v", res, err)
	}

	got, err = receiptreattribute.Run(ctx, r.db, &tn.tenant, true)
	if err != nil || got.Moved != 1 {
		t.Fatalf("apply = %+v, %v", got, err)
	}
	var movedRef, ikind, iid string
	var marked bool
	if err := r.db.QueryRowContext(context.Background(), `SELECT r.source_kind, r.released_from_quarantine, t.instance_kind, t.instance_id
		FROM ingest_receipts r JOIN ingest_receipt_tools t ON t.receipt_id = r.id
		WHERE r.tenant_id = $1 AND r.source_ref <> 'real-sync-1'`, tid).Scan(&movedRef, &marked, &ikind, &iid); err != nil {
		t.Fatal(err)
	}
	if movedRef != "sensor" || !marked || ikind != "sensor" || iid != tn.sensor.String() {
		t.Fatalf("moved receipt = %s %v %s %s", movedRef, marked, ikind, iid)
	}
	var untouched string
	if err := r.db.QueryRowContext(context.Background(), `SELECT source_kind FROM ingest_receipts WHERE tenant_id = $1 AND source_ref = 'real-sync-1'`, tid).Scan(&untouched); err != nil || untouched != "connector" {
		t.Fatalf("a connector receipt with no released item was changed: %q, %v", untouched, err)
	}
	if again, err := receiptreattribute.Run(ctx, r.db, &tn.tenant, true); err != nil || again.Receipts != 0 {
		t.Fatalf("second apply = %+v, %v", again, err)
	}
}
