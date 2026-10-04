package integration

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/easmdns"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Takeover confirmation through the real ingest and schema (migration
// 000485): a nuclei takeover-template finding from a command-bound report
// on an asset with an open dangling_cname raises subdomain_takeover (high)
// and marks the dangling_cname confirmed. An unsolicited report, a command
// that did not cover the asset, or a name without a dangling_cname confirm
// nothing, and another tenant's exposure is never touched.
func TestIngest_TakeoverConfirmation(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("nuclei")
	other := r.newTenant("nuclei")
	db := &postgres.DB{DB: r.db}
	ctx := context.Background()
	exposures := postgres.NewExposureRepository(db)
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	svc.SetTakeoverConfirmer(easmdns.NewTakeoverConfirmer(postgres.NewEASMDNSRepository(db), exposures, logger.NewNop()))

	sensorOf := func(v v2Tenant) *sensor.Sensor {
		tid := v.tenant
		return &sensor.Sensor{ID: v.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	}
	report := func(host string) *ctis.Report {
		return &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "nuclei"},
			Assets: []ctis.Asset{{ID: "a", Type: ctis.AssetTypeDomain, Value: host}},
			Findings: []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "Azure takeover", Severity: ctis.SeverityHigh,
				RuleID: "azure-takeover-detection", Tags: []string{"takeover"}, AssetRef: "a", Evidence: "404 Web Site not found"}},
			Metadata: ctis.ReportMetadata{Timestamp: time.Now().UTC()}}
	}
	run := func(v v2Tenant, bind ingest.Binding, host string) {
		t.Helper()
		out, err := svc.Ingest(ctx, sensorOf(v), ingest.Input{Report: report(host), Options: ingest.Options{Binding: bind}})
		if err != nil || len(out.Errors) > 0 {
			t.Fatalf("Ingest: %v %v", err, out.Errors)
		}
	}
	assetID := func(v v2Tenant, name string) shared.ID {
		t.Helper()
		var id string
		if err := r.db.QueryRowContext(ctx, `SELECT id FROM assets WHERE tenant_id = $1 AND name = $2`, v.tenant.String(), name).Scan(&id); err != nil {
			t.Fatalf("asset %s: %v", name, err)
		}
		out, _ := shared.IDFromString(id)
		return out
	}
	dangling := func(v v2Tenant, name string) {
		t.Helper()
		id := assetID(v, name)
		ev, err := exposuredom.NewExposureEvent(v.tenant, exposuredom.EventTypeDanglingCNAME, exposuredom.SeverityMedium,
			"Dangling CNAME: "+name, easmdns.Source, map[string]any{"domain": name, "target": "gone.azurewebsites.net", "confirmation": "pending"})
		if err != nil {
			t.Fatal(err)
		}
		ev.SetAssetID(&id)
		if err := exposures.BulkUpsert(ctx, []*exposuredom.ExposureEvent{ev}); err != nil {
			t.Fatal(err)
		}
	}
	takeovers := func(v v2Tenant) (n int, sev string) {
		t.Helper()
		_ = r.db.QueryRowContext(ctx, `SELECT count(*), coalesce(max(severity), '') FROM exposure_events
			WHERE tenant_id = $1 AND event_type = 'subdomain_takeover'`, v.tenant.String()).Scan(&n, &sev)
		return n, sev
	}
	confirmation := func(v v2Tenant, name string) string {
		t.Helper()
		var c string
		_ = r.db.QueryRowContext(ctx, `SELECT details->>'confirmation' FROM exposure_events
			WHERE tenant_id = $1 AND event_type = 'dangling_cname' AND details->>'domain' = $2`, v.tenant.String(), name).Scan(&c)
		return c
	}

	// The names exist as assets with open dangling CNAMEs, in both tenants.
	run(tn, ingest.Binding{}, "shop.example.com")
	run(other, ingest.Binding{}, "shop.example.com")
	dangling(tn, "shop.example.com")
	dangling(other, "shop.example.com")
	if n, _ := takeovers(tn); n != 0 {
		t.Fatal("an unsolicited report confirmed a takeover")
	}

	// A command for another target does not cover shop.example.com.
	cmd := shared.NewID()
	run(tn, ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd, Targets: []string{"www.example.org"}}, "shop.example.com")
	if n, _ := takeovers(tn); n != 0 {
		t.Fatal("a command confirmed a takeover on an asset outside its targets")
	}

	// A name without a dangling CNAME: the template match alone confirms nothing.
	run(tn, ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd, Targets: []string{"blog.example.com"}}, "blog.example.com")
	if n, _ := takeovers(tn); n != 0 {
		t.Fatal("a takeover without a dangling CNAME")
	}

	// The scan that targeted the name confirms it.
	run(tn, ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd, Targets: []string{"shop.example.com"}}, "shop.example.com")
	if n, sev := takeovers(tn); n != 1 || sev != "high" {
		t.Fatalf("takeovers = %d %s, want 1 high", n, sev)
	}
	if c := confirmation(tn, "shop.example.com"); c != "confirmed" {
		t.Fatalf("dangling_cname confirmation = %q", c)
	}
	// A repeat sighting does not duplicate it.
	run(tn, ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd, Targets: []string{"shop.example.com"}}, "shop.example.com")
	if n, _ := takeovers(tn); n != 1 {
		t.Fatalf("duplicate takeovers: %d", n)
	}
	// The other tenant's identical name is untouched.
	if n, _ := takeovers(other); n != 0 || confirmation(other, "shop.example.com") != "pending" {
		t.Fatal("another tenant's exposure changed")
	}
}
