package integration

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Complete reports from trusted collectors (RFC-040 §12): a complete report
// of a trusted collector may change the assets its own source created and
// marks the ones it no longer lists as not seen; nothing else may.

func completeRig(t *testing.T, guard ingest.BlindingGuard) *v2Rig {
	t.Helper()
	return newV2RigWith(t, guard, func(svc *ingest.Service, db *postgres.DB) {
		svc.SetGrants(postgres.NewSensorGrantRepository(db), nil)
		svc.SetCollectorAssets(postgres.NewCollectorAssetRepository(db))
		svc.SetAssetStateHistoryRepository(postgres.NewAssetStateHistoryRepository(db))
	})
}

// vcVM is a vCenter virtual machine in a given power state.
func vcVM(name, power string) ctis.Asset {
	return ctis.Asset{ID: name, Type: ctis.AssetTypeHost, Value: name, Name: name,
		Properties: ctis.Properties{"power_state": power, "vcenter": "vc01.example.com"}}
}

// vcReport is a vCenter collector report of one instance.
func vcReport(coverage string, at time.Time, assets ...ctis.Asset) *ctis.Report {
	return &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "vcenter"},
		Metadata: ctis.ReportMetadata{Timestamp: at.UTC(), SourceType: "collector", SourceRef: "vc01", CoverageType: coverage},
		Assets:   assets}
}

// sendCollector sends rep through protocol v2 (segment, process, commit) as
// the collector sensorID of tenant tn.
func (r *v2Rig) sendCollector(tn v2Tenant, sensorID shared.ID, rep *ctis.Report) {
	r.t.Helper()
	as := v2Tenant{tenant: tn.tenant, sensor: sensorID, repo: tn.repo}
	stored := r.openAs(as, shared.NewID().String(), "collector", nil, rep)
	r.sendWhole(as, stored, rep)
}

type assetState struct {
	power, status string
	deleted       bool
}

func (r *v2Rig) assetState(tn v2Tenant, name string) assetState {
	r.t.Helper()
	var s assetState
	if err := r.db.QueryRowContext(context.Background(), `SELECT COALESCE(properties->>'power_state', ''), status, deleted_at IS NOT NULL
		FROM assets WHERE tenant_id = $1 AND name = $2`, tn.tenant.String(), name).Scan(&s.power, &s.status, &s.deleted); err != nil {
		r.t.Fatalf("asset %s: %v", name, err)
	}
	return s
}

func TestIngest_CollectorCompleteReports(t *testing.T) {
	ctx := context.Background()

	t.Run("a complete report changes its own assets and marks unlisted ones not seen", func(t *testing.T) {
		r := completeRig(t, ingest.DefaultBlindingGuard())
		tn := r.newTenant()
		col := r.addCollector(tn, sensor.TrustTrusted)
		t0 := time.Now().Add(-2 * time.Hour)
		r.sendCollector(tn, col, vcReport("full", t0, vcVM("vm01.example.com", "poweredOn"), vcVM("vm02.example.com", "poweredOn"), vcVM("vm03.example.com", "poweredOn")))

		r.sendCollector(tn, col, vcReport("full", t0.Add(time.Hour), vcVM("vm01.example.com", "poweredOff"), vcVM("vm02.example.com", "poweredOn")))
		if s := r.assetState(tn, "vm01.example.com"); s.power != "poweredOff" || s.status != "active" {
			t.Fatalf("vm01 = %+v, want poweredOff and active (updated by its own source)", s)
		}
		if s := r.assetState(tn, "vm03.example.com"); s.status != "stale" || s.deleted {
			t.Fatalf("vm03 = %+v, want stale and not deleted (no longer listed)", s)
		}
		var hist int
		if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM asset_state_history h JOIN assets a ON a.id = h.asset_id
			WHERE h.tenant_id = $1 AND a.name = 'vm03.example.com' AND h.change_type = 'disappeared'`, tn.tenant.String()).Scan(&hist); err != nil || hist != 1 {
			t.Fatalf("disappeared history rows = %d (%v), want 1", hist, err)
		}

		// Listed again: active again.
		r.sendCollector(tn, col, vcReport("full", t0.Add(90*time.Minute), vcVM("vm01.example.com", "poweredOff"), vcVM("vm02.example.com", "poweredOn"), vcVM("vm03.example.com", "poweredOn")))
		if s := r.assetState(tn, "vm03.example.com"); s.status != "active" {
			t.Fatalf("vm03 listed again = %+v, want active", s)
		}
	})

	t.Run("a partial report changes nothing existing and marks nothing", func(t *testing.T) {
		r := completeRig(t, ingest.DefaultBlindingGuard())
		tn := r.newTenant()
		col := r.addCollector(tn, sensor.TrustTrusted)
		t0 := time.Now().Add(-2 * time.Hour)
		r.sendCollector(tn, col, vcReport("full", t0, vcVM("vm01.example.com", "poweredOn"), vcVM("vm02.example.com", "poweredOn")))
		r.sendCollector(tn, col, vcReport("partial", t0.Add(time.Hour), vcVM("vm01.example.com", "poweredOff")))
		if s := r.assetState(tn, "vm01.example.com"); s.power != "poweredOn" {
			t.Fatalf("vm01 = %+v: a partial report changed an existing asset", s)
		}
		if s := r.assetState(tn, "vm02.example.com"); s.status != "active" {
			t.Fatalf("vm02 = %+v: a partial report marked an asset not seen", s)
		}
	})

	t.Run("an untrusted collector neither changes nor marks", func(t *testing.T) {
		r := completeRig(t, ingest.DefaultBlindingGuard())
		tn := r.newTenant()
		col := r.addCollector(tn, sensor.TrustNew)
		t0 := time.Now().Add(-2 * time.Hour)
		// Its reports are refused at the push gate, so the assets exist
		// only because the tenant imported them.
		r.trustedImport(tn, vcVM("vm01.example.com", "poweredOn"), vcVM("vm02.example.com", "poweredOn"))
		r.sendCollector(tn, col, vcReport("full", t0.Add(time.Hour), vcVM("vm01.example.com", "poweredOff")))
		if s := r.assetState(tn, "vm01.example.com"); s.power != "poweredOn" {
			t.Fatalf("vm01 = %+v: an untrusted collector changed it", s)
		}
		if s := r.assetState(tn, "vm02.example.com"); s.status != "active" {
			t.Fatalf("vm02 = %+v: an untrusted collector marked it", s)
		}
	})

	t.Run("assets of another source or a person's decision are never overwritten", func(t *testing.T) {
		r := completeRig(t, ingest.DefaultBlindingGuard())
		tn := r.newTenant()
		col := r.addCollector(tn, sensor.TrustTrusted)
		t0 := time.Now().Add(-2 * time.Hour)
		// Another source created vm-scan before the collector saw it.
		r.trustedImport(tn, vcVM("vm-scan.example.com", "poweredOn"))
		r.sendCollector(tn, col, vcReport("full", t0, vcVM("vm-scan.example.com", "poweredOn"),
			vcVM("vm-locked.example.com", "poweredOn"), vcVM("vm-pinned.example.com", "poweredOn"), vcVM("vm-keep.example.com", "poweredOn")))
		// A person decided on two of the collector's own assets.
		if _, err := r.db.ExecContext(ctx, `INSERT INTO asset_attribute_sources (tenant_id, asset_id, attribute, source_kind, source_name, value, observed_at)
			SELECT tenant_id, id, 'criticality', 'manual', 'person', 'high', now() FROM assets WHERE tenant_id = $1 AND name = 'vm-locked.example.com'`,
			tn.tenant.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := r.db.ExecContext(ctx, `UPDATE assets SET manual_status_override = true WHERE tenant_id = $1 AND name = 'vm-pinned.example.com'`,
			tn.tenant.String()); err != nil {
			t.Fatal(err)
		}

		r.sendCollector(tn, col, vcReport("full", t0.Add(time.Hour), vcVM("vm-scan.example.com", "poweredOff"),
			vcVM("vm-locked.example.com", "poweredOff"), vcVM("vm-keep.example.com", "poweredOn")))
		if s := r.assetState(tn, "vm-scan.example.com"); s.power != "poweredOn" {
			t.Fatalf("vm-scan = %+v: the collector overwrote another source's asset", s)
		}
		if s := r.assetState(tn, "vm-locked.example.com"); s.power != "poweredOn" {
			t.Fatalf("vm-locked = %+v: the collector overwrote an asset a person decided on", s)
		}
		if s := r.assetState(tn, "vm-pinned.example.com"); s.status != "active" {
			t.Fatalf("vm-pinned = %+v: a manual status override was demoted", s)
		}

		// Another source's asset absent from a complete report is not marked.
		r.sendCollector(tn, col, vcReport("full", t0.Add(90*time.Minute), vcVM("vm-keep.example.com", "poweredOn")))
		if s := r.assetState(tn, "vm-scan.example.com"); s.status != "active" {
			t.Fatalf("vm-scan = %+v: another source's asset was marked not seen", s)
		}
	})

	t.Run("cross tenant: another tenant's assets and sensor are never touched", func(t *testing.T) {
		r := completeRig(t, ingest.DefaultBlindingGuard())
		a, b := r.newTenant(), r.newTenant()
		colA := r.addCollector(a, sensor.TrustTrusted)
		colB := r.addCollector(b, sensor.TrustTrusted)
		t0 := time.Now().Add(-2 * time.Hour)
		r.sendCollector(b, colB, vcReport("full", t0, vcVM("vm01.example.com", "poweredOn"), vcVM("vm02.example.com", "poweredOn")))
		r.sendCollector(a, colA, vcReport("full", t0, vcVM("vm01.example.com", "poweredOn")))
		r.sendCollector(a, colA, vcReport("full", t0.Add(time.Hour), vcVM("vm01.example.com", "poweredOff"), vcVM("vm09.example.com", "poweredOn")))
		for _, n := range []string{"vm01.example.com", "vm02.example.com"} {
			if s := r.assetState(b, n); s.power != "poweredOn" || s.status != "active" {
				t.Fatalf("tenant B %s = %+v: changed by tenant A's collector", n, s)
			}
		}
		// Tenant A's collector reporting into tenant B (a forged tenant; the
		// v2 report row itself is refused by its foreign key, so through the
		// ingest core) is not a trusted collector there: nothing of B's
		// changes.
		r.collect(b.tenant, colA, vcReport("full", t0.Add(2*time.Hour), vcVM("vm01.example.com", "poweredOff")))
		if s := r.assetState(b, "vm01.example.com"); s.power != "poweredOn" {
			t.Fatalf("tenant B vm01 = %+v: changed by another tenant's sensor", s)
		}
		if s := r.assetState(b, "vm02.example.com"); s.status != "active" {
			t.Fatalf("tenant B vm02 = %+v: marked by another tenant's sensor", s)
		}
		var rows int
		if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM collector_assets ca JOIN assets x ON x.id = ca.asset_id
			WHERE x.tenant_id <> ca.tenant_id`).Scan(&rows); err != nil || rows != 0 {
			t.Fatalf("%d collector rows cross a tenant (%v)", rows, err)
		}
	})

	t.Run("replay: an older complete report changes and marks nothing newer", func(t *testing.T) {
		r := completeRig(t, ingest.DefaultBlindingGuard())
		tn := r.newTenant()
		col := r.addCollector(tn, sensor.TrustTrusted)
		t0 := time.Now().Add(-3 * time.Hour)
		old := vcReport("full", t0, vcVM("vm01.example.com", "poweredOn"))
		r.sendCollector(tn, col, old)
		r.sendCollector(tn, col, vcReport("full", t0.Add(2*time.Hour), vcVM("vm01.example.com", "poweredOff"), vcVM("vm02.example.com", "poweredOn")))
		// The old report again, under a new report id.
		r.sendCollector(tn, col, vcReport("full", t0, vcVM("vm01.example.com", "poweredOn")))
		if s := r.assetState(tn, "vm01.example.com"); s.power != "poweredOff" {
			t.Fatalf("vm01 = %+v: an older report overwrote a newer value", s)
		}
		if s := r.assetState(tn, "vm02.example.com"); s.status != "active" {
			t.Fatalf("vm02 = %+v: an older report marked a newer asset not seen", s)
		}
	})

	t.Run("the blinding guard holds a sweep that would drop most assets", func(t *testing.T) {
		r := completeRig(t, ingest.BlindingGuard{Ratio: 0.5, MinFindings: 1})
		tn := r.newTenant()
		col := r.addCollector(tn, sensor.TrustTrusted)
		t0 := time.Now().Add(-2 * time.Hour)
		r.sendCollector(tn, col, vcReport("full", t0, vcVM("vm01.example.com", "poweredOn"), vcVM("vm02.example.com", "poweredOn"),
			vcVM("vm03.example.com", "poweredOn"), vcVM("vm04.example.com", "poweredOn")))
		r.sendCollector(tn, col, vcReport("full", t0.Add(time.Hour), vcVM("vm01.example.com", "poweredOn")))
		for _, n := range []string{"vm02.example.com", "vm03.example.com", "vm04.example.com"} {
			if s := r.assetState(tn, n); s.status != "active" {
				t.Fatalf("%s = %+v: the guard did not hold", n, s)
			}
		}
	})
}

// trustedImport stores assets through a server-side (trusted) ingest: a
// source other than the collector.
func (r *v2Rig) trustedImport(tn v2Tenant, assets ...ctis.Asset) {
	r.t.Helper()
	tid := tn.tenant
	agt := &sensor.Sensor{TenantID: &tid, Status: sensor.SensorStatusActive}
	rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "import"},
		Metadata: ctis.ReportMetadata{Timestamp: time.Now().Add(-3 * time.Hour).UTC()}, Assets: assets}
	out, err := r.svc.Ingest(context.Background(), agt, ingest.Input{Report: rep})
	if err != nil {
		r.t.Fatal(err)
	}
	if len(out.Errors) > 0 {
		r.t.Fatal(out.Errors)
	}
}
