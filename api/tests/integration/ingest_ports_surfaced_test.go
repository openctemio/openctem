package integration

// research/22 P0-6 (22c B6, 17a) through the real ingest on a migrated
// database: a port scan's open ports become open_port service assets with
// an `exposes` edge from the address and a port_open exposure; the scanner's
// host name gets `resolves_to` when the tenant has that name; a port the next
// scan no longer sees is closed (inactive, "disappeared" history, exposure
// resolved); an unchanged rescan writes nothing new; another tenant's report
// for the same address changes nothing here.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/exposurebridge"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestIngest_PortsSurfaced(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("naabu")
	other := r.newTenant("naabu")
	db := &postgres.DB{DB: r.db}
	ctx := context.Background()
	newSvc := func() *ingest.Service {
		svc := ingest.NewService(
			postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
			postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
			postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
			postgres.NewAuditRepository(db), logger.NewNop())
		svc.SetRelationshipRepository(postgres.NewAssetRelationshipRepository(db))
		svc.SetAssetStateHistoryRepository(postgres.NewAssetStateHistoryRepository(db))
		svc.SetAssetExposureProjector(exposurebridge.NewAssetBridge(
			postgres.NewAnnouncingExposureRepository(db, postgres.NewEASMAlerter(db)),
			postgres.NewExposureStateHistoryRepository(db), logger.NewNop()))
		svc.SetPortReconciler(postgres.NewEASMPortRepository(db))
		return svc
	}
	svc := newSvc()
	tid, oid := tn.tenant, other.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	otherAgt := &sensor.Sensor{ID: other.sensor, TenantID: &oid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}

	// The tenant already knows www.ports.example.com.
	if _, err := r.db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, 'www.ports.example.com', 'subdomain', 'active')`,
		shared.NewID().String(), tid.String()); err != nil {
		t.Fatal(err)
	}

	const ip = "203.0.113.77"
	cmd := shared.NewID()
	bound := ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd, Targets: []string{ip}, Tool: "naabu"}
	scanAs := func(a *sensor.Sensor, bind ingest.Binding, ports ...int) {
		t.Helper()
		var list []ctis.PortInfo
		for _, p := range ports {
			list = append(list, ctis.PortInfo{Port: p, Protocol: "tcp", State: "open"})
		}
		rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "naabu"},
			Assets: []ctis.Asset{{ID: "ip-1", Type: ctis.AssetTypeIPAddress, Value: ip,
				Technical: &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{Hostname: "www.ports.example.com", Ports: list}}}},
			Metadata: ctis.ReportMetadata{ID: "rep-" + shared.NewID().String(), Timestamp: time.Now().UTC()}}
		out, err := svc.Ingest(ctx, a, ingest.Input{Report: rep, Options: ingest.Options{Binding: bind}})
		if err != nil || len(out.Errors) > 0 {
			t.Fatalf("Ingest: %v %v", err, out.Errors)
		}
	}
	scan := func(a *sensor.Sensor, ports ...int) { t.Helper(); scanAs(a, bound, ports...) }
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := r.db.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	activePorts := func(tenant shared.ID) int {
		return count(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND asset_type = 'service' AND sub_type = 'open_port'
			AND status = 'active' AND deleted_at IS NULL`, tenant.String())
	}
	openExposures := func(tenant shared.ID) int {
		return count(`SELECT count(*) FROM exposure_events WHERE tenant_id = $1 AND event_type = 'port_open' AND state = 'active'`, tenant.String())
	}
	announced := func(tenant shared.ID) int {
		var n int
		_ = r.db.QueryRowContext(ctx, `SELECT COALESCE(SUM((metadata->>'count')::int), 0) FROM notification_outbox
			WHERE tenant_id = $1 AND aggregate_type = 'easm_digest'`, tenant.String()).Scan(&n)
		return n + count(`SELECT count(*) FROM notification_outbox WHERE tenant_id = $1 AND aggregate_type = 'exposure'
			AND metadata->>'event_type' = 'port_open'`, tenant.String())
	}
	history := func(tenant shared.ID, change string) int {
		return count(`SELECT count(*) FROM asset_state_history h JOIN assets a ON a.id = h.asset_id
			WHERE h.tenant_id = $1 AND a.sub_type = 'open_port' AND h.change_type = $2`, tenant.String(), change)
	}

	scan(agt, 80, 8080)
	if activePorts(tid) != 2 || openExposures(tid) != 2 || history(tid, "appeared") != 2 {
		t.Fatalf("first scan: ports=%d exposures=%d appeared=%d", activePorts(tid), openExposures(tid), history(tid, "appeared"))
	}
	if n := count(`SELECT count(*) FROM asset_relationships rel JOIN assets a ON a.id = rel.source_asset_id
		WHERE rel.tenant_id = $1 AND rel.relationship_type = 'exposes' AND a.name = $2`, tid.String(), ip); n != 2 {
		t.Fatalf("exposes edges = %d", n)
	}
	if n := count(`SELECT count(*) FROM asset_relationships rel JOIN assets a ON a.id = rel.source_asset_id
		WHERE rel.tenant_id = $1 AND rel.relationship_type = 'resolves_to' AND a.name = 'www.ports.example.com'`, tid.String()); n != 1 {
		t.Fatalf("resolves_to edges = %d", n)
	}

	// Each new open port is announced once (info: the daily digest, P0-7).
	if got := announced(tid); got != 2 {
		t.Fatalf("announced = %d, want 2", got)
	}

	// Unchanged rescan: nothing new.
	scan(agt, 80, 8080)
	if got := announced(tid); got != 2 {
		t.Fatalf("a rescan announced again: %d", got)
	}
	if activePorts(tid) != 2 || openExposures(tid) != 2 || history(tid, "appeared") != 2 || history(tid, "disappeared") != 0 {
		t.Fatalf("unchanged rescan wrote something: ports=%d exposures=%d", activePorts(tid), openExposures(tid))
	}

	// Another tenant scans the same address with nothing on 8080: tenant A unaffected.
	scan(otherAgt, 80)
	if activePorts(tid) != 2 || openExposures(tid) != 2 || announced(tid) != 2 {
		t.Fatal("tenant B's scan changed tenant A's ports or alerts")
	}

	// A report not bound to a command on this address (unsolicited) may not
	// change it, so it closes nothing (RFC-040 §5.3).
	scanAs(agt, ingest.Binding{}, 80)
	if activePorts(tid) != 2 || history(tid, "disappeared") != 0 {
		t.Fatal("an unsolicited report closed ports")
	}

	// 8080 closed.
	scan(agt, 80)
	if activePorts(tid) != 1 || openExposures(tid) != 1 || history(tid, "disappeared") != 1 {
		t.Fatalf("close: ports=%d exposures=%d disappeared=%d", activePorts(tid), openExposures(tid), history(tid, "disappeared"))
	}
	if n := count(`SELECT count(*) FROM exposure_events e JOIN assets a ON a.id = e.asset_id
		WHERE e.tenant_id = $1 AND a.name = $2 AND e.state = 'resolved'`, tid.String(), ip+":8080:tcp"); n != 1 {
		t.Fatalf("closed port exposure resolved = %d", n)
	}
	// Reopened: active again, exposure active again.
	scan(agt, 80, 8080)
	if activePorts(tid) != 2 || openExposures(tid) != 2 || history(tid, "recovered") != 1 {
		t.Fatalf("reopen: ports=%d exposures=%d recovered=%d", activePorts(tid), openExposures(tid), history(tid, "recovered"))
	}
}
