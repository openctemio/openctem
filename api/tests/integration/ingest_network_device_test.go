package integration

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A network device reported by its address lands on the tenant's device
// that records that address: inside the trust window, only one device, only
// devices, never another tenant's.
func TestIngest_NetworkDeviceMatchedByIP(t *testing.T) {
	r := newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		svc.SetCorrelator(ingest.NewAssetCorrelator(postgres.NewAssetRepository(db), logger.NewNop(), ingest.CorrelationConfig{}))
	})
	ctx := context.Background()
	device := func(name, sub string, ips ...string) ctis.Asset {
		list := make([]any, 0, len(ips))
		for _, ip := range ips {
			list = append(list, ip)
		}
		return ctis.Asset{ID: name, Type: ctis.AssetTypeNetwork, Value: name, Name: name,
			Properties: ctis.Properties{"sub_type": sub, "ip_addresses": list}}
	}
	send := func(tn v2Tenant, tool string, assets ...ctis.Asset) {
		t.Helper()
		tid := tn.tenant
		agt := &sensor.Sensor{TenantID: &tid, Status: sensor.SensorStatusActive}
		rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: tool},
			Metadata: ctis.ReportMetadata{Timestamp: time.Now().UTC()}, Assets: assets}
		out, err := r.svc.Ingest(ctx, agt, ingest.Input{Report: rep})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Errors) > 0 {
			t.Fatal(out.Errors)
		}
	}
	count := func(tn v2Tenant) int {
		t.Helper()
		var n int
		if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM assets WHERE tenant_id = $1 AND asset_type = 'network'`,
			tn.tenant.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	a, b := r.newTenant(), r.newTenant()
	send(b, "prtg", device("core-sw-01", "switch", "192.0.2.1"))
	send(a, "prtg", device("core-sw-01", "switch", "192.0.2.1"), device("edge-fw-01", "firewall", "192.0.2.9"),
		device("office-lan", "subnet", "192.0.2.20"))

	// The log collector names the switch by its address: same device.
	send(a, "splunk", device("192.0.2.1", "switch", "192.0.2.1"))
	if n := count(a); n != 3 {
		t.Fatalf("tenant A network assets = %d, want 3 (the switch matched by address)", n)
	}
	var byAddress int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM assets WHERE tenant_id = $1 AND name = '192.0.2.1'`,
		a.tenant.String()).Scan(&byAddress); err != nil || byAddress != 0 {
		t.Fatalf("a second asset named by the address exists (%d, %v)", byAddress, err)
	}
	// Tenant B's switch with the same address is its own.
	if n := count(b); n != 1 {
		t.Fatalf("tenant B network assets = %d, want 1", n)
	}

	// A segment is never matched by address.
	send(a, "splunk", device("192.0.2.20", "switch", "192.0.2.20"))
	if n := count(a); n != 4 {
		t.Fatalf("tenant A network assets = %d, want 4 (a segment is not a device)", n)
	}

	// A device last seen outside the trust window does not match.
	if _, err := r.db.ExecContext(ctx, `UPDATE assets SET last_seen = now() - interval '30 days' WHERE tenant_id = $1 AND name = 'edge-fw-01'`,
		a.tenant.String()); err != nil {
		t.Fatal(err)
	}
	send(a, "splunk", device("192.0.2.9", "firewall", "192.0.2.9"))
	if n := count(a); n != 5 {
		t.Fatalf("tenant A network assets = %d, want 5 (stale device not matched)", n)
	}

	// Two devices with one address: ambiguous, no match.
	send(a, "prtg", device("dist-sw-02", "switch", "192.0.2.30"), device("dist-sw-03", "switch", "192.0.2.30"))
	send(a, "splunk", device("192.0.2.30", "switch", "192.0.2.30"))
	if n := count(a); n != 8 {
		t.Fatalf("tenant A network assets = %d, want 8 (ambiguous address not matched)", n)
	}
}
