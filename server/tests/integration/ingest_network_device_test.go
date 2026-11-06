package integration

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/internal/app/ingest"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// A network device reported by its address lands on the tenant's device
// that records that address: inside the trust window, only one device, only
// devices, never another tenant's. A device's addresses come from its
// has_address relationships; the reports come from a sensor, so a producer's
// ip_addresses property is stripped and never matches.
func TestIngest_NetworkDeviceMatchedByIP(t *testing.T) {
	r := newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		svc.SetCorrelator(ingest.NewAssetCorrelator(postgres.NewAssetRepository(db), logger.NewNop(), ingest.CorrelationConfig{}))
	})
	ctx := context.Background()
	// reported is one asset of a report and the has_address edges (with their
	// ip_address assets) that give it addresses.
	type reported struct {
		assets []ctis.Asset
		rels   []ctis.Relationship
	}
	device := func(name, sub string, ips ...string) reported {
		if sub == "subnet" {
			// A range never records addresses: a producer property is all it
			// could carry, and it is dropped.
			return reported{assets: []ctis.Asset{{ID: "a-" + name, Type: ctis.AssetTypeIPRange, Value: name,
				Properties: ctis.Properties{"ip_addresses": []any{ips[0]}}}}}
		}
		out := reported{assets: []ctis.Asset{{ID: "a-" + name, Type: ctis.AssetTypeNetworkDevice, Value: name,
			Technical: &ctis.AssetTechnical{NetworkDevice: &ctis.NetworkDeviceTechnical{Kind: ctis.NetworkDeviceKind(sub)}}}}}
		for _, ip := range ips {
			if ip == name {
				continue // named by its address: the name is the address
			}
			out.assets = append(out.assets, ctis.Asset{ID: "ip-" + ip, Type: ctis.AssetTypeIPAddress, Value: ip})
			out.rels = append(out.rels, ctis.Relationship{Type: ctis.RelHasAddress, FromRef: "a-" + name, ToRef: "ip-" + ip})
		}
		return out
	}
	// propsOnly is a device whose producer put its address in properties.
	propsOnly := func(name, sub, ip string) reported {
		return reported{assets: []ctis.Asset{{ID: "a-" + name, Type: ctis.AssetTypeNetworkDevice, Value: name,
			Technical:  &ctis.AssetTechnical{NetworkDevice: &ctis.NetworkDeviceTechnical{Kind: ctis.NetworkDeviceKind(sub)}},
			Properties: ctis.Properties{"ip_addresses": []any{ip}}}}}
	}
	send := func(tn v2Tenant, tool string, items ...reported) {
		t.Helper()
		tid := tn.tenant
		agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
		var assets []ctis.Asset
		var rels []ctis.Relationship
		seen := map[string]bool{}
		for _, it := range items {
			for _, as := range it.assets {
				if !seen[as.ID] { // one ip_address asset per address
					seen[as.ID] = true
					assets = append(assets, as)
				}
			}
			rels = append(rels, it.rels...)
		}
		rep := &ctis.Report{Version: ctis.SchemaVersion, Tool: &ctis.Tool{Name: tool},
			Metadata: ctis.ReportMetadata{ID: ctis.NewReportID(), GeneratedAt: time.Now().UTC()}, Assets: assets, Relationships: rels}
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
		device("192.0.2.16/28", "subnet", "192.0.2.20"))

	// lastSeenDaysAgo is how long ago a device was last seen: matching a
	// report to it refreshes it. A device named by its address shares its
	// name with the ip_address asset its has_address edge recorded (names
	// are unique per tenant), so these cases check the device, not a count.
	lastSeenDaysAgo := func(name string) float64 {
		t.Helper()
		var days float64
		if err := r.db.QueryRowContext(ctx, `SELECT extract(epoch FROM now() - last_seen) / 86400 FROM assets
			WHERE tenant_id = $1 AND asset_type = 'network' AND name = $2`, a.tenant.String(), name).Scan(&days); err != nil {
			t.Fatal(err)
		}
		return days
	}
	age := func(days int, names ...string) {
		t.Helper()
		for _, n := range names {
			if _, err := r.db.ExecContext(ctx, `UPDATE assets SET last_seen = now() - make_interval(days => $3)
				WHERE tenant_id = $1 AND asset_type = 'network' AND name = $2`, a.tenant.String(), n, days); err != nil {
				t.Fatal(err)
			}
		}
	}

	// The log collector names the switch by its address: same device.
	age(2, "core-sw-01")
	send(a, "splunk", device("192.0.2.1", "switch", "192.0.2.1"))
	if d := lastSeenDaysAgo("core-sw-01"); d > 1 {
		t.Fatalf("the switch was not matched by its address (last seen %.1f days ago)", d)
	}
	if n := count(a); n != 3 {
		t.Fatalf("tenant A network assets = %d, want 3 (the switch matched by address)", n)
	}
	var byAddress int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM assets WHERE tenant_id = $1 AND asset_type = 'network' AND name = '192.0.2.1'`,
		a.tenant.String()).Scan(&byAddress); err != nil || byAddress != 0 {
		t.Fatalf("a second asset named by the address exists (%d, %v)", byAddress, err)
	}
	// Tenant B's switch with the same address is its own.
	if n := count(b); n != 1 {
		t.Fatalf("tenant B network assets = %d, want 1", n)
	}

	// A producer's ip_addresses property is ignored: a device stating the
	// switch's address only there is a device of its own.
	send(a, "splunk", propsOnly("rogue-sw", "switch", "192.0.2.1"))
	if n := count(a); n != 4 {
		t.Fatalf("tenant A network assets = %d, want 4 (properties.ip_addresses matched a device)", n)
	}

	// A segment is never matched by address.
	send(a, "splunk", device("192.0.2.20", "switch", "192.0.2.20"))
	if n := count(a); n != 5 {
		t.Fatalf("tenant A network assets = %d, want 5 (a segment is not a device)", n)
	}

	// A device last seen outside the trust window does not match.
	age(30, "edge-fw-01")
	send(a, "splunk", device("192.0.2.9", "firewall", "192.0.2.9"))
	if d := lastSeenDaysAgo("edge-fw-01"); d < 29 {
		t.Fatalf("stale device matched: last seen %.1f days ago, want about 30", d)
	}

	// Two devices with one address: ambiguous, no match.
	send(a, "prtg", device("dist-sw-02", "switch", "192.0.2.30"), device("dist-sw-03", "switch", "192.0.2.30"))
	age(2, "dist-sw-02", "dist-sw-03") // inside the window
	send(a, "splunk", device("192.0.2.30", "switch", "192.0.2.30"))
	for _, n := range []string{"dist-sw-02", "dist-sw-03"} {
		if d := lastSeenDaysAgo(n); d < 1.5 {
			t.Fatalf("ambiguous address matched %s (last seen %.1f days ago)", n, d)
		}
	}
	// Control: one device with the address inside the window is matched.
	send(a, "prtg", device("dist-sw-04", "switch", "192.0.2.40"))
	age(2, "dist-sw-04")
	send(a, "splunk", device("192.0.2.40", "switch", "192.0.2.40"))
	if d := lastSeenDaysAgo("dist-sw-04"); d > 1 {
		t.Fatalf("the only device with the address was not matched (last seen %.1f days ago)", d)
	}
}
