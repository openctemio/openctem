package integration

// Set-valued asset attributes reconciled per source (RFC-069 §13) through
// the real ingest on a migrated database: a partial scan never removes what
// lies outside its coverage; the same source observing the same coverage
// again without an element removes it; another source keeps it; a source
// past its TTL stops counting; flapping folds into one timeline event; a
// re-sighting writes nothing; and nothing crosses tenants.

import (
	"context"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/openctemio/ctis"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// wireSetReconciliation wires attribute and set reconciliation (which also
// closes the open ports a port scan no longer sees) into an ingest service.
func wireSetReconciliation(svc *ingest.Service, db *postgres.DB) *assetapp.AssetService {
	assets := assetapp.NewAssetService(postgres.NewAssetRepository(db), logger.NewNop())
	assets.SetAttributeSources(postgres.NewAssetAttributeSourceRepository(db), postgres.NewTenantRepository(db))
	assets.SetAttributeSourceLister(postgres.NewAssetChangeEventRepository(db))
	assets.SetStateHistoryRepository(postgres.NewAssetStateHistoryRepository(db))
	svc.SetAttributeReconciler(assets)
	return assets
}

type setRig struct {
	t      *testing.T
	r      *v2Rig
	tn     v2Tenant
	assets *assetapp.AssetService
}

func newSetRig(t *testing.T) *setRig {
	t.Helper()
	var assets *assetapp.AssetService
	r := newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		assets = wireSetReconciliation(svc, db)
	})
	return &setRig{t: t, r: r, tn: r.newTenant("naabu", "nmap", "dnsx", "httpx"), assets: assets}
}

// send ingests one asset from tool, bound to a command on target with the
// given port settings, as the tenant's sensor.
func (g *setRig) send(tn v2Tenant, tool string, observed time.Time, jobPorts string, a ctis.Asset) {
	g.t.Helper()
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	cmd := shared.NewID()
	bind := ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd, Targets: []string{a.Value}, Tool: tool, JobPorts: jobPorts}
	rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: tool}, Assets: []ctis.Asset{a},
		Metadata: ctis.ReportMetadata{ID: "rep-" + shared.NewID().String(), Timestamp: observed}}
	out, err := g.r.svc.Ingest(context.Background(), agt, ingest.Input{Report: rep, Options: ingest.Options{Binding: bind}})
	if err != nil || len(out.Errors) > 0 {
		g.t.Fatalf("Ingest: %v %v", err, out.Errors)
	}
}

func (g *setRig) portScan(tn v2Tenant, tool, ip string, observed time.Time, jobPorts string, ports ...int) {
	g.t.Helper()
	list := make([]ctis.PortInfo, 0, len(ports))
	for _, p := range ports {
		list = append(list, ctis.PortInfo{Port: p, Protocol: "tcp", State: "open"})
	}
	g.send(tn, tool, observed, jobPorts, ctis.Asset{ID: "ip", Type: ctis.AssetTypeIPAddress, Value: ip,
		Technical: &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{Ports: list}}})
}

func (g *setRig) activePorts(tn v2Tenant, ip string) map[string]bool {
	g.t.Helper()
	rows, err := g.r.db.QueryContext(context.Background(), `
		SELECT name FROM assets WHERE tenant_id = $1 AND sub_type = 'open_port' AND status = 'active'
		   AND properties->>'host' = $2`, tn.tenant.String(), ip)
	if err != nil {
		g.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		out[n] = true
	}
	if err := rows.Err(); err != nil {
		g.t.Fatal(err)
	}
	return out
}

func (g *setRig) ips(tn v2Tenant, name string) []string {
	g.t.Helper()
	var list pq.StringArray
	if err := g.r.db.QueryRowContext(context.Background(), `
		SELECT COALESCE(ARRAY(SELECT jsonb_array_elements_text(properties->'ip_addresses') ORDER BY 1), '{}')
		  FROM assets WHERE tenant_id = $1 AND name = $2`, tn.tenant.String(), name).Scan(&list); err != nil {
		g.t.Fatalf("read %s: %v", name, err)
	}
	return list
}

type setEvent struct {
	added, removed pq.StringArray
	reason, source string
	flaps          int
}

func (g *setRig) events(tn v2Tenant, name, attr string) []setEvent {
	g.t.Helper()
	rows, err := g.r.db.QueryContext(context.Background(), `
		SELECT COALESCE(e.added, '{}'), COALESCE(e.removed, '{}'), e.reason, e.source_name, e.flap_count
		  FROM asset_change_events e JOIN assets a ON a.tenant_id = e.tenant_id AND a.id = e.asset_id
		 WHERE e.tenant_id = $1 AND a.name = $2 AND e.attribute = $3
		 ORDER BY e.created_at, e.at`, tn.tenant.String(), name, attr)
	if err != nil {
		g.t.Fatal(err)
	}
	defer rows.Close()
	var out []setEvent
	for rows.Next() {
		var e setEvent
		if err := rows.Scan(&e.added, &e.removed, &e.reason, &e.source, &e.flaps); err != nil {
			g.t.Fatal(err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		g.t.Fatal(err)
	}
	return out
}

func TestAssetSets_PortCoverage(t *testing.T) {
	g := newSetRig(t)
	const ip = "203.0.113.120"
	now := time.Now().UTC()
	port := func(p string) string { return ip + ":" + p + ":tcp" }

	g.portScan(g.tn, "naabu", ip, now.Add(-50*time.Minute), "full", 80, 8443)
	if got := g.activePorts(g.tn, ip); !got[port("80")] || !got[port("8443")] {
		t.Fatalf("after the full scan: %v", got)
	}

	// A partial scan (1-1000) of the same source does not see 8443, which is
	// outside its range: it stays open.
	g.portScan(g.tn, "naabu", ip, now.Add(-40*time.Minute), "1-1000", 80)
	if got := g.activePorts(g.tn, ip); !got[port("8443")] {
		t.Fatalf("a 1-1000 scan closed 8443: %v", got)
	}
	// A top-100 scan names no ports: it covers only what an earlier top-100
	// scan found, never what the full scan found.
	g.portScan(g.tn, "naabu", ip, now.Add(-35*time.Minute), "top-100", 80)
	if got := g.activePorts(g.tn, ip); !got[port("8443")] {
		t.Fatalf("a top-100 scan closed 8443: %v", got)
	}

	// Another source (nmap) finds 22.
	g.portScan(g.tn, "nmap", ip, now.Add(-30*time.Minute), "22", 22)
	// The same source scans the same (full) range again without 8443: it
	// closes. 22 is outside naabu's records: nmap still reports it, it stays.
	g.portScan(g.tn, "naabu", ip, now.Add(-20*time.Minute), "full", 80)
	got := g.activePorts(g.tn, ip)
	if got[port("8443")] || !got[port("80")] || !got[port("22")] {
		t.Fatalf("after the second full scan: %v (want 80 and 22, 8443 closed)", got)
	}
	evs := g.events(g.tn, ip, "open_ports")
	last := evs[len(evs)-1]
	if len(last.removed) != 1 || last.removed[0] != "8443/tcp" || last.source != "naabu" || last.reason != "newer_observation" {
		t.Fatalf("removal event = %+v", last)
	}

	// A delayed older full scan from naabu (before 8443 was removed) does
	// not bring it back.
	g.portScan(g.tn, "naabu", ip, now.Add(-45*time.Minute), "full", 80, 8443)
	if got := g.activePorts(g.tn, ip); got[port("8443")] {
		t.Fatalf("a delayed older scan reopened 8443: %v", got)
	}

	// nmap is not re-seen within the scan TTL (30 days): 22 leaves the set
	// on the daily re-resolution, with the reason.
	if _, err := g.r.db.ExecContext(context.Background(), `
		UPDATE asset_attribute_set_elements SET first_seen = now() - interval '40 days', last_seen = now() - interval '40 days'
		 WHERE tenant_id = $1 AND source_name = 'nmap'`, g.tn.tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := g.assets.ReResolveTenant(context.Background(), g.tn.tenant, ""); err != nil {
		t.Fatal(err)
	}
	if got := g.activePorts(g.tn, ip); got[port("22")] || !got[port("80")] {
		t.Fatalf("after the TTL: %v (want only 80)", got)
	}
	evs = g.events(g.tn, ip, "open_ports")
	if last := evs[len(evs)-1]; len(last.removed) != 1 || last.removed[0] != "22/tcp" || last.reason != "ttl_expiry" {
		t.Fatalf("TTL event = %+v", last)
	}
	// A second sweep changes nothing more.
	before := len(evs)
	if _, err := g.assets.ReResolveTenant(context.Background(), g.tn.tenant, ""); err != nil {
		t.Fatal(err)
	}
	if n := len(g.events(g.tn, ip, "open_ports")); n != before {
		t.Fatalf("a second sweep wrote %d more events", n-before)
	}
}

func TestAssetSets_IPAddresses(t *testing.T) {
	g := newSetRig(t)
	const name = "www.sets.example.com"
	now := time.Now().UTC()
	resolve := func(tool string, at time.Time, ips ...string) {
		t.Helper()
		list := make([]any, 0, len(ips))
		for _, ip := range ips {
			list = append(list, ip)
		}
		g.send(g.tn, tool, at, "", ctis.Asset{ID: "d", Type: ctis.AssetTypeDomain, Value: name,
			Properties: ctis.Properties{"ip_addresses": list}})
	}
	elementRows := func() (n int, maxUpdated time.Time) {
		t.Helper()
		if err := g.r.db.QueryRowContext(context.Background(), `
			SELECT count(*), COALESCE(max(updated_at), 'epoch') FROM asset_attribute_set_elements
			 WHERE tenant_id = $1 AND attribute = 'ip_addresses'`, g.tn.tenant.String()).Scan(&n, &maxUpdated); err != nil {
			t.Fatal(err)
		}
		return n, maxUpdated
	}

	resolve("dnsx", now.Add(-50*time.Minute), "198.51.100.1", "198.51.100.2")
	if got := g.ips(g.tn, name); len(got) != 2 {
		t.Fatalf("after the first resolution: %v", got)
	}

	// A re-sighting within the hour: no event, no element write.
	n0, upd0 := elementRows()
	events0 := len(g.events(g.tn, name, "ip_addresses"))
	resolve("dnsx", now.Add(-45*time.Minute), "198.51.100.2", "198.51.100.1")
	if n, upd := elementRows(); n != n0 || !upd.Equal(upd0) {
		t.Fatalf("a re-sighting wrote element rows (%d→%d)", n0, n)
	}
	if n := len(g.events(g.tn, name, "ip_addresses")); n != events0 {
		t.Fatalf("a re-sighting wrote %d events", n-events0)
	}

	// A web probe reports the one address it connected to: a sighting that
	// removes nothing.
	resolve("httpx", now.Add(-40*time.Minute), "198.51.100.1")
	if got := g.ips(g.tn, name); len(got) != 2 {
		t.Fatalf("a partial sighting removed an address: %v", got)
	}

	// dnsx resolves the name again without .2: removed. Then .2 again, and
	// gone again, within the hour: one event with the flap count.
	resolve("dnsx", now.Add(-30*time.Minute), "198.51.100.1")
	if got := g.ips(g.tn, name); len(got) != 1 || got[0] != "198.51.100.1" {
		t.Fatalf("after the re-resolution: %v", got)
	}
	resolve("dnsx", now.Add(-20*time.Minute), "198.51.100.1", "198.51.100.2")
	resolve("dnsx", now.Add(-10*time.Minute), "198.51.100.1")
	evs := g.events(g.tn, name, "ip_addresses")
	if len(evs) != events0+1 {
		t.Fatalf("flapping wrote %d events, want one: %+v", len(evs)-events0, evs)
	}
	if last := evs[len(evs)-1]; last.flaps != 3 || len(last.removed) != 1 || last.removed[0] != "198.51.100.2" {
		t.Fatalf("folded event = %+v (want removed .2, 3 flips)", last)
	}

	// An older report delivered late never brings .2 back.
	resolve("dnsx", now.Add(-55*time.Minute), "198.51.100.1", "198.51.100.2")
	if got := g.ips(g.tn, name); len(got) != 1 {
		t.Fatalf("a delayed older resolution brought an address back: %v", got)
	}
}

func TestAssetSets_TenantIsolation(t *testing.T) {
	g := newSetRig(t)
	other := g.r.newTenant("naabu")
	const ip = "203.0.113.121"
	now := time.Now().UTC()
	g.portScan(g.tn, "naabu", ip, now.Add(-30*time.Minute), "full", 80, 443)
	// Another tenant scans the same address and finds nothing on 443.
	g.portScan(other, "naabu", ip, now.Add(-20*time.Minute), "full", 80)
	if got := g.activePorts(g.tn, ip); len(got) != 2 {
		t.Fatalf("tenant B's scan changed tenant A's ports: %v", got)
	}

	// A set observation naming tenant A's asset under tenant B is dropped.
	var aID string
	if err := g.r.db.QueryRowContext(context.Background(), `SELECT id FROM assets WHERE tenant_id = $1 AND name = $2`,
		g.tn.tenant.String(), ip).Scan(&aID); err != nil {
		t.Fatal(err)
	}
	id, _ := shared.IDFromString(aID)
	repo := postgres.NewAssetAttributeSourceRepository(&postgres.DB{DB: g.r.db})
	res, err := repo.ApplySets(context.Background(), other.tenant, asset.SetApply{
		Observations: []asset.SetObservation{{AssetID: id, Attribute: asset.SetAttrOpenPorts, Kind: asset.SourceKindScan,
			Name: "naabu", ObservedAt: now, Coverage: asset.PortScanCoverage("full", ""), Elements: []string{"80/tcp"}}},
		Policy: asset.DefaultReconciliationPolicy(), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Changes) != 0 || res.Events != 0 {
		t.Fatalf("cross-tenant apply changed something: %+v", res)
	}
	if got := g.activePorts(g.tn, ip); len(got) != 2 {
		t.Fatalf("cross-tenant apply closed tenant A's ports: %v", got)
	}
	if rows, err := repo.ListSetElements(context.Background(), other.tenant, id); err != nil || len(rows) != 0 {
		t.Fatalf("tenant B reads tenant A's elements: %v %v", rows, err)
	}
}
