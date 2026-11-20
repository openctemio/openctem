package integration

// Provider shared addresses a name resolves to (research/531 D1), through
// the real ingest on a migrated database:
//   - an address inside a published shared provider range seen only as a
//     name's DNS answer gets no address asset and no resolves_to edge; it is
//     recorded on the name per source with first and last seen, and the
//     receipt counts it;
//   - a later resolution without it keeps the history (removed_at set);
//   - a dedicated address keeps today's path (asset and edge);
//   - an address a scan reports results on itself is still recorded, as a
//     dependency (the provider's);
//   - the name stays capped to the web ports by the shared address it
//     resolves to, even with a dedicated address beside it;
//   - nothing crosses tenants.

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	assetapp "github.com/openctemio/openctem/server/internal/app/asset"
	"github.com/openctemio/openctem/server/internal/app/easm"
	"github.com/openctemio/openctem/server/internal/app/ingest"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/attribution"
	"github.com/openctemio/openctem/server/pkg/domain/edgeaddr"
	"github.com/openctemio/openctem/server/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

const (
	// Inside the built-in dataset's shared ranges (Microsoft 365 mail front
	// ends, Amazon CloudFront edge).
	m365Addr       = "13.107.128.10"
	cloudfrontAddr = "3.11.53.20"
	// Documentation range: never a provider's.
	dedicatedAddr = "198.51.100.77"
)

func TestIngest_ProviderAddressesRecordedOnName(t *testing.T) {
	for _, a := range []string{m365Addr, cloudfrontAddr} {
		if _, ok := edgeaddr.Default().SharedFrontEnd(a); !ok {
			t.Fatalf("test address %s is not inside a shared range of the built-in dataset", a)
		}
	}
	if _, ok := edgeaddr.Default().SharedFrontEnd(dedicatedAddr); ok {
		t.Fatalf("test address %s is shared", dedicatedAddr)
	}

	var attr *postgres.AttributionRepository
	r := newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		wireSetReconciliation(svc, db)
		svc.SetRelationshipRepository(postgres.NewAssetRelationshipRepository(db))
		svc.SetReceiptRecorder(postgres.NewIngestReceiptRepository(db))
		attr = postgres.NewAttributionRepository(db)
		svc.SetScanAttributionStamper(easm.NewScanStamper(attr, postgres.NewVerifiedDomainNameRepository(db)))
	})
	g := &setRig{t: t, r: r, tn: r.newTenant("dnsx", "naabu")}
	other := r.newTenant("dnsx")
	ctx := context.Background()
	const name = "mail.example.com"
	now := time.Now().UTC()

	// resolve ingests a dnsx answer for the name as the tenant's sensor, on
	// a platform receipt of its own; it returns how many addresses the
	// ingest recorded on the name.
	resolve := func(tn v2Tenant, at time.Time, ips ...string) int {
		t.Helper()
		tid := tn.tenant
		agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
		cmd := shared.NewID()
		rep := &ctis.Report{Version: ctis.SchemaVersion, Tool: &ctis.Tool{Name: "dnsx"},
			Assets:   []ctis.Asset{{ID: "d", Type: ctis.AssetTypeDomainName, Value: name, Technical: dnsAddrs(name, ips...)}},
			Metadata: ctis.ReportMetadata{ID: ctis.NewReportID(), GeneratedAt: at}}
		out, err := r.svc.Ingest(ctx, agt, ingest.Input{Report: rep, Options: ingest.Options{
			Binding: ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd, Targets: []string{name}, Tool: "dnsx"},
			Receipt: &ingestreceipt.Source{Kind: ingestreceipt.SourcePlatform, Ref: shared.NewID().String()},
		}})
		if err != nil || len(out.Errors) > 0 {
			t.Fatalf("ingest: %v %v", err, out)
		}
		return out.AddressesOnName
	}
	assetCount := func(tn v2Tenant, n string) int {
		t.Helper()
		var c int
		if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM assets WHERE tenant_id = $1 AND name = $2`,
			tn.tenant.String(), n).Scan(&c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	edgesTo := func(tn v2Tenant, ip string) int {
		t.Helper()
		var c int
		if err := r.db.QueryRowContext(ctx, `
			SELECT count(*) FROM asset_relationships rel
			  JOIN assets d ON d.id = rel.source_asset_id AND d.tenant_id = rel.tenant_id
			  JOIN assets ip ON ip.id = rel.target_asset_id AND ip.tenant_id = rel.tenant_id
			 WHERE rel.tenant_id = $1 AND rel.relationship_type = 'resolves_to' AND d.name = $2 AND ip.name = $3`,
			tn.tenant.String(), name, ip).Scan(&c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	type element struct {
		first, last time.Time
		removed     sql.NullTime
	}
	elementOf := func(tn v2Tenant, ip string) (element, bool) {
		t.Helper()
		var e element
		err := r.db.QueryRowContext(ctx, `
			SELECT el.first_seen, el.last_seen, el.removed_at FROM asset_attribute_set_elements el
			  JOIN assets a ON a.id = el.asset_id AND a.tenant_id = el.tenant_id
			 WHERE el.tenant_id = $1 AND a.name = $2 AND el.attribute = 'ip_addresses'
			   AND el.source_name = 'dnsx' AND el.element = $3`, tn.tenant.String(), name, ip).
			Scan(&e.first, &e.last, &e.removed)
		if err == sql.ErrNoRows {
			return e, false
		}
		if err != nil {
			t.Fatal(err)
		}
		return e, true
	}
	onName := func(tn v2Tenant) int {
		t.Helper()
		var n int
		if err := r.db.QueryRowContext(ctx, `SELECT COALESCE(sum(addresses_on_name), 0) FROM ingest_receipts WHERE tenant_id = $1`,
			tn.tenant.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	first := now.Add(-6 * time.Hour)
	if n := resolve(g.tn, first, m365Addr, cloudfrontAddr, dedicatedAddr); n != 2 {
		t.Fatalf("ingest recorded %d addresses on the name, want 2", n)
	}

	// The provider addresses: no asset, no edge, recorded on the name.
	for _, ip := range []string{m365Addr, cloudfrontAddr} {
		if n := assetCount(g.tn, ip); n != 0 {
			t.Fatalf("shared address %s became %d asset(s)", ip, n)
		}
		e, ok := elementOf(g.tn, ip)
		if !ok {
			t.Fatalf("shared address %s not recorded on the name", ip)
		}
		if !e.first.Equal(first.Round(time.Microsecond)) || e.removed.Valid {
			t.Fatalf("shared address %s element = %+v, want first seen %v and current", ip, e, first)
		}
	}
	if got := g.ips(g.tn, name); !slices.Contains(got, m365Addr) || !slices.Contains(got, dedicatedAddr) {
		t.Fatalf("the name's addresses = %v, want the provider and the dedicated address", got)
	}
	// The dedicated address keeps today's path.
	if assetCount(g.tn, dedicatedAddr) != 1 || edgesTo(g.tn, dedicatedAddr) != 1 {
		t.Fatalf("dedicated address: %d asset(s), %d edge(s), want 1 and 1",
			assetCount(g.tn, dedicatedAddr), edgesTo(g.tn, dedicatedAddr))
	}
	if n := onName(g.tn); n != 2 {
		t.Fatalf("receipt counts %d addresses recorded on the name, want 2", n)
	}

	// The name stays capped by its shared address: it is among the
	// addresses the gate reads, beside the dedicated one.
	addrs, err := attr.AddressesOf(ctx, g.tn.tenant, []string{name})
	if err != nil {
		t.Fatal(err)
	}
	if got := addrs[name]; !slices.Contains(got, m365Addr) || !slices.Contains(got, dedicatedAddr) {
		t.Fatalf("addresses behind the name = %v, want the shared and the dedicated address", got)
	}

	// The resolver sees the name again (hours later: a re-sighting within
	// the hour writes nothing) without the CloudFront address:
	// history kept, last seen moves for the one still there.
	later := now.Add(-4 * time.Hour)
	resolve(g.tn, later, m365Addr, dedicatedAddr)
	e, ok := elementOf(g.tn, cloudfrontAddr)
	if !ok || !e.removed.Valid || !e.first.Equal(first.Round(time.Microsecond)) {
		t.Fatalf("CloudFront element after it left = %+v (found %v), want kept with removed_at", e, ok)
	}
	if e, _ := elementOf(g.tn, m365Addr); !e.last.Equal(later.Round(time.Microsecond)) || e.removed.Valid {
		t.Fatalf("Microsoft 365 element = %+v, want last seen %v", e, later)
	}
	if n := assetCount(g.tn, cloudfrontAddr) + assetCount(g.tn, m365Addr); n != 0 {
		t.Fatalf("a re-resolution created %d provider address assets", n)
	}

	// A scan that reports a result on the shared address itself: the
	// address is recorded as an asset, the provider's (dependency).
	host := ctis.Asset{ID: "ip", Type: ctis.AssetTypeIPAddress, Value: m365Addr}
	ports, rels := withOpenPorts(host, 443)
	g.sendWith(g.tn, "naabu", now.Add(-2*time.Hour), "", rels,
		append([]ctis.Asset{{ID: "d", Type: ctis.AssetTypeDomainName, Value: name}}, ports...)...)
	var ipID string
	if err := r.db.QueryRowContext(ctx, `SELECT id FROM assets WHERE tenant_id = $1 AND name = $2`,
		g.tn.tenant.String(), m365Addr).Scan(&ipID); err != nil {
		t.Fatalf("a scan result on the shared address was not recorded: %v", err)
	}
	recs, err := attr.Records(ctx, g.tn.tenant, []string{ipID})
	if err != nil {
		t.Fatal(err)
	}
	if rec := recs[ipID]; rec.State != attribution.StateDependency || rec.Reason != attribution.RuleProviderSharedFrontEnd {
		t.Fatalf("scanned shared address attribution = %+v, want dependency / provider_shared_front_end", rec)
	}
	// Even now that the asset exists, a DNS answer adds no edge to it.
	resolve(g.tn, now.Add(-time.Hour), m365Addr, dedicatedAddr)
	if n := edgesTo(g.tn, m365Addr); n != 0 {
		t.Fatalf("a DNS answer linked the name to the shared address asset (%d edges)", n)
	}

	// Tenant isolation: the other tenant's resolution of the same name is
	// its own; neither sees the other's elements or receipt counts.
	resolve(other, now.Add(-3*time.Hour), cloudfrontAddr)
	if _, ok := elementOf(other, m365Addr); ok {
		t.Fatal("tenant B sees tenant A's address history")
	}
	if e, ok := elementOf(other, cloudfrontAddr); !ok || e.removed.Valid {
		t.Fatalf("tenant B's own element = %+v (found %v)", e, ok)
	}
	if e, _ := elementOf(g.tn, cloudfrontAddr); !e.removed.Valid {
		t.Fatal("tenant B's resolution changed tenant A's history")
	}
	if n := onName(other); n != 1 {
		t.Fatalf("tenant B's receipts count %d, want 1", n)
	}
	if addrs, err := attr.AddressesOf(ctx, other.tenant, []string{name}); err != nil || slices.Contains(addrs[name], m365Addr) {
		t.Fatalf("tenant B reads tenant A's addresses: %v %v", addrs, err)
	}
}

// failingSets is the asset service with a set write that always fails.
type failingSets struct{ *assetapp.AssetService }

func (failingSets) ReconcileSets(context.Context, shared.ID, []asset.SetObservation) ([]asset.SetChange, error) {
	return nil, errors.New("set store down")
}

// A2: when the name's address set is not written, a shared answer takes the
// normal path after all (an address asset, the provider's, and its edge):
// never counted on the name and lost.
func TestIngest_ProviderAnswerFallsBackWhenNameNotWritten(t *testing.T) {
	var attr *postgres.AttributionRepository
	r := newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		assets := assetapp.NewAssetService(postgres.NewAssetRepository(db), logger.NewNop())
		assets.SetAttributeSources(postgres.NewAssetAttributeSourceRepository(db), postgres.NewTenantRepository(db))
		svc.SetAttributeReconciler(failingSets{assets})
		svc.SetRelationshipRepository(postgres.NewAssetRelationshipRepository(db))
		attr = postgres.NewAttributionRepository(db)
		svc.SetScanAttributionStamper(easm.NewScanStamper(attr, postgres.NewVerifiedDomainNameRepository(db)))
	})
	tn := r.newTenant("dnsx")
	ctx := context.Background()
	const name = "autodiscover.example.com"
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	cmd := shared.NewID()
	rep := &ctis.Report{Version: ctis.SchemaVersion, Tool: &ctis.Tool{Name: "dnsx"},
		Assets:   []ctis.Asset{{ID: "d", Type: ctis.AssetTypeDomainName, Value: name, Technical: dnsAddrs(name, m365Addr)}},
		Metadata: ctis.ReportMetadata{ID: ctis.NewReportID(), GeneratedAt: time.Now().UTC()}}
	out, err := r.svc.Ingest(ctx, agt, ingest.Input{Report: rep, Options: ingest.Options{
		Binding: ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd, Targets: []string{name}, Tool: "dnsx"}}})
	if err != nil {
		t.Fatal(err)
	}
	if out.AddressesOnName != 0 {
		t.Fatalf("counted %d on the name although its set was not written", out.AddressesOnName)
	}
	var ipID string
	if err := r.db.QueryRowContext(ctx, `SELECT a.id FROM assets a
		JOIN asset_relationships rel ON rel.tenant_id = a.tenant_id AND rel.target_asset_id = a.id AND rel.relationship_type = 'resolves_to'
		WHERE a.tenant_id = $1 AND a.name = $2`, tid.String(), m365Addr).Scan(&ipID); err != nil {
		t.Fatalf("the answer was dropped: no address asset with its edge (%v)", err)
	}
	recs, err := attr.Records(ctx, tid, []string{ipID})
	if err != nil {
		t.Fatal(err)
	}
	if rec := recs[ipID]; !attribution.IsProviderAddress(rec) {
		t.Fatalf("fallback address attribution = %+v, want the provider's", rec)
	}
}
