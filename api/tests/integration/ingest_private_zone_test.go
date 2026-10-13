package integration

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// A cloud DNS collector's private-zone names, and a root domain only they
// name, are stored private and not internet-accessible; public-zone names
// and their root keep the public default.
func TestIngest_PrivateDNSZoneExposure(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	ctx := context.Background()
	tn := r.newTenant("gcp-dns")
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeCollector, Status: sensor.SensorStatusActive}
	name := func(n, root, vis string) ctis.Asset {
		return ctis.Asset{ID: n, Type: ctis.AssetTypeSubdomain, Value: n, Name: n,
			Properties: ctis.Properties{"root_domain": root, "zone_visibility": vis, "dns_zone": "zone-" + vis, "ip_addresses": []any{"10.20.0.5"}}}
	}
	rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "gcp-dns"},
		Metadata: ctis.ReportMetadata{Timestamp: time.Now().UTC(), SourceType: "collector", CoverageType: "full"},
		Assets: []ctis.Asset{
			name("db.internal-only.example", "internal-only.example", "private"),
			name("www.example.org", "example.org", "public"),
			name("vpn.example.org", "example.org", "private"),
		}}
	out, err := r.svc.Ingest(ctx, agt, ingest.Input{Report: rep, Options: ingest.Options{Admitted: true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Errors) > 0 {
		t.Fatal(out.Errors)
	}
	want := map[string]string{
		"db.internal-only.example": "private",
		"internal-only.example":    "private", // only a private-zone name named it
		"www.example.org":          "public",
		"vpn.example.org":          "private",
		"example.org":              "public", // a public-zone name named it too
	}
	for n, exp := range want {
		var got string
		var internet bool
		if err := r.db.QueryRowContext(ctx, `SELECT exposure, COALESCE(is_internet_accessible, false) FROM assets WHERE tenant_id = $1 AND name = $2`,
			tid.String(), n).Scan(&got, &internet); err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		if got != exp || (exp == "private" && internet) {
			t.Errorf("%s: exposure %s internet %v, want %s", n, got, internet, exp)
		}
	}
}
