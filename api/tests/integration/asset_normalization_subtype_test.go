package integration

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// RFC-043 section 10: a new asset's name is normalized with the same
// (type, sub-type) key lookups use. Before, an http_service URL was stored
// as "https:::host" (three spellings of one URL → three assets) and an ARN
// was cut at the first "/" (two EC2 instances → one asset).
func TestIngest_AssetNameNormalizedWithSubType(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("httpx")
	db := &postgres.DB{DB: r.db}
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	one := func(typ ctis.AssetType, v string) {
		t.Helper()
		rep := &ctis.Report{Version: ctis.SchemaVersion, Tool: &ctis.Tool{Name: "httpx"},
			Metadata: ctis.ReportMetadata{ID: ctis.NewReportID(), GeneratedAt: time.Now().UTC()},
			Assets:   []ctis.Asset{{ID: "a", Type: typ, Value: v}}}
		out, err := svc.Ingest(context.Background(), agt, ingest.Input{Report: rep})
		if err != nil {
			t.Fatalf("ingest %q: %v", v, err)
		}
		if len(out.Errors) > 0 {
			t.Fatalf("ingest %q: %v", v, out.Errors)
		}
	}
	refused := func(typ ctis.AssetType, v string) {
		t.Helper()
		rep := &ctis.Report{Version: ctis.SchemaVersion, Tool: &ctis.Tool{Name: "httpx"},
			Metadata: ctis.ReportMetadata{ID: ctis.NewReportID(), GeneratedAt: time.Now().UTC()},
			Assets:   []ctis.Asset{{ID: "a", Type: typ, Value: v}}}
		if _, err := svc.Ingest(context.Background(), agt, ingest.Input{Report: rep}); err == nil {
			t.Fatalf("non-canonical %q was accepted", v)
		}
	}
	names := func(where string) []string {
		t.Helper()
		rows, err := r.db.Query(`SELECT name FROM assets WHERE tenant_id = $1 AND `+where+` ORDER BY name`, tn.tenant.String())
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var n string
			_ = rows.Scan(&n)
			out = append(out, n)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// CTIS 2.0 documents carry the canonical form only: other spellings of the
	// same origin are refused by validation instead of being folded.
	one(ctis.AssetTypeWebOrigin, "https://api.example.com")
	one(ctis.AssetTypeWebOrigin, "https://api.example.com")
	for _, v := range []string{"https://api.example.com:443", "HTTPS://API.example.com/"} {
		refused(ctis.AssetTypeWebOrigin, v)
	}
	if got := names("asset_type = 'service'"); len(got) != 1 || got[0] != "https://api.example.com" {
		t.Errorf("http_service spellings stored as %q, want one asset https://api.example.com", got)
	}

	one(ctis.AssetTypeCloudResource, "arn:aws:ec2:us-east-1:123456789012:instance/i-0aaa")
	one(ctis.AssetTypeCloudResource, "arn:aws:ec2:us-east-1:123456789012:instance/i-0bbb")
	if got := names("name LIKE 'arn:%'"); len(got) != 2 {
		t.Errorf("two EC2 instances stored as %q, want two assets", got)
	}
}
