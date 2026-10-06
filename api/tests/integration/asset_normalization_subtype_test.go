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
		rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "httpx"},
			Metadata: ctis.ReportMetadata{ID: shared.NewID().String(), Timestamp: time.Now().UTC()},
			Assets:   []ctis.Asset{{ID: "a", Type: typ, Value: v}}}
		out, err := svc.Ingest(context.Background(), agt, ingest.Input{Report: rep})
		if err != nil || len(out.Errors) > 0 {
			t.Fatalf("ingest %q: %v %v", v, err, out.Errors)
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

	for _, v := range []string{"https://api.example.com", "https://api.example.com:443", "HTTPS://API.example.com/"} {
		one(ctis.AssetTypeHTTPService, v)
	}
	if got := names("asset_type = 'service'"); len(got) != 1 || got[0] != "https://api.example.com" {
		t.Errorf("http_service spellings stored as %q, want one asset https://api.example.com", got)
	}

	one(ctis.AssetTypeCompute, "arn:aws:ec2:us-east-1:123456789012:instance/i-0aaa")
	one(ctis.AssetTypeCompute, "arn:aws:ec2:us-east-1:123456789012:instance/i-0bbb")
	if got := names("name LIKE 'arn:%'"); len(got) != 2 {
		t.Errorf("two EC2 instances stored as %q, want two assets", got)
	}
}
