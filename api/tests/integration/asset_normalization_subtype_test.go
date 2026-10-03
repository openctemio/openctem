package integration

import (
	"context"
	"os"
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

// Migration 000294 queues review items (never merges) for names stored by the
// old normalizer. Running the migration body again on seeded rows must queue:
// one garbled group, one single rename, one truncated ARN.
func TestMigration000294_QueuesReviewsForGarbledNames(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("httpx")
	ctx := context.Background()
	seed := func(name, typ, sub string) string {
		t.Helper()
		var id string
		if err := r.db.QueryRowContext(ctx, `INSERT INTO assets (tenant_id, name, asset_type, sub_type, criticality, status)
			VALUES ($1, $2, $3, NULLIF($4, ''), 'medium', 'active') RETURNING id`,
			tn.tenant.String(), name, typ, sub).Scan(&id); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		return id
	}
	canonical := seed("https://api.example.com", "service", "http")
	g1 := seed("https:::api.example.com", "service", "http")
	g2 := seed("https:::api.example.com:443", "service", "http")
	single := seed("http:::shop.example.com:8080", "service", "http")
	arn := seed("arn:aws:ec2:us-east-1:123456789012:instance", "host", "compute")
	seed("arn:aws:ec2:us-east-1:123456789012:instance/i-0ccc", "host", "compute") // intact: not flagged
	seed("https://ok.example.com", "service", "http")                             // canonical: not flagged

	body, err := os.ReadFile("../../migrations/000294_asset_normalization_review.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.db.ExecContext(ctx, string(body)); err != nil {
		t.Fatalf("run migration body: %v", err)
	}

	type review struct {
		keep, reason, proposed string
		merge                  []string
	}
	rows, err := r.db.QueryContext(ctx, `SELECT keep_asset_id, reason, COALESCE(evidence->>'proposed_name', ''), array_to_string(merge_asset_ids, ',')
		FROM asset_dedup_review WHERE tenant_id = $1 AND status = 'pending' ORDER BY reason`, tn.tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]review{}
	for rows.Next() {
		var rv review
		var merge string
		if err := rows.Scan(&rv.keep, &rv.reason, &rv.proposed, &merge); err != nil {
			t.Fatal(err)
		}
		if merge != "" {
			rv.merge = splitComma(merge)
		}
		got[rv.reason] = rv
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("reviews = %+v, want 3 (garbled, rename, truncated arn)", got)
	}
	if g := got["normalization_garbled"]; g.keep != canonical || g.proposed != "https://api.example.com" || len(g.merge) != 2 ||
		!contains(g.merge, g1) || !contains(g.merge, g2) {
		t.Errorf("garbled review = %+v, want keep %s (the canonical asset) merging %s and %s", g, canonical, g1, g2)
	}
	if s := got["normalization_rename"]; s.keep != single || s.proposed != "http://shop.example.com:8080" || len(s.merge) != 0 {
		t.Errorf("rename review = %+v, want keep %s proposed http://shop.example.com:8080", s, single)
	}
	if a := got["normalization_truncated_arn"]; a.keep != arn {
		t.Errorf("truncated ARN review = %+v, want keep %s", a, arn)
	}

	// Re-running queues nothing new (idempotent).
	if _, err := r.db.ExecContext(ctx, string(body)); err != nil {
		t.Fatalf("rerun: %v", err)
	}
	var n int
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM asset_dedup_review WHERE tenant_id = $1`, tn.tenant.String()).Scan(&n)
	if n != 3 {
		t.Errorf("after rerun %d reviews, want 3", n)
	}
	// No asset was renamed or deleted.
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM assets WHERE tenant_id = $1`, tn.tenant.String()).Scan(&n)
	if n != 7 {
		t.Errorf("assets = %d, want 7 untouched", n)
	}
}

func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}
