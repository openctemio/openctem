package postgres

// The reads behind a version re-check and the template sightings
// (docs/architecture/finding-retest-strategy.md), against a migrated
// database: each is scoped to the tenant.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestRetestVersionEvidence_TenantScoped(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	tA, tB := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	aA := seedTestAsset(ctx, t, db, tA)
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	product, oldV, newV := shared.NewID(), shared.NewID(), shared.NewID()
	mustExec(`INSERT INTO software_products (id, part, vendor, name, source) VALUES ($1, 'a', 'f5', $2, 'curated')`,
		product.String(), "nginx-"+product.String()[:8])
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM software_products WHERE id = $1`, product.String())
	})
	mustExec(`INSERT INTO software_versions (id, product_id, raw, normalized) VALUES ($1, $2, '1.25.2', '1.25.2'), ($3, $2, '1.25.3', '1.25.3')`,
		oldV.String(), product.String(), newV.String())
	start := time.Now().Add(-time.Minute)
	// The old version was seen before the retest and superseded by the new
	// one the fingerprint read after it.
	mustExec(`INSERT INTO asset_software (tenant_id, asset_id, product_id, software_version_id, location, source, confidence, last_seen_at, superseded_at)
		VALUES ($1, $2, $3, $4, '', 'technology', 80, $5, now()), ($1, $2, $3, $6, '', 'technology', 80, now(), NULL)`,
		tA.String(), aA.String(), product.String(), oldV.String(), start.Add(-time.Hour), newV.String())
	finding := shared.NewID()
	mustExec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, rule_id, message, severity, fingerprint, status, metadata, sensor_id)
		VALUES ($1, $2, $3, 'va', 'version-match', 'CVE-2023-44487', 'm', 'high', $4, 'new',
			jsonb_build_object('version_match', jsonb_build_object('product_id', $5::text, 'version_id', $6::text, 'location', '', 'product', 'nginx', 'version', '1.25.2')), NULL)`,
		finding.String(), tA.String(), aA.String(), "fp-"+finding.String(), product.String(), oldV.String())

	repo := NewSoftwareMatchRepository(&DB{DB: db})
	link, err := repo.FindingLink(ctx, tA, finding)
	if err != nil || link == nil {
		t.Fatalf("link %v %v", link, err)
	}
	if link.ProductID != product || link.VersionID != oldV || link.Source != "technology" || link.Product != "nginx" || link.LastSeenTool != "version-match" {
		t.Fatalf("link %+v", link)
	}
	if other, err := repo.FindingLink(ctx, tB, finding); err != nil || other != nil {
		t.Fatalf("another tenant read the link: %+v %v", other, err)
	}

	seen, err := repo.ObservedSince(ctx, tA, aA, product, "", start)
	if err != nil || len(seen) != 1 || seen[0].VersionID != newV || seen[0].Raw != "1.25.3" || !seen[0].Comparable || seen[0].Superseded {
		t.Fatalf("observed %+v %v", seen, err)
	}
	if seen, err := repo.ObservedSince(ctx, tB, aA, product, "", start); err != nil || len(seen) != 0 {
		t.Fatalf("another tenant read the inventory: %+v %v", seen, err)
	}

	// Template sightings: the sensor of a nuclei finding of tenant A only.
	sensorA := shared.NewID()
	mustExec(`INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status) VALUES ($1, $2, $3, $4, 'octs_tst', 'active')`, sensorA.String(), tA.String(), "s-"+sensorA.String()[:8], "h-"+sensorA.String())
	mustExec(`INSERT INTO findings (tenant_id, asset_id, source, tool_name, rule_id, message, severity, fingerprint, status, sensor_id)
		VALUES ($1, $2, 'dast', 'nuclei', 'CVE-2021-41773', 'm', 'high', $3, 'new', $4)`,
		tA.String(), aA.String(), "fp2-"+finding.String(), sensorA.String())
	frepo := NewFindingRepository(&DB{DB: db})
	got, err := frepo.TemplateSightingSensors(ctx, tA, "nuclei", "CVE-2021-41773", 5)
	if err != nil || len(got) != 1 || got[0] != sensorA {
		t.Fatalf("sightings %v %v", got, err)
	}
	if got, err := frepo.TemplateSightingSensors(ctx, tB, "nuclei", "CVE-2021-41773", 5); err != nil || len(got) != 0 {
		t.Fatalf("another tenant saw the sightings: %v %v", got, err)
	}
	if got, _ := frepo.TemplateSightingSensors(ctx, tA, "nuclei", "CVE-2023-44487", 5); len(got) != 0 {
		t.Fatalf("a version-match finding counted as a template sighting: %v", got)
	}
}
