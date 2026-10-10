package integration

// Inventory matching through the real ingest (RFC-066): a scan report's
// technologies and banners become software links, the matcher turns an
// affected version into a finding, and a report may not use the matcher's
// reserved tool name.

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestVulnMatching_ThroughIngest(t *testing.T) {
	e := newMatchEnv(t)
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("vm-ingest")
	db := &postgres.DB{DB: r.db}
	ctx := context.Background()
	_, err := r.db.Exec(`UPDATE tenants SET settings = '{"general": {"timezone": "UTC"}, "vuln_matching": {"enabled": true}}'::jsonb WHERE id = $1`, tn.tenant.String())
	require.NoError(t, err)

	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	svc.SetSoftwareRepository(postgres.NewSoftwareRepository(db))
	svc.SetSoftwareChangeSink(e.svc)
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}

	ingestReport := func(tool string, rep *ctis.Report) *ingest.Output {
		t.Helper()
		rep.Version, rep.Tool = "1.0", &ctis.Tool{Name: tool}
		rep.Metadata = ctis.ReportMetadata{ID: "rep-" + shared.NewID().String(), Timestamp: time.Now().UTC()}
		out, err := svc.Ingest(ctx, agt, ingest.Input{Report: rep, Options: ingest.Options{Binding: ingest.TrustedBinding()}})
		require.NoError(t, err)
		return out
	}

	host := "vm-" + shared.NewID().String()[:8] + ".example.com"
	out := ingestReport("httpx", &ctis.Report{Assets: []ctis.Asset{{
		ID: "a1", Type: ctis.AssetTypeDomain, Value: host, Name: host,
		Technologies: []ctis.Technology{{Name: "widget", CPE: "cpe:2.3:a:" + e.vendor + ":widget:1.4.2:*:*:*:*:*:*:*"}},
		Properties:   ctis.Properties{"technologies": []any{"Nginx:1.18.0", "Cloudflare"}, "server": "nginx/1.18.0 (Ubuntu)"},
	}}})
	require.Empty(t, out.Errors)

	rows, err := r.db.Query(`SELECT p.name, v.raw, v.qualifier, s.confidence, (p.tenant_id IS NULL)
		FROM asset_software s JOIN software_products p ON p.id = s.product_id
		JOIN software_versions v ON v.id = s.software_version_id
		WHERE s.tenant_id = $1 ORDER BY p.name, v.qualifier`, tn.tenant.String())
	require.NoError(t, err)
	defer rows.Close()
	var got []string
	for rows.Next() {
		var name, raw, qual string
		var conf int
		var global bool
		require.NoError(t, rows.Scan(&name, &raw, &qual, &conf, &global))
		got = append(got, strings.Join([]string{name, raw, qual}, "|")+map[bool]string{true: " global", false: " private"}[global]+" "+strconv.Itoa(conf))
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []string{
		"cloudflare|| private 50",       // unknown name: tenant-private, never matched
		"nginx|1.18.0| global 65",       // technology string, curated name
		"nginx|1.18.0|ubuntu global 35", // Server header: distribution build
		"widget|1.4.2| global 80",       // CPE from the typed technology
	}, got)

	e.run()
	assert.Len(t, e.findings(tn.tenant), 1, "the affected widget became a finding")

	// A report may not claim the matcher's tool name.
	out = ingestReport("version-match", &ctis.Report{
		Assets:   []ctis.Asset{{ID: "a1", Type: ctis.AssetTypeDomain, Value: host, Name: host}},
		Findings: []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "forged", Severity: ctis.SeverityHigh, AssetRef: "a1"}},
	})
	require.NotEmpty(t, out.Errors)
	assert.Contains(t, strings.Join(out.Errors, " "), "reserved")
	var forged int
	require.NoError(t, r.db.QueryRow(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND title = 'forged'`, tn.tenant.String()).Scan(&forged))
	assert.Zero(t, forged)
}
