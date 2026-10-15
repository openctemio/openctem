package integration

// Remediation group keys (research 156 P0-5) through the real ingest, CVE
// matching and the backfill: an upgrade key is the package and the version
// that fixes it, a leaked secret is grouped only with the same secret, a
// re-sighting re-derives the key, and the backfill is idempotent and keeps to
// one tenant.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type keyRow struct{ key, title string }

// remediationKeys maps rule_id to the finding's stored key in the tenant.
func remediationKeys(t *testing.T, r *v2Rig, tenant shared.ID) map[string]keyRow {
	t.Helper()
	rows, err := r.db.Query(`SELECT f.rule_id, frk.remediation_key, frk.title
		FROM findings f JOIN finding_remediation_keys frk ON frk.finding_id = f.id AND frk.tenant_id = f.tenant_id
		WHERE f.tenant_id = $1`, tenant.String())
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]keyRow{}
	for rows.Next() {
		var rule string
		var k keyRow
		require.NoError(t, rows.Scan(&rule, &k.key, &k.title))
		out[rule] = k
	}
	require.NoError(t, rows.Err())
	return out
}

func newKeyIngest(t *testing.T) (*v2Rig, *ingest.Service, *remediation.KeyApplier) {
	t.Helper()
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	db := &postgres.DB{DB: r.db}
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	svc.SetComponentRepository(postgres.NewComponentRepository(db))
	svc.SetSecretFingerprinter(vulnerability.NewSecretFingerprinter([]byte("remediation-keys-server-secret-0123456789")))
	keys := remediation.NewKeyApplier(postgres.NewFindingRemediationKeyRepository(db), logger.NewNop())
	svc.SetRemediationKeyApplier(keys)
	return r, svc, keys
}

func ingestFindings(t *testing.T, svc *ingest.Service, tn v2Tenant, tool string, findings ...ctis.Finding) {
	t.Helper()
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	for i := range findings {
		findings[i].AssetRef = "a"
	}
	rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: tool},
		Metadata: ctis.ReportMetadata{ID: shared.NewID().String(), Timestamp: time.Now().UTC()},
		Assets:   []ctis.Asset{{ID: "a", Type: ctis.AssetTypeRepository, Value: tn.repo}},
		Findings: findings}
	out, err := svc.Ingest(context.Background(), agt, ingest.Input{Report: rep})
	require.NoError(t, err)
	require.Empty(t, out.Errors)
}

func scaFinding(cve, version, fixed string) ctis.Finding {
	return ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "django: " + cve, Severity: ctis.SeverityHigh,
		RuleID: cve, Location: &ctis.FindingLocation{Path: "requirements.txt"},
		Vulnerability: &ctis.VulnerabilityDetails{CVEID: cve, Package: "django", PURL: "pkg:pypi/django@" + version,
			AffectedVersion: version, FixedVersion: fixed}}
}

func secretFinding(rule, path, value string) ctis.Finding {
	return ctis.Finding{Type: ctis.FindingTypeSecret, Title: "Leaked key", Severity: ctis.SeverityCritical,
		RuleID: rule, Location: &ctis.FindingLocation{Path: path, StartLine: 3},
		Remediation: &ctis.Remediation{Recommendation: "Rotate the secret"},
		Secret:      &ctis.SecretDetails{SecretType: "aws_access_key", MaskedValue: value}}
}

func TestRemediationKeys_ThroughIngest(t *testing.T) {
	r, svc, applier := newKeyIngest(t)
	tn := r.newTenant()

	ingestFindings(t, svc, tn, "trivy",
		scaFinding("CVE-2026-0001", "4.2.20", "5.2.8, 4.2.30"),
		scaFinding("CVE-2026-0002", "4.2.25", "4.2.30"))
	ingestFindings(t, svc, tn, "betterleaks",
		secretFinding("aws-1", "config/a.env", "AKIA************7Q2X"),
		secretFinding("aws-2", "config/b.env", "ASIA************KE99"))

	keys := remediationKeys(t, r, tn.tenant)
	// Two installed versions that one upgrade fixes share one readable group.
	assert.Equal(t, keyRow{"upgrade:pypi:django:4.2.30", "Upgrade django to 4.2.30"}, keys["CVE-2026-0001"])
	assert.Equal(t, keys["CVE-2026-0001"], keys["CVE-2026-0002"])
	keys0 := keys["CVE-2026-0001"].key
	// Two different secrets never share a group, though their advice is the same.
	require.Contains(t, keys, "aws-1")
	require.Contains(t, keys, "aws-2")
	assert.Regexp(t, `^rotate:secret:[0-9a-f]+$`, keys["aws-1"].key)
	assert.NotEqual(t, keys["aws-1"].key, keys["aws-2"].key)

	// A finding a person creates on the same package and CVE joins the group.
	var assetID, compID, vulnID string
	require.NoError(t, r.db.QueryRow(`SELECT asset_id, component_id, vulnerability_id FROM findings
		WHERE tenant_id = $1 AND rule_id = 'CVE-2026-0001'`, tn.tenant.String()).Scan(&assetID, &compID, &vulnID))
	vsvc := finding.NewVulnerabilityService(postgres.NewVulnerabilityRepository(&postgres.DB{DB: r.db}),
		postgres.NewFindingRepository(&postgres.DB{DB: r.db}), logger.NewNop())
	vsvc.SetRemediationKeyApplier(applier)
	vsvc.SetAssetRefChecker(allowAssetRefs{})
	_, err := vsvc.CreateFinding(context.Background(), finding.CreateFindingInput{TenantID: tn.tenant.String(), AssetID: assetID,
		ComponentID: compID, VulnerabilityID: vulnID, Source: "manual", ToolName: "manual", RuleID: "MANUAL-1",
		Message: "django found by a reviewer", Severity: "high"})
	require.NoError(t, err)
	assert.Equal(t, keys0, remediationKeys(t, r, tn.tenant)["MANUAL-1"].key)

	// A re-sighting re-derives the key: a finding keyed by the old recipe (a
	// package-version id) moves to its upgrade group on the next scan.
	_, err = r.db.Exec(`UPDATE finding_remediation_keys SET remediation_key = 'sca:' || gen_random_uuid()::text, title = 'Upgrade 3f2a'
		WHERE tenant_id = $1`, tn.tenant.String())
	require.NoError(t, err)
	ingestFindings(t, svc, tn, "trivy", scaFinding("CVE-2026-0002", "4.2.25", "4.2.30"))
	assert.Equal(t, keyRow{"upgrade:pypi:django:4.2.30", "Upgrade django to 4.2.30"}, remediationKeys(t, r, tn.tenant)["CVE-2026-0002"])
}

func TestRemediationKeys_VersionMatch(t *testing.T) {
	e := newMatchEnv(t)
	db := &postgres.DB{DB: e.pdb.DB}
	e.svc.SetRemediationKeyApplier(remediation.NewKeyApplier(postgres.NewFindingRemediationKeyRepository(db), logger.NewNop()))
	tenant := e.tenant("rk-vm", true)
	e.observe(tenant, shared.ID{}, "1.4.2")
	e.run()

	var key, title string
	require.NoError(t, e.pdb.QueryRow(`SELECT frk.remediation_key, frk.title FROM findings f
		JOIN finding_remediation_keys frk ON frk.finding_id = f.id AND frk.tenant_id = f.tenant_id
		WHERE f.tenant_id = $1`, tenant.String()).Scan(&key, &title))
	assert.Equal(t, "upgrade:cpe:widget:2.0", key)
	assert.Equal(t, "Upgrade widget to 2.0", title)
}

func TestRemediationKeys_BackfillIdempotentAndTenantScoped(t *testing.T) {
	r, _, keys := newKeyIngest(t)
	ctx := context.Background()
	a, b := r.newTenant(), r.newTenant()
	assetA, assetB := shared.NewID(), shared.NewID()
	for _, x := range []struct{ tenant, asset shared.ID }{{a.tenant, assetA}, {b.tenant, assetB}} {
		_, err := r.db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'repository')`,
			x.asset.String(), x.tenant.String(), "rk-"+x.asset.String()[:8])
		require.NoError(t, err)
	}
	seed := func(tenant, asset shared.ID, rule, typeDetails, oldKey string) shared.ID {
		id := shared.NewID()
		_, err := r.db.Exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, rule_id, finding_type, type_details)
			VALUES ($1, $2, $3, 'secret', 'betterleaks', 'm', 'high', $4, 'new', $5, 'secret', $6::jsonb)`,
			id.String(), tenant.String(), asset.String(), id.String(), rule, typeDetails)
		require.NoError(t, err)
		if oldKey != "" {
			_, err = r.db.Exec(`INSERT INTO finding_remediation_keys (finding_id, tenant_id, remediation_key, title) VALUES ($1, $2, $3, 'Rotate')`,
				id.String(), tenant.String(), oldKey)
			require.NoError(t, err)
		}
		return id
	}
	// Tenant A: two different secrets under one generic text key (the old
	// over-grouping), and a secret with no fingerprint that must lose its key.
	seed(a.tenant, assetA, "s1", `{"v":1,"secret":{"fingerprint":"aaaa1111"}}`, "sol:generic")
	seed(a.tenant, assetA, "s2", `{"v":1,"secret":{"fingerprint":"bbbb2222"}}`, "sol:generic")
	seed(a.tenant, assetA, "s3", `{"v":1}`, "sol:generic")
	// Tenant B: the same stale key, untouched by A's backfill.
	seed(b.tenant, assetB, "s1", `{"v":1,"secret":{"fingerprint":"cccc3333"}}`, "sol:generic")

	dry, err := keys.Backfill(ctx, a.tenant, false, 2)
	require.NoError(t, err)
	assert.Equal(t, 3, dry.Scanned)
	assert.Equal(t, 2, dry.Changed)
	assert.Equal(t, 1, dry.Removed)
	assert.Equal(t, map[string]int{"sol": 3}, dry.Before)
	assert.Equal(t, map[string]int{"rotate": 2}, dry.After)
	assert.Equal(t, "sol:generic", remediationKeys(t, r, a.tenant)["s1"].key, "a dry run writes nothing")

	applied, err := keys.Backfill(ctx, a.tenant, true, 2)
	require.NoError(t, err)
	assert.Equal(t, 2, applied.Changed)
	got := remediationKeys(t, r, a.tenant)
	assert.Equal(t, "rotate:secret:aaaa1111", got["s1"].key)
	assert.Equal(t, "rotate:secret:bbbb2222", got["s2"].key)
	assert.NotContains(t, got, "s3")

	again, err := keys.Backfill(ctx, a.tenant, true, 2)
	require.NoError(t, err)
	assert.Equal(t, 0, again.Added+again.Changed+again.Removed, "idempotent")
	assert.Equal(t, 3, again.Unchanged)

	assert.Equal(t, "sol:generic", remediationKeys(t, r, b.tenant)["s1"].key, "another tenant is untouched")

	// The tenant-scoped reader never returns another tenant's finding.
	bIDs, err := postgres.NewFindingRemediationKeyRepository(&postgres.DB{DB: r.db}).FindingIDsAfter(ctx, b.tenant, shared.ID{}, 10)
	require.NoError(t, err)
	srcs, err := postgres.NewFindingRemediationKeyRepository(&postgres.DB{DB: r.db}).KeySources(ctx, a.tenant, bIDs)
	require.NoError(t, err)
	assert.Empty(t, srcs, "another tenant's ids read nothing")
}

// allowAssetRefs lets a test create a finding on its own asset (the data
// scope check is covered elsewhere).
type allowAssetRefs struct{}

func (allowAssetRefs) AssertAssetRef(context.Context, shared.ID, shared.ID) error { return nil }
