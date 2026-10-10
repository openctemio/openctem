package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/app/vulnmatch"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/cvecorpus"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	vm "github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type matchEnv struct {
	t       *testing.T
	pdb     *postgres.DB
	sw      *postgres.SoftwareRepository
	corpus  *postgres.CVECorpusRepository
	svc     *vulnmatch.Service
	vendor  string
	cveID   string
	product string
}

func newMatchEnv(t *testing.T) *matchEnv {
	t.Helper()
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	pdb := &postgres.DB{DB: db}
	e := &matchEnv{t: t, pdb: pdb, sw: postgres.NewSoftwareRepository(pdb), corpus: postgres.NewCVECorpusRepository(pdb),
		vendor: "vm" + uuid.NewString()[:8], product: "widget", cveID: testCVEID()}
	require.NoError(t, e.sw.EnsureCurated(context.Background(), software.CuratedProducts()))
	e.svc = vulnmatch.NewService(postgres.NewSoftwareMatchRepository(pdb),
		vulnmatch.TenantPolicy(postgres.NewTenantRepository(pdb)), postgres.NewFindingRepository(pdb), logger.NewNop())
	e.feed(vm.Range{End: "2.0"})
	return e
}

// feed (re)publishes the test CVE with one range of the test product.
func (e *matchEnv) feed(r vm.Range) {
	e.t.Helper()
	score := 8.1
	c, err := vm.ParseCPE("cpe:2.3:a:" + e.vendor + ":" + e.product + ":*")
	require.NoError(e.t, err)
	_, err = e.corpus.ApplyPage(context.Background(), []cvecorpus.CVE{{
		ID: e.cveID, Status: "Analyzed", Description: "Widget overflow.", CVSSScore: &score, Severity: "high",
		Ranges: []cvecorpus.Range{{Product: c, Range: r}},
	}})
	require.NoError(e.t, err)
}

func (e *matchEnv) tenant(name string, enabled bool) shared.ID {
	e.t.Helper()
	id := createTestTenant(e.t, e.pdb.DB, name)
	// An organization with stored settings and no vuln_matching section
	// (one created before the feature) has it off.
	section := `{"general": {"timezone": "UTC"}}`
	if enabled {
		section = `{"general": {"timezone": "UTC"}, "vuln_matching": {"enabled": true}}`
	}
	_, err := e.pdb.Exec(`UPDATE tenants SET settings = $2::jsonb WHERE id = $1`, id.String(), section)
	require.NoError(e.t, err)
	return id
}

// observe links the product at version to a new asset of the tenant, the
// way ingest does, and tells the matcher.
func (e *matchEnv) observe(tenantID, assetID shared.ID, version string) shared.ID {
	e.t.Helper()
	ctx := context.Background()
	if assetID.IsZero() {
		assetID = createTestAsset(e.t, e.pdb.DB, tenantID, "vm-asset-"+uuid.NewString()[:6])
	}
	p, ok := software.Parse(software.Observation{CPE: "cpe:2.3:a:" + e.vendor + ":" + e.product + ":" + version, Port: 443, Transport: "tcp", Location: "tcp/443", Source: software.SourceService})
	require.True(e.t, ok)
	refs, err := e.sw.Resolve(ctx, tenantID, []software.Identity{p.Identity})
	require.NoError(e.t, err)
	ref := refs[p.Identity]
	require.True(e.t, ref.Global, "the feed product must resolve globally")
	vid, err := e.sw.EnsureVersion(ctx, tenantID, ref, p.Version)
	require.NoError(e.t, err)
	_, err = e.sw.UpsertLinks(ctx, tenantID, []software.Link{{
		AssetID: assetID, ProductID: ref.ID, VersionID: vid, Location: "tcp/443", Port: 443, Transport: "tcp",
		Source: software.SourceService, Evidence: "widget/" + version, Confidence: software.ConfidenceCPE,
	}})
	require.NoError(e.t, err)
	e.svc.SoftwareChanged(tenantID, []shared.ID{assetID})
	return assetID
}

func (e *matchEnv) run() vulnmatch.Stats {
	e.t.Helper()
	st, err := e.svc.Run(context.Background(), time.Minute)
	require.NoError(e.t, err)
	return st
}

type matchRow struct {
	Status, Source, Method string
	Confidence             int
	Priority               string
}

func (e *matchEnv) findings(tenantID shared.ID) []matchRow {
	e.t.Helper()
	rows, err := e.pdb.Query(`SELECT status, source, COALESCE(resolution_method, ''), COALESCE(confidence, 0), COALESCE(priority_class, '')
		FROM findings WHERE tenant_id = $1 AND tool_name = 'version-match' AND cve_id = $2 ORDER BY created_at`, tenantID.String(), e.cveID)
	require.NoError(e.t, err)
	defer rows.Close()
	var out []matchRow
	for rows.Next() {
		var r matchRow
		require.NoError(e.t, rows.Scan(&r.Status, &r.Source, &r.Method, &r.Confidence, &r.Priority))
		out = append(out, r)
	}
	require.NoError(e.t, rows.Err())
	return out
}

func TestVulnMatching_EndToEnd(t *testing.T) {
	e := newMatchEnv(t)
	affected := e.tenant("vm-affected", true)
	patched := e.tenant("vm-patched", true)
	off := e.tenant("vm-off", false)

	assetA := e.observe(affected, shared.ID{}, "1.4.2")
	e.observe(patched, shared.ID{}, "2.1.0")
	e.observe(off, shared.ID{}, "1.4.2")
	e.run()

	// Only the organization running an affected version, with matching on,
	// gets a finding; nothing crosses to another organization.
	got := e.findings(affected)
	require.Len(t, got, 1)
	assert.Equal(t, "new", got[0].Status)
	assert.Equal(t, "va", got[0].Source)
	assert.Equal(t, 80, got[0].Confidence)
	assert.Empty(t, e.findings(patched))
	assert.Empty(t, e.findings(off), "matching is off for this organization")

	// A second pass changes nothing.
	e.run()
	assert.Len(t, e.findings(affected), 1)

	// Upgrade out of range: resolved, the version changed.
	e.observe(affected, assetA, "2.0.1")
	e.run()
	got = e.findings(affected)
	require.Len(t, got, 1)
	assert.Equal(t, "resolved", got[0].Status)
	assert.Equal(t, "version_changed", got[0].Method)

	// Downgrade back into range: the same finding reopens.
	e.observe(affected, assetA, "1.4.2")
	e.run()
	got = e.findings(affected)
	require.Len(t, got, 1)
	assert.Equal(t, "confirmed", got[0].Status)
}

func TestVulnMatching_AdvisoryUpdatedAndStale(t *testing.T) {
	e := newMatchEnv(t)
	advisory := e.tenant("vm-advisory", true)
	stale := e.tenant("vm-stale", true)
	e.observe(advisory, shared.ID{}, "1.4.2")
	staleAsset := e.observe(stale, shared.ID{}, "1.4.2")
	e.run()
	require.Len(t, e.findings(advisory), 1)
	require.Len(t, e.findings(stale), 1)

	// The software was not seen for 31 days: not observed (not fixed).
	_, err := e.pdb.Exec(`UPDATE asset_software SET last_seen_at = now() - interval '31 days' WHERE tenant_id = $1 AND asset_id = $2`,
		stale.String(), staleAsset.String())
	require.NoError(t, err)
	// The feed narrows the range so 1.4.2 is no longer affected.
	e.feed(vm.Range{End: "1.0"})
	require.NoError(t, postgres.NewSoftwareMatchRepository(e.pdb).QueueTenants(context.Background(), []shared.ID{stale}))
	e.run()

	got := e.findings(advisory)
	require.Len(t, got, 1)
	assert.Equal(t, "false_positive", got[0].Status)
	assert.Equal(t, "advisory_updated", got[0].Method)
	got = e.findings(stale)
	require.Len(t, got, 1)
	assert.Equal(t, "not_observed", got[0].Status)
}

// A CVE a scanner already reported on the asset gets no second finding,
// and a scanner-reported finding is never closed by the matcher.
func TestVulnMatching_ScannerFindingWins(t *testing.T) {
	e := newMatchEnv(t)
	tn := e.tenant("vm-scanner", true)
	asset := createTestAsset(t, e.pdb.DB, tn, "vm-scanned")
	_, err := e.pdb.Exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, severity, message, status, fingerprint, cve_id)
		VALUES ($1, $2, $3, 'dast', 'nuclei', 'high', 'scanner', 'new', $4, $5)`,
		uuid.NewString(), tn.String(), asset.String(), "fp-"+uuid.NewString(), e.cveID)
	require.NoError(t, err)
	e.observe(tn, asset, "1.4.2")
	e.run()
	assert.Empty(t, e.findings(tn))

	var n int
	require.NoError(t, e.pdb.QueryRow(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND cve_id = $2 AND status = 'new'`, tn.String(), e.cveID).Scan(&n))
	assert.Equal(t, 1, n)
}

// Every version is evaluated once, whatever the number of assets.
func TestVulnMatching_OneEvaluationPerVersion(t *testing.T) {
	e := newMatchEnv(t)
	for i := 0; i < 3; i++ {
		e.observe(e.tenant("vm-many", true), shared.ID{}, "1.4.2")
	}
	e.run()
	var rows int
	require.NoError(t, e.pdb.QueryRow(`
		SELECT count(*) FROM software_version_vulns m JOIN software_versions v ON v.id = m.software_version_id
		JOIN software_products p ON p.id = v.product_id WHERE p.cpe_vendor = $1`, e.vendor).Scan(&rows))
	assert.Equal(t, 1, rows)
}
