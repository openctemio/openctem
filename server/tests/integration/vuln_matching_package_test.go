package integration

// Version matches on package links take the package identity scanners use
// (asset, package URL without version, CVE): one finding per package and
// CVE whoever reported it, the matched version as its component, the
// organization's VEX statements applied, and the matcher's own findings
// stored under the old network key moved in place.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vexapp "github.com/openctemio/openctem/api/internal/app/vex"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	vexdom "github.com/openctemio/openctem/api/pkg/domain/vex"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	vm "github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type pkgMatchEnv struct {
	*matchEnv
	pkgName   string
	productID string
}

// newPkgMatchEnv publishes the test product with a package identity too
// (a feed product known by CPE and by package URL) and a semver range.
func newPkgMatchEnv(t *testing.T) *pkgMatchEnv {
	t.Helper()
	e := &pkgMatchEnv{matchEnv: newMatchEnv(t), pkgName: "vmpkg-" + uuid.NewString()[:8]}
	e.feed(vm.Range{End: "2.0.0"})
	require.NoError(t, e.pdb.QueryRow(`
		UPDATE software_products SET purl_type = 'npm', purl_namespace = '', purl_name = $2
		WHERE tenant_id IS NULL AND cpe_vendor = $1 RETURNING id`, e.vendor, e.pkgName).Scan(&e.productID))
	return e
}

func (e *pkgMatchEnv) purl(version string) string { return "pkg:npm/" + e.pkgName + "@" + version }

// install writes the package at version on the asset the way ingest does
// and returns the linked version id.
func (e *pkgMatchEnv) install(tenantID, assetID shared.ID, version string) shared.ID {
	e.t.Helper()
	p, err := software.ParsePURL(e.purl(version))
	require.NoError(e.t, err)
	_, err = postgres.NewSoftwarePackageWriter(e.pdb).WritePackages(context.Background(), tenantID, software.PackageSnapshot{
		AssetID: assetID, Channel: software.ChannelSensor, Replace: true,
		Packages: []software.PackageNode{{Ref: "a", PURL: p, DisplayName: p.Name, Relationship: "direct", Location: "package-lock.json"}},
	})
	require.NoError(e.t, err)
	var vid string
	require.NoError(e.t, e.pdb.QueryRow(`SELECT software_version_id FROM asset_software WHERE tenant_id = $1 AND asset_id = $2 AND product_id = $3`,
		tenantID.String(), assetID.String(), e.productID).Scan(&vid))
	e.svc.SoftwareChanged(tenantID, []shared.ID{assetID})
	return shared.MustIDFromString(vid)
}

// scannerFP is the key ingest gives a scanner's report of the package.
func (e *pkgMatchEnv) scannerFP(assetID shared.ID, reportedVersion string) string {
	e.t.Helper()
	k, ok := vulnerability.SCAIdentity(assetID.String(), e.purl(reportedVersion), "", "", e.cveID, "")
	require.True(e.t, ok)
	return k.Fingerprint()
}

func (e *pkgMatchEnv) insertFinding(tenantID, assetID shared.ID, tool, status, fingerprint string, metadata string) string {
	e.t.Helper()
	id := uuid.NewString()
	_, err := e.pdb.Exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, severity, message, status, fingerprint, cve_id, metadata)
		VALUES ($1, $2, $3, $4, $5, 'high', 'seeded', $6, $7, $8, $9::jsonb)`,
		id, tenantID.String(), assetID.String(), map[bool]string{true: "va", false: "sca"}[tool == "version-match"],
		tool, status, fingerprint, e.cveID, metadata)
	require.NoError(e.t, err)
	return id
}

func (e *pkgMatchEnv) run() {
	e.t.Helper()
	_, err := e.svc.Run(context.Background(), time.Minute)
	require.NoError(e.t, err)
}

func TestVulnMatchingPackage_ScannerKeyComponentAndCount(t *testing.T) {
	e := newPkgMatchEnv(t)
	tn := e.tenant("vmp-key", true)
	other := e.tenant("vmp-other", true)
	asset := createTestAsset(t, e.pdb.DB, tn, "vmp-app")
	otherAsset := createTestAsset(t, e.pdb.DB, other, "vmp-other-app")
	vid := e.install(tn, asset, "1.4.2")
	e.install(other, otherAsset, "2.1.0") // not affected
	e.run()

	var fp, component string
	require.NoError(t, e.pdb.QueryRow(`SELECT fingerprint, COALESCE(component_id::text, '') FROM findings
		WHERE tenant_id = $1 AND tool_name = 'version-match' AND cve_id = $2`, tn.String(), e.cveID).Scan(&fp, &component))
	// The scanner's key, whatever version the scanner saw.
	assert.Equal(t, e.scannerFP(asset, "1.4.0"), fp)
	assert.Equal(t, vid.String(), component, "the matched version is the finding's component")
	assert.Empty(t, e.findings(other), "nothing crosses to another organization")

	// The package counts the finding (Components page).
	var open int
	require.NoError(t, e.pdb.QueryRow(`
		SELECT count(*) FROM findings f JOIN asset_software s ON s.software_version_id = f.component_id AND s.tenant_id = f.tenant_id
		WHERE f.tenant_id = $1 AND s.product_id = $2 AND f.status = 'new'`, tn.String(), e.productID).Scan(&open))
	assert.Equal(t, 1, open)
}

// A scanner finding a person closed holds the package identity: the
// matcher does not create the same issue again.
func TestVulnMatchingPackage_ClosedScannerFindingNotRecreated(t *testing.T) {
	e := newPkgMatchEnv(t)
	tn := e.tenant("vmp-closed", true)
	asset := createTestAsset(t, e.pdb.DB, tn, "vmp-closed-app")
	e.insertFinding(tn, asset, "trivy", "false_positive", e.scannerFP(asset, "1.4.2"), `{}`)
	e.install(tn, asset, "1.4.2")
	e.run()
	assert.Empty(t, e.findings(tn))
}

// The matcher's finding stored under the network key before moves to the
// package key in place: same finding, same status, component set, the old
// key kept as an alias. When another finding already holds the package key
// the legacy finding keeps its key (no merge).
func TestVulnMatchingPackage_LegacyFindingRekeyed(t *testing.T) {
	e := newPkgMatchEnv(t)
	tn := e.tenant("vmp-legacy", true)
	asset := createTestAsset(t, e.pdb.DB, tn, "vmp-legacy-app")
	vid := e.install(tn, asset, "1.4.2")
	legacy, ok := vulnerability.NetworkIdentity(asset.String(), e.cveID, "", 0, "")
	require.True(t, ok)
	meta := `{"version_match": {"product_id": "` + e.productID + `", "version_id": "` + vid.String() + `", "location": "package-lock.json"}}`
	id := e.insertFinding(tn, asset, "version-match", "confirmed", legacy.Fingerprint(), meta)
	e.run()

	var fp, status, component string
	require.NoError(t, e.pdb.QueryRow(`SELECT fingerprint, status, COALESCE(component_id::text, '') FROM findings WHERE id = $1`, id).
		Scan(&fp, &status, &component))
	assert.Equal(t, e.scannerFP(asset, "1.4.2"), fp)
	assert.Equal(t, "confirmed", status)
	assert.Equal(t, vid.String(), component)
	assert.Len(t, e.findings(tn), 1, "re-keyed, not recreated")
	var alias string
	require.NoError(t, e.pdb.QueryRow(`SELECT finding_id::text FROM finding_fingerprints WHERE tenant_id = $1 AND fingerprint = $2`,
		tn.String(), legacy.Fingerprint()).Scan(&alias))
	assert.Equal(t, id, alias, "the old key stays an alias of the finding")

	// Held: a second asset whose package key a scanner finding holds.
	asset2 := createTestAsset(t, e.pdb.DB, tn, "vmp-held-app")
	vid2 := e.install(tn, asset2, "1.4.2")
	legacy2, _ := vulnerability.NetworkIdentity(asset2.String(), e.cveID, "", 0, "")
	scanner := e.insertFinding(tn, asset2, "trivy", "false_positive", e.scannerFP(asset2, "1.4.2"), `{}`)
	meta2 := `{"version_match": {"product_id": "` + e.productID + `", "version_id": "` + vid2.String() + `", "location": "package-lock.json"}}`
	id2 := e.insertFinding(tn, asset2, "version-match", "new", legacy2.Fingerprint(), meta2)
	e.run()
	require.NoError(t, e.pdb.QueryRow(`SELECT fingerprint, status FROM findings WHERE id = $1`, id2).Scan(&fp, &status))
	assert.Equal(t, legacy2.Fingerprint(), fp, "held package key: the legacy finding keeps its key")
	assert.Equal(t, "new", status)
	require.NoError(t, e.pdb.QueryRow(`SELECT status FROM findings WHERE id = $1`, scanner).Scan(&status))
	assert.Equal(t, "false_positive", status, "the scanner finding is untouched")
}

// An organization's VEX statement covers the matcher's finding when it is
// created, as it covers a scanner's.
func TestVulnMatchingPackage_VEXStatementApplies(t *testing.T) {
	e := newPkgMatchEnv(t)
	tn := e.tenant("vmp-vex", true)
	asset := createTestAsset(t, e.pdb.DB, tn, "vmp-vex-app")
	repo := postgres.NewVEXStatementRepository(e.pdb)
	st := &vexdom.Statement{ID: shared.NewID(), TenantID: tn, VulnID: e.cveID, ProductID: shared.MustIDFromString(e.productID),
		Status: vexdom.StatusNotAffected, Justification: "vulnerable_code_not_present", Origin: "manual",
		CreatedAt: time.Now(), UpdatedAt: time.Now()}
	require.NoError(t, repo.Create(context.Background(), st))
	e.svc.SetVEXApplier(vexapp.NewService(repo, nil, nil, logger.NewNop()))

	e.install(tn, asset, "1.4.2")
	e.run()
	var stmt string
	require.NoError(t, e.pdb.QueryRow(`SELECT COALESCE(vex_statement_id::text, '') FROM findings
		WHERE tenant_id = $1 AND tool_name = 'version-match' AND cve_id = $2`, tn.String(), e.cveID).Scan(&stmt))
	assert.Equal(t, st.ID.String(), stmt, "the statement covers the matched finding")
}
