package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/cvecorpus"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	vm "github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
)

// aliasEnv: a canonical product (the identity tenants report) and the
// string a CNA wrote for the same product, which the feed carries as a
// name-derived product key until the alias dictionary maps it.
type aliasEnv struct {
	*matchEnv
	canonical string // vendor of the canonical product
	cna       string // vendor string the CNA wrote
}

func newAliasEnv(t *testing.T) *aliasEnv {
	e := newMatchEnv(t)
	sfx := uuid.NewString()[:8]
	return &aliasEnv{matchEnv: e, canonical: "acme" + sfx, cna: "acme" + sfx + "_inc"}
}

// publish (re)writes one CVE with ranges of vendor:widget.
func (e *aliasEnv) publish(cveID string, rejected bool, ranges map[string]vm.Range) {
	e.t.Helper()
	score := 9.1
	c := cvecorpus.CVE{ID: cveID, Status: "Published", Description: "Widget overflow.", CVSSScore: &score, Severity: "critical", Rejected: rejected}
	if rejected {
		c.Status = "Rejected"
	}
	for vendor, r := range ranges {
		p, err := vm.ParseCPE("cpe:2.3:a:" + vendor + ":widget:*")
		require.NoError(e.t, err)
		c.Ranges = append(c.Ranges, cvecorpus.Range{Product: p, Range: r, Source: "cve5"})
	}
	_, err := e.corpus.ApplyPage(context.Background(), []cvecorpus.CVE{c})
	require.NoError(e.t, err)
}

// observeCPE links vendor:widget at version to the asset (a new one when
// zero), the way ingest does.
func (e *aliasEnv) observeCPE(tenantID, assetID shared.ID, vendor, version string) shared.ID {
	e.t.Helper()
	ctx := context.Background()
	if assetID.IsZero() {
		assetID = createTestAsset(e.t, e.pdb.DB, tenantID, "alias-asset-"+uuid.NewString()[:6])
	}
	p, ok := software.Parse(software.Observation{CPE: "cpe:2.3:a:" + vendor + ":widget:" + version, Port: 443, Transport: "tcp", Location: "tcp/443", Source: software.SourceService})
	require.True(e.t, ok)
	refs, err := e.sw.Resolve(ctx, tenantID, []software.Identity{p.Identity})
	require.NoError(e.t, err)
	ref := refs[p.Identity]
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

// alias applies a one-entry dictionary whose entry was learned (not
// reviewed).
func (e *aliasEnv) alias(kind, value, target string) software.AliasResult {
	e.t.Helper()
	return e.aliasBasis(kind, value, target, "learned")
}

func (e *aliasEnv) aliasBasis(kind, value, target, basis string) software.AliasResult {
	e.t.Helper()
	res, err := e.corpus.ApplyFeedAliases(context.Background(), []software.FeedAlias{{Kind: kind, Value: value, Target: target, Basis: basis}}, 100)
	require.NoError(e.t, err)
	return res
}

// publishNVD (re)writes one CVE with an NVD range of vendor:widget.
func (e *aliasEnv) publishNVD(cveID, vendor string, r vm.Range) {
	e.t.Helper()
	score := 7.5
	p, err := vm.ParseCPE("cpe:2.3:a:" + vendor + ":widget:*")
	require.NoError(e.t, err)
	_, err = e.corpus.ApplyPage(context.Background(), []cvecorpus.CVE{{ID: cveID, Status: "Analyzed", Description: "Widget bug.",
		CVSSScore: &score, Severity: "high", Ranges: []cvecorpus.Range{{Product: p, Range: r, Source: "nvd"}}}})
	require.NoError(e.t, err)
}

func (e *aliasEnv) openFindings(tenantID shared.ID, cveID string) []string {
	e.t.Helper()
	return queryStrings(e.t, e.pdb.DB, `SELECT status || '|' || asset_id::text FROM findings
		WHERE tenant_id = $1 AND tool_name = 'version-match' AND cve_id = $2 ORDER BY 1`, tenantID.String(), cveID)
}

func (e *aliasEnv) productExists(vendor string) bool {
	e.t.Helper()
	var n int
	require.NoError(e.t, e.pdb.QueryRow(`SELECT count(*) FROM software_products WHERE tenant_id IS NULL AND cpe_vendor = $1`, vendor).Scan(&n))
	return n > 0
}

// A CVE whose only affected data is the CNA's vendor/product strings is
// kept in the corpus but matches nothing until the alias dictionary maps
// the CNA's name to the catalog product; then the existing ranges match
// without any re-ingest, a later update through the old key lands on the
// canonical product, re-applying the dictionary changes nothing, and a
// rejection removes the ranges.
func TestSoftwareAlias_CNANameResolvesAfterDictionary(t *testing.T) {
	e := newAliasEnv(t)
	tn := e.tenant("alias-cna", true)
	cve := testCVEID()
	e.publish(cve, false, map[string]vm.Range{e.cna: {Start: "2.0", StartIncl: true, End: "2.4.1"}})
	// The catalog knows the canonical product (another CVE names it).
	e.publish(testCVEID(), false, map[string]vm.Range{e.canonical: {Exact: "1.0.0"}})
	asset := e.observeCPE(tn, shared.ID{}, e.canonical, "2.3.0")
	e.run()
	// Unresolved: kept (record and range), unmatched.
	assert.Empty(t, e.openFindings(tn, cve))
	assert.Len(t, rangesOf(t, e.pdb, cve), 1)

	res := e.alias(software.AliasKindCPE, "a:"+e.cna+":widget", "a:"+e.canonical+":widget")
	assert.Equal(t, 1, res.Written)
	assert.Equal(t, 1, res.Merged)
	assert.Equal(t, 1, res.Requeued)
	assert.False(t, e.productExists(e.cna), "the name-derived product folds into the canonical one")
	e.run()
	got := e.openFindings(tn, cve)
	require.Len(t, got, 1)
	assert.Equal(t, "new|"+asset.String(), got[0])

	// Case 5: a later update adds a range through the CNA's key; it
	// resolves to the canonical product and matches without a re-ingest.
	cve2 := testCVEID()
	e.publish(cve2, false, map[string]vm.Range{e.cna: {Exact: "2.3.0"}})
	assert.False(t, e.productExists(e.cna), "the alias resolves the key; no new product")
	e.run()
	require.Len(t, e.openFindings(tn, cve2), 1)

	// Case 8: the same dictionary again changes nothing, and nothing flaps.
	res = e.alias(software.AliasKindCPE, "a:"+e.cna+":widget", "a:"+e.canonical+":widget")
	res.Removed = 0 // other tests' feed aliases in the shared database
	assert.Equal(t, software.AliasResult{Unchanged: 1}, res)
	e.run()
	assert.Equal(t, got, e.openFindings(tn, cve))

	// Case 7: rejected upstream removes the CVE's ranges; the finding is
	// flagged and demoted elsewhere, never auto-closed by the matcher
	// (RFC-066 §10, RFC-044 D4), and no new finding appears.
	e.publish(cve, true, nil)
	assert.Empty(t, rangesOf(t, e.pdb, cve))
	require.NoError(t, postgres.NewSoftwareMatchRepository(e.pdb).QueueTenants(context.Background(), []shared.ID{tn}))
	e.run()
	assert.Equal(t, got, e.openFindings(tn, cve))
}

// Case 20 and tenant isolation: a deprecated CPE becomes an alias of its
// replacement. Assets that reported the deprecated identity move to the
// canonical product (a version both have folds into one row), each link
// and finding keeps its own tenant, and a tenant's private product is
// never touched.
func TestSoftwareAlias_DeprecatedCPEMergesAcrossTenantsSafely(t *testing.T) {
	e := newAliasEnv(t)
	oldT := e.tenant("alias-old", true)
	newT := e.tenant("alias-new", true)
	privT := e.tenant("alias-private", true)
	cve := testCVEID()
	e.publish(cve, false, map[string]vm.Range{e.canonical: {End: "3.0"}})
	// An older CVE named the product under its deprecated CPE.
	e.publish(testCVEID(), false, map[string]vm.Range{e.cna: {Exact: "1.0.0"}})
	assetOld := e.observeCPE(oldT, shared.ID{}, e.cna, "2.0.1")
	assetNew := e.observeCPE(newT, shared.ID{}, e.canonical, "2.0.1")
	// A tenant-private product with the same CPE identity (private rows
	// are never merged by a public dictionary).
	var privProduct string
	require.NoError(t, e.pdb.QueryRow(`INSERT INTO software_products (tenant_id, part, vendor, name, cpe_vendor, cpe_product, source)
		VALUES ($1, 'a', $2, 'widget', $2, 'widget', 'observed') RETURNING id`, privT.String(), e.cna).Scan(&privProduct))
	e.run()
	assert.Empty(t, e.openFindings(oldT, cve))
	require.Len(t, e.openFindings(newT, cve), 1)

	e.alias(software.AliasKindCPE, "a:"+e.cna+":widget", "a:"+e.canonical+":widget")
	e.run()
	gotOld := e.openFindings(oldT, cve)
	require.Len(t, gotOld, 1)
	assert.Equal(t, "new|"+assetOld.String(), gotOld[0])
	gotNew := e.openFindings(newT, cve)
	require.Len(t, gotNew, 1, "no duplicate for the tenant already on the canonical product")
	assert.Equal(t, "new|"+assetNew.String(), gotNew[0])
	assert.Empty(t, e.openFindings(privT, cve))

	// One global 2.0 version remains, linked by both tenants' own assets.
	rows := queryStrings(t, e.pdb.DB, `SELECT s.tenant_id::text || '|' || s.asset_id::text FROM asset_software s
		JOIN software_products p ON p.id = s.product_id WHERE p.tenant_id IS NULL AND p.cpe_vendor = $1 ORDER BY 1`, e.canonical)
	assert.ElementsMatch(t, []string{oldT.String() + "|" + assetOld.String(), newT.String() + "|" + assetNew.String()}, rows)
	var versions int
	require.NoError(t, e.pdb.QueryRow(`SELECT count(*) FROM software_versions v JOIN software_products p ON p.id = v.product_id
		WHERE p.cpe_vendor = $1 AND v.raw = '2.0.1'`, e.canonical).Scan(&versions))
	assert.Equal(t, 1, versions)
	var priv int
	require.NoError(t, e.pdb.QueryRow(`SELECT count(*) FROM software_products WHERE id = $1 AND tenant_id = $2`, privProduct, privT.String()).Scan(&priv))
	assert.Equal(t, 1, priv, "a tenant-private product is never merged")
}

// Case 21: a package identity (purl) and a CPE for the same software are
// one product: a package the dictionary maps resolves to the global
// product even when the tenant already has its own row, and the asset
// gets one finding per CVE.
func TestSoftwareAlias_PURLAndCPEAreOneProduct(t *testing.T) {
	e := newAliasEnv(t)
	tn := e.tenant("alias-purl", true)
	cve := testCVEID()
	e.publish(cve, false, map[string]vm.Range{e.canonical: {End: "2.17.1"}})
	ns := "org." + e.canonical
	purl, err := software.ParsePURL("pkg:maven/" + ns + "/widget-core@2.14.0")
	require.NoError(t, err)
	writer := postgres.NewSoftwarePackageWriter(e.pdb)
	asset := e.observeCPE(tn, shared.ID{}, e.canonical, "2.14.0")
	snap := software.PackageSnapshot{AssetID: asset, Channel: software.ChannelSBOMUpload, Replace: true,
		Packages: []software.PackageNode{{Ref: "a", PURL: purl, DisplayName: "widget-core", Location: "app.jar"}}}
	_, err = writer.WritePackages(context.Background(), tn, snap)
	require.NoError(t, err)

	// A learned package alias is refused: it would win over the tenant's
	// own package row (dependency confusion).
	res := e.alias(software.AliasKindPURL, "pkg:maven/"+ns+"/widget-core", "a:"+e.canonical+":widget")
	res.Removed = 0 // other tests' feed aliases in the shared database
	assert.Equal(t, software.AliasResult{Skipped: 1}, res)
	res = e.aliasBasis(software.AliasKindPURL, "pkg:maven/"+ns+"/widget-core", "a:"+e.canonical+":widget", software.BasisCurated)
	assert.Equal(t, 1, res.Written)
	_, err = writer.WritePackages(context.Background(), tn, snap)
	require.NoError(t, err)
	products := queryStrings(t, e.pdb.DB, `SELECT DISTINCT p.cpe_vendor FROM asset_software s
		JOIN software_products p ON p.id = s.product_id
		WHERE s.tenant_id = $1 AND s.asset_id = $2 AND s.superseded_at IS NULL AND p.tenant_id IS NULL`, tn.String(), asset.String())
	assert.Equal(t, []string{e.canonical}, products, "the package resolves to the canonical global product")
	e.svc.SoftwareChanged(tn, nil)
	e.run()
	assert.Len(t, e.openFindings(tn, cve), 1, "one finding per asset and CVE across both identities")
}

// Untrusted dictionary entries: malformed ones are skipped (never fatal,
// never written), a curated alias or curated product is never changed, and
// a dictionary that would merge too much is refused whole.
func TestSoftwareAlias_RefusesBadAndPoisonedEntries(t *testing.T) {
	e := newAliasEnv(t)
	ctx := context.Background()
	target := "a:" + e.canonical + ":widget"
	bad := []software.FeedAlias{
		{Kind: "name", Value: "nginx", Target: target},                                 // name aliases are curated only
		{Kind: "cpe", Value: "a:UPPER:widget", Target: target},                         // not lower case
		{Kind: "cpe", Value: "a:x:" + strings.Repeat("w", 300), Target: target},        // oversized
		{Kind: "cpe", Value: target, Target: target},                                   // names itself
		{Kind: "cpe", Value: "a:x:widget", Target: "a:*:widget"},                       // wildcard target
		{Kind: "cpe", Value: "a:x:wid\x00get", Target: target},                         // control character
		{Kind: "purl", Value: "pkg:npm/widget@1.0.0", Target: target},                  // purl with a version
		{Kind: "purl", Value: "not-a-purl", Target: target},                            // not a purl
		{Kind: "cpe", Value: "x:a:b", Target: target},                                  // bad part
		{Kind: "cpe", Value: "a:nginx:nginx", Target: target},                          // a curated alias (F5 nginx)
		{Kind: "cpe", Value: "a:f5:nginx", Target: target},                             // a curated product
		{Kind: "cpe", Value: "a:apache:http_server", Target: "a:" + e.cna + ":widget"}, // a curated product
	}
	res, err := e.corpus.ApplyFeedAliases(ctx, bad, 100)
	require.NoError(t, err)
	assert.Equal(t, len(bad), res.Skipped)
	assert.Zero(t, res.Written+res.Merged+res.Repointed)
	var curated string
	require.NoError(t, e.pdb.QueryRow(`SELECT p.cpe_vendor || ':' || a.source FROM software_product_aliases a
		JOIN software_products p ON p.id = a.product_id WHERE a.tenant_id IS NULL AND a.kind = 'cpe' AND a.value = 'a:nginx:nginx'`).Scan(&curated))
	assert.Equal(t, "f5:curated", curated)
	assert.True(t, e.productExists("f5"))

	// The merge guard: two merges with a limit of one roll back entirely.
	cve := testCVEID()
	e.publish(cve, false, map[string]vm.Range{e.cna: {End: "1"}, e.cna + "2": {End: "1"}})
	_, err = e.corpus.ApplyFeedAliases(ctx, []software.FeedAlias{
		{Kind: "cpe", Value: "a:" + e.cna + ":widget", Target: target},
		{Kind: "cpe", Value: "a:" + e.cna + "2:widget", Target: target},
	}, 1)
	require.ErrorIs(t, err, software.ErrMergeLimit)
	// An empty dictionary is refused (it would remove every feed alias).
	_, err = e.corpus.ApplyFeedAliases(ctx, nil, 1)
	require.ErrorIs(t, err, software.ErrInvalidAlias)
	_, err = e.corpus.ApplyFeedAliases(ctx, []software.FeedAlias{
		{Kind: "cpe", Value: "a:" + e.cna + ":widget", Target: target},
		{Kind: "cpe", Value: "a:" + e.cna + "2:widget", Target: target},
	}, 1)
	require.ErrorIs(t, err, software.ErrMergeLimit)
	assert.True(t, e.productExists(e.cna))
	var n int
	require.NoError(t, e.pdb.QueryRow(`SELECT count(*) FROM software_product_aliases WHERE value LIKE $1`, "a:"+e.cna+"%").Scan(&n))
	assert.Zero(t, n, "a refused dictionary writes nothing")

	// Too many entries are refused before anything is read.
	_, err = e.corpus.ApplyFeedAliases(ctx, make([]software.FeedAlias, software.MaxFeedAliases+1), 1)
	require.ErrorIs(t, err, software.ErrInvalidAlias)
}

// A changed dictionary repoints a feed alias to the new product, and a
// curated alias later added for a value the feed holds takes it over.
func TestSoftwareAlias_RepointAndCuratedWins(t *testing.T) {
	e := newAliasEnv(t)
	value := "a:" + e.cna + ":widget"
	e.alias(software.AliasKindCPE, value, "a:"+e.canonical+":widget")
	res := e.alias(software.AliasKindCPE, value, "a:"+e.canonical+"x:widget")
	assert.Equal(t, 1, res.Repointed)
	var vendor string
	require.NoError(t, e.pdb.QueryRow(`SELECT p.cpe_vendor FROM software_product_aliases a JOIN software_products p ON p.id = a.product_id
		WHERE a.tenant_id IS NULL AND a.kind = 'cpe' AND a.value = $1 AND a.source = 'feed'`, value).Scan(&vendor))
	assert.Equal(t, e.canonical+"x", vendor)

	// A feed alias on a curated value is taken over by the curated list.
	_, err := e.pdb.Exec(`UPDATE software_product_aliases SET source = 'feed',
		product_id = (SELECT id FROM software_products WHERE tenant_id IS NULL AND cpe_vendor = $1 LIMIT 1)
		WHERE tenant_id IS NULL AND kind = 'cpe' AND value = 'a:nginx:nginx'`, e.canonical+"x")
	require.NoError(t, err)
	require.NoError(t, e.sw.EnsureCurated(context.Background(), software.CuratedProducts()))
	var curated string
	require.NoError(t, e.pdb.QueryRow(`SELECT p.cpe_vendor || ':' || a.source FROM software_product_aliases a
		JOIN software_products p ON p.id = a.product_id WHERE a.tenant_id IS NULL AND a.kind = 'cpe' AND a.value = 'a:nginx:nginx'`).Scan(&curated))
	assert.Equal(t, "f5:curated", curated)
}

// Poisoning: a learned entry (advisory text, not reviewed) that names a
// product with data of its own (NVD ranges, tenant links) is held: no
// alias, no fold, the tenant's link and finding stay. The same entry,
// reviewed, folds the product and journals the fold so it can be split.
func TestSoftwareAlias_LearnedEntryNeverFoldsARealProduct(t *testing.T) {
	e := newAliasEnv(t)
	tn := e.tenant("alias-poison", true)
	victim := e.cna // a real product that NVD names
	cve := testCVEID()
	e.publishNVD(cve, victim, vm.Range{End: "3.0"})
	e.publishNVD(testCVEID(), e.canonical, vm.Range{Exact: "9.9"})
	asset := e.observeCPE(tn, shared.ID{}, victim, "2.0.0")
	e.run()
	before := e.openFindings(tn, cve)
	require.Len(t, before, 1)

	value, target := "a:"+victim+":widget", "a:"+e.canonical+":widget"
	res := e.alias(software.AliasKindCPE, value, target)
	assert.Equal(t, 1, res.Held)
	assert.Equal(t, []string{value + " -> " + target}, res.HeldValues)
	assert.Zero(t, res.Written+res.Merged)
	assert.True(t, e.productExists(victim), "a learned entry never folds a product NVD names")
	var n int
	require.NoError(t, e.pdb.QueryRow(`SELECT count(*) FROM software_product_aliases WHERE tenant_id IS NULL AND value = $1`, value).Scan(&n))
	assert.Zero(t, n, "a held entry changes no resolution")
	e.run()
	assert.Equal(t, before, e.openFindings(tn, cve))

	res = e.aliasBasis(software.AliasKindCPE, value, target, software.BasisCurated)
	assert.Equal(t, 1, res.Merged)
	assert.False(t, e.productExists(victim))
	var identity, basis string
	var cves, moved int
	require.NoError(t, e.pdb.QueryRow(`SELECT from_identity, basis, cardinality(cve_ids), cardinality(moved_version_ids)
		FROM software_product_merges m JOIN software_products p ON p.id = m.into_product_id
		WHERE p.cpe_vendor = $1`, e.canonical).Scan(&identity, &basis, &cves, &moved))
	assert.Equal(t, value, identity)
	assert.Equal(t, software.BasisCurated, basis)
	assert.Equal(t, 1, cves)
	assert.Equal(t, 1, moved, "the 2.0.0 version moved as it is (journaled for a split)")
	e.run()
	got := e.openFindings(tn, cve)
	require.Len(t, got, 1)
	assert.Equal(t, "new|"+asset.String(), got[0])
}

// A feed alias the dictionary no longer carries is removed (a retracted
// entry stops resolving); curated and tenant aliases are never removed.
func TestSoftwareAlias_RetractedEntryIsRemoved(t *testing.T) {
	e := newAliasEnv(t)
	gone, kept := "a:"+e.cna+":widget", "a:"+e.cna+"2:widget"
	target := "a:" + e.canonical + ":widget"
	_, err := e.corpus.ApplyFeedAliases(context.Background(), []software.FeedAlias{
		{Kind: "cpe", Value: gone, Target: target}, {Kind: "cpe", Value: kept, Target: target}}, 10)
	require.NoError(t, err)
	res := e.alias(software.AliasKindCPE, kept, target)
	assert.Equal(t, 1, res.Unchanged)
	assert.GreaterOrEqual(t, res.Removed, 1)
	values := queryStrings(t, e.pdb.DB, `SELECT value FROM software_product_aliases WHERE tenant_id IS NULL AND source = 'feed' AND value LIKE $1 ORDER BY 1`, "a:"+e.cna+"%")
	assert.Equal(t, []string{kept}, values)
	var curated int
	require.NoError(t, e.pdb.QueryRow(`SELECT count(*) FROM software_product_aliases WHERE tenant_id IS NULL AND source = 'curated' AND value = 'a:nginx:nginx'`).Scan(&curated))
	assert.Equal(t, 1, curated)
}

// A tenant's VEX statements on both products for the same subject: the
// fold keeps the one on the canonical product instead of failing the whole
// dictionary on the one-statement-per-subject key, and each statement keeps
// its tenant.
func TestSoftwareAlias_FoldKeepsOneVEXStatementPerSubject(t *testing.T) {
	e := newAliasEnv(t)
	tn := e.tenant("alias-vex", true)
	other := e.tenant("alias-vex-other", true)
	cve := testCVEID()
	e.publish(cve, false, map[string]vm.Range{e.cna: {End: "2"}, e.canonical: {End: "2"}})
	product := func(vendor string) string {
		var id string
		require.NoError(t, e.pdb.QueryRow(`SELECT id FROM software_products WHERE tenant_id IS NULL AND cpe_vendor = $1`, vendor).Scan(&id))
		return id
	}
	from, into := product(e.cna), product(e.canonical)
	vex := func(tenant shared.ID, productID, status string) {
		_, err := e.pdb.Exec(`INSERT INTO vex_statements (tenant_id, vuln_id, product_id, status, justification, origin)
			VALUES ($1, $2, $3, $4, CASE WHEN $4 = 'not_affected' THEN 'component_not_present' END, 'manual')`, tenant.String(), cve, productID, status)
		require.NoError(t, err)
	}
	vex(tn, from, "not_affected")
	vex(tn, into, "affected")
	vex(other, from, "not_affected")

	res := e.alias(software.AliasKindCPE, "a:"+e.cna+":widget", "a:"+e.canonical+":widget")
	require.Equal(t, 1, res.Merged)
	rows := queryStrings(t, e.pdb.DB, `SELECT tenant_id::text || '|' || status FROM vex_statements WHERE product_id = $1 ORDER BY 1`, into)
	assert.ElementsMatch(t, []string{tn.String() + "|affected", other.String() + "|not_affected"}, rows)
}

// Folds serialize with the bundle importer of every replica: while a chunk
// transaction holds the vulnfeed checkpoint, the dictionary waits.
func TestSoftwareAlias_WaitsForTheBundleImporter(t *testing.T) {
	e := newAliasEnv(t)
	_, err := e.pdb.Exec(`INSERT INTO feed_checkpoints (feed) VALUES ('vulnfeed') ON CONFLICT (feed) DO NOTHING`)
	require.NoError(t, err)
	tx, err := e.pdb.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SELECT 1 FROM feed_checkpoints WHERE feed = 'vulnfeed' FOR UPDATE`)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err = e.corpus.ApplyFeedAliases(ctx, []software.FeedAlias{{Kind: "cpe", Value: "a:" + e.cna + ":widget", Target: "a:" + e.canonical + ":widget"}}, 10)
	require.Error(t, err, "the dictionary must not run beside a chunk transaction")
}
