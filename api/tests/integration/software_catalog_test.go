package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
)

func softwareRepo(t *testing.T) (*postgres.SoftwareRepository, *postgres.DB) {
	t.Helper()
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	pdb := &postgres.DB{DB: db}
	repo := postgres.NewSoftwareRepository(pdb)
	require.NoError(t, repo.EnsureCurated(context.Background(), software.CuratedProducts()))
	return repo, pdb
}

func versionKey(raw string) software.VersionKey {
	v := software.VersionKey{Raw: raw, Scheme: vulnmatch.SchemeGeneric}
	if pv, ok := vulnmatch.ParseVersion(raw); ok {
		v.Normalized = pv.Normalized()
	}
	return v
}

// The curated list is idempotent and resolves names and alternate CPEs to
// one global product.
func TestSoftwareCatalog_CuratedResolvesGlobally(t *testing.T) {
	repo, pdb := softwareRepo(t)
	ctx := context.Background()
	require.NoError(t, repo.EnsureCurated(ctx, software.CuratedProducts()))
	tenant := createTestTenant(t, pdb.DB, "sw-curated")

	byName := software.Identity{Part: "a", Name: "nginx"}
	byCPE := software.Identity{Part: "a", CPEVendor: "f5", CPEProduct: "nginx"}
	byAlt := software.Identity{Part: "a", CPEVendor: "nginx", CPEProduct: "nginx"}
	refs, err := repo.Resolve(ctx, tenant, []software.Identity{byName, byCPE, byAlt})
	require.NoError(t, err)
	assert.True(t, refs[byName].Global)
	assert.Equal(t, refs[byName].ID, refs[byCPE].ID)
	assert.Equal(t, refs[byName].ID, refs[byAlt].ID)
}

// An unknown product is private to the tenant that observed it: another
// tenant observing the same name gets its own product, and can never reach
// the first tenant's product or version.
func TestSoftwareCatalog_PrivateProductsAreIsolated(t *testing.T) {
	repo, pdb := softwareRepo(t)
	ctx := context.Background()
	tenantA := createTestTenant(t, pdb.DB, "sw-a")
	tenantB := createTestTenant(t, pdb.DB, "sw-b")
	internal := software.Identity{Part: "a", Name: "acme internal billing portal"}
	privateCPE := software.Identity{Part: "a", CPEVendor: "acme-corp-private", CPEProduct: "billing"}

	ra, err := repo.Resolve(ctx, tenantA, []software.Identity{internal, privateCPE})
	require.NoError(t, err)
	rb, err := repo.Resolve(ctx, tenantB, []software.Identity{internal, privateCPE})
	require.NoError(t, err)
	assert.False(t, ra[internal].Global)
	assert.False(t, ra[privateCPE].Global)
	assert.NotEqual(t, ra[internal].ID, rb[internal].ID, "two tenants share a private product")
	assert.NotEqual(t, ra[privateCPE].ID, rb[privateCPE].ID, "two tenants share a private CPE product")

	// Resolving again is stable.
	ra2, err := repo.Resolve(ctx, tenantA, []software.Identity{internal})
	require.NoError(t, err)
	assert.Equal(t, ra[internal].ID, ra2[internal].ID)

	// Nothing global was created from an observation.
	var global int
	require.NoError(t, pdb.QueryRowContext(ctx, `SELECT count(*) FROM software_products
		WHERE tenant_id IS NULL AND (lower(name) = $1 OR cpe_vendor = $2)`, internal.Name, privateCPE.CPEVendor).Scan(&global))
	assert.Zero(t, global)

	// A private version is private; tenant B cannot link tenant A's
	// private product or version (the scope trigger refuses it).
	va, err := repo.EnsureVersion(ctx, tenantA, ra[internal], versionKey("3.1.4"))
	require.NoError(t, err)
	var vt *string
	require.NoError(t, pdb.QueryRowContext(ctx, `SELECT tenant_id::text FROM software_versions WHERE id = $1`, va.String()).Scan(&vt))
	require.NotNil(t, vt)
	assert.Equal(t, tenantA.String(), *vt)

	assetB := createTestAsset(t, pdb.DB, tenantB, "sw-b-asset")
	_, err = repo.UpsertLinks(ctx, tenantB, []software.Link{{
		AssetID: assetB, ProductID: ra[internal].ID, VersionID: va, Source: software.SourceTechnology, Confidence: 50,
	}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "another tenant")

	// A tenant cannot create a version of another tenant's private product
	// either: the product is not in its scope.
	_, err = repo.EnsureVersion(ctx, tenantB, ra[internal], versionKey("9.9"))
	require.Error(t, err)
}

// A tenant's private alias never shadows a public product: global first.
func TestSoftwareCatalog_GlobalBeforePrivate(t *testing.T) {
	repo, pdb := softwareRepo(t)
	ctx := context.Background()
	tenant := createTestTenant(t, pdb.DB, "sw-shadow")
	_, err := pdb.ExecContext(ctx, `
		WITH p AS (INSERT INTO software_products (tenant_id, part, name, source) VALUES ($1, 'a', 'nginx-shadow', 'observed') RETURNING id)
		INSERT INTO software_product_aliases (product_id, tenant_id, kind, value) SELECT id, $1, 'name', 'nginx' FROM p`, tenant.String())
	require.NoError(t, err)
	refs, err := repo.Resolve(ctx, tenant, []software.Identity{{Part: "a", Name: "nginx"}})
	require.NoError(t, err)
	assert.True(t, refs[software.Identity{Part: "a", Name: "nginx"}].Global)
}

// Versions of a global product are global and created once; the canonical
// form folds 1.18 and 1.18.0; an unparseable version keeps its raw text.
func TestSoftwareCatalog_Versions(t *testing.T) {
	repo, pdb := softwareRepo(t)
	ctx := context.Background()
	tenantA := createTestTenant(t, pdb.DB, "sw-va")
	tenantB := createTestTenant(t, pdb.DB, "sw-vb")
	id := software.Identity{Part: "a", Name: "nginx"}
	ra, err := repo.Resolve(ctx, tenantA, []software.Identity{id})
	require.NoError(t, err)

	v1, err := repo.EnsureVersion(ctx, tenantA, ra[id], versionKey("1.18.0"))
	require.NoError(t, err)
	v2, err := repo.EnsureVersion(ctx, tenantB, ra[id], versionKey("1.18"))
	require.NoError(t, err)
	assert.Equal(t, v1, v2)
	var vt *string
	require.NoError(t, pdb.QueryRowContext(ctx, `SELECT tenant_id::text FROM software_versions WHERE id = $1`, v1.String()).Scan(&vt))
	assert.Nil(t, vt, "a version of a global product must be global")

	q := versionKey("1.18.0")
	q.Qualifier = "ubuntu"
	v3, err := repo.EnsureVersion(ctx, tenantA, ra[id], q)
	require.NoError(t, err)
	assert.NotEqual(t, v1, v3, "a distribution build is its own version")

	u1, err := repo.EnsureVersion(ctx, tenantA, ra[id], versionKey("latest"))
	require.NoError(t, err)
	u2, err := repo.EnsureVersion(ctx, tenantA, ra[id], versionKey("latest"))
	require.NoError(t, err)
	assert.Equal(t, u1, u2)
	var norm *string
	require.NoError(t, pdb.QueryRowContext(ctx, `SELECT normalized FROM software_versions WHERE id = $1`, u1.String()).Scan(&norm))
	assert.Nil(t, norm)
}

// A new version of the same product at the same location supersedes the
// old link; two versions in one write (two copies of a library on one page)
// both stay; another location is untouched.
func TestSoftwareCatalog_LinksSupersede(t *testing.T) {
	repo, pdb := softwareRepo(t)
	ctx := context.Background()
	tenant := createTestTenant(t, pdb.DB, "sw-links")
	asset := createTestAsset(t, pdb.DB, tenant, "sw-links-asset")
	id := software.Identity{Part: "a", Name: "jquery"}
	refs, err := repo.Resolve(ctx, tenant, []software.Identity{id})
	require.NoError(t, err)
	p := refs[id]
	ver := func(s string) shared.ID {
		v, err := repo.EnsureVersion(ctx, tenant, p, versionKey(s))
		require.NoError(t, err)
		return v
	}
	link := func(v shared.ID, loc string) software.Link {
		return software.Link{AssetID: asset, ProductID: p.ID, VersionID: v, Location: loc, Source: software.SourceTechnology, Confidence: 65}
	}
	v1, v2, v3 := ver("1.12.4"), ver("3.5.1"), ver("3.7.1")

	res, err := repo.UpsertLinks(ctx, tenant, []software.Link{link(v1, ""), link(v2, ""), link(v1, "tcp/8443")})
	require.NoError(t, err)
	assert.Equal(t, 3, res.Inserted)
	assert.Zero(t, res.Superseded)
	assert.Equal(t, []shared.ID{asset}, res.ChangedAssets)

	// Seen again unchanged: nothing changes for the matcher.
	res, err = repo.UpsertLinks(ctx, tenant, []software.Link{link(v1, ""), link(v2, "")})
	require.NoError(t, err)
	assert.Zero(t, res.Inserted)
	assert.Empty(t, res.ChangedAssets, "%+v", res)

	// Upgraded at the origin: both old versions there are superseded, the
	// other location is not.
	res, err = repo.UpsertLinks(ctx, tenant, []software.Link{link(v3, "")})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Inserted)
	assert.Equal(t, 2, res.Superseded)
	var active []string
	rows, err := pdb.QueryContext(ctx, `SELECT v.raw || '@' || s.location FROM asset_software s
		JOIN software_versions v ON v.id = s.software_version_id
		WHERE s.tenant_id = $1 AND s.asset_id = $2 AND s.superseded_at IS NULL ORDER BY 1`, tenant.String(), asset.String())
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		active = append(active, s)
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []string{"1.12.4@tcp/8443", "3.7.1@"}, active)

	// Seen again: a superseded link comes back.
	res, err = repo.UpsertLinks(ctx, tenant, []software.Link{link(v1, "")})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Superseded, "the newest link is superseded by the re-seen one")
}

// Evidence is clipped to the column limit without breaking UTF-8.
func TestSoftwareCatalog_EvidenceClipped(t *testing.T) {
	repo, pdb := softwareRepo(t)
	ctx := context.Background()
	tenant := createTestTenant(t, pdb.DB, "sw-clip")
	asset := createTestAsset(t, pdb.DB, tenant, "sw-clip-asset")
	id := software.Identity{Part: "a", Name: "nginx"}
	refs, err := repo.Resolve(ctx, tenant, []software.Identity{id})
	require.NoError(t, err)
	v, err := repo.EnsureVersion(ctx, tenant, refs[id], versionKey("1.25.3"))
	require.NoError(t, err)
	_, err = repo.UpsertLinks(ctx, tenant, []software.Link{{
		AssetID: asset, ProductID: refs[id].ID, VersionID: v, Source: software.SourceService,
		Evidence: strings.Repeat("é", 400), Confidence: 65,
	}})
	require.NoError(t, err)
	var n int
	require.NoError(t, pdb.QueryRowContext(ctx, `SELECT octet_length(evidence) FROM asset_software WHERE tenant_id = $1`, tenant.String()).Scan(&n))
	assert.LessOrEqual(t, n, software.MaxEvidenceLen)
}
