package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/cvecorpus"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/domain/vulncatalog"
	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
)

// A global product the feed creates gets the deterministic id of its
// canonical key, the same id the database function computes; so does a
// version of it. A tenant-private product and its versions keep random ids.
func TestVulnCatalogKeys_NewGlobalRowsAreDeterministic(t *testing.T) {
	repo, pdb := corpusRepo(t)
	ctx := context.Background()
	vendor := "vkey" + uuid.NewString()[:8]
	_, err := repo.ApplyPage(ctx, []cvecorpus.CVE{{
		ID: testCVEID(), Status: "Analyzed",
		Ranges: []cvecorpus.Range{{Product: cpe(t, "cpe:2.3:a:"+vendor+":gadget:*:*:*:*:*:*:*:*"), Range: vulnmatch.Range{End: "3.0"}}},
	}})
	require.NoError(t, err)

	var id string
	var sqlMatches bool
	require.NoError(t, pdb.QueryRowContext(ctx, `
		SELECT id, id = vuln_catalog_product_id(part::text, cpe_vendor, cpe_product, purl_type, purl_namespace, purl_name)
		FROM software_products WHERE tenant_id IS NULL AND cpe_vendor = $1 AND cpe_product = 'gadget'`, vendor).Scan(&id, &sqlMatches))
	assert.Equal(t, vulncatalog.ProductID(vulncatalog.ProductKeyCPE("a", vendor, "gadget")).String(), id)
	assert.True(t, sqlMatches, "Go and the database compute the same product id")

	sw := postgres.NewSoftwareRepository(pdb)
	tenant := createTestTenant(t, pdb.DB, "vulncatalog-keys")
	global := software.ProductRef{ID: shared.MustIDFromString(id), Global: true}
	key := software.VersionKey{Raw: "2.4.1", Normalized: "2.4.1", Scheme: "semver"}
	vid, err := sw.EnsureVersion(ctx, tenant, global, key)
	require.NoError(t, err)
	assert.Equal(t, vulncatalog.VersionID(global.ID, "semver", "2.4.1", "2.4.1", "", ""), vid)
	require.NoError(t, pdb.QueryRowContext(ctx, `
		SELECT id = vuln_catalog_version_id(product_id, scheme, normalized, raw, qualifier, edition)
		FROM software_versions WHERE id = $1`, vid.String()).Scan(&sqlMatches))
	assert.True(t, sqlMatches, "Go and the database compute the same version id")
	again, err := sw.EnsureVersion(ctx, shared.NewID(), global, key)
	require.NoError(t, err)
	assert.Equal(t, vid, again, "the same global version resolves to one row")

	// Tenant-private rows are tenant data: random ids, never derived.
	var pid string
	require.NoError(t, pdb.QueryRowContext(ctx, `INSERT INTO software_products (tenant_id, part, name, source)
		VALUES ($1, 'a', 'private gadget', 'observed') RETURNING id`, tenant.String()).Scan(&pid))
	private := software.ProductRef{ID: shared.MustIDFromString(pid)}
	pvid, err := sw.EnsureVersion(ctx, tenant, private, key)
	require.NoError(t, err)
	assert.NotEqual(t, vulncatalog.VersionID(private.ID, "semver", "2.4.1", "2.4.1", "", ""), pvid)
}
