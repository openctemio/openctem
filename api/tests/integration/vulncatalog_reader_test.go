package integration

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/cvecorpus"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulncatalog"
	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
)

// vulnCatalogFixture writes one CVE with two ranges on a fresh global
// product, KEV, EPSS and an advisory alias, and returns the CVE and product.
func vulnCatalogFixture(t *testing.T, repo *postgres.CVECorpusRepository, pdb *postgres.DB) (string, shared.ID) {
	t.Helper()
	ctx := context.Background()
	id := testCVEID()
	vendor := "vcat" + uuid.NewString()[:8]
	score := 9.8
	_, err := repo.ApplyPage(ctx, []cvecorpus.CVE{{
		ID: id, Status: "Analyzed", Description: "remote code execution", CVSSScore: &score, CVSSVersion: "3.1",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Severity: "critical", CWEs: []string{"CWE-502"},
		Ranges: []cvecorpus.Range{
			{Product: cpe(t, "cpe:2.3:a:"+vendor+":widget:*:*:*:*:*:*:*:*"), Range: vulnmatch.Range{End: "2.0"}},
			{Product: cpe(t, "cpe:2.3:a:"+vendor+":widget:*:*:*:*:*:*:*:*"), Range: vulnmatch.Range{Exact: "2.1.0"}},
		},
	}})
	require.NoError(t, err)
	var pid string
	require.NoError(t, pdb.QueryRowContext(ctx, `SELECT product_id FROM vulnerability_affected WHERE cve_id = $1 LIMIT 1`, id).Scan(&pid))
	_, err = pdb.ExecContext(ctx, `INSERT INTO kev_catalog (cve_id, vendor_project, product, vulnerability_name, date_added, due_date, known_ransomware_campaign_use)
		VALUES ($1, 'Vendor', 'Widget', 'Widget RCE', '2026-01-02', '2026-01-23', 'Known')`, id)
	require.NoError(t, err)
	_, err = pdb.ExecContext(ctx, `INSERT INTO epss_scores (cve_id, epss_score, model_version) VALUES ($1, 0.91234, 'v2025')`, id)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pdb.ExecContext(context.Background(), `DELETE FROM kev_catalog WHERE cve_id = $1`, id)
		_, _ = pdb.ExecContext(context.Background(), `DELETE FROM epss_scores WHERE cve_id = $1`, id)
	})
	return id, shared.MustIDFromString(pid)
}

// The reader answers what today's tables hold, and the matcher's ranges read
// through it are unchanged.
func TestVulnCatalogReader_ReadsTodaysTables(t *testing.T) {
	repo, pdb := corpusRepo(t)
	ctx := context.Background()
	cve, product := vulnCatalogFixture(t, repo, pdb)
	r := postgres.NewVulnCatalogReader(pdb)
	assert.Equal(t, vulncatalog.ModeFull, r.Mode())

	_, err := r.Version(ctx)
	require.NoError(t, err)

	ranges, err := r.Ranges(ctx, product)
	require.NoError(t, err)
	require.Len(t, ranges, 2)
	got := []string{}
	for _, a := range ranges {
		assert.Equal(t, cve, a.Range.VulnID)
		assert.Equal(t, fmt.Sprint(a.LegacyID), a.Range.ID)
		got = append(got, a.Range.Exact+"|"+a.Range.End)
	}
	assert.ElementsMatch(t, []string{"|2.0", "2.1.0|"}, got)

	// Parity: the matcher store returns the same ranges in the same order.
	stored, err := postgres.NewSoftwareMatchRepository(pdb).RangesForProduct(ctx, product)
	require.NoError(t, err)
	require.Len(t, stored, len(ranges))
	for i := range stored {
		assert.Equal(t, ranges[i].LegacyID, stored[i].ID)
		assert.Equal(t, ranges[i].Range, stored[i].Range)
	}

	none, err := r.Ranges(ctx, shared.NewID())
	require.NoError(t, err)
	assert.Empty(t, none, "a product with no statements has no ranges")

	p, err := r.Product(ctx, product)
	require.NoError(t, err)
	assert.Equal(t, "widget", p.CPEProduct)

	facts, err := r.Facts(ctx, []string{" " + cve, cve, "CVE-1999-0000000"})
	require.NoError(t, err)
	require.Len(t, facts, 1, "duplicates collapse and unknown ids are left out")
	f := facts[0]
	assert.Equal(t, "critical", f.Severity)
	require.NotNil(t, f.CVSSScore)
	assert.InDelta(t, 9.8, *f.CVSSScore, 0.001)
	assert.Equal(t, []string{"CWE-502"}, f.CWEs)
	require.NotNil(t, f.KEV)
	assert.True(t, f.KEV.Ransomware)
	assert.Equal(t, "Widget RCE", f.KEV.Name)
	require.NotNil(t, f.KEV.DueDate)
	assert.Equal(t, time.Date(2026, 1, 23, 0, 0, 0, 0, time.UTC), f.KEV.DueDate.UTC())
	require.NotNil(t, f.EPSS)
	assert.InDelta(t, 0.91234, f.EPSS.Score, 1e-6)

	rec, err := r.CVE(ctx, cve)
	require.NoError(t, err)
	assert.Equal(t, "remote code execution", rec.Description)
	_, err = r.CVE(ctx, "CVE-1999-0000000")
	assert.ErrorIs(t, err, vulncatalog.ErrNotFound)

	kev, err := r.KEVSet(ctx)
	require.NoError(t, err)
	assert.Contains(t, kev, cve)

	epss, err := r.EPSS(ctx, []string{cve})
	require.NoError(t, err)
	require.Len(t, epss, 1)
}

func TestVulnCatalogReader_CanonicalVulnID(t *testing.T) {
	_, pdb := corpusRepo(t)
	ctx := context.Background()
	cve := testCVEID()
	alias := "GHSA-" + uuid.NewString()[:4] + "-abcd-efgh"
	_, err := pdb.ExecContext(ctx, `INSERT INTO vuln_id_aliases (alias_id, cve_id, source, version) VALUES ($1, $2, 'ghsa', 1)`, alias, cve)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pdb.ExecContext(context.Background(), `DELETE FROM vuln_id_aliases WHERE alias_id = $1`, alias)
	})
	r := postgres.NewVulnCatalogReader(pdb)

	got, err := r.CanonicalVulnID(ctx, " ghsa-"+alias[5:])
	require.NoError(t, err)
	assert.Equal(t, cve, got)
	got, err = r.CanonicalVulnID(ctx, "cve-2021-44228")
	require.NoError(t, err)
	assert.Equal(t, "CVE-2021-44228", got, "an id with no alias is its own canonical id")
	_, err = r.CanonicalVulnID(ctx, "  ")
	assert.ErrorIs(t, err, shared.ErrValidation)
}

// Tenant isolation: the catalog is public data. A tenant-private product, or a
// tenant's own alias, is never read through the catalog, so one tenant's
// inventory naming cannot reach another tenant's matching.
func TestVulnCatalogReader_NeverReadsTenantPrivateRows(t *testing.T) {
	_, pdb := corpusRepo(t)
	ctx := context.Background()
	tenant := createTestTenant(t, pdb.DB, "vulncatalog-private")
	var pid string
	require.NoError(t, pdb.QueryRowContext(ctx, `INSERT INTO software_products (tenant_id, part, name, source)
		VALUES ($1, 'a', 'private widget', 'observed') RETURNING id`, tenant.String()).Scan(&pid))
	value := "private-" + uuid.NewString()[:8]
	_, err := pdb.ExecContext(ctx, `INSERT INTO software_product_aliases (product_id, tenant_id, kind, value, source)
		VALUES ($1, $2, 'name', $3, 'observed')`, pid, tenant.String(), value)
	require.NoError(t, err)
	r := postgres.NewVulnCatalogReader(pdb)

	_, err = r.Product(ctx, shared.MustIDFromString(pid))
	assert.ErrorIs(t, err, vulncatalog.ErrNotFound)
	_, err = r.ResolveAlias(ctx, "name", value)
	assert.ErrorIs(t, err, vulncatalog.ErrNotFound)
}

func TestVulnCatalogReader_ResolvesGlobalAlias(t *testing.T) {
	repo, pdb := corpusRepo(t)
	ctx := context.Background()
	_, product := vulnCatalogFixture(t, repo, pdb)
	value := "vcat-alias-" + uuid.NewString()[:8]
	_, err := pdb.ExecContext(ctx, `INSERT INTO software_product_aliases (product_id, kind, value, source)
		VALUES ($1, 'name', $2, 'curated')`, product.String(), value)
	require.NoError(t, err)
	got, err := postgres.NewVulnCatalogReader(pdb).ResolveAlias(ctx, "name", value)
	require.NoError(t, err)
	assert.Equal(t, product, got)
}

// With the catalog disabled the matcher store fails with ErrUnavailable, never
// with an empty range list.
func TestSoftwareMatchRepository_DisabledCatalogIsUnavailable(t *testing.T) {
	repo, pdb := corpusRepo(t)
	_, product := vulnCatalogFixture(t, repo, pdb)
	store := postgres.NewSoftwareMatchRepository(pdb).WithVulnCatalog(vulncatalog.Disabled{})
	ranges, err := store.RangesForProduct(context.Background(), product)
	assert.True(t, errors.Is(err, vulncatalog.ErrUnavailable), "err = %v", err)
	assert.Nil(t, ranges)
}
