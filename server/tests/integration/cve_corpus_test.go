package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/cvecorpus"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
)

func corpusRepo(t *testing.T) (*postgres.CVECorpusRepository, *postgres.DB) {
	t.Helper()
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	pdb := &postgres.DB{DB: db}
	require.NoError(t, postgres.NewSoftwareRepository(pdb).EnsureCurated(context.Background(), software.CuratedProducts()))
	return postgres.NewCVECorpusRepository(pdb), pdb
}

func testCVEID() string {
	return fmt.Sprintf("CVE-2099-%d", 10000+time.Now().UnixNano()%900000000)
}

func cpe(t *testing.T, s string) vulnmatch.CPE {
	t.Helper()
	c, err := vulnmatch.ParseCPE(s)
	require.NoError(t, err)
	return c
}

func rangesOf(t *testing.T, pdb *postgres.DB, cveID string) []string {
	t.Helper()
	rows, err := pdb.QueryContext(context.Background(), `
		SELECT p.cpe_vendor || ':' || p.cpe_product || ' ' || coalesce(a.exact_version, '') || '|' ||
		       coalesce(a.v_start, '') || '|' || coalesce(a.v_end, '') || '|' || a.edition || '|' ||
		       coalesce(c.cpe_product, '')
		FROM vulnerability_affected a
		JOIN software_products p ON p.id = a.product_id
		LEFT JOIN software_products c ON c.id = a.condition_product_id
		WHERE a.cve_id = $1 ORDER BY 1`, cveID)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(t, rows.Err())
	return out
}

func TestCVECorpus_ApplyPage(t *testing.T) {
	repo, pdb := corpusRepo(t)
	ctx := context.Background()
	id := testCVEID()
	unknownVendor := "vendor" + uuid.NewString()[:8]
	score := 7.5
	page := []cvecorpus.CVE{{
		ID: id, Status: "Analyzed", Description: "d", CVSSScore: &score, CVSSVersion: "3.1", Severity: "high",
		CWEs: []string{"CWE-79"},
		Ranges: []cvecorpus.Range{
			// The alternate vendor resolves to the curated product.
			{Product: cpe(t, "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"), Range: vulnmatch.Range{End: "1.20.1"}},
			{Product: cpe(t, "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"), Range: vulnmatch.Range{Exact: "1.21.0"}},
			// A product nothing resolves becomes a global nvd product.
			{Product: cpe(t, "cpe:2.3:a:"+unknownVendor+":widget:*:*:*:*:*:*:*:*"), Range: vulnmatch.Range{Start: "2.0", StartIncl: true, Edition: "community"},
				Condition: ptr(cpe(t, "cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:*:*:*:*"))},
		},
	}}
	res, err := repo.ApplyPage(ctx, page)
	require.NoError(t, err)
	assert.Equal(t, 1, res.Upserted)
	assert.Equal(t, 3, res.RangesWritten)
	assert.Equal(t, []string{
		"f5:nginx 1.21.0||||",
		"f5:nginx ||1.20.1||",
		unknownVendor + ":widget |2.0||community|ubuntu_linux",
	}, rangesOf(t, pdb, id))

	var tenant *string
	var source string
	require.NoError(t, pdb.QueryRowContext(ctx, `SELECT tenant_id::text, source FROM software_products WHERE cpe_vendor = $1`, unknownVendor).Scan(&tenant, &source))
	assert.Nil(t, tenant)
	assert.Equal(t, "nvd", source)

	// A modified record replaces its ranges.
	page[0].Ranges = page[0].Ranges[:1]
	page[0].Ranges[0].Range.End = "1.20.2"
	_, err = repo.ApplyPage(ctx, page)
	require.NoError(t, err)
	assert.Equal(t, []string{"f5:nginx ||1.20.2||"}, rangesOf(t, pdb, id))

	// Emptied (not rejected): counted by the guard.
	empty := []cvecorpus.CVE{{ID: id}}
	n, err := repo.EmptiedRanges(ctx, empty)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	// Too many statements: the record is updated, its ranges kept.
	_, err = repo.ApplyPage(ctx, []cvecorpus.CVE{{ID: id, Status: "Modified", TooManyRanges: true}})
	require.NoError(t, err)
	assert.Len(t, rangesOf(t, pdb, id), 1)

	// Rejected: the record stays (so findings follow the rejection rule)
	// with no range.
	_, err = repo.ApplyPage(ctx, []cvecorpus.CVE{{ID: id, Status: "Rejected", Rejected: true}})
	require.NoError(t, err)
	assert.Empty(t, rangesOf(t, pdb, id))
	var status string
	require.NoError(t, pdb.QueryRowContext(ctx, `SELECT status FROM cve_records WHERE cve_id = $1`, id).Scan(&status))
	assert.Equal(t, "Rejected", status)
}

func TestCVECorpus_SkipsNewRecordsWithoutRanges(t *testing.T) {
	repo, pdb := corpusRepo(t)
	ctx := context.Background()
	id := testCVEID()
	res, err := repo.ApplyPage(ctx, []cvecorpus.CVE{{ID: id, Status: "Deferred"}, {ID: id + "1", Rejected: true}})
	require.NoError(t, err)
	assert.Equal(t, 2, res.Skipped)
	var n int
	require.NoError(t, pdb.QueryRowContext(ctx, `SELECT count(*) FROM cve_records WHERE cve_id IN ($1, $2)`, id, id+"1").Scan(&n))
	assert.Zero(t, n)
}

// A range can never name a tenant-private product.
func TestCVECorpus_RangesNameGlobalProductsOnly(t *testing.T) {
	_, pdb := corpusRepo(t)
	ctx := context.Background()
	tenant := createTestTenant(t, pdb.DB, "corpus-private")
	id := testCVEID()
	_, err := pdb.ExecContext(ctx, `INSERT INTO cve_records (cve_id) VALUES ($1)`, id)
	require.NoError(t, err)
	var pid string
	require.NoError(t, pdb.QueryRowContext(ctx, `INSERT INTO software_products (tenant_id, part, name, source)
		VALUES ($1, 'a', 'private thing', 'observed') RETURNING id`, tenant.String()).Scan(&pid))
	_, err = pdb.ExecContext(ctx, `INSERT INTO vulnerability_affected (cve_id, product_id) VALUES ($1, $2)`, id, pid)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "global products only")
}

func ptr[T any](v T) *T { return &v }
