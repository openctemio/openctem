package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/pagination"
)

// TestListComponentCVEPairs_EmptyForUnknownTenant verifies that querying with
// a tenant that has no data returns an empty result without error.
func TestListComponentCVEPairs_EmptyForUnknownTenant(t *testing.T) {
	db := setupTestDB(t)
	repo := postgres.NewFindingRepository(&postgres.DB{DB: db})
	tenantID := shared.NewID()

	res, err := repo.ListComponentCVEPairs(
		context.Background(),
		tenantID,
		vulnerability.ComponentCVEFilter{},
		pagination.New(1, 20),
	)
	require.NoError(t, err)
	assert.Empty(t, res.Data)
	assert.Equal(t, int64(0), res.Total)
}

// TestListComponentCVEPairs_ReturnsSeededPair seeds a minimal chain
// (tenant → asset → component (global) → vulnerability → finding) and
// verifies ListComponentCVEPairs returns the expected pair.
//
// Schema note: findings.component_id → components(id) directly (FK-verified).
func TestListComponentCVEPairs_ReturnsSeededPair(t *testing.T) {
	db := setupTestDB(t)
	repo := postgres.NewFindingRepository(&postgres.DB{DB: db})
	ctx := context.Background()

	tenantID := uuid.New().String()
	assetID := uuid.New().String()
	componentID := uuid.New().String()
	vulnID := uuid.New().String()
	findingID := uuid.New().String()
	cveID := fmt.Sprintf("CVE-2099-pair-%s", uuid.New().String()[:8])
	now := time.Now().UTC().Truncate(time.Second)

	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM findings WHERE id = ANY($1)`, pq.Array([]string{findingID}))
		_, _ = db.Exec(`DELETE FROM components WHERE id = ANY($1)`, pq.Array([]string{componentID}))
		_, _ = db.Exec(`DELETE FROM vulnerabilities WHERE id = ANY($1)`, pq.Array([]string{vulnID}))
		_, _ = db.Exec(`DELETE FROM assets WHERE id = ANY($1)`, pq.Array([]string{assetID}))
		_, _ = db.Exec(`DELETE FROM tenants WHERE id = ANY($1)`, pq.Array([]string{tenantID}))
	})

	_, err := db.Exec(
		`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		tenantID, "cve-pair-test-tenant", fmt.Sprintf("cve-pair-%s", tenantID[:8]),
	)
	require.NoError(t, err, "seed tenant")

	_, err = db.Exec(
		`INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status, scope, exposure) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		assetID, tenantID, "test-asset", "repository", "medium", "active", "internal", "unknown",
	)
	require.NoError(t, err, "seed asset")

	_, err = db.Exec(
		`INSERT INTO components (id, purl, name, ecosystem) VALUES ($1,$2,$3,$4)`,
		componentID,
		fmt.Sprintf("pkg:npm/test-lib@1.0.0-%s", componentID[:8]),
		"test-lib", "npm",
	)
	require.NoError(t, err, "seed component")

	_, err = db.Exec(
		`INSERT INTO vulnerabilities (id, cve_id, title, severity) VALUES ($1,$2,$3,$4)`,
		vulnID, cveID, "Test CVE for pair query", "high",
	)
	require.NoError(t, err, "seed vulnerability")

	// findings.component_id → components(id) directly.
	_, err = db.Exec(
		`INSERT INTO findings (id, tenant_id, asset_id, component_id, vulnerability_id,
		  source, tool_name, message, severity, fingerprint, status, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		findingID, tenantID, assetID, componentID, vulnID,
		"sca", "trivy", "test finding message", "high",
		fmt.Sprintf("fp-%s", findingID[:8]),
		"new", now, now,
	)
	require.NoError(t, err, "seed finding")

	tenantSharedID, err := shared.IDFromString(tenantID)
	require.NoError(t, err)

	res, err := repo.ListComponentCVEPairs(ctx, tenantSharedID, vulnerability.ComponentCVEFilter{}, pagination.New(1, 20))
	require.NoError(t, err)

	require.Equal(t, int64(1), res.Total, "expected exactly one component-cve pair")
	require.Len(t, res.Data, 1)

	pair := res.Data[0]
	assert.Equal(t, componentID, pair.ComponentID.String())
	assert.Equal(t, cveID, pair.CVEID)
	assert.Equal(t, vulnID, pair.VulnerabilityID.String())
	assert.Equal(t, int64(1), pair.FindingCount)
	assert.Equal(t, vulnerability.SeverityHigh, pair.MaxSeverity)
}

// TestListComponentCVEPairs_TenantIsolation verifies that findings from
// tenant B are not returned when querying for tenant A.
func TestListComponentCVEPairs_TenantIsolation(t *testing.T) {
	db := setupTestDB(t)
	repo := postgres.NewFindingRepository(&postgres.DB{DB: db})
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)

	type row struct {
		tenantID, assetID, componentID, vulnID, findingID, cveID string
	}

	mkRow := func(suffix string) row {
		return row{
			tenantID:    uuid.New().String(),
			assetID:     uuid.New().String(),
			componentID: uuid.New().String(),
			vulnID:      uuid.New().String(),
			findingID:   uuid.New().String(),
			cveID:       fmt.Sprintf("CVE-2099-iso-%s", suffix),
		}
	}

	a := mkRow("a-" + uuid.New().String()[:6])
	b := mkRow("b-" + uuid.New().String()[:6])

	cleanup := func(r row) {
		_, _ = db.Exec(`DELETE FROM findings WHERE id = $1`, r.findingID)
		_, _ = db.Exec(`DELETE FROM components WHERE id = $1`, r.componentID)
		_, _ = db.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, r.vulnID)
		_, _ = db.Exec(`DELETE FROM assets WHERE id = $1`, r.assetID)
		_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, r.tenantID)
	}
	t.Cleanup(func() { cleanup(a); cleanup(b) })

	seedRow := func(r row) {
		t.Helper()
		_, err := db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1,$2,$3)`,
			r.tenantID, "iso-tenant-"+r.tenantID[:8], "iso-"+r.tenantID[:8])
		require.NoError(t, err)
		_, err = db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status, scope, exposure) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			r.assetID, r.tenantID, "iso-asset", "repository", "medium", "active", "internal", "unknown")
		require.NoError(t, err)
		_, err = db.Exec(`INSERT INTO components (id, purl, name, ecosystem) VALUES ($1,$2,$3,$4)`,
			r.componentID, "pkg:npm/iso-lib-"+r.componentID[:8]+"@1.0", "iso-lib", "npm")
		require.NoError(t, err)
		_, err = db.Exec(`INSERT INTO vulnerabilities (id, cve_id, title, severity) VALUES ($1,$2,$3,$4)`,
			r.vulnID, r.cveID, "Isolation test CVE", "medium")
		require.NoError(t, err)
		_, err = db.Exec(`INSERT INTO findings (id, tenant_id, asset_id, component_id, vulnerability_id, source, tool_name, message, severity, fingerprint, status, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			r.findingID, r.tenantID, r.assetID, r.componentID, r.vulnID,
			"sca", "trivy", "msg", "medium", "fp-"+r.findingID[:8], "new", now, now)
		require.NoError(t, err)
	}

	seedRow(a)
	seedRow(b)

	tenantA, err := shared.IDFromString(a.tenantID)
	require.NoError(t, err)

	res, err := repo.ListComponentCVEPairs(ctx, tenantA, vulnerability.ComponentCVEFilter{}, pagination.New(1, 20))
	require.NoError(t, err)

	require.Equal(t, int64(1), res.Total, "should see only tenant A's pair")
	require.Len(t, res.Data, 1)
	assert.Equal(t, a.cveID, res.Data[0].CVEID)
}
