package integration

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/pagination"
)

// seedOccurrenceFixture creates the FK chain (tenant → repository asset →
// asset_repositories → branch → finding) needed to exercise the branch-aware
// occurrence upsert, and returns the tenant id, branch id, and finding fingerprint.
func seedOccurrenceFixture(t *testing.T, db *sql.DB) (tenantID, assetID, branchID shared.ID, fingerprint string) {
	t.Helper()
	tenantID = shared.NewID()
	assetID = shared.NewID()
	branchID = shared.NewID()
	fingerprint = "fbo" + shared.NewID().String()[:29] // unique 32-char-ish

	_, err := db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		tenantID.String(), "fbo-tenant-"+tenantID.String()[:8], "fbo-"+tenantID.String()[:8])
	require.NoError(t, err)

	_, err = db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'repository')`,
		assetID.String(), tenantID.String(), "fbo-repo-"+assetID.String()[:8])
	require.NoError(t, err)

	_, err = db.Exec(`INSERT INTO asset_repositories (asset_id, full_name, default_branch) VALUES ($1, $2, 'main')`,
		assetID.String(), "org/fbo-repo")
	require.NoError(t, err)

	_, err = db.Exec(`INSERT INTO repository_branches (id, repository_id, name, branch_type, is_default)
		VALUES ($1, $2, 'main', 'main', true)`, branchID.String(), assetID.String())
	require.NoError(t, err)

	_, err = db.Exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint)
		VALUES ($1, $2, $3, 'sast', 'semgrep', 'test finding', 'high', $4)`,
		shared.NewID().String(), tenantID.String(), assetID.String(), fingerprint)
	require.NoError(t, err)

	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, tenantID.String()) })
	return tenantID, assetID, branchID, fingerprint
}

func TestUpsertBranchOccurrences_InsertThenReopen(t *testing.T) {
	sqlDB := setupTestDB(t)
	repo := postgres.NewFindingRepository(&postgres.DB{DB: sqlDB})
	ctx := context.Background()

	tenantID, _, branchID, fp := seedOccurrenceFixture(t, sqlDB)

	item := vulnerability.BranchOccurrenceUpsert{
		Fingerprint: fp, BranchID: branchID, ScanID: "scan-1", CommitSHA: "abc123",
	}

	// First upsert → one open occurrence with repository_id populated.
	require.NoError(t, repo.UpsertBranchOccurrences(ctx, tenantID, []vulnerability.BranchOccurrenceUpsert{item}))

	var count int
	var status string
	var repoID sql.NullString
	require.NoError(t, sqlDB.QueryRow(
		`SELECT count(*), max(status), max(repository_id::text) FROM finding_branch_occurrences WHERE branch_id = $1`,
		branchID.String()).Scan(&count, &status, &repoID))
	require.Equal(t, 1, count, "expected exactly one occurrence")
	require.Equal(t, "open", status)
	require.True(t, repoID.Valid, "repository_id should be denormalized from the branch")

	// Idempotent: second upsert does not create a duplicate.
	require.NoError(t, repo.UpsertBranchOccurrences(ctx, tenantID, []vulnerability.BranchOccurrenceUpsert{item}))
	require.NoError(t, sqlDB.QueryRow(
		`SELECT count(*) FROM finding_branch_occurrences WHERE branch_id = $1`, branchID.String()).Scan(&count))
	require.Equal(t, 1, count, "upsert must not duplicate")

	// Simulate auto-resolve, then re-observe → occurrence reopens to 'open'.
	_, err := sqlDB.Exec(`UPDATE finding_branch_occurrences SET status = 'auto_fixed' WHERE branch_id = $1`, branchID.String())
	require.NoError(t, err)

	item.ScanID = "scan-2"
	item.CommitSHA = "def456"
	require.NoError(t, repo.UpsertBranchOccurrences(ctx, tenantID, []vulnerability.BranchOccurrenceUpsert{item}))

	var lastCommit string
	require.NoError(t, sqlDB.QueryRow(
		`SELECT status, last_commit_sha FROM finding_branch_occurrences WHERE branch_id = $1`,
		branchID.String()).Scan(&status, &lastCommit))
	require.Equal(t, "open", status, "re-observing must reopen an auto_fixed occurrence")
	require.Equal(t, "def456", lastCommit, "last_commit_sha must be bumped")
}

func TestUpsertBranchOccurrences_UnknownFingerprintMatchesNothing(t *testing.T) {
	sqlDB := setupTestDB(t)
	repo := postgres.NewFindingRepository(&postgres.DB{DB: sqlDB})
	ctx := context.Background()

	tenantID, _, branchID, _ := seedOccurrenceFixture(t, sqlDB)

	// A fingerprint with no matching finding → no occurrence, no error.
	require.NoError(t, repo.UpsertBranchOccurrences(ctx, tenantID, []vulnerability.BranchOccurrenceUpsert{
		{Fingerprint: "nonexistent-fingerprint", BranchID: branchID, ScanID: "s", CommitSHA: "c"},
	}))

	var count int
	require.NoError(t, sqlDB.QueryRow(
		`SELECT count(*) FROM finding_branch_occurrences WHERE branch_id = $1`, branchID.String()).Scan(&count))
	require.Equal(t, 0, count)
}

// TestListFilterByBranch_UsesOccurrences proves the branch filter now matches via
// occurrences — it returns a finding whose legacy findings.branch_id is NULL but
// which has an occurrence on the target branch, and correctly separates two
// findings that live on different branches of the same repository.
func TestListFilterByBranch_UsesOccurrences(t *testing.T) {
	sqlDB := setupTestDB(t)
	repo := postgres.NewFindingRepository(&postgres.DB{DB: sqlDB})
	ctx := context.Background()

	tenantID, assetID, branchX, fp1 := seedOccurrenceFixture(t, sqlDB)

	// F1 (fp1) has branch_id = NULL (the fixture inserts no branch_id) but gets
	// an occurrence on branchX — the legacy `branch_id = X` filter would miss it.
	require.NoError(t, repo.UpsertBranchOccurrences(ctx, tenantID,
		[]vulnerability.BranchOccurrenceUpsert{{Fingerprint: fp1, BranchID: branchX, ScanID: "s1"}}))

	// A second branch Y on the same repo + a second finding only on Y.
	branchY := shared.NewID()
	_, err := sqlDB.Exec(`INSERT INTO repository_branches (id, repository_id, name, branch_type)
		VALUES ($1, $2, 'feature/y', 'feature')`, branchY.String(), assetID.String())
	require.NoError(t, err)
	fp2 := "fbo" + shared.NewID().String()[:29]
	_, err = sqlDB.Exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint)
		VALUES ($1, $2, $3, 'sast', 'semgrep', 'f2', 'high', $4)`,
		shared.NewID().String(), tenantID.String(), assetID.String(), fp2)
	require.NoError(t, err)
	require.NoError(t, repo.UpsertBranchOccurrences(ctx, tenantID,
		[]vulnerability.BranchOccurrenceUpsert{{Fingerprint: fp2, BranchID: branchY, ScanID: "s2"}}))

	// Filter by branchX → only F1 (even though F1.branch_id IS NULL).
	resX, err := repo.List(ctx,
		vulnerability.NewFindingFilter().WithTenantID(tenantID).WithBranchID(branchX),
		vulnerability.NewFindingListOptions(), pagination.New(1, 20))
	require.NoError(t, err)
	require.Len(t, resX.Data, 1, "branchX should match exactly F1 via occurrence")
	require.Equal(t, fp1, resX.Data[0].Fingerprint())

	// Filter by branchY → only F2.
	resY, err := repo.List(ctx,
		vulnerability.NewFindingFilter().WithTenantID(tenantID).WithBranchID(branchY),
		vulnerability.NewFindingListOptions(), pagination.New(1, 20))
	require.NoError(t, err)
	require.Len(t, resY.Data, 1, "branchY should match exactly F2 via occurrence")
	require.Equal(t, fp2, resY.Data[0].Fingerprint())
}

// TestAutoResolveStaleBranchOccurrences verifies a full scan that no longer
// reports an occurrence marks it auto_fixed, scoped to the parent finding's tool.
func TestAutoResolveStaleBranchOccurrences(t *testing.T) {
	sqlDB := setupTestDB(t)
	repo := postgres.NewFindingRepository(&postgres.DB{DB: sqlDB})
	ctx := context.Background()

	tenantID, _, branchID, fp := seedOccurrenceFixture(t, sqlDB) // finding tool_name = 'semgrep'

	// Observe in scan s1.
	require.NoError(t, repo.UpsertBranchOccurrences(ctx, tenantID,
		[]vulnerability.BranchOccurrenceUpsert{{Fingerprint: fp, BranchID: branchID, ScanID: "s1"}}))

	// A different tool's scan must NOT resolve it.
	n, err := repo.AutoResolveStaleBranchOccurrences(ctx, tenantID, branchID, "trivy", "s2")
	require.NoError(t, err)
	require.Equal(t, int64(0), n, "tool mismatch must not resolve")

	var status string
	require.NoError(t, sqlDB.QueryRow(`SELECT status FROM finding_branch_occurrences WHERE branch_id = $1`,
		branchID.String()).Scan(&status))
	require.Equal(t, "open", status)

	// The same tool's NEXT full scan (s2) no longer reports it → auto_fixed.
	n, err = repo.AutoResolveStaleBranchOccurrences(ctx, tenantID, branchID, "semgrep", "s2")
	require.NoError(t, err)
	require.Equal(t, int64(1), n)
	require.NoError(t, sqlDB.QueryRow(`SELECT status FROM finding_branch_occurrences WHERE branch_id = $1`,
		branchID.String()).Scan(&status))
	require.Equal(t, "auto_fixed", status)

	// Re-observing in a later scan reopens it.
	require.NoError(t, repo.UpsertBranchOccurrences(ctx, tenantID,
		[]vulnerability.BranchOccurrenceUpsert{{Fingerprint: fp, BranchID: branchID, ScanID: "s3"}}))
	require.NoError(t, sqlDB.QueryRow(`SELECT status FROM finding_branch_occurrences WHERE branch_id = $1`,
		branchID.String()).Scan(&status))
	require.Equal(t, "open", status, "re-observing reopens an auto_fixed occurrence")
}
