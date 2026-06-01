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
)

// seedOccurrenceFixture creates the FK chain (tenant → repository asset →
// asset_repositories → branch → finding) needed to exercise the branch-aware
// occurrence upsert, and returns the tenant id, branch id, and finding fingerprint.
func seedOccurrenceFixture(t *testing.T, db *sql.DB) (tenantID, branchID shared.ID, fingerprint string) {
	t.Helper()
	tenantID = shared.NewID()
	assetID := shared.NewID()
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
	return tenantID, branchID, fingerprint
}

func TestUpsertBranchOccurrences_InsertThenReopen(t *testing.T) {
	sqlDB := setupTestDB(t)
	repo := postgres.NewFindingRepository(&postgres.DB{DB: sqlDB})
	ctx := context.Background()

	tenantID, branchID, fp := seedOccurrenceFixture(t, sqlDB)

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

	tenantID, branchID, _ := seedOccurrenceFixture(t, sqlDB)

	// A fingerprint with no matching finding → no occurrence, no error.
	require.NoError(t, repo.UpsertBranchOccurrences(ctx, tenantID, []vulnerability.BranchOccurrenceUpsert{
		{Fingerprint: "nonexistent-fingerprint", BranchID: branchID, ScanID: "s", CommitSHA: "c"},
	}))

	var count int
	require.NoError(t, sqlDB.QueryRow(
		`SELECT count(*) FROM finding_branch_occurrences WHERE branch_id = $1`, branchID.String()).Scan(&count))
	require.Equal(t, 0, count)
}
