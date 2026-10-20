package scan

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// uniqueNameRepo is the scan mock with the database's per-tenant unique name.
type uniqueNameRepo struct{ *mockScanRepository }

func (r uniqueNameRepo) Create(ctx context.Context, s *scan.Scan) error {
	for _, o := range r.scans {
		if o.TenantID == s.TenantID && o.Name == s.Name {
			return shared.NewDomainError("ALREADY_EXISTS", "scan with this name already exists", shared.ErrAlreadyExists)
		}
	}
	return r.mockScanRepository.Create(ctx, s)
}

// A member's scan named like the coverage scan is never adopted: coverage
// creates its own managed scan under another name and leaves the member's
// scan (targets, owner, schedule) untouched.
func TestCoverageScan_NeverAdoptsASameNamedUserScan(t *testing.T) {
	ctx := context.Background()
	repo := uniqueNameRepo{newMockScanRepository()}
	svc := &Service{scanRepo: repo, logger: logger.NewNop()}
	tenant, member := shared.NewID(), shared.NewID()

	mine, err := scan.NewScan(tenant, CoverageScanName("probe.http"), member, scan.ScanTypeSingle)
	require.NoError(t, err)
	mine.SetTargets([]string{"mine.example.com"})
	mine.SetCreatedBy(member)
	require.NoError(t, repo.Create(ctx, mine))

	got, err := svc.coverageScan(ctx, tenant, "probe.http")
	require.NoError(t, err)
	assert.NotEqual(t, mine.ID, got.ID, "the member's scan was adopted")
	assert.True(t, got.IsManaged())
	assert.Equal(t, scan.ManagedByCoverage, got.ManagedBy)
	assert.Equal(t, "probe.http", got.ManagedKey)
	assert.NotEqual(t, mine.Name, got.Name)
	require.NotNil(t, mine.CreatedBy)
	assert.Equal(t, member, *mine.CreatedBy)
	assert.False(t, mine.IsManaged())
	assert.Equal(t, []string{"mine.example.com"}, mine.Targets)

	// Found by key on the next batch, not created again.
	again, err := svc.coverageScan(ctx, tenant, "probe.http")
	require.NoError(t, err)
	assert.Equal(t, got.ID, again.ID)
	assert.Len(t, repo.scans, 2)

	// Another tenant has its own.
	other, err := svc.coverageScan(ctx, shared.NewID(), "probe.http")
	require.NoError(t, err)
	assert.NotEqual(t, got.ID, other.ID)
}

// Without a clash the managed scan keeps the readable name.
func TestCoverageScan_CreatesManagedScan(t *testing.T) {
	repo := uniqueNameRepo{newMockScanRepository()}
	svc := &Service{scanRepo: repo, logger: logger.NewNop()}
	got, err := svc.coverageScan(context.Background(), shared.NewID(), "scan.ports")
	require.NoError(t, err)
	assert.Equal(t, CoverageScanName("scan.ports"), got.Name)
	assert.True(t, got.AdHoc)
	assert.True(t, got.IsManaged())
}
