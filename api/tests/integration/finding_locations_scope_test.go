package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SECURITY: a finding's locations on other assets are shown only to users
// whose data scope includes those assets; nothing says a hidden one exists,
// and nothing reaches another tenant.
func TestFindingLocations_DataScopeAndTenant(t *testing.T) {
	ctx := context.Background()
	f := newLocMergeFixture(t, "locscope-read")
	other := newLocMergeFixture(t, "locscope-read-other")
	old := time.Now().Add(-24 * time.Hour).UTC()
	a := f.service("http://"+f.host, old)
	b := f.service("https://"+f.host, old)
	fid := f.finding(a, 80, "new", old, old.Add(720*time.Hour))
	for _, l := range []struct {
		asset shared.ID
		port  int
	}{{a, 80}, {b, 443}} {
		_, err := f.db.ExecContext(context.Background(), `INSERT INTO finding_locations (tenant_id, finding_id, asset_id, location_key, port, transport, state)
			VALUES ($1, $2, $3, $4, $5, 'tcp', 'affected')`, f.tenant.String(), fid.String(), l.asset.String(), uuid.NewString(), l.port)
		require.NoError(t, err)
	}
	onlyA := createTestUser(t, f.db, "only-a-"+uuid.NewString()[:8]+"@example.com", "Only A")
	both := createTestUser(t, f.db, "both-"+uuid.NewString()[:8]+"@example.com", "Both")
	for _, g := range []struct{ user, asset shared.ID }{{onlyA, a}, {both, a}, {both, b}} {
		_, err := f.db.ExecContext(context.Background(), `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'primary')`,
			g.user.String(), f.tenant.String(), g.asset.String())
		require.NoError(t, err)
	}

	db := &postgres.DB{DB: f.db}
	log := logger.NewNop()
	enforcer := datascope.New(postgres.NewDataScopeRepository(db), func(context.Context) datascope.Caller { return datascope.Caller{} }, log)
	svc := finding.NewVulnerabilityService(postgres.NewVulnerabilityRepository(db), postgres.NewFindingRepository(db), log)
	svc.SetDataScope(enforcer)
	svc.SetLocationReader(postgres.NewSoftwareMatchRepository(db))

	ports := func(user string, admin bool) []int {
		t.Helper()
		got, err := svc.GetFindingWithScope(ctx, f.tenant.String(), fid.String(), user, admin)
		require.NoError(t, err)
		locs, err := svc.GetFindingLocations(ctx, got, user, admin)
		require.NoError(t, err)
		var out []int
		for _, l := range locs {
			out = append(out, l.Port)
		}
		return out
	}
	assert.Equal(t, []int{80}, ports(onlyA.String(), false), "the https service is outside this user's scope")
	assert.Equal(t, []int{80, 443}, ports(both.String(), false))
	assert.Equal(t, []int{80, 443}, ports(shared.NewID().String(), true), "an administrator sees every service")

	// Another tenant reads nothing of it, by finding id or through its own
	// location reader.
	_, err := svc.GetFindingWithScope(ctx, other.tenant.String(), fid.String(), "", true)
	require.Error(t, err)
	locs, err := postgres.NewSoftwareMatchRepository(db).FindingLocations(ctx, other.tenant, fid)
	require.NoError(t, err)
	assert.Empty(t, locs)
}
