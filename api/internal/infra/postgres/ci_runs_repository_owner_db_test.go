package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A developer sees the CI runs of the repositories their team owns, and no
// other: making the team (a group) an owner of the repository asset is how an
// administrator gives developers their runs (research/133, decision 2).
func TestCIRunsVisibleToRepositoryOwners_DB(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCIRunRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	owned, other := seedTestAsset(ctx, t, db, tenant), seedTestAsset(ctx, t, db, tenant)
	now := time.Now().UTC()
	newRun := func(asset shared.ID) shared.ID {
		t.Helper()
		_, hash, _ := cirun.NewToken()
		r := &cirun.Run{ID: shared.NewID(), TenantID: tenant, RepositoryAssetID: asset, Provider: cirun.ProviderGitHub,
			Issuer: cirun.GitHubIssuer, Repository: "github.com/acme/" + asset.String()[:8], Status: cirun.StatusRunning,
			TokenHash: hash, CreatedAt: now, UpdatedAt: now}
		if err := repo.CreateRun(ctx, r); err != nil {
			t.Fatal(err)
		}
		return r.ID
	}
	ownedRun := newRun(owned)
	newRun(other)

	dev := shared.NewID()
	group := shared.NewID()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'dev')`, dev.String(), dev.String()+"@ci.test")
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, dev.String()) })
	exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, dev.String(), tenant.String())
	exec(`INSERT INTO groups (id, tenant_id, name, slug) VALUES ($1, $2, 'payments team', $3)`, group.String(), tenant.String(), "payments-"+group.String()[:8])
	exec(`INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)`, group.String(), dev.String())

	scope := &shared.DataScope{TenantID: tenant, UserID: dev}
	if _, total, err := repo.ListRuns(ctx, tenant, cirun.RunFilter{DataScope: scope}); err != nil || total != 0 {
		t.Fatalf("before ownership the developer sees %d runs (%v)", total, err)
	}

	// The team becomes an owner of the repository.
	exec(`INSERT INTO asset_owners (asset_id, group_id, ownership_type) VALUES ($1, $2, 'primary')`, owned.String(), group.String())
	runs, total, err := repo.ListRuns(ctx, tenant, cirun.RunFilter{DataScope: scope})
	if err != nil || total != 1 || runs[0].ID != ownedRun {
		t.Fatalf("after ownership: %d runs %v", total, err)
	}

	// Leaving the team takes the runs away again.
	exec(`DELETE FROM group_members WHERE group_id = $1 AND user_id = $2`, group.String(), dev.String())
	if _, total, _ := repo.ListRuns(ctx, tenant, cirun.RunFilter{DataScope: scope}); total != 0 {
		t.Fatalf("after leaving the team the developer still sees %d runs", total)
	}
}
