package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/codescan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func seedCodeScanRepo(ctx context.Context, t *testing.T, db *sql.DB, tenantID shared.ID, name, defaultBranch string) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'repository')`,
		id.String(), tenantID.String(), name); err != nil {
		t.Fatalf("seed repository: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO asset_repositories (asset_id, default_branch, visibility, clone_url)
		VALUES ($1, $2, 'private', $3)`, id.String(), defaultBranch, "https://github.com/"+name+".git"); err != nil {
		t.Fatalf("seed repository row: %v", err)
	}
	return id
}

func TestCodeScanRepository(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCodeScanRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	api := seedCodeScanRepo(ctx, t, db, tenant, "acme/api", "main")
	web := seedCodeScanRepo(ctx, t, db, tenant, "acme/web", "trunk")
	foreign := seedCodeScanRepo(ctx, t, db, other, "evil/repo", "main")
	host := seedTestAsset(ctx, t, db, tenant)

	// Template: none, then stored, then updated in place.
	if s, err := repo.GetSettings(ctx, tenant, nil); err != nil || s != nil {
		t.Fatalf("no template: %v %v", s, err)
	}
	tmpl := codescan.Defaults(tenant)
	tmpl.Schedule = codescan.ScheduleDaily
	if err := repo.UpsertSettings(ctx, &tmpl); err != nil {
		t.Fatal(err)
	}
	tmpl2 := codescan.Defaults(tenant)
	tmpl2.Schedule = codescan.ScheduleMonthly
	if err := repo.UpsertSettings(ctx, &tmpl2); err != nil {
		t.Fatal(err)
	}
	if s, err := repo.GetSettings(ctx, tenant, nil); err != nil || s == nil || s.Schedule != codescan.ScheduleMonthly {
		t.Fatalf("template upsert: %+v %v", s, err)
	}
	if s, _ := repo.GetSettings(ctx, other, nil); s != nil {
		t.Fatal("another tenant reads the template")
	}

	// Repository settings: only on the tenant's own repository.
	own := codescan.Defaults(tenant)
	own.RepositoryAssetID = &api
	own.ProtectedBranches = []string{"main", "release/*"}
	if err := repo.UpsertSettings(ctx, &own); err != nil {
		t.Fatal(err)
	}
	stolen := codescan.Defaults(tenant)
	stolen.RepositoryAssetID = &foreign
	if err := repo.UpsertSettings(ctx, &stolen); !errors.Is(err, codescan.ErrNotFound) {
		t.Fatalf("settings on another tenant's repository: %v", err)
	}
	byRepo, err := repo.RepositorySettings(ctx, tenant, []shared.ID{api, web, foreign})
	if err != nil || len(byRepo) != 1 || byRepo[api].ProtectedBranches[1] != "release/*" {
		t.Fatalf("repository settings: %+v %v", byRepo, err)
	}

	// Repositories: the tenant's, repository type only, data scope applied.
	if _, err := repo.GetRepository(ctx, other, api); !errors.Is(err, codescan.ErrNotFound) {
		t.Fatalf("cross-tenant repository: %v", err)
	}
	if _, err := repo.GetRepository(ctx, tenant, host); !errors.Is(err, codescan.ErrNotFound) {
		t.Fatalf("a host is not a repository: %v", err)
	}
	if ref, err := repo.GetRepository(ctx, tenant, web); err != nil || ref.DefaultBranch != "trunk" || ref.Name != "acme/web" {
		t.Fatalf("repository: %+v %v", ref, err)
	}
	list, total, err := repo.ListRepositories(ctx, tenant, nil, 10, 0)
	if err != nil || total != 2 || len(list) != 2 || list[0].Name != "acme/api" {
		t.Fatalf("list: %+v %d %v", list, total, err)
	}
	if list, total, _ := repo.ListRepositories(ctx, tenant, &shared.DataScope{TenantID: tenant, UserID: shared.NewID()}, 10, 0); total != 0 || len(list) != 0 {
		t.Fatalf("a member without scope sees %d repositories", total)
	}

	// Branches: the default branch is recorded once, never on another
	// tenant's repository; queueing is per repository and tenant.
	if err := repo.EnsureDefaultBranch(ctx, tenant, api, "main"); err != nil {
		t.Fatal(err)
	}
	if err := repo.EnsureDefaultBranch(ctx, tenant, api, "main"); err != nil {
		t.Fatal(err)
	}
	if err := repo.EnsureDefaultBranch(ctx, tenant, foreign, "main"); err != nil {
		t.Fatal(err)
	}
	branches, err := repo.Branches(ctx, tenant, []shared.ID{api, foreign})
	if err != nil || len(branches[api]) != 1 || len(branches[foreign]) != 0 || branches[api][0].BaselineState != codescan.BaselineNone {
		t.Fatalf("branches: %+v %v", branches, err)
	}
	var foreignBranches int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM repository_branches WHERE repository_id = $1`, foreign.String()).Scan(&foreignBranches)
	if foreignBranches != 0 {
		t.Fatal("a branch was recorded on another tenant's repository")
	}
	ids := []shared.ID{branches[api][0].ID}
	if n, err := repo.QueueFullScan(ctx, other, api, ids, codescan.TriggerManual); err != nil || n != 0 {
		t.Fatalf("cross-tenant queue: %d %v", n, err)
	}
	if n, err := repo.QueueFullScan(ctx, tenant, web, ids, codescan.TriggerManual); err != nil || n != 0 {
		t.Fatalf("a branch queued through another repository: %d %v", n, err)
	}
	if n, err := repo.QueueFullScan(ctx, tenant, api, ids, codescan.TriggerManual); err != nil || n != 1 {
		t.Fatalf("queue: %d %v", n, err)
	}
	if n, _ := repo.QueueFullScan(ctx, tenant, api, ids, codescan.TriggerManual); n != 0 {
		t.Fatal("a queued branch was queued again")
	}
	branches, _ = repo.Branches(ctx, tenant, []shared.ID{api})
	if b := branches[api][0]; b.BaselineState != codescan.BaselineQueued || b.LastFullScanTrigger != codescan.TriggerManual || !b.IsDefault {
		t.Fatalf("queued branch: %+v", b)
	}

	// Reset: the repository inherits the template again.
	if err := repo.DeleteSettings(ctx, other, api); err != nil {
		t.Fatal(err)
	}
	if s, _ := repo.GetSettings(ctx, tenant, &api); s == nil {
		t.Fatal("another tenant deleted the repository's settings")
	}
	if err := repo.DeleteSettings(ctx, tenant, api); err != nil {
		t.Fatal(err)
	}
	if s, _ := repo.GetSettings(ctx, tenant, &api); s != nil {
		t.Fatal("settings not reset")
	}
}
