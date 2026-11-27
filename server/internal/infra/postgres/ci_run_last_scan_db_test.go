package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// A CI run's report moves its repository's last scan time, inside the
// run's own tenant only. Requires DATABASE_URL.
func TestCIRunReportRecordsRepositoryLastScan(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCIRunRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	asset := seedTestAsset(ctx, t, db, tenant)
	untouched := seedTestAsset(ctx, t, db, other)
	for _, id := range []shared.ID{asset, untouched} {
		if _, err := db.ExecContext(ctx, `INSERT INTO asset_repositories (asset_id, full_name) VALUES ($1, 'example.com/acme/api')`,
			id.String()); err != nil {
			t.Fatal(err)
		}
	}

	now := time.Now().UTC()
	_, hash, _ := cirun.NewToken()
	exp := now.Add(10 * time.Minute)
	run := &cirun.Run{ID: shared.NewID(), TenantID: tenant, RepositoryAssetID: asset, Provider: cirun.ProviderGitHub,
		Issuer: cirun.GitHubIssuer, Repository: "example.com/acme/api", Ref: "refs/heads/main", Branch: "main",
		CommitSHA: "abcdef1234567", Status: cirun.StatusRunning, TokenHash: hash, TokenExpiresAt: &exp, CreatedAt: now, UpdatedAt: now}
	if err := repo.CreateRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	lastScan := func(id shared.ID) *time.Time {
		var at *time.Time
		if err := db.QueryRowContext(ctx, `SELECT last_scanned_at FROM asset_repositories WHERE asset_id = $1`, id.String()).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	if lastScan(asset) != nil {
		t.Fatal("repository starts as never scanned")
	}
	// Another tenant cannot move it through this run.
	if err := repo.RecordRunReport(ctx, other, run.ID, nil); err == nil {
		t.Fatal("cross-tenant report accepted")
	}
	if lastScan(asset) != nil {
		t.Fatal("a cross-tenant report moved the last scan")
	}
	if err := repo.RecordRunReport(ctx, tenant, run.ID, []string{"fp-1"}); err != nil {
		t.Fatal(err)
	}
	if at := lastScan(asset); at == nil || time.Since(*at) > time.Minute {
		t.Fatalf("last scan not set by the run's report: %v", at)
	}
	if lastScan(untouched) != nil {
		t.Fatal("another tenant's repository was touched")
	}
}
