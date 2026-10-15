package integration_test

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/infra/scm"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Repository import and CI share one asset per repository, keyed by the code
// host and its immutable repository id: import names new assets host/path
// (the name CI uses), adopts an asset CI created, follows a rename by id, and
// never matches another tenant's asset or the same id on another host.
// Requires DATABASE_URL.
func TestRepositoryImportUsesHostAndProviderID(t *testing.T) {
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	pdb := &postgres.DB{DB: db}
	tenant, other := shared.NewID(), shared.NewID()
	for _, id := range []shared.ID{tenant, other} {
		if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, id.String(), "t-"+id.String()[:8]+id.String()[28:]); err != nil {
			t.Fatal(err)
		}
	}
	svc := integration.NewIntegrationService(nil, nil, nil, logger.NewNop())
	svc.SetRepoImportRepos(postgres.NewAssetRepository(pdb), postgres.NewRepositoryExtensionRepository(pdb), nil)
	ident := postgres.NewRepositoryIdentityRepository(pdb)
	aud := &renameAudits{}
	svc.SetRepositoryIdentity(ident, aud)
	repo := func(id, full string) scm.Repository {
		return scm.Repository{ID: id, FullName: full, HTMLURL: "https://github.com/" + full,
			CloneURL: "https://github.com/" + full + ".git", DefaultBranch: "main"}
	}
	assetOf := func(tid shared.ID, name string) string {
		t.Helper()
		var id string
		_ = db.QueryRowContext(ctx, `SELECT id FROM assets WHERE tenant_id = $1 AND name = $2`, tid.String(), name).Scan(&id)
		return id
	}
	count := func(tid shared.ID) int {
		t.Helper()
		var n int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM assets WHERE tenant_id = $1 AND asset_type = 'repository'`, tid.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// A new import is named host/path, with its id on the extension.
	if created, err := svc.UpsertRepositoryAssetForTest(ctx, tenant, repo("101", "acme/api")); err != nil || !created {
		t.Fatalf("import: %v %v", created, err)
	}
	api := assetOf(tenant, "github.com/acme/api")
	if api == "" {
		t.Fatal("imported repository not named github.com/acme/api")
	}
	if id, ok, err := ident.FindRepositoryByProviderID(ctx, tenant, "github.com", "101"); err != nil || !ok || id.String() != api {
		t.Fatalf("find by id: %v %v %v", id, ok, err)
	}
	// The same id on another host, or in another tenant, is not this asset.
	if _, ok, _ := ident.FindRepositoryByProviderID(ctx, tenant, "gitlab.example.com", "101"); ok {
		t.Fatal("an id matched on another host")
	}
	if _, ok, _ := ident.FindRepositoryByProviderID(ctx, other, "github.com", "101"); ok {
		t.Fatal("an id matched in another tenant")
	}

	// Renamed on the code host: the same asset, renamed.
	if created, err := svc.UpsertRepositoryAssetForTest(ctx, tenant, repo("101", "acme/api-v2")); err != nil || created {
		t.Fatalf("renamed import: %v %v", created, err)
	}
	if assetOf(tenant, "github.com/acme/api-v2") != api || count(tenant) != 1 {
		t.Fatalf("rename split the repository: %d assets", count(tenant))
	}
	if len(aud.events) != 1 || aud.events[0].ResourceID != api || aud.events[0].Metadata["old_name"] != "github.com/acme/api" ||
		aud.events[0].Metadata["new_name"] != "github.com/acme/api-v2" || aud.tenants[0] != tenant.String() {
		t.Fatalf("rename audit = %+v", aud.events)
	}

	// CI reported a repository first (asset github.com/acme/web): import
	// adopts it instead of creating "acme/web".
	ciAsset := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status)
		VALUES ($1, $2, 'github.com/acme/web', 'repository', 'medium', 'active')`, ciAsset.String(), tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO asset_repositories (asset_id, full_name, visibility) VALUES ($1, 'github.com/acme/web', 'private')
		ON CONFLICT (asset_id) DO NOTHING`, ciAsset.String()); err != nil {
		t.Fatal(err)
	}
	if created, err := svc.UpsertRepositoryAssetForTest(ctx, tenant, repo("202", "acme/web")); err != nil || created {
		t.Fatalf("import of a CI repository: %v %v", created, err)
	}
	if count(tenant) != 2 || assetOf(tenant, "acme/web") != "" {
		t.Fatalf("import duplicated a CI repository: %d assets", count(tenant))
	}
	if id, ok, _ := ident.FindRepositoryByProviderID(ctx, tenant, "github.com", "202"); !ok || id != ciAsset {
		t.Fatal("the adopted asset does not carry the repository id")
	}

	// Another tenant importing the same repository gets its own asset.
	if created, err := svc.UpsertRepositoryAssetForTest(ctx, other, repo("101", "acme/api-v2")); err != nil || !created {
		t.Fatalf("other tenant: %v %v", created, err)
	}
	if count(tenant) != 2 || count(other) != 1 {
		t.Fatalf("tenants mixed: %d %d", count(tenant), count(other))
	}
}

type renameAudits struct {
	events  []auditapp.AuditEvent
	tenants []string
}

func (a *renameAudits) LogEvent(_ context.Context, actx auditapp.AuditContext, ev auditapp.AuditEvent) error {
	a.events = append(a.events, ev)
	a.tenants = append(a.tenants, actx.TenantID)
	return nil
}
