package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scmapp"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// One installation belongs to at most one tenant; every tenant read and
// write is scoped; the webhook's status change finds it by GitHub id.
// Requires DATABASE_URL.
func TestSCMAppInstallationRepository(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewSCMAppInstallationRepository(&DB{DB: db})
	a, b := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	iid := 900000000 + time.Now().UnixNano()%100000000

	inst := &scmapp.Installation{ID: shared.NewID(), TenantID: a, Provider: scmapp.ProviderGitHub, InstallationID: iid,
		AccountLogin: "Acme", AccountID: 5, AccountType: "Organization", RepositorySelection: "all"}
	if err := repo.Create(ctx, inst); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM scm_app_installations WHERE installation_id = $1`, iid)
	})
	// Another tenant cannot take it; the same tenant re-binding keeps the row.
	if err := repo.Create(ctx, &scmapp.Installation{ID: shared.NewID(), TenantID: b, Provider: scmapp.ProviderGitHub,
		InstallationID: iid, AccountLogin: "Acme"}); !errors.Is(err, scmapp.ErrBoundElsewhere) {
		t.Fatalf("other tenant: %v", err)
	}
	again := &scmapp.Installation{ID: shared.NewID(), TenantID: a, Provider: scmapp.ProviderGitHub, InstallationID: iid, AccountLogin: "acme"}
	if err := repo.Create(ctx, again); err != nil || again.ID != inst.ID {
		t.Fatalf("rebind: %v %s vs %s", err, again.ID, inst.ID)
	}
	if got, err := repo.ActiveForAccount(ctx, a, scmapp.ProviderGitHub, "ACME"); err != nil || got.ID != inst.ID {
		t.Fatalf("active for account: %v", err)
	}
	// Tenant isolation.
	if _, err := repo.Get(ctx, b, inst.ID); !errors.Is(err, scmapp.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if list, _ := repo.List(ctx, b); len(list) != 0 {
		t.Fatalf("cross-tenant list: %d", len(list))
	}
	if _, err := repo.ActiveForAccount(ctx, b, scmapp.ProviderGitHub, "acme"); !errors.Is(err, scmapp.ErrNotFound) {
		t.Fatalf("cross-tenant account: %v", err)
	}
	if err := repo.Delete(ctx, b, inst.ID); !errors.Is(err, scmapp.ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}
	// Webhook status: suspended installations are not active.
	if n, err := repo.SetStatusByInstallationID(ctx, scmapp.ProviderGitHub, iid, scmapp.StatusSuspended); err != nil || n != 1 {
		t.Fatalf("suspend: %d %v", n, err)
	}
	if _, err := repo.ActiveForAccount(ctx, a, scmapp.ProviderGitHub, "acme"); !errors.Is(err, scmapp.ErrNotFound) {
		t.Fatalf("suspended still active: %v", err)
	}
	if err := repo.Delete(ctx, a, inst.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

// GitLab connections: the deepest group holding a project wins, a group's
// name is matched literally (LIKE wildcards in a name match nothing else),
// and every read is tenant-scoped.
func TestSCMGitLabConnections(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewSCMAppInstallationRepository(&DB{DB: db})
	a, b := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	mk := func(tid shared.ID, path string, gid int64) *scmapp.GitLabConnection {
		c := &scmapp.GitLabConnection{ID: shared.NewID(), TenantID: tid, Host: "gitlab.example.com", GroupPath: path,
			GroupID: gid, TokenEncrypted: "sealed", TokenUserID: 9}
		if err := repo.CreateGitLab(ctx, c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	top := mk(a, "acme", 1)
	deep := mk(a, "acme/platform", 2)
	mk(a, "a_c", 3)
	mk(b, "beta", 4)
	if c, err := repo.GitLabForProject(ctx, a, "GitLab.example.com", "acme/platform/api"); err != nil || c.ID != deep.ID {
		t.Fatalf("deepest group: %v %v", c, err)
	}
	if c, err := repo.GitLabForProject(ctx, a, "gitlab.example.com", "acme/web"); err != nil || c.ID != top.ID {
		t.Fatalf("top group: %v %v", c, err)
	}
	if _, err := repo.GitLabForProject(ctx, a, "gitlab.example.com", "abc/x"); !errors.Is(err, scmapp.ErrNotFound) {
		t.Fatalf("LIKE wildcard in a group name matched: %v", err)
	}
	if _, err := repo.GitLabForProject(ctx, b, "gitlab.example.com", "acme/web"); !errors.Is(err, scmapp.ErrNotFound) {
		t.Fatalf("cross-tenant: %v", err)
	}
	if _, err := repo.GitLabForProject(ctx, a, "other.example.com", "acme/web"); !errors.Is(err, scmapp.ErrNotFound) {
		t.Fatalf("other host: %v", err)
	}
	// Reconnecting the same group replaces its token, keeping one row.
	again := &scmapp.GitLabConnection{ID: shared.NewID(), TenantID: a, Host: "gitlab.example.com", GroupPath: "acme", GroupID: 1,
		TokenEncrypted: "sealed2", TokenUserID: 10}
	if err := repo.CreateGitLab(ctx, again); err != nil || again.ID != top.ID || again.TokenEncrypted != "sealed2" {
		t.Fatalf("reconnect: %v %+v", err, again)
	}
	if list, _ := repo.ListGitLab(ctx, b); len(list) != 1 {
		t.Fatalf("tenant b sees %d", len(list))
	}
	if _, err := repo.DeleteGitLab(ctx, b, top.ID); !errors.Is(err, scmapp.ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}
	if _, err := repo.DeleteGitLab(ctx, a, top.ID); err != nil {
		t.Fatal(err)
	}
}
