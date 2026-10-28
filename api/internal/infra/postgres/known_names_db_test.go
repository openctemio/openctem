package postgres

import (
	"context"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The names a job's generated wordlist draws on are the organization's own,
// under the asked root, active and not deleted; another organization's names
// are never read, whatever the root, and LIKE wildcards in a root match
// nothing extra.
func TestKnownNames_TenantScoped(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewKnownNamesRepository(&DB{DB: db})
	tenantA := seedTestTenant(ctx, t, db)
	tenantB := seedTestTenant(ctx, t, db)

	add := func(tenant shared.ID, name, typ, status string, deleted bool) {
		t.Helper()
		q := `INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, $4, $5)`
		if deleted {
			q = `INSERT INTO assets (id, tenant_id, name, asset_type, status, deleted_at) VALUES ($1, $2, $3, $4, $5, now())`
		}
		if _, err := db.ExecContext(ctx, q, shared.NewID().String(), tenant.String(), name, typ, status); err != nil {
			t.Fatal(err)
		}
	}
	add(tenantA, "example.com", "domain", "active", false)
	add(tenantA, "api.example.com", "subdomain", "active", false)
	add(tenantA, "mail.example.com", "domain", "active", false)
	add(tenantA, "old.example.com", "subdomain", "active", true)     // deleted
	add(tenantA, "gone.example.com", "subdomain", "inactive", false) // not active
	add(tenantA, "host.example.com", "host", "active", false)        // not a name asset
	add(tenantA, "notexample.com", "domain", "active", false)        // another root with the same suffix text
	add(tenantA, "api.example.org", "subdomain", "active", false)    // another root
	add(tenantA, "exampleXcom", "domain", "active", false)           // a '.' wildcard must not match
	add(tenantB, "secret.example.com", "subdomain", "active", false) // another organization's

	got, err := repo.KnownNames(ctx, tenantA, "example.com", 100)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	if want := []string{"api.example.com", "example.com", "mail.example.com"}; !slices.Equal(got, want) {
		t.Fatalf("names = %v, want %v", got, want)
	}
	gotB, err := repo.KnownNames(ctx, tenantB, "example.com", 100)
	if err != nil || !slices.Equal(gotB, []string{"secret.example.com"}) {
		t.Fatalf("tenant B names = %v, %v", gotB, err)
	}
	if got, _ := repo.KnownNames(ctx, tenantA, "%", 100); len(got) != 0 {
		t.Errorf("a LIKE wildcard root matched %v", got)
	}
	if got, _ := repo.KnownNames(ctx, tenantA, "example.com", 2); len(got) != 2 {
		t.Errorf("limit not applied: %v", got)
	}
	if got, err := repo.KnownNames(ctx, shared.ID{}, "example.com", 10); err != nil || got != nil {
		t.Errorf("no tenant: %v, %v", got, err)
	}
}
