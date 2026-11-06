package integration

// The data region of an organization (RFC-104): set once at creation from
// DEPLOYMENT_REGION, kept by updates, empty for organizations from before.

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

func TestTenantRegionIsSetOnceAtCreation(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	repo := postgres.NewTenantRepository(&postgres.DB{DB: db})
	repo.SetRegionSource(func(context.Context) string { return "eu-central" })

	creator := createTestUser(t, db, "region-"+uuid.NewString()[:8]+"@example.com", "Creator")
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM users WHERE id = $1`, creator.String()) })
	org, err := tenant.NewTenant("Region Org", "region-"+uuid.NewString()[:8], creator.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, org); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleanupTestData(db, org.ID()) })
	got, err := repo.GetByID(ctx, org.ID())
	if err != nil || got.Region() != "eu-central" {
		t.Fatalf("a new organization gets the deployment's region: %q %v", got.Region(), err)
	}

	// A later deployment region never moves an existing organization.
	repo.SetRegionSource(func(context.Context) string { return "us-east" })
	_ = got.UpdateName("Renamed")
	if err := repo.UpdateProfile(ctx, got); err != nil {
		t.Fatal(err)
	}
	again, _ := repo.GetBySlug(ctx, org.Slug())
	if again.Region() != "eu-central" || again.WithRegion("us-east").Region() != "eu-central" {
		t.Fatalf("the region is fixed for the organization's life, got %q", again.Region())
	}

	// An organization from before regions reads as empty.
	old := createTestTenant(t, db, "pre-region")
	t.Cleanup(func() { cleanupTestData(db, old) })
	if o, _ := repo.GetByID(ctx, old); o.Region() != "" {
		t.Fatalf("a pre-region organization has no region, got %q", o.Region())
	}

	// The database refuses a malformed region.
	if _, err := db.Exec(`UPDATE tenants SET region = 'EU Central!' WHERE id = $1`, old.String()); err == nil {
		t.Fatal("a malformed region must be refused")
	}
}
