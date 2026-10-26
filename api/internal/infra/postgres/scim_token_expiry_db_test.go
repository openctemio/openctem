package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scimtoken"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The expiry is stored and read back, a rotation only ever brings it
// forward, never touches a revoked token and stays inside the tenant.
func TestScimTokenRepository_Expiry(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewScimTokenRepository(&DB{DB: db})
	tenantA := seedTestTenant(ctx, t, db)
	tenantB := seedTestTenant(ctx, t, db)

	exp := time.Now().UTC().Add(90 * 24 * time.Hour).Truncate(time.Second)
	tok := scimtoken.New(shared.NewID(), tenantA, "okta", "hash-"+shared.NewID().String(), "oct_scim_abcd", exp)
	if err := repo.Create(ctx, tok); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM scim_tokens WHERE tenant_id IN ($1, $2)`, tenantA.String(), tenantB.String())
	})

	got, err := repo.GetByID(ctx, tenantA, tok.ID())
	if err != nil || !got.ExpiresAt().Equal(exp) {
		t.Fatalf("expires_at %v err %v, want %v", got.ExpiresAt(), err, exp)
	}

	// Another tenant cannot cut the token off.
	if err := repo.ShortenExpiry(ctx, tenantB, tok.ID(), time.Now()); !errors.Is(err, scimtoken.ErrNotFound) {
		t.Fatalf("other tenant: %v", err)
	}
	// Never later than it was.
	if err := repo.ShortenExpiry(ctx, tenantA, tok.ID(), exp.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, _ = repo.GetByID(ctx, tenantA, tok.ID())
	if !got.ExpiresAt().Equal(exp) {
		t.Fatalf("expiry extended to %v", got.ExpiresAt())
	}
	soon := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
	if err := repo.ShortenExpiry(ctx, tenantA, tok.ID(), soon); err != nil {
		t.Fatal(err)
	}
	got, _ = repo.GetByID(ctx, tenantA, tok.ID())
	if !got.ExpiresAt().Equal(soon) || got.Status() != scimtoken.StatusActive {
		t.Fatalf("after shortening: %v %s", got.ExpiresAt(), got.Status())
	}

	// A revoked token stays revoked.
	got.Revoke()
	if err := repo.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	if err := repo.ShortenExpiry(ctx, tenantA, tok.ID(), time.Now()); !errors.Is(err, scimtoken.ErrNotFound) {
		t.Fatalf("revoked token: %v", err)
	}
	got, _ = repo.GetByID(ctx, tenantA, tok.ID())
	if got.Status() != scimtoken.StatusRevoked {
		t.Fatalf("status %s", got.Status())
	}
}
