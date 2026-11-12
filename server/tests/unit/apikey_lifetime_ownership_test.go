package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/apikey"
	apikeydom "github.com/openctemio/openctem/api/pkg/domain/apikey"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Every API key expires, at most 365 days after it is minted (B14): no
// "never" (expires_in_days=0) and nothing longer.
func TestCreateAPIKey_ExpiryIsRequiredAndBounded(t *testing.T) {
	svc := newTestAPIKeyService(newMockAPIKeyRepo())
	tenantID := shared.NewID().String()
	for _, days := range []int{0, -1, 366, 10000} {
		_, err := svc.Create(context.Background(), apikey.CreateInput{TenantID: tenantID, Name: "k", ExpiresInDays: days})
		if !errors.Is(err, apikey.ErrExpiryRequired) || !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expires_in_days=%d: err = %v, want ErrExpiryRequired", days, err)
		}
	}
	res, err := svc.Create(context.Background(), apikey.CreateInput{TenantID: tenantID, Name: "k", ExpiresInDays: apikey.MaxExpiresInDays})
	if err != nil {
		t.Fatalf("365 days: %v", err)
	}
	if res.Key.ExpiresAt() == nil {
		t.Fatal("key minted without an expiry")
	}
}

// A member may revoke or delete only their own keys; someone else's key in
// the same tenant reads as not found. An owner/admin (no owner filter) may act
// on any key of the tenant.
func TestRevokeDeleteAPIKey_OwnershipEnforced(t *testing.T) {
	repo := newMockAPIKeyRepo()
	svc := newTestAPIKeyService(repo)
	ctx := context.Background()
	tenantID := shared.NewID().String()
	alice, bob := shared.NewID().String(), shared.NewID().String()

	mint := func(owner string) string {
		res, err := svc.Create(ctx, apikey.CreateInput{TenantID: tenantID, UserID: owner, Name: "k", ExpiresInDays: 30})
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		return res.Key.ID().String()
	}
	aliceKey := mint(alice)

	if _, err := svc.Revoke(ctx, apikey.RevokeInput{ID: aliceKey, TenantID: tenantID, RevokedBy: bob, OwnerID: bob}); !errors.Is(err, apikeydom.ErrAPIKeyNotFound) {
		t.Fatalf("bob revoking alice's key: err = %v, want not found", err)
	}
	if err := svc.DeleteOwned(ctx, aliceKey, tenantID, bob); !errors.Is(err, apikeydom.ErrAPIKeyNotFound) {
		t.Fatalf("bob deleting alice's key: err = %v, want not found", err)
	}
	if _, err := svc.Revoke(ctx, apikey.RevokeInput{ID: aliceKey, TenantID: tenantID, RevokedBy: alice, OwnerID: alice}); err != nil {
		t.Fatalf("alice revoking her own key: %v", err)
	}

	otherKey := mint(alice)
	if err := svc.DeleteOwned(ctx, otherKey, tenantID, ""); err != nil {
		t.Fatalf("admin deleting a member's key: %v", err)
	}
}
