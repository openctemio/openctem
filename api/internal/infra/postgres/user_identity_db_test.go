package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/useridentity"
)

// The two unique rules of user_identities, and SAML scoping, enforced by the
// database (run as the application role in CI).
func TestUserIdentityRepository_Constraints(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewUserIdentityRepository(&DB{DB: db})
	alice := seedGroupsUser(ctx, t, db, "idt.example")
	bob := seedGroupsUser(ctx, t, db, "idt.example")
	tenantA := seedTestTenant(ctx, t, db)
	tenantB := seedTestTenant(ctx, t, db)
	iss := "https://idp-" + shared.NewID().String() + ".example"

	mk := func(user shared.ID, sub string, scope *shared.ID) *useridentity.Identity {
		ident, err := useridentity.New(user, useridentity.Key{Issuer: iss, Subject: sub, ScopeTenantID: scope})
		if err != nil {
			t.Fatal(err)
		}
		return ident
	}

	// Platform-wide identity for alice.
	a1 := mk(alice, "sub-a", nil)
	if err := repo.Create(ctx, a1); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := repo.GetByKey(ctx, a1.Key)
	if err != nil || got.UserID != alice || got.Key.ScopeTenantID != nil {
		t.Fatalf("get by key: %+v / %v", got, err)
	}

	// The same identity cannot be bound to bob.
	if err := repo.Create(ctx, mk(bob, "sub-a", nil)); !errors.Is(err, useridentity.ErrConflict) {
		t.Fatalf("same identity on a second account: want ErrConflict, got %v", err)
	}
	// Alice cannot get a second subject from the same issuer.
	if err := repo.Create(ctx, mk(alice, "sub-a2", nil)); !errors.Is(err, useridentity.ErrConflict) {
		t.Fatalf("second subject from the issuer: want ErrConflict, got %v", err)
	}

	// SAML scope: the same (issuer, subject) in organization A and B are two
	// identities, and neither is the platform-wide one.
	scopedA := mk(bob, "sub-a", &tenantA)
	if err := repo.Create(ctx, scopedA); err != nil {
		t.Fatalf("scoped identity in A: %v", err)
	}
	if got, err := repo.GetByKey(ctx, useridentity.Key{Issuer: iss, Subject: "sub-a", ScopeTenantID: &tenantB}); !errors.Is(err, useridentity.ErrNotFound) {
		t.Fatalf("A's identity must not resolve in B: %+v / %v", got, err)
	}
	if got, _ := repo.GetByKey(ctx, a1.Key); got == nil || got.UserID != alice {
		t.Fatal("the platform-wide identity must still be alice's")
	}
	if got, _ := repo.GetByKey(ctx, scopedA.Key); got == nil || got.UserID != bob {
		t.Fatal("A's scoped identity must be bob's")
	}

	// Re-key and use.
	if err := repo.ChangeSubject(ctx, a1.ID, "oid-a"); err != nil {
		t.Fatalf("change subject: %v", err)
	}
	if err := repo.MarkUsed(ctx, a1.ID, time.Now()); err != nil {
		t.Fatalf("mark used: %v", err)
	}
	list, err := repo.ListByUser(ctx, alice)
	if err != nil || len(list) != 1 || list[0].Key.Subject != "oid-a" || list[0].LastUsedAt == nil {
		t.Fatalf("list after re-key: %+v / %v", list, err)
	}

	// Deleting the account removes its identities.
	if _, err := db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, alice.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetByKey(ctx, useridentity.Key{Issuer: iss, Subject: "oid-a"}); !errors.Is(err, useridentity.ErrNotFound) {
		t.Fatalf("identity must go with the account, got %v", err)
	}
}
