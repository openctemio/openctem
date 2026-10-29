package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/useridentity"
)

// Unlinking a sign-in method: only the account's own identity is removed, and
// an account without a password always keeps one, even under concurrent
// unlinks (the account row is locked).
func TestUserIdentityRepository_DeleteForUser(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewUserIdentityRepository(&DB{DB: db})
	alice := seedGroupsUser(ctx, t, db, "unlink.example")
	bob := seedGroupsUser(ctx, t, db, "unlink.example")
	bind := func(user shared.ID, issuer string) *useridentity.Identity {
		ident, err := useridentity.New(user, useridentity.Key{Issuer: issuer + "-" + shared.NewID().String(), Subject: "s-" + shared.NewID().String()})
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.Create(ctx, ident); err != nil {
			t.Fatalf("create: %v", err)
		}
		return ident
	}

	a1 := bind(alice, "https://a1")
	b1 := bind(bob, "https://b1")

	// Another account's identity: not found, and untouched.
	if err := repo.DeleteForUser(ctx, alice, b1.ID, false); !errors.Is(err, useridentity.ErrNotFound) {
		t.Fatalf("other account's identity: want ErrNotFound, got %v", err)
	}
	if got, err := repo.GetByKey(ctx, b1.Key); err != nil || got.UserID != bob {
		t.Fatalf("bob's identity changed: %+v %v", got, err)
	}

	// keepOne: the only identity stays.
	if err := repo.DeleteForUser(ctx, alice, a1.ID, true); !errors.Is(err, useridentity.ErrLastIdentity) {
		t.Fatalf("last identity: want ErrLastIdentity, got %v", err)
	}
	// A password account may remove it.
	if err := repo.DeleteForUser(ctx, alice, a1.ID, false); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := repo.DeleteForUser(ctx, alice, a1.ID, false); !errors.Is(err, useridentity.ErrNotFound) {
		t.Fatalf("second delete: want ErrNotFound, got %v", err)
	}

	// Two identities, two concurrent keepOne unlinks: exactly one succeeds.
	x := bind(alice, "https://x")
	y := bind(alice, "https://y")
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, id := range []shared.ID{x.ID, y.ID} {
		wg.Add(1)
		go func(i int, id shared.ID) {
			defer wg.Done()
			errs[i] = repo.DeleteForUser(ctx, alice, id, true)
		}(i, id)
	}
	wg.Wait()
	ok, last := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, useridentity.ErrLastIdentity):
			last++
		default:
			t.Fatalf("unexpected: %v", err)
		}
	}
	left, err := repo.ListByUser(ctx, alice)
	if err != nil {
		t.Fatal(err)
	}
	if ok != 1 || last != 1 || len(left) != 1 {
		t.Fatalf("concurrent unlinks: ok=%d last=%d left=%d", ok, last, len(left))
	}
}
