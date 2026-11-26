package datascope

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// ListActor fails closed: a caller who is not an administrator is never
// compiled as an unrestricted reader, whether or not a user is attached.
func TestListActor_NonAdminFailsClosed(t *testing.T) {
	ctx := context.Background()
	tenant := shared.NewID()
	user := shared.NewID()
	asset := shared.NewID()
	e := New(&fakeRepo{rows: map[shared.ID]map[shared.ID]bool{user: {asset: true}}}, nil, nil)

	t.Run("no user and no API key is refused", func(t *testing.T) {
		_, _, err := ListActor(ctx, e, ListCaller{TenantID: tenant.String()})
		if !errors.Is(err, ErrScopeUnresolved) || !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("err = %v, want ErrScopeUnresolved (forbidden)", err)
		}
	})

	t.Run("no user without an enforcer is refused", func(t *testing.T) {
		if _, _, err := ListActor(ctx, nil, ListCaller{TenantID: tenant.String()}); err == nil {
			t.Fatal("a non-administrator read ran without a data scope enforcer")
		}
	})

	t.Run("member without an enforcer is refused", func(t *testing.T) {
		if _, _, err := ListActor(ctx, nil, ListCaller{TenantID: tenant.String(), UserID: user.String()}); err == nil {
			t.Fatal("a member read ran without a data scope enforcer")
		}
	})

	t.Run("user-less API key reads an empty scope", func(t *testing.T) {
		a, _, err := ListActor(ctx, e, ListCaller{TenantID: tenant.String(), APIKey: true})
		if err != nil {
			t.Fatal(err)
		}
		if !a.Restricted() {
			t.Fatal("a user-less API key compiled as an unrestricted reader")
		}
		if sql, _ := a.AssetScopeSQL("a.id", 1); sql == "TRUE" {
			t.Fatalf("scope predicate = %q, want a restriction", sql)
		}
	})

	t.Run("member is narrowed to their scope", func(t *testing.T) {
		a, _, err := ListActor(ctx, e, ListCaller{TenantID: tenant.String(), UserID: user.String()})
		if err != nil {
			t.Fatal(err)
		}
		if !a.Restricted() {
			t.Fatal("a member compiled as an unrestricted reader")
		}
	})

	t.Run("lookup error is refused", func(t *testing.T) {
		broken := New(&fakeRepo{err: errors.New("db down")}, nil, nil)
		if _, _, err := ListActor(ctx, broken, ListCaller{TenantID: tenant.String(), UserID: user.String()}); err == nil {
			t.Fatal("a failed scope lookup ran the read")
		}
	})

	t.Run("administrator is not narrowed", func(t *testing.T) {
		a, _, err := ListActor(ctx, e, ListCaller{TenantID: tenant.String(), IsAdmin: true})
		if err != nil {
			t.Fatal(err)
		}
		if a.Restricted() {
			t.Fatal("an administrator was narrowed to scope rows")
		}
	})
}
