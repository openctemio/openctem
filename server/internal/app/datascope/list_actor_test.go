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

// A has_full_data_access role holder who is not an administrator sees the
// whole tenant: the resolver says so explicitly (ResolutionUnrestricted),
// which ListActor accepts, while "nothing resolved" stays refused.
func TestListActor_FullDataRoleIsUnrestrictedNotUnresolved(t *testing.T) {
	ctx := context.Background()
	tenant := shared.NewID()
	reader, hiddenReader := shared.NewID(), shared.NewID()
	e := New(&fakeRepo{
		fullData: map[shared.ID]bool{reader: true, hiddenReader: true},
		hidden:   map[shared.ID]map[shared.ID]bool{hiddenReader: {shared.NewID(): true}},
	}, nil, nil)

	if _, kind, err := e.ResolveForKind(ctx, tenant, Caller{UserID: reader.String()}); err != nil || kind != ResolutionUnrestricted {
		t.Fatalf("full-data role: kind %v, err %v; want unrestricted", kind, err)
	}
	a, _, err := ListActor(ctx, e, ListCaller{TenantID: tenant.String(), UserID: reader.String()})
	if err != nil {
		t.Fatalf("full-data role refused: %v", err)
	}
	if a.Restricted() {
		t.Error("a full-data role holder was narrowed to scope rows")
	}
	// With hidden private program assets the scope still applies (it hides
	// those assets only).
	a, _, err = ListActor(ctx, e, ListCaller{TenantID: tenant.String(), UserID: hiddenReader.String()})
	if err != nil || !a.Restricted() {
		t.Errorf("full-data role with hidden program assets: restricted=%v err=%v, want the hiding scope", a.Restricted(), err)
	}
	// Through an API key the role grants nothing beyond the holder's rows.
	a, _, err = ListActor(ctx, e, ListCaller{TenantID: tenant.String(), UserID: reader.String(), APIKey: true})
	if err != nil || !a.Restricted() {
		t.Errorf("full-data role through an API key: restricted=%v err=%v, want scoped", a.Restricted(), err)
	}
}

func TestResolveForKind_Kinds(t *testing.T) {
	ctx := context.Background()
	tenant, member := shared.NewID(), shared.NewID()
	e := New(&fakeRepo{}, nil, nil)
	for _, tc := range []struct {
		name   string
		e      *Enforcer
		caller Caller
		want   Resolution
	}{
		{"no enforcer", nil, Caller{UserID: member.String()}, ResolutionNone},
		{"no user, no key", e, Caller{}, ResolutionNone},
		{"user-less API key", e, Caller{APIKey: true}, ResolutionScoped},
		{"member", e, Caller{UserID: member.String()}, ResolutionScoped},
		{"owner", e, Caller{UserID: member.String(), IsOwner: true}, ResolutionUnrestricted},
		{"administrator", e, Caller{UserID: member.String(), IsAdmin: true}, ResolutionUnrestricted},
	} {
		if _, kind, err := tc.e.ResolveForKind(WithRequestMemo(ctx), tenant, tc.caller); err != nil || kind != tc.want {
			t.Errorf("%s: kind %v err %v, want %v", tc.name, kind, err, tc.want)
		}
	}
}
