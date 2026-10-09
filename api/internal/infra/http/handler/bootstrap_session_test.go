package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The session parts of GET /me/bootstrap replace /users/me,
// /users/me/tenants, /notifications/unread-count and the review-queue count
// on every page load, so they must answer exactly what those endpoints
// answer for the same caller, and nothing about anyone else.

const (
	bsTenant = "11111111-1111-1111-1111-111111111111"
	bsUser   = "22222222-2222-2222-2222-222222222222"
)

type bsCalls struct {
	unreadTenant, unreadUser shared.ID
	tenantsUser              shared.ID
	reviewTenant             shared.ID
	reviewCalled             bool
}

func bsRequest(t *testing.T, u *user.User, perms []string, admin bool) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/me/bootstrap", nil)
	ctx := context.WithValue(r.Context(), middleware.LocalUserKey, u)
	ctx = context.WithValue(ctx, middleware.PermissionsKey, perms)
	ctx = context.WithValue(ctx, middleware.IsAdminKey, admin)
	return r.WithContext(ctx)
}

func bsUserEntity(t *testing.T, id string) *user.User {
	t.Helper()
	uid, err := shared.IDFromString(id)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	return user.Reconstitute(uid, nil, "perf@example.test", "Perf", "", "",
		user.StatusActive, user.Preferences{}, nil, now, now,
		user.AuthProviderLocal, nil, true, nil, nil, nil, nil, 0, nil)
}

func bsHandler(calls *bsCalls, failing bool) *BootstrapHandler {
	h := &BootstrapHandler{logger: logger.NewNop()}
	fail := errors.New("source down")
	return h.WithSession(BootstrapSession{
		Me: func(_ context.Context, u *user.User) UserResponse {
			return UserResponse{ID: u.ID().String(), Email: u.Email()}
		},
		MyTenants: func(_ context.Context, userID shared.ID) ([]TenantMembershipResponse, error) {
			calls.tenantsUser = userID
			if failing {
				return nil, fail
			}
			return []TenantMembershipResponse{{ID: bsTenant, Role: "member"}}, nil
		},
		UnreadCount: func(_ context.Context, tenantID, userID shared.ID) (int, error) {
			calls.unreadTenant, calls.unreadUser = tenantID, userID
			if failing {
				return 0, fail
			}
			return 7, nil
		},
		EASMReviewCount: func(_ context.Context, tenantID shared.ID) (int, error) {
			calls.reviewTenant, calls.reviewCalled = tenantID, true
			if failing {
				return 0, fail
			}
			return 3, nil
		},
		TenantCreationMode: func(context.Context) string { return "admin_only" },
	})
}

func withModules(ids ...string) *BootstrapResponse {
	return &BootstrapResponse{Modules: &TenantModulesResponse{ModuleIDs: ids}}
}

func TestBootstrapSession_FillsTheCallersOwnData(t *testing.T) {
	calls := &bsCalls{}
	h := bsHandler(calls, false)
	resp := withModules(module.ModuleAttackSurface)
	h.addSession(bsRequest(t, bsUserEntity(t, bsUser), []string{permission.AssetsRead.String()}, false), resp, bsTenant, bsUser)

	if resp.User == nil || resp.User.ID != bsUser {
		t.Fatalf("user = %+v, want the token's own user", resp.User)
	}
	if len(resp.Tenants) != 1 || calls.tenantsUser.String() != bsUser {
		t.Fatalf("tenants = %+v for %s, want the caller's memberships", resp.Tenants, calls.tenantsUser)
	}
	if resp.Badges == nil || resp.Badges.UnreadNotifications == nil || *resp.Badges.UnreadNotifications != 7 {
		t.Fatalf("unread badge = %+v", resp.Badges)
	}
	// The count is the caller's own channel: the token's tenant and user,
	// never a value from the request.
	if calls.unreadTenant.String() != bsTenant || calls.unreadUser.String() != bsUser {
		t.Fatalf("unread count read for %s/%s", calls.unreadTenant, calls.unreadUser)
	}
	if resp.Badges.EASMReview == nil || *resp.Badges.EASMReview != 3 || calls.reviewTenant.String() != bsTenant {
		t.Fatalf("review badge = %+v (tenant %s)", resp.Badges.EASMReview, calls.reviewTenant)
	}
	if resp.TenantCreationMode != "admin_only" {
		t.Fatalf("tenant_creation_mode = %q", resp.TenantCreationMode)
	}
}

func TestBootstrapSession_ReviewCountNeedsAssetsRead(t *testing.T) {
	calls := &bsCalls{}
	h := bsHandler(calls, false)
	resp := withModules(module.ModuleAttackSurface)
	h.addSession(bsRequest(t, bsUserEntity(t, bsUser), []string{permission.FindingsRead.String()}, false), resp, bsTenant, bsUser)

	if calls.reviewCalled {
		t.Fatal("the review queue was counted for a caller without assets:read")
	}
	if resp.Badges != nil && resp.Badges.EASMReview != nil {
		t.Fatalf("review badge = %d, want omitted", *resp.Badges.EASMReview)
	}
}

func TestBootstrapSession_ReviewCountNeedsTheModule(t *testing.T) {
	calls := &bsCalls{}
	h := bsHandler(calls, false)
	resp := withModules(module.ModuleFindings)
	h.addSession(bsRequest(t, bsUserEntity(t, bsUser), nil, true), resp, bsTenant, bsUser)

	if calls.reviewCalled {
		t.Fatal("the review queue was counted with the attack_surface module off")
	}
}

func TestBootstrapSession_ProfileOnlyForTheTokensOwnUser(t *testing.T) {
	calls := &bsCalls{}
	h := bsHandler(calls, false)
	resp := withModules()
	other := bsUserEntity(t, "33333333-3333-3333-3333-333333333333")
	h.addSession(bsRequest(t, other, nil, false), resp, bsTenant, bsUser)

	if resp.User != nil {
		t.Fatalf("user = %+v, want none when the synced user is not the token's user", resp.User)
	}
}

func TestBootstrapSession_AFailingSourceIsLeftOut(t *testing.T) {
	calls := &bsCalls{}
	h := bsHandler(calls, true)
	resp := withModules(module.ModuleAttackSurface)
	h.addSession(bsRequest(t, bsUserEntity(t, bsUser), nil, true), resp, bsTenant, bsUser)

	if resp.Tenants != nil {
		t.Fatalf("tenants = %+v, want omitted after a failure", resp.Tenants)
	}
	if resp.Badges != nil {
		t.Fatalf("badges = %+v, want omitted after failures", resp.Badges)
	}
	if resp.User == nil {
		t.Fatal("a failing count must not drop the profile")
	}
}

func TestBootstrapSession_NothingWithoutAValidIdentity(t *testing.T) {
	calls := &bsCalls{}
	h := bsHandler(calls, false)
	resp := withModules(module.ModuleAttackSurface)
	h.addSession(bsRequest(t, bsUserEntity(t, bsUser), nil, true), resp, "not-a-uuid", bsUser)

	if resp.User != nil || resp.Tenants != nil || resp.Badges != nil {
		t.Fatalf("session parts filled without a valid tenant: %+v", resp)
	}
}
