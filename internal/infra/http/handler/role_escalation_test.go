package handler

import (
	"context"
	"testing"

	"github.com/openctemio/api/internal/infra/http/middleware"
)

// assertCanGrantPermissions must block a non-admin from granting a permission
// they don't hold, allow grants within their own set, and let admins bypass.
func TestAssertCanGrantPermissions(t *testing.T) {
	withPerms := func(perms []string, admin bool) context.Context {
		ctx := context.WithValue(context.Background(), middleware.PermissionsKey, perms)
		return context.WithValue(ctx, middleware.IsAdminKey, admin)
	}

	// Non-admin granting a permission they hold → allowed.
	if e := assertCanGrantPermissions(withPerms([]string{"assets:read", "assets:write"}, false), []string{"assets:read"}); e != nil {
		t.Errorf("granting a held permission should be allowed, got %v", e)
	}
	// Non-admin granting a permission they do NOT hold → blocked (escalation).
	if e := assertCanGrantPermissions(withPerms([]string{"assets:read"}, false), []string{"team:delete"}); e == nil {
		t.Error("granting an unheld permission must be blocked")
	}
	// Admin bypasses entirely.
	if e := assertCanGrantPermissions(withPerms(nil, true), []string{"team:delete", "billing:write"}); e != nil {
		t.Errorf("admin should bypass the grant ceiling, got %v", e)
	}
	// Non-admin with no perms cannot grant anything.
	if e := assertCanGrantPermissions(withPerms(nil, false), []string{"assets:read"}); e == nil {
		t.Error("a caller with no permissions must not grant any")
	}
}
