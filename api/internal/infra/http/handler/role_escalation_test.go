package handler

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
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

	// Bulk-assign escalation: a `roles:assign` holder must not assign a role
	// whose permission BUNDLE exceeds their own (e.g. the system admin role).
	// The bulk-members handler now runs this guard on the target role's
	// Permissions(), same as AssignRole / SetUserRoles. Here the caller holds
	// only findings:read but the target role bundles a broader set.
	adminBundle := []string{"findings:read", "team:roles:write", "settings:billing:write"}
	if e := assertCanGrantPermissions(withPerms([]string{"findings:read"}, false), adminBundle); e == nil {
		t.Error("bulk-assigning a role whose bundle exceeds the caller's must be blocked")
	}
	// Same bundle is fine for an admin (bypass).
	if e := assertCanGrantPermissions(withPerms(nil, true), adminBundle); e != nil {
		t.Errorf("admin bulk-assigning any role bundle should be allowed, got %v", e)
	}
}
