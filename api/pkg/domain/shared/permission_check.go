package shared

import "context"

// The caller's permissions as a check the application layer can ask without
// knowing the HTTP layer: the tenant chain records it once per request
// (middleware.PermissionCheckContext). A context without one (a platform
// job, a webhook, an automation) holds no person's permissions.

type permissionCheckKey struct{}

// WithPermissionCheck records how to ask whether the caller holds a
// permission.
func WithPermissionCheck(ctx context.Context, has func(permission string) bool) context.Context {
	return context.WithValue(ctx, permissionCheckKey{}, has)
}

// CallerHasPermission reports whether the caller holds the permission; false
// when the context records no caller permissions.
func CallerHasPermission(ctx context.Context, permission string) bool {
	has, ok := ctx.Value(permissionCheckKey{}).(func(string) bool)
	return ok && has != nil && has(permission)
}
