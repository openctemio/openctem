package middleware

import "github.com/openctemio/openctem/api/pkg/apierror"

// PermissionDeniedDetails tells the caller exactly which grant a refused
// request lacked, so they can ask an administrator for that and nothing
// more. The permission catalog and the role names are public within the
// organization (the role editor lists them), so naming them discloses nothing.
// Data-scope refusals never come through here: an asset outside the caller's
// scope answers 404.
type PermissionDeniedDetails struct {
	// MissingPermissions must all be granted.
	MissingPermissions []string `json:"missing_permissions,omitempty"`
	// AnyOf: one of these must be granted.
	AnyOf []string `json:"any_of,omitempty"`
	// RequiredRole: the team role needed (admin or owner).
	RequiredRole string `json:"required_role,omitempty"`
}

func permissionDenied(missing ...string) *apierror.Error {
	return apierror.Forbidden("Insufficient permissions").WithDetails(PermissionDeniedDetails{MissingPermissions: missing})
}

func permissionDeniedAnyOf(anyOf ...string) *apierror.Error {
	return apierror.Forbidden("Insufficient permissions").WithDetails(PermissionDeniedDetails{AnyOf: anyOf})
}

func roleRequired(message, role string) *apierror.Error {
	return apierror.Forbidden(message).WithDetails(PermissionDeniedDetails{RequiredRole: role})
}
