package handler

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PlatformAdminChecker answers whether a users-table account is linked to an
// active platform administrator (RFC-022). Login and /users/me expose the
// answer so the UI can send the administrator to the admin console instead of
// organization onboarding; the console itself still requires its own TOTP step.
type PlatformAdminChecker interface {
	IsPlatformAdmin(ctx context.Context, userID shared.ID) bool
}
