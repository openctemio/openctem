package auth

import (
	"context"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// PlatformAdminGate answers whether a users-table account is linked to an
// active platform administrator. Such an account signs in on the admin
// console only: the main (tenant) site never opens a session for it.
type PlatformAdminGate interface {
	IsPlatformAdmin(ctx context.Context, userID shared.ID) bool
}

// SetPlatformAdminGate wires the main-site refusal of platform administrators
// (password, refresh-token and exchange paths).
func (s *AuthService) SetPlatformAdminGate(g PlatformAdminGate) { s.platformAdmins = g }

// SetPlatformAdminGate wires the same refusal on the social sign-in path.
func (s *OAuthService) SetPlatformAdminGate(g PlatformAdminGate) { s.platformAdmins = g }

// SetPlatformAdminGate wires the same refusal on the organization SSO/SAML path.
func (s *SSOService) SetPlatformAdminGate(g PlatformAdminGate) { s.platformAdmins = g }

// refusePlatformAdmin reports whether the main site must refuse this account
// because it is a platform administrator, and logs the attempt as an alert.
// The caller answers with the same error a wrong password gets, so neither
// the endpoint nor its timing says which emails are administrators. The log
// line carries no password and a CR/LF-free email.
func refusePlatformAdmin(ctx context.Context, g PlatformAdminGate, log *logger.Logger, u *userdom.User, via string) bool {
	if g == nil || u == nil || !g.IsPlatformAdmin(ctx, u.ID()) {
		return false
	}
	if log != nil {
		log.Warn("platform administrator refused on the main site",
			"alert", "platform_admin_main_site_sign_in",
			"via", via,
			"user_id", u.ID().String(),
			"email", singleLine(u.Email()))
	}
	return true
}

func singleLine(s string) string {
	const maxLen = 256
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}
