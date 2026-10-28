package auth

import (
	"context"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// BreakGlassGate answers whether a users-table account is linked to a
// break-glass administrator. A regular platform administrator signs in on the
// main site like any user (RFC-134); a break-glass account is sealed for
// emergencies and signs in on the admin console only, where its use raises
// the break-glass alert and audit. The main site never opens a session for it.
type BreakGlassGate interface {
	IsBreakGlass(ctx context.Context, userID shared.ID) bool
}

// SetBreakGlassGate wires the main-site refusal of break-glass accounts
// (password, refresh-token and exchange paths).
func (s *AuthService) SetBreakGlassGate(g BreakGlassGate) { s.breakGlassGate = g }

// SetBreakGlassGate wires the same refusal on the social sign-in path.
func (s *OAuthService) SetBreakGlassGate(g BreakGlassGate) { s.breakGlassGate = g }

// SetBreakGlassGate wires the same refusal on the organization SSO/SAML path.
func (s *SSOService) SetBreakGlassGate(g BreakGlassGate) { s.breakGlassGate = g }

// refuseBreakGlass reports whether the main site must refuse this account
// because it is a break-glass administrator, and logs the attempt as an alert.
// The caller answers with the same error a wrong password gets, so neither
// the endpoint nor its timing says which emails are break-glass accounts. The
// log line carries no password and a CR/LF-free email.
func refuseBreakGlass(ctx context.Context, g BreakGlassGate, log *logger.Logger, u *userdom.User, via string) bool {
	if g == nil || u == nil || !g.IsBreakGlass(ctx, u.ID()) {
		return false
	}
	if log != nil {
		log.Warn("break-glass account refused on the main site",
			"alert", "break_glass_main_site_sign_in",
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
