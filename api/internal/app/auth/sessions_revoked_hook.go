package auth

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SessionsRevokedHook runs after the sessions of an account were revoked
// because one of its credentials changed: a password reset or change, an
// administrator's two-step reset, enabling two-step verification. The
// platform admin console uses it to end the console sessions of the
// administrator linked to that account, so a stolen console session does not
// outlive the password it was opened with.
type SessionsRevokedHook func(ctx context.Context, userID shared.ID)

// SetSessionsRevokedHook wires the hook (nil: none).
func (s *AuthService) SetSessionsRevokedHook(h SessionsRevokedHook) { s.onSessionsRevoked = h }

func (s *AuthService) runSessionsRevokedHook(ctx context.Context, userID shared.ID) {
	if s.onSessionsRevoked != nil {
		s.onSessionsRevoked(ctx, userID)
	}
}
