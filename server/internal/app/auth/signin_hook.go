package auth

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SignInHook runs after a sign-in created a session: signing in again
// cancels a pending self-service account deletion (accountdeletion). It never
// fails the sign-in.
type SignInHook func(ctx context.Context, userID shared.ID)

// SetSignInHook wires the hook run after a password sign-in.
func (s *AuthService) SetSignInHook(h SignInHook) { s.onSignIn = h }

// SetSignInHook wires the hook run after a social sign-in.
func (s *OAuthService) SetSignInHook(h SignInHook) { s.onSignIn = h }

// SetSignInHook wires the hook run after an SSO sign-in.
func (s *SSOService) SetSignInHook(h SignInHook) { s.onSignIn = h }

func runSignInHook(ctx context.Context, h SignInHook, userID shared.ID) {
	if h != nil {
		h(ctx, userID)
	}
}
