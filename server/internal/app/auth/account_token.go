package auth

// Account-only access tokens: docs/architecture/tenantless-account-space.md.

import (
	"context"
	"fmt"
	"time"

	sessiondom "github.com/openctemio/openctem/server/pkg/domain/session"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// AccountTokenResult is an access token with no tenant and the rotated
// refresh token (for the httpOnly cookie only).
type AccountTokenResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// AccountToken mints an access token without a tenant claim for any
// signed-in account, member of an organization or not. That token reaches
// only the account allow-list (middleware/tenantless.go): the caller's own
// profile, sign-in methods, second factor, sessions, preferences, invitations
// and organization creation where allowed. Every other route refuses it with
// 401 TENANT_REQUIRED, so it opens no organization data and skips none of an
// organization's sign-in rules (SSO, 2FA, verified e-mail): those are checked
// when the session asks for that organization's token (ExchangeToken).
// A person whose organization refuses this session (2FA not set up, its own
// IdP required, suspended) therefore still reaches their account settings and
// the one step that admits them, instead of holding no usable token.
// The refresh token is checked exactly as for an organization token (replay
// detection, active session and account) and is rotated in the same family;
// the access token is bound to the same session, so signing out ends both.
func (s *AuthService) AccountToken(ctx context.Context, refreshToken string) (*AccountTokenResult, error) {
	storedToken, sess, u, err := s.refreshForMint(ctx, refreshToken, "account_token")
	if err != nil {
		return nil, err
	}

	if err := s.spendRefreshToken(ctx, storedToken); err != nil {
		return nil, err
	}

	accessToken, expiresAt, err := s.tokenGenerator.GenerateAccessToken(u.ID().String(), sess.ID().String(), "user")
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	sess.UpdateActivity()
	if err := s.sessionRepo.Update(ctx, sess); err != nil {
		s.logger.Error("failed to update session activity", "error", err)
	}

	newRefresh, err := s.issueSuccessorRefreshToken(ctx, u.ID().String(), u.Email(), u.Name(), sess.ID().String(), storedToken)
	if err != nil {
		return nil, err
	}
	return &AccountTokenResult{AccessToken: accessToken, RefreshToken: newRefresh, ExpiresAt: expiresAt}, nil
}

// issueSuccessorRefreshToken issues the refresh token that replaces stored
// (already spent) in the same family and stores it.
func (s *AuthService) issueSuccessorRefreshToken(ctx context.Context, userID, email, name, sessionID string, stored *sessiondom.RefreshToken) (string, error) {
	raw, _, err := s.tokenGenerator.GenerateGlobalRefreshToken(userID, email, name, sessionID)
	if err != nil {
		return "", fmt.Errorf("failed to generate refresh token: %w", err)
	}
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return "", fmt.Errorf("invalid user id: %w", err)
	}
	next, err := sessiondom.NewRefreshTokenInFamily(uid, stored.SessionID(), raw, stored.Family(), s.config.RefreshTokenDuration)
	if err != nil {
		return "", fmt.Errorf("failed to create refresh token: %w", err)
	}
	if err := s.refreshTokenRepo.Create(ctx, next); err != nil {
		return "", fmt.Errorf("failed to save refresh token: %w", err)
	}
	return raw, nil
}
