package auth

// Account-only access tokens: docs/architecture/tenantless-account-space.md.

import (
	"context"
	"errors"
	"fmt"
	"time"

	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ErrAccountTokenHasOrganization: the account can open an organization, so
// it exchanges its refresh token for that organization's token instead.
var ErrAccountTokenHasOrganization = errors.New("the account belongs to an organization; exchange the token for it")

// AccountTokenResult is an access token with no tenant and the rotated
// refresh token (for the httpOnly cookie only).
type AccountTokenResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// AccountToken mints an access token without a tenant claim for an account
// that has no organization it can open (none at all, or every one is
// suspended or closed). That token reaches only the account allow-list
// (middleware/tenantless.go); every other route refuses it. The refresh
// token is checked exactly as for an organization token (replay detection,
// active session and account) and is rotated in the same family. An account
// that can open an organization is refused, so a member never holds a token
// that skips the organization's sign-in policies (SSO, 2FA, verified email).
func (s *AuthService) AccountToken(ctx context.Context, refreshToken string) (*AccountTokenResult, error) {
	storedToken, sess, u, err := s.refreshForMint(ctx, refreshToken, "account_token")
	if err != nil {
		return nil, err
	}

	memberships, err := s.tenantRepo.GetUserMemberships(ctx, u.ID())
	if err != nil {
		return nil, fmt.Errorf("failed to get user memberships: %w", err)
	}
	for _, m := range memberships {
		if s.organizationOpen(ctx, m.TenantID) == nil {
			return nil, ErrAccountTokenHasOrganization
		}
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
