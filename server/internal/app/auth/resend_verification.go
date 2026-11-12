package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/password"
)

// ResendVerificationCooldown is the least time between two verification
// emails to one address: the per-address cap of POST /auth/resend-verification.
const ResendVerificationCooldown = 2 * time.Minute

// ResendVerificationResult is a fresh verification token to email. A nil
// result means nothing is to be sent; callers answer the same either way, so
// the response never says whether the address has an account.
type ResendVerificationResult struct {
	Token    string
	UserName string
}

// ResendVerification issues a new verification token for the account with
// email when it is a local, active, still unverified account and no
// verification email left in the last ResendVerificationCooldown (the issue
// time is the stored expiry minus the verification lifetime). The previous
// link stops working. Every other case returns (nil, nil).
func (s *AuthService) ResendVerification(ctx context.Context, email string) (*ResendVerificationResult, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	u, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		if shared.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if u.AuthProvider() != userdom.AuthProviderLocal || u.EmailVerified() || !u.IsActive() {
		return nil, nil
	}
	lifetime := s.config.EmailVerificationDuration
	if exp := u.EmailVerificationExpiresAt(); exp != nil && time.Since(exp.Add(-lifetime)) < ResendVerificationCooldown {
		return nil, nil
	}
	token, err := password.GenerateVerificationToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification token: %w", err)
	}
	// Only the hash is stored; the raw token is emailed.
	u.SetEmailVerificationToken(crypto.HashToken(token), time.Now().Add(lifetime))
	if err := s.userRepo.Update(ctx, u); err != nil {
		return nil, fmt.Errorf("failed to store verification token: %w", err)
	}
	s.logger.Info("verification email requested", "user_id", u.ID().String())
	return &ResendVerificationResult{Token: token, UserName: u.Name()}, nil
}
