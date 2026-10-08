// Package platformuser holds the platform admin console's support actions on
// one account (Console > Users, RFC-022 revision 14): revoke its sessions,
// unlock it, send a password reset, resend email verification.
//
// They act on the account only, never on what an organization holds, and
// never hand the administrator a credential: links go to the account's own
// mailbox. Platform administrator accounts are refused (they are managed in
// Security > Administrators), as are erased accounts.
package platformuser

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/password"
)

var (
	// ErrPlatformAdmin: the account is a platform administrator.
	ErrPlatformAdmin = fmt.Errorf("%w: platform administrator accounts are managed in Security > Administrators", shared.ErrConflict)
	// ErrErased: the account was erased.
	ErrErased = fmt.Errorf("%w: the account was erased", shared.ErrConflict)
	// ErrNotLocal: the account signs in through an identity provider.
	ErrNotLocal = fmt.Errorf("%w: the account signs in through an identity provider and has no password", shared.ErrConflict)
	// ErrAlreadyVerified: the email is already verified.
	ErrAlreadyVerified = fmt.Errorf("%w: the email is already verified", shared.ErrConflict)
	// ErrNotLocked: the account is not locked.
	ErrNotLocked = fmt.Errorf("%w: the account is not locked", shared.ErrConflict)
	// ErrEmailUnavailable: no email can be sent from this installation.
	ErrEmailUnavailable = errors.New("email is not configured on this installation")
)

// SessionRevoker ends every session of an account.
type SessionRevoker interface {
	RevokeAllSessions(ctx context.Context, userID, exceptSessionID string) error
}

// ResetIssuer issues a password reset token (the forgot-password flow).
type ResetIssuer interface {
	ForgotPassword(ctx context.Context, input auth.ForgotPasswordInput) (*auth.ForgotPasswordResult, error)
}

// Mailer sends the account's own links.
type Mailer interface {
	IsConfigured() bool
	SendPasswordResetEmail(ctx context.Context, userEmail, userName, token string, expiresIn time.Duration, ipAddress string) error
	SendVerificationEmail(ctx context.Context, userEmail, userName, token string, expiresIn time.Duration) error
}

// AccountStates reports whether an account is linked to a platform
// administrator and whether it was erased.
type AccountStates interface {
	AccountState(ctx context.Context, id shared.ID) (isAdmin, erased bool, err error)
	// ClearLockout clears the failed sign-in count and lockout (the user
	// repository's Update deliberately never writes those columns).
	ClearLockout(ctx context.Context, id shared.ID) error
}

// Durations of the links the actions send.
type Durations struct {
	PasswordReset     time.Duration
	EmailVerification time.Duration
}

// Service runs the support actions.
type Service struct {
	users     user.Repository
	sessions  SessionRevoker
	resets    ResetIssuer
	mailer    Mailer
	states    AccountStates
	durations Durations
}

// NewService creates the service. Any dependency may be nil; the action that
// needs it then answers ErrEmailUnavailable or an error.
func NewService(users user.Repository, sessions SessionRevoker, resets ResetIssuer, mailer Mailer, states AccountStates, d Durations) *Service {
	return &Service{users: users, sessions: sessions, resets: resets, mailer: mailer, states: states, durations: d}
}

// target loads the account and refuses the ones the console must not touch.
func (s *Service) target(ctx context.Context, id shared.ID) (*user.User, error) {
	isAdmin, erased, err := s.states.AccountState(ctx, id)
	if err != nil {
		return nil, err
	}
	if isAdmin {
		return nil, ErrPlatformAdmin
	}
	if erased {
		return nil, ErrErased
	}
	return s.users.GetByID(ctx, id)
}

// RevokeSessions signs the account out everywhere (every organization, every
// device). Its permission caches are cleared with the sessions.
func (s *Service) RevokeSessions(ctx context.Context, id shared.ID) error {
	if _, err := s.target(ctx, id); err != nil {
		return err
	}
	if s.sessions == nil {
		return errors.New("session service not configured")
	}
	if err := s.sessions.RevokeAllSessions(ctx, id.String(), ""); err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}
	return nil
}

// Unlock clears a lockout from failed sign-ins.
func (s *Service) Unlock(ctx context.Context, id shared.ID) error {
	u, err := s.target(ctx, id)
	if err != nil {
		return err
	}
	if !u.IsLocked() && u.FailedLoginAttempts() == 0 {
		return ErrNotLocked
	}
	return s.states.ClearLockout(ctx, id)
}

// SendPasswordReset emails the account a password reset link (the same link
// and lifetime as forgot-password). The administrator never sees it.
func (s *Service) SendPasswordReset(ctx context.Context, id shared.ID) error {
	u, err := s.target(ctx, id)
	if err != nil {
		return err
	}
	if !u.IsLocalUser() {
		return ErrNotLocal
	}
	if s.mailer == nil || !s.mailer.IsConfigured() || s.resets == nil {
		return ErrEmailUnavailable
	}
	res, err := s.resets.ForgotPassword(ctx, auth.ForgotPasswordInput{Email: u.Email()})
	if err != nil {
		return fmt.Errorf("issue reset: %w", err)
	}
	if res == nil || res.Token == "" {
		// The forgot-password flow refused (for example the email's domain
		// lost its verified owner): nothing was issued.
		return fmt.Errorf("%w: no reset link can be sent to this address", shared.ErrConflict)
	}
	return s.mailer.SendPasswordResetEmail(ctx, u.Email(), u.Name(), res.Token, s.durations.PasswordReset, "")
}

// ResendVerification emails a fresh verification link to an unverified
// account; the previous link stops working.
func (s *Service) ResendVerification(ctx context.Context, id shared.ID) error {
	u, err := s.target(ctx, id)
	if err != nil {
		return err
	}
	if u.EmailVerified() {
		return ErrAlreadyVerified
	}
	if s.mailer == nil || !s.mailer.IsConfigured() {
		return ErrEmailUnavailable
	}
	token, err := password.GenerateVerificationToken()
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}
	// Only the hash is stored; the raw token is emailed.
	u.SetEmailVerificationToken(crypto.HashToken(token), time.Now().Add(s.durations.EmailVerification))
	if err := s.users.Update(ctx, u); err != nil {
		return fmt.Errorf("store token: %w", err)
	}
	return s.mailer.SendVerificationEmail(ctx, u.Email(), u.Name(), token, s.durations.EmailVerification)
}
