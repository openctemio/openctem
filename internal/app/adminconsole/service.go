// Package adminconsole implements human login to the platform admin console
// (RFC-022, docs/rfcs/RFC-022-platform-admin-console.md): password plus a
// mandatory TOTP second factor, backed by server-side sessions.
//
// API-key authentication for admins (CLI, automation) is separate and
// unchanged; a session and an API key both resolve to the same AdminUser, so
// every /api/v1/admin route and role guard works for either.
package adminconsole

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/openctemio/api/pkg/crypto"
	"github.com/openctemio/api/pkg/domain/admin"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/totp"
)

// Audit actions written to admin_audit_logs.
const (
	ActionLogin            = "console.login"
	ActionLoginFailed      = "console.login_failed"
	ActionMFAEnrolled      = "console.mfa_enrolled"
	ActionMFAFailed        = "console.mfa_failed"
	ActionLogout           = "console.logout"
	ActionPasswordSet      = "console.password_set"
	ActionCredentialsReset = "console.credentials_reset"
)

// Issuer is the account label shown in authenticator apps.
const Issuer = "OpenCTEM Admin"

// touchInterval throttles last_seen_at writes to one per minute per session.
const touchInterval = time.Minute

// LoginStatus tells the caller what the second step is.
type LoginStatus string

const (
	// StatusMFARequired: enter the code from the enrolled authenticator.
	StatusMFARequired LoginStatus = "mfa_required"
	// StatusMFAEnrollment: MFA is not set up yet; scan the secret, then enter a code.
	StatusMFAEnrollment LoginStatus = "mfa_enrollment_required"
)

// LoginResult is the outcome of a successful password step.
type LoginResult struct {
	Status LoginStatus
	// PendingToken authorizes only the TOTP step; it expires after PendingMFATTL.
	PendingToken string
	// OTPAuthURI and Secret are set only for StatusMFAEnrollment.
	OTPAuthURI string
	Secret     string
}

// ClientInfo is recorded on sessions and audit entries.
type ClientInfo struct {
	IP        string
	UserAgent string
}

// Service implements console authentication.
type Service struct {
	admins    admin.Repository
	console   admin.ConsoleRepository
	audit     admin.AuditLogRepository
	encryptor crypto.Encryptor
	log       *logger.Logger
	now       func() time.Time
	// dummyHash keeps the password step's timing similar when the email is
	// unknown or has no password, so response time does not reveal either.
	dummyHash []byte
}

// NewService creates the console authentication service.
func NewService(
	admins admin.Repository,
	console admin.ConsoleRepository,
	audit admin.AuditLogRepository,
	encryptor crypto.Encryptor,
	log *logger.Logger,
) *Service {
	dummy, _ := bcrypt.GenerateFromPassword([]byte("timing-equalizer-not-a-password"), admin.BcryptCost)
	if _, noop := encryptor.(*crypto.NoOpEncryptor); noop {
		log.Warn("APP_ENCRYPTION_KEY is not set: admin console TOTP secrets will be stored unencrypted (development only)")
	}
	return &Service{
		admins:    admins,
		console:   console,
		audit:     audit,
		encryptor: encryptor,
		log:       log.With("service", "admin_console"),
		now:       time.Now,
		dummyHash: dummy,
	}
}

func newToken() (token, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generate session token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(buf)
	return token, hashToken(token), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Login performs the password step. Every failure returns
// admin.ErrInvalidCredentials, whether the email is unknown, the account is
// inactive or locked, no password is set, or the password is wrong, so the
// response never tells an attacker which one it was. A locked account is not
// password-checked at all, so lockout cannot be used to confirm a guess.
func (s *Service) Login(ctx context.Context, email, password string, client ClientInfo) (*LoginResult, error) {
	// Sessions carry an absolute expiry; sweep dead rows here (an indexed delete)
	// instead of running a dedicated background job for a low-volume table.
	if _, err := s.console.DeleteExpiredSessions(ctx, s.now()); err != nil {
		s.log.Warn("purge expired admin sessions", "error", err)
	}

	a, err := s.admins.GetByEmail(ctx, email)
	if err != nil {
		if admin.IsAdminNotFound(err) {
			_ = bcrypt.CompareHashAndPassword(s.dummyHash, []byte(password))
			return nil, admin.ErrInvalidCredentials
		}
		return nil, fmt.Errorf("login: %w", err)
	}
	if !a.IsActive() || a.IsLocked() {
		_ = bcrypt.CompareHashAndPassword(s.dummyHash, []byte(password))
		s.record(ctx, a, ActionLoginFailed, client, "inactive or locked")
		return nil, admin.ErrInvalidCredentials
	}

	creds, err := s.console.GetCredentials(ctx, a.ID())
	if err != nil && !errors.Is(err, admin.ErrCredentialsNotFound) {
		return nil, fmt.Errorf("login: %w", err)
	}
	if creds == nil || creds.PasswordHash == "" {
		_ = bcrypt.CompareHashAndPassword(s.dummyHash, []byte(password))
		s.record(ctx, a, ActionLoginFailed, client, "no console password set")
		return nil, admin.ErrInvalidCredentials
	}
	if bcrypt.CompareHashAndPassword([]byte(creds.PasswordHash), []byte(password)) != nil {
		s.recordFailure(ctx, a, client, ActionLoginFailed, "wrong password")
		return nil, admin.ErrInvalidCredentials
	}

	pending, err := s.newSession(ctx, a.ID(), false, admin.PendingMFATTL, client)
	if err != nil {
		return nil, err
	}
	if creds.MFAEnabled {
		return &LoginResult{Status: StatusMFARequired, PendingToken: pending}, nil
	}

	// First login: issue a fresh secret. It only becomes active once a code
	// from it is verified, so abandoning enrollment leaves MFA disabled.
	secret, err := totp.GenerateSecret()
	if err != nil {
		return nil, err
	}
	enc, err := s.encryptor.EncryptString(secret)
	if err != nil {
		return nil, fmt.Errorf("encrypt mfa secret: %w", err)
	}
	creds.MFASecretEncrypted = enc
	creds.MFAEnabled = false
	creds.MFALastStep = 0
	if err := s.console.SaveCredentials(ctx, creds); err != nil {
		return nil, err
	}
	return &LoginResult{
		Status:       StatusMFAEnrollment,
		PendingToken: pending,
		OTPAuthURI:   totp.URI(secret, Issuer, a.Email()),
		Secret:       secret,
	}, nil
}

// VerifyMFA completes a login: it checks the TOTP code against the pending
// session and, on success, replaces it with a verified session. Wrong codes
// count toward the same lockout as wrong passwords.
func (s *Service) VerifyMFA(ctx context.Context, pendingToken, code string, client ClientInfo) (string, *admin.AdminUser, error) {
	if pendingToken == "" {
		return "", nil, admin.ErrInvalidMFACode
	}
	sess, err := s.console.GetSessionByTokenHash(ctx, hashToken(pendingToken))
	if err != nil {
		if errors.Is(err, admin.ErrSessionNotFound) {
			return "", nil, admin.ErrInvalidMFACode
		}
		return "", nil, err
	}
	now := s.now()
	if sess.MFAVerified || !now.Before(sess.ExpiresAt) {
		return "", nil, admin.ErrInvalidMFACode
	}
	a, err := s.admins.GetByID(ctx, sess.AdminID)
	if err != nil {
		return "", nil, admin.ErrInvalidMFACode
	}
	if !a.IsActive() || a.IsLocked() {
		_ = s.console.DeleteSession(ctx, sess.ID)
		return "", nil, admin.ErrInvalidMFACode
	}
	creds, err := s.console.GetCredentials(ctx, a.ID())
	if err != nil || creds.MFASecretEncrypted == "" {
		return "", nil, admin.ErrInvalidMFACode
	}
	secret, err := s.encryptor.DecryptString(creds.MFASecretEncrypted)
	if err != nil {
		return "", nil, fmt.Errorf("decrypt mfa secret: %w", err)
	}

	step, ok := totp.Verify(secret, code, now)
	if ok {
		// Reject a code whose step was already used (replay), atomically.
		ok, err = s.console.AdvanceMFAStep(ctx, a.ID(), step)
		if err != nil {
			return "", nil, err
		}
	}
	if !ok {
		s.recordFailure(ctx, a, client, ActionMFAFailed, "wrong or reused code")
		return "", nil, admin.ErrInvalidMFACode
	}

	if !creds.MFAEnabled {
		creds.MFAEnabled = true
		creds.MFALastStep = step
		if err := s.console.SaveCredentials(ctx, creds); err != nil {
			return "", nil, err
		}
		s.record(ctx, a, ActionMFAEnrolled, client, "")
	}
	if a.FailedLoginCount() > 0 {
		a.ResetFailedLogins()
		if err := s.admins.Update(ctx, a); err != nil {
			s.log.Warn("reset admin failed-login counter", "error", err)
		}
	}

	_ = s.console.DeleteSession(ctx, sess.ID)
	token, err := s.newSession(ctx, a.ID(), true, admin.SessionTTL, client)
	if err != nil {
		return "", nil, err
	}
	s.record(ctx, a, ActionLogin, client, "")
	return token, a, nil
}

// Authenticate resolves a verified session token to its admin. It is what the
// admin auth middleware calls for cookie-authenticated requests.
func (s *Service) Authenticate(ctx context.Context, token string) (*admin.AdminUser, error) {
	if token == "" {
		return nil, admin.ErrSessionNotFound
	}
	sess, err := s.console.GetSessionByTokenHash(ctx, hashToken(token))
	if err != nil {
		return nil, err
	}
	now := s.now()
	if !sess.Usable(now) {
		_ = s.console.DeleteSession(ctx, sess.ID)
		return nil, admin.ErrSessionNotFound
	}
	a, err := s.admins.GetByID(ctx, sess.AdminID)
	if err != nil {
		return nil, admin.ErrSessionNotFound
	}
	if !a.IsActive() || a.IsLocked() {
		_ = s.console.DeleteSessionsForAdmin(ctx, a.ID())
		return nil, admin.ErrSessionNotFound
	}
	if now.Sub(sess.LastSeenAt) >= touchInterval {
		if err := s.console.TouchSession(ctx, sess.ID, now); err != nil {
			s.log.Warn("touch admin session", "error", err)
		}
	}
	return a, nil
}

// Logout ends the session behind token. Unknown tokens are ignored.
func (s *Service) Logout(ctx context.Context, token string, client ClientInfo) error {
	if token == "" {
		return nil
	}
	sess, err := s.console.GetSessionByTokenHash(ctx, hashToken(token))
	if err != nil {
		if errors.Is(err, admin.ErrSessionNotFound) {
			return nil
		}
		return err
	}
	if err := s.console.DeleteSession(ctx, sess.ID); err != nil {
		return err
	}
	if a, err := s.admins.GetByID(ctx, sess.AdminID); err == nil {
		s.record(ctx, a, ActionLogout, client, "")
	}
	return nil
}

// SetPassword sets or changes an admin's own console password. When a password
// already exists the current one is required, unless the caller authenticated
// with the admin's API key (requireCurrent=false): the key already grants full
// admin access, and it is the bootstrap path for the first password. Every
// existing session of the admin is ended.
func (s *Service) SetPassword(ctx context.Context, a *admin.AdminUser, current, next string, requireCurrent bool, client ClientInfo) error {
	if len(next) < admin.MinPasswordLength || len(next) > admin.MaxPasswordLength {
		return admin.ErrWeakPassword
	}
	creds, err := s.console.GetCredentials(ctx, a.ID())
	if err != nil && !errors.Is(err, admin.ErrCredentialsNotFound) {
		return err
	}
	if creds == nil {
		creds = &admin.Credentials{AdminID: a.ID()}
	}
	if requireCurrent && creds.PasswordHash != "" &&
		bcrypt.CompareHashAndPassword([]byte(creds.PasswordHash), []byte(current)) != nil {
		s.recordFailure(ctx, a, client, ActionPasswordSet, "wrong current password")
		return admin.ErrCurrentPassword
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(next), admin.BcryptCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	now := s.now()
	creds.PasswordHash = string(hash)
	creds.PasswordChangedAt = &now
	if err := s.console.SaveCredentials(ctx, creds); err != nil {
		return err
	}
	if err := s.console.DeleteSessionsForAdmin(ctx, a.ID()); err != nil {
		return err
	}
	s.record(ctx, a, ActionPasswordSet, client, "")
	return nil
}

// ResetCredentials removes another admin's password and MFA and ends their
// sessions (for a lost authenticator). They set a new password with their API
// key and re-enroll MFA on next login. actor is the super admin doing it.
func (s *Service) ResetCredentials(ctx context.Context, actor *admin.AdminUser, targetID shared.ID, client ClientInfo) error {
	target, err := s.admins.GetByID(ctx, targetID)
	if err != nil {
		return err
	}
	if err := s.console.DeleteSessionsForAdmin(ctx, target.ID()); err != nil {
		return err
	}
	if err := s.console.DeleteCredentials(ctx, target.ID()); err != nil {
		return err
	}
	if s.audit != nil {
		entry := admin.NewAuditLogBuilder(actor, ActionCredentialsReset).
			Resource("admin_user", ptr(target.ID()), target.Email()).
			Context(client.IP, client.UserAgent).
			Build()
		if err := s.audit.Create(ctx, entry); err != nil {
			s.log.Warn("audit console credentials reset", "error", err)
		}
	}
	return nil
}

// PurgeExpiredSessions deletes sessions past their absolute expiry.
func (s *Service) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	return s.console.DeleteExpiredSessions(ctx, s.now())
}

func (s *Service) newSession(ctx context.Context, adminID shared.ID, verified bool, ttl time.Duration, client ClientInfo) (string, error) {
	token, hash, err := newToken()
	if err != nil {
		return "", err
	}
	now := s.now()
	err = s.console.CreateSession(ctx, &admin.Session{
		ID:          shared.NewID(),
		AdminID:     adminID,
		TokenHash:   hash,
		MFAVerified: verified,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
		LastSeenAt:  now,
		IP:          client.IP,
		UserAgent:   truncate(client.UserAgent, 512),
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

// recordFailure counts a failed factor toward lockout and audits it.
func (s *Service) recordFailure(ctx context.Context, a *admin.AdminUser, client ClientInfo, action, reason string) {
	a.RecordFailedLogin(client.IP)
	if err := s.admins.Update(ctx, a); err != nil {
		s.log.Warn("record admin failed login", "error", err)
	}
	if a.IsLocked() {
		// A locked account keeps no live sessions.
		if err := s.console.DeleteSessionsForAdmin(ctx, a.ID()); err != nil {
			s.log.Warn("end sessions of locked admin", "error", err)
		}
	}
	s.record(ctx, a, action, client, reason)
}

func (s *Service) record(ctx context.Context, a *admin.AdminUser, action string, client ClientInfo, reason string) {
	if s.audit == nil {
		return
	}
	b := admin.NewAuditLogBuilder(a, action).Context(client.IP, client.UserAgent)
	if reason != "" {
		b = b.Error(reason)
	}
	if err := s.audit.Create(ctx, b.Build()); err != nil {
		s.log.Warn("audit admin console event", "action", action, "error", err)
	}
}

func ptr[T any](v T) *T { return &v }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
