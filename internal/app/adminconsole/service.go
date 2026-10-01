// Package adminconsole implements the platform admin console session
// (RFC-022, docs/rfcs/RFC-022-platform-admin-console.md).
//
// Following Tenable Security Center, a platform administrator is a normal user
// account with a system-level role: it signs in on the same /login page as
// everyone else, then this service opens a console session after a mandatory
// TOTP code. admin_users holds the role, the TOTP secret and the audit trail,
// linked to the users row. Only a password sign-in can open the console: no
// organization's SSO/SAML identity provider can authenticate an administrator.
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
	ActionAdminProvisioned = "console.admin_provisioned"
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
	accounts  AccountDirectory
	now       func() time.Time
}

// SignedInUser is the user behind a normal (/login) sign-in session.
type SignedInUser struct {
	UserID shared.ID
	Email  string
	Name   string
	// Active is false for suspended or deactivated user accounts.
	Active bool
	// PasswordSignIn is true when the session came from the local email and
	// password form, not from SSO, SAML or a social provider.
	PasswordSignIn bool
}

// AccountDirectory is the tenant-user side the console needs: who is signed in
// behind a refresh token, and creating an account for a new administrator.
// Implemented over the auth service in the composition root.
type AccountDirectory interface {
	// SignedInUser validates a refresh token (without rotating it).
	SignedInUser(ctx context.Context, refreshToken string) (*SignedInUser, error)
	// ProvisionAccount returns the user with this email, creating a local account
	// with a temporary password when none exists (temporaryPassword is then set).
	ProvisionAccount(ctx context.Context, email, name string) (userID shared.ID, temporaryPassword string, err error)
	// EndSignIn revokes the /login session behind a refresh token.
	EndSignIn(ctx context.Context, refreshToken string) error
}

// NewService creates the console authentication service.
func NewService(
	admins admin.Repository,
	console admin.ConsoleRepository,
	audit admin.AuditLogRepository,
	encryptor crypto.Encryptor,
	accounts AccountDirectory,
	log *logger.Logger,
) *Service {
	if _, noop := encryptor.(*crypto.NoOpEncryptor); noop {
		log.Warn("APP_ENCRYPTION_KEY is not set: admin console TOTP secrets will be stored unencrypted (development only)")
	}
	return &Service{
		admins:    admins,
		console:   console,
		audit:     audit,
		encryptor: encryptor,
		accounts:  accounts,
		log:       log.With("service", "admin_console"),
		now:       time.Now,
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

// Start opens the TOTP step of a console session for the user signed in behind
// refreshToken (their normal /login session). It succeeds only when that
// session came from the password form and the user is linked to an active,
// unlocked administrator. On first use it issues a fresh TOTP secret to
// enroll; the secret becomes active only once a code from it is verified.
func (s *Service) Start(ctx context.Context, refreshToken string, client ClientInfo) (*LoginResult, error) {
	// Sessions carry an absolute expiry; sweep dead rows here (an indexed delete)
	// instead of running a dedicated background job for a low-volume table.
	if _, err := s.console.DeleteExpiredSessions(ctx, s.now()); err != nil {
		s.log.Warn("purge expired admin sessions", "error", err)
	}

	if refreshToken == "" {
		return nil, admin.ErrNotSignedIn
	}
	u, err := s.accounts.SignedInUser(ctx, refreshToken)
	if err != nil {
		return nil, admin.ErrNotSignedIn
	}
	if !u.Active {
		return nil, admin.ErrNotSignedIn
	}
	a, err := s.admins.GetByUserID(ctx, u.UserID)
	if err != nil {
		if admin.IsAdminNotFound(err) {
			return nil, admin.ErrNotPlatformAdmin
		}
		return nil, fmt.Errorf("start console session: %w", err)
	}
	if !u.PasswordSignIn {
		// An organization's IdP must never be able to authenticate a platform
		// administrator.
		s.record(ctx, a, ActionLoginFailed, client, "not a password sign-in")
		return nil, admin.ErrPasswordSignInRequired
	}
	if !a.IsActive() || a.IsLocked() {
		s.record(ctx, a, ActionLoginFailed, client, "inactive or locked")
		return nil, admin.ErrNotPlatformAdmin
	}

	creds, err := s.console.GetCredentials(ctx, a.ID())
	if err != nil && !errors.Is(err, admin.ErrCredentialsNotFound) {
		return nil, fmt.Errorf("start console session: %w", err)
	}
	if creds == nil {
		creds = &admin.Credentials{AdminID: a.ID()}
	}

	pending, err := s.newSession(ctx, a.ID(), false, admin.PendingMFATTL, client)
	if err != nil {
		return nil, err
	}
	if creds.MFAEnabled {
		return &LoginResult{Status: StatusMFARequired, PendingToken: pending}, nil
	}

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

// Logout ends the console session behind token and, when refreshToken is set,
// the /login session it was opened from, so signing out of the console signs
// the administrator out completely. Unknown tokens are ignored.
func (s *Service) Logout(ctx context.Context, token, refreshToken string, client ClientInfo) error {
	if refreshToken != "" {
		if err := s.accounts.EndSignIn(ctx, refreshToken); err != nil {
			s.log.Debug("end sign-in on console logout", "error", err)
		}
	}
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

// ProvisionAdmin makes the person with this email a platform administrator
// (super admin action). An existing user account is linked (refused if it
// belongs to an organization); otherwise a local account is created and its
// temporary password returned once. The administrator then signs in on the
// normal /login page and enrolls TOTP when opening the console.
func (s *Service) ProvisionAdmin(ctx context.Context, actor *admin.AdminUser, email, name string, role admin.AdminRole, client ClientInfo) (*admin.AdminUser, string, error) {
	if _, err := s.admins.GetByEmail(ctx, email); err == nil {
		return nil, "", admin.ErrAdminAlreadyExists
	}
	var creatorID *shared.ID
	if actor != nil {
		id := actor.ID()
		creatorID = &id
	}
	// The API key is not returned: human administrators sign in with their user
	// account. Rows need a key hash, so one is generated and discarded.
	a, _, err := admin.NewAdminUser(email, name, role, creatorID)
	if err != nil {
		return nil, "", err
	}
	userID, temp, err := s.accounts.ProvisionAccount(ctx, a.Email(), a.Name())
	if err != nil {
		return nil, "", fmt.Errorf("provision user account: %w", err)
	}
	if err := s.admins.Create(ctx, a); err != nil {
		return nil, "", err
	}
	if err := s.admins.LinkUser(ctx, a.ID(), userID); err != nil {
		// Compensate: do not leave an unlinked administrator behind.
		if derr := s.admins.Delete(ctx, a.ID()); derr != nil {
			s.log.Error("remove unlinked administrator", "error", derr)
		}
		return nil, "", err
	}
	if s.audit != nil && actor != nil {
		entry := admin.NewAuditLogBuilder(actor, ActionAdminProvisioned).
			Resource("admin_user", ptr(a.ID()), a.Email()).
			Context(client.IP, client.UserAgent).
			Build()
		if err := s.audit.Create(ctx, entry); err != nil {
			s.log.Warn("audit admin provisioning", "error", err)
		}
	}
	return a, temp, nil
}

// ResetCredentials removes another administrator's second factor and ends
// their console sessions (for a lost authenticator); they enroll a new one the
// next time they open the console. Their password is their user account's and
// is reset through the normal forgot-password flow. actor is the super admin.
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
