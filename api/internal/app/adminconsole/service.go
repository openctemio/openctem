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
// The console session is the only way to authenticate as an administrator:
// there are no admin API keys, so every admin action has passed the TOTP step.
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

	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/totp"
)

// Audit actions written to admin_audit_logs.
const (
	ActionLogin            = "console.login"
	ActionLoginFailed      = "console.login_failed"
	ActionMFAEnrolled      = "console.mfa_enrolled"
	ActionMFAFailed        = "console.mfa_failed"
	ActionLogout           = "console.logout"
	ActionAdminProvisioned = "console.admin_provisioned"
	ActionPasswordChanged  = "console.password_changed"
	ActionCredentialsReset = "console.credentials_reset"
	ActionStepUp           = "console.step_up"
	ActionStepUpFailed     = "console.step_up_failed"
)

// StatusSignedIn is the IdP callback outcome when the IdP's MFA was trusted
// and a verified session was issued directly.
const StatusSignedIn LoginStatus = "signed_in"

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

	// Platform identity provider (RFC-022 revision 4); nil when not wired.
	idps admin.PlatformIdPRepository
	oidc OIDCProvider
	// notifier tells the other administrators about a break-glass sign-in.
	notifier BreakGlassNotifier
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
	// CreateAccount creates a new local account with a temporary password. It
	// returns admin.ErrEmailHasAccount when the email already has an account:
	// an existing account is never linked, because whoever registered it (with
	// self-registration, possibly an attacker who guessed the email) owns its
	// password and would become the administrator.
	CreateAccount(ctx context.Context, email, name string) (userID shared.ID, temporaryPassword string, err error)
	// AccountActive reports whether the linked account can still sign in.
	AccountActive(ctx context.Context, userID shared.ID) (bool, error)
	// ChangePassword changes the account's password after checking the current
	// one, and ends all of its /login sessions.
	ChangePassword(ctx context.Context, userID shared.ID, current, next string) error
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
	if err := s.checkPasswordPathAllowed(ctx, a); err != nil {
		if errors.Is(err, admin.ErrIdPSignInRequired) {
			s.record(ctx, a, ActionLoginFailed, client, "identity provider sign-in required")
		}
		return nil, err
	}
	return s.beginSecondFactor(ctx, a, admin.AuthMethodPassword, client)
}

// checkPasswordPathAllowed refuses the local password path for a
// non-break-glass administrator while "require IdP" is in force.
func (s *Service) checkPasswordPathAllowed(ctx context.Context, a *admin.AdminUser) error {
	if a.IsBreakGlass() {
		return nil
	}
	p, err := s.platformIdP(ctx)
	if err != nil {
		return fmt.Errorf("read sign-in policy: %w", err)
	}
	if p.Enforced() {
		return admin.ErrIdPSignInRequired
	}
	return nil
}

// beginSecondFactor issues a pending session for the TOTP step and, on first
// use, a fresh TOTP secret to enroll. authMethod records how the first factor
// was proven and carries over to the verified session.
func (s *Service) beginSecondFactor(ctx context.Context, a *admin.AdminUser, authMethod string, client ClientInfo) (*LoginResult, error) {
	creds, err := s.console.GetCredentials(ctx, a.ID())
	if err != nil && !errors.Is(err, admin.ErrCredentialsNotFound) {
		return nil, fmt.Errorf("start console session: %w", err)
	}
	if creds == nil {
		creds = &admin.Credentials{AdminID: a.ID()}
	}

	pending, err := s.newSession(ctx, a.ID(), false, admin.PendingMFATTL, authMethod, client)
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
	authMethod := sessionAuthMethod(sess)
	if authMethod == admin.AuthMethodPassword {
		// "require IdP" may have been turned on after the password step.
		if err := s.checkPasswordPathAllowed(ctx, a); err != nil {
			_ = s.console.DeleteSession(ctx, sess.ID)
			return "", nil, err
		}
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
	token, err := s.openVerifiedSession(ctx, a, authMethod, client, "")
	if err != nil {
		return "", nil, err
	}
	return token, a, nil
}

// StepUp re-confirms the signed-in administrator with a fresh code from the
// console authenticator before an irreversible action (purpose names it in the
// admin audit log). The console session alone is not enough: it may be hours
// old, or opened through the platform identity provider without this
// authenticator. A code can be used once (the same replay guard as sign-in), and
// a wrong code counts toward the same lockout as a wrong password.
func (s *Service) StepUp(ctx context.Context, a *admin.AdminUser, code, purpose string, client ClientInfo) error {
	if a == nil {
		return admin.ErrInvalidMFACode
	}
	creds, err := s.console.GetCredentials(ctx, a.ID())
	if err != nil || !creds.MFAEnabled || creds.MFASecretEncrypted == "" {
		return admin.ErrStepUpUnavailable
	}
	secret, err := s.encryptor.DecryptString(creds.MFASecretEncrypted)
	if err != nil {
		return fmt.Errorf("decrypt mfa secret: %w", err)
	}
	step, ok := totp.Verify(secret, code, s.now())
	if ok {
		ok, err = s.console.AdvanceMFAStep(ctx, a.ID(), step)
		if err != nil {
			return err
		}
	}
	if !ok {
		s.recordFailure(ctx, a, client, ActionStepUpFailed, "wrong or reused code for "+purpose)
		return admin.ErrInvalidMFACode
	}
	s.recordNote(ctx, a, ActionStepUp, client, purpose)
	return nil
}

// openVerifiedSession issues a verified console session and records the
// sign-in. A break-glass sign-in is alerted every time.
func (s *Service) openVerifiedSession(ctx context.Context, a *admin.AdminUser, authMethod string, client ClientInfo, note string) (string, error) {
	token, err := s.newSession(ctx, a.ID(), true, admin.SessionTTL, authMethod, client)
	if err != nil {
		return "", err
	}
	if err := s.admins.RecordUsage(ctx, a.ID(), client.IP); err != nil {
		s.log.Warn("record admin console usage", "error", err)
	}
	s.recordNote(ctx, a, ActionLogin, client, note)
	if a.IsBreakGlass() {
		s.alertBreakGlass(ctx, a, client)
	}
	return token, nil
}

func sessionAuthMethod(sess *admin.Session) string {
	if sess.AuthMethod == admin.AuthMethodIdP {
		return admin.AuthMethodIdP
	}
	return admin.AuthMethodPassword
}

// Authenticate resolves a verified session token to its admin. It is what the
// admin auth middleware calls for cookie-authenticated requests.
func (s *Service) Authenticate(ctx context.Context, token string) (*admin.AdminUser, error) {
	a, _, err := s.AuthenticateSession(ctx, token)
	return a, err
}

// AuthenticateSession is Authenticate that also returns the session (how it
// was authenticated), for the password-change gate.
func (s *Service) AuthenticateSession(ctx context.Context, token string) (*admin.AdminUser, *admin.Session, error) {
	if token == "" {
		return nil, nil, admin.ErrSessionNotFound
	}
	sess, err := s.console.GetSessionByTokenHash(ctx, hashToken(token))
	if err != nil {
		return nil, nil, err
	}
	now := s.now()
	if !sess.Usable(now) {
		_ = s.console.DeleteSession(ctx, sess.ID)
		return nil, nil, admin.ErrSessionNotFound
	}
	a, err := s.admins.GetByID(ctx, sess.AdminID)
	if err != nil {
		return nil, nil, admin.ErrSessionNotFound
	}
	if !a.IsActive() || a.IsLocked() || !s.accountActive(ctx, a) {
		_ = s.console.DeleteSessionsForAdmin(ctx, a.ID())
		return nil, nil, admin.ErrSessionNotFound
	}
	if now.Sub(sess.LastSeenAt) >= touchInterval {
		if err := s.console.TouchSession(ctx, sess.ID, now); err != nil {
			s.log.Warn("touch admin session", "error", err)
		}
	}
	sess.AuthMethod = sessionAuthMethod(sess)
	return a, sess, nil
}

// accountActive reports whether the administrator's linked account can still
// sign in. Suspending or deactivating the account ends console access on the
// next request, not when the console session expires. An unlinked
// administrator has no way in.
func (s *Service) accountActive(ctx context.Context, a *admin.AdminUser) bool {
	if a.UserID() == nil {
		return false
	}
	ok, err := s.accounts.AccountActive(ctx, *a.UserID())
	if err != nil {
		s.log.Warn("check administrator account", "error", err)
		return false
	}
	return ok
}

// ChangePassword changes the signed-in administrator's own password (the
// linked account's). Every /login session of the account and every console
// session of the administrator ends, so the change also evicts anyone else
// who knew the old password.
func (s *Service) ChangePassword(ctx context.Context, a *admin.AdminUser, current, next string, client ClientInfo) error {
	if a.UserID() == nil {
		return admin.ErrNotPlatformAdmin
	}
	if err := s.accounts.ChangePassword(ctx, *a.UserID(), current, next); err != nil {
		return err
	}
	if a.PasswordChangeRequired() {
		if err := s.admins.SetPasswordChangeRequired(ctx, a.ID(), false); err != nil {
			s.log.Warn("clear temporary-password marker", "error", err)
		}
	}
	if err := s.console.DeleteSessionsForAdmin(ctx, a.ID()); err != nil {
		s.log.Warn("end console sessions after password change", "error", err)
	}
	s.record(ctx, a, ActionPasswordChanged, client, "")
	return nil
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

// ProvisionAdmin makes a new platform administrator (super admin action). A
// new local account is created for the email and its temporary password
// returned once; an email that already has an account is refused
// (admin.ErrEmailHasAccount), see AccountDirectory.CreateAccount. The
// administrator then signs in on the normal /login page and enrolls TOTP when
// opening the console.
func (s *Service) ProvisionAdmin(ctx context.Context, actor *admin.AdminUser, email, name string, role admin.AdminRole, client ClientInfo) (*admin.AdminUser, string, error) {
	return s.Provision(ctx, actor, ProvisionInput{Email: email, Name: name, Role: role}, client)
}

// ProvisionInput describes a new administrator.
type ProvisionInput struct {
	Email string
	Name  string
	Role  admin.AdminRole
	// BreakGlass makes a local emergency-access administrator (super_admin only).
	BreakGlass bool
}

// Provision is ProvisionAdmin with options. The account gets a temporary
// password, so the administrator must change it after the first sign-in.
func (s *Service) Provision(ctx context.Context, actor *admin.AdminUser, in ProvisionInput, client ClientInfo) (*admin.AdminUser, string, error) {
	email, name, role := in.Email, in.Name, in.Role
	if in.BreakGlass && role != admin.AdminRoleSuperAdmin {
		return nil, "", shared.NewDomainError("VALIDATION", "a break-glass administrator must be a super admin", shared.ErrValidation)
	}
	if _, err := s.admins.GetByEmail(ctx, email); err == nil {
		return nil, "", admin.ErrAdminAlreadyExists
	}
	var creatorID *shared.ID
	if actor != nil {
		id := actor.ID()
		creatorID = &id
	}
	a, err := admin.NewAdminUser(email, name, role, creatorID)
	if err != nil {
		return nil, "", err
	}
	a.RequirePasswordChange()
	if in.BreakGlass {
		if err := a.SetBreakGlass(true); err != nil {
			return nil, "", err
		}
	}
	userID, temp, err := s.accounts.CreateAccount(ctx, a.Email(), a.Name())
	if err != nil {
		return nil, "", fmt.Errorf("create sign-in account: %w", err)
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
		b := admin.NewAuditLogBuilder(actor, ActionAdminProvisioned).
			Resource("admin_user", ptr(a.ID()), a.Email()).
			Context(client.IP, client.UserAgent)
		if a.IsBreakGlass() {
			b = b.High().Request("", "", map[string]interface{}{"break_glass": true})
		}
		entry := b.Build()
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

func (s *Service) newSession(ctx context.Context, adminID shared.ID, verified bool, ttl time.Duration, authMethod string, client ClientInfo) (string, error) {
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
		AuthMethod:  authMethod,
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
	s.writeAudit(ctx, action, b.Build())
}

// recordNote audits a successful event with an optional note (e.g. how the
// second factor was satisfied).
func (s *Service) recordNote(ctx context.Context, a *admin.AdminUser, action string, client ClientInfo, note string) {
	if s.audit == nil {
		return
	}
	b := admin.NewAuditLogBuilder(a, action).Context(client.IP, client.UserAgent)
	if note != "" {
		b = b.Request("", "", map[string]interface{}{"note": note})
	}
	s.writeAudit(ctx, action, b.Build())
}

func (s *Service) writeAudit(ctx context.Context, action string, entry *admin.AuditLog) {
	if s.audit == nil {
		return
	}
	if err := s.audit.Create(ctx, entry); err != nil {
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
