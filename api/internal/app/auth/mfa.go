package auth

// TOTP two-factor authentication for organization users who sign in with a
// local password.
//
// Login flow when a second step is needed:
//
//	POST /auth/login           password OK → MFA challenge (opaque, 5 min, no session)
//	POST /auth/mfa/verify      challenge + TOTP or recovery code → session + refresh token
//
// When an organization the user belongs to requires 2FA and the user has not
// enrolled, the challenge is an enrollment challenge instead:
//
//	POST /auth/mfa/enroll/start    challenge → secret + otpauth URI
//	POST /auth/mfa/enroll/confirm  challenge + code → recovery codes + session
//
// A challenge is never a session: it is a random string (not a JWT), stored
// only as a SHA-256 hash, accepted by nothing but the steps above, single use,
// and burned after MaxChallengeAttempts wrong codes. Wrong codes also count
// against the account's existing failed-login lockout, and the failed-login
// counter is NOT reset by a correct password alone while a second step is
// pending, so alternating "correct password, wrong code" cannot brute-force
// the code.
//
// Federated users (SSO/SAML/OAuth) never reach this code: Login refuses them
// before the password check and their identity provider owns the second
// factor. Token-mint enforcement of the organization policy skips federated
// sessions for the same reason, so they are never double-prompted.

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/crypto"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/mfa"
	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/password"
	"github.com/openctemio/openctem/api/pkg/totp"
)

// DefaultMFAIssuer is the issuer label shown by authenticator apps.
const DefaultMFAIssuer = "OpenCTEM"

// recoveryCodeAlphabet omits look-alike characters (0/o, 1/l/i).
const recoveryCodeAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// recoveryCodeLength is the number of significant characters in a recovery
// code (~49 bits of entropy), displayed as two groups of five.
const recoveryCodeLength = 10

// recoveryCodeBcryptCost keeps verifying up to ten stored hashes well under a
// second while still making an offline guess of a leaked hash expensive.
const recoveryCodeBcryptCost = 10

var (
	// ErrMFAChallengeInvalid: the challenge token is unknown, expired, used,
	// burned by too many attempts, or for a different step.
	ErrMFAChallengeInvalid = errors.New("invalid or expired two-factor verification")
	// ErrMFACodeInvalid: the code (TOTP or recovery) was wrong or already used.
	ErrMFACodeInvalid = errors.New("invalid verification code")
	// ErrMFANotEnabled: the operation needs 2FA to be on.
	ErrMFANotEnabled = errors.New("two-factor authentication is not enabled")
	// ErrMFAAlreadyEnabled: setup was requested while 2FA is already on.
	ErrMFAAlreadyEnabled = errors.New("two-factor authentication is already enabled")
	// ErrMFANoPendingSetup: enable was called without a setup first.
	ErrMFANoPendingSetup = errors.New("start two-factor setup first")
	// ErrMFANotSupported: the account signs in through an identity provider,
	// which owns the second factor.
	ErrMFANotSupported = errors.New("two-factor authentication is managed by your identity provider")
	// ErrMFAEnrollmentRequired: an organization requires 2FA and this session
	// has not been through it: a password session whose user has not enrolled,
	// or a federated session not issued by that organization's own IdP.
	ErrMFAEnrollmentRequired = errors.New("this organization requires two-factor authentication")
	// ErrMFAUnavailable: the server was started without 2FA storage.
	ErrMFAUnavailable = errors.New("two-factor authentication is not available")
)

// SecurityNotifier tells a user about security-relevant changes to their
// account. Implementations must not block: calls happen after the change is
// committed and failures are only logged.
type SecurityNotifier interface {
	NotifyMFADisabled(ctx context.Context, email, name, ipAddress string)
	NotifyRecoveryCodeUsed(ctx context.Context, email, name, ipAddress string, remaining int)
	NotifyPasswordChanged(ctx context.Context, email, name, ipAddress string)
}

// SessionRevocationStore records revoked session ids so the authentication
// middleware can refuse access tokens of a revoked session immediately
// instead of when they expire. ttl only needs to outlive the access tokens.
type SessionRevocationStore interface {
	MarkSessionRevoked(ctx context.Context, sessionID string, ttl time.Duration) error
}

// MFAChallengeInfo is returned by Login (inside LoginResult) when the password
// was right but a second step is needed. Token is shown to the client once.
type MFAChallengeInfo struct {
	Token     string
	Purpose   mfa.Purpose
	ExpiresAt time.Time
}

// MFAStatus describes a user's 2FA state for their account page.
type MFAStatus struct {
	// Supported is false for federated accounts (2FA is the IdP's job).
	Supported              bool       `json:"supported"`
	Enabled                bool       `json:"enabled"`
	EnabledAt              *time.Time `json:"enabled_at,omitempty"`
	RecoveryCodesRemaining int        `json:"recovery_codes_remaining"`
	// RequiredByOrganization is true when any organization the user belongs
	// to requires 2FA.
	RequiredByOrganization bool `json:"required_by_organization"`
}

// MFASetup is a freshly generated secret awaiting confirmation.
type MFASetup struct {
	Secret     string `json:"secret"`
	OTPAuthURI string `json:"otpauth_uri"`
}

// VerifyMFAInput is the second login step.
type VerifyMFAInput struct {
	Token        string
	Code         string
	RecoveryCode string
	IPAddress    string
	UserAgent    string
}

// CompleteMFAEnrollmentInput confirms an enrollment started from a login
// enrollment challenge.
type CompleteMFAEnrollmentInput struct {
	Token     string
	Code      string
	IPAddress string
	UserAgent string
}

// SetMFA enables two-factor authentication. Without it Login never asks for a
// second step and the /users/me/2fa endpoints report ErrMFAUnavailable.
func (s *AuthService) SetMFA(repo mfa.Repository, encryptor crypto.Encryptor, issuer string) {
	s.mfaRepo = repo
	s.mfaEncryptor = encryptor
	if strings.TrimSpace(issuer) == "" {
		issuer = DefaultMFAIssuer
	}
	s.mfaIssuer = issuer
	s.recoveryHasher = password.New(password.WithCost(recoveryCodeBcryptCost))
}

// SetSecurityNotifier wires the account security e-mails.
func (s *AuthService) SetSecurityNotifier(n SecurityNotifier) {
	s.securityNotifier = n
}

// SetSessionRevocationStore wires immediate access-token revocation.
func (s *AuthService) SetSessionRevocationStore(store SessionRevocationStore) {
	s.revocations = store
}

func (s *AuthService) mfaEnabled() bool { return s.mfaRepo != nil && s.mfaEncryptor != nil }

// ---------------------------------------------------------------------------
// Login integration
// ---------------------------------------------------------------------------

// loginMFAChallenge decides whether a password login needs a second step and,
// if so, issues the challenge. nil means the login can complete now.
func (s *AuthService) loginMFAChallenge(ctx context.Context, u *userdom.User, ip, ua string) (*MFAChallengeInfo, error) {
	if !s.mfaEnabled() {
		return nil, nil
	}
	f, err := s.mfaRepo.GetFactor(ctx, u.ID())
	if err != nil && !errors.Is(err, mfa.ErrFactorNotFound) {
		return nil, fmt.Errorf("load mfa factor: %w", err)
	}
	if f != nil && f.Enabled {
		return s.issueMFAChallenge(ctx, u.ID(), mfa.PurposeVerify, ip, ua)
	}
	if s.mfaRequiredByAnyOrganization(ctx, u.ID()) {
		return s.issueMFAChallenge(ctx, u.ID(), mfa.PurposeEnroll, ip, ua)
	}
	return nil, nil
}

func (s *AuthService) issueMFAChallenge(ctx context.Context, userID shared.ID, purpose mfa.Purpose, ip, ua string) (*MFAChallengeInfo, error) {
	token, err := password.GenerateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("generate mfa challenge: %w", err)
	}
	now := time.Now().UTC()
	c := &mfa.Challenge{
		ID:        shared.NewID(),
		UserID:    userID,
		TokenHash: crypto.HashToken(token),
		Purpose:   purpose,
		IPAddress: ip,
		UserAgent: ua,
		ExpiresAt: now.Add(mfa.ChallengeTTL),
		CreatedAt: now,
	}
	if err := s.mfaRepo.CreateChallenge(ctx, c); err != nil {
		return nil, err
	}
	return &MFAChallengeInfo{Token: token, Purpose: purpose, ExpiresAt: c.ExpiresAt}, nil
}

// openChallenge loads a challenge for the given step, checks the account can
// still sign in, and counts the attempt.
func (s *AuthService) openChallenge(ctx context.Context, token string, purpose mfa.Purpose) (*mfa.Challenge, *userdom.User, error) {
	if !s.mfaEnabled() {
		return nil, nil, ErrMFAUnavailable
	}
	if strings.TrimSpace(token) == "" {
		return nil, nil, ErrMFAChallengeInvalid
	}
	c, err := s.mfaRepo.GetChallengeByTokenHash(ctx, crypto.HashToken(token))
	if err != nil {
		if errors.Is(err, mfa.ErrChallengeNotFound) {
			return nil, nil, ErrMFAChallengeInvalid
		}
		return nil, nil, err
	}
	if c.Purpose != purpose || !c.Usable(time.Now()) {
		return nil, nil, ErrMFAChallengeInvalid
	}
	u, err := s.userRepo.GetByID(ctx, c.UserID)
	if err != nil {
		if shared.IsNotFound(err) {
			return nil, nil, ErrMFAChallengeInvalid
		}
		return nil, nil, fmt.Errorf("failed to get user: %w", err)
	}
	if u.IsLocked() {
		return nil, nil, ErrAccountLocked
	}
	if !u.IsActive() {
		return nil, nil, ErrAccountSuspended
	}
	attempts, err := s.mfaRepo.RecordChallengeAttempt(ctx, c.ID)
	if err != nil {
		if errors.Is(err, mfa.ErrChallengeNotFound) {
			return nil, nil, ErrMFAChallengeInvalid
		}
		return nil, nil, err
	}
	if attempts > mfa.MaxChallengeAttempts {
		_, _ = s.mfaRepo.ConsumeChallenge(ctx, c.ID)
		return nil, nil, ErrMFAChallengeInvalid
	}
	return c, u, nil
}

// recordSecondFactorFailure applies the account lockout and audits the miss.
func (s *AuthService) recordSecondFactorFailure(ctx context.Context, c *mfa.Challenge, u *userdom.User, ip, ua string) {
	s.recordPasswordFailure(ctx, u)
	if u.IsLocked() {
		// Locked accounts get no further tries on this challenge.
		_, _ = s.mfaRepo.ConsumeChallenge(ctx, c.ID)
	}
	s.audit(ctx, auditapp.AuditContext{ActorID: u.ID().String(), ActorEmail: u.Email(), ActorIP: ip, UserAgent: ua},
		auditapp.NewFailureEvent(auditdom.ActionAuthMFAFailed, auditdom.ResourceTypeUser, u.ID().String(), nil).
			WithResourceName(u.Email()).
			WithMessage("Two-factor verification failed"))
}

// VerifyMFALogin completes a login that needed a second factor. On success it
// returns the same result a password-only login would have.
func (s *AuthService) VerifyMFALogin(ctx context.Context, input VerifyMFAInput) (*LoginResult, error) {
	c, u, err := s.openChallenge(ctx, input.Token, mfa.PurposeVerify)
	if err != nil {
		return nil, err
	}
	f, err := s.mfaRepo.GetFactor(ctx, u.ID())
	if err != nil || !f.Enabled {
		// 2FA was turned off after the challenge was issued.
		return nil, ErrMFAChallengeInvalid
	}

	method := "totp"
	remaining := -1
	var ok bool
	switch {
	case strings.TrimSpace(input.Code) != "":
		ok, err = s.checkTOTP(ctx, f, input.Code)
	case strings.TrimSpace(input.RecoveryCode) != "":
		method = "recovery_code"
		ok, remaining, err = s.useRecoveryCode(ctx, u.ID(), input.RecoveryCode)
	default:
		return nil, fmt.Errorf("%w: a verification code is required", shared.ErrValidation)
	}
	if err != nil {
		return nil, err
	}
	if !ok {
		s.recordSecondFactorFailure(ctx, c, u, input.IPAddress, input.UserAgent)
		return nil, ErrMFACodeInvalid
	}
	consumed, err := s.mfaRepo.ConsumeChallenge(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	if !consumed {
		return nil, ErrMFAChallengeInvalid
	}

	actx := auditapp.AuditContext{ActorID: u.ID().String(), ActorEmail: u.Email(), ActorIP: input.IPAddress, UserAgent: input.UserAgent}
	if method == "recovery_code" {
		s.audit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionAuthMFARecoveryCodeUsed, auditdom.ResourceTypeUser, u.ID().String()).
			WithResourceName(u.Email()).
			WithMessage("Signed in with a two-factor recovery code").
			WithMetadata("recovery_codes_remaining", remaining))
		if s.securityNotifier != nil {
			s.securityNotifier.NotifyRecoveryCodeUsed(ctx, u.Email(), u.Name(), input.IPAddress, remaining)
		}
	}

	s.recordLoginSuccess(ctx, u)
	return s.completeLogin(ctx, u, input.IPAddress, input.UserAgent)
}

// BeginMFAEnrollmentFromChallenge issues a secret to a user who was sent to
// enrollment by their organization's policy. The challenge stays open until
// CompleteMFAEnrollmentFromChallenge.
func (s *AuthService) BeginMFAEnrollmentFromChallenge(ctx context.Context, token string) (*MFASetup, error) {
	_, u, err := s.openChallenge(ctx, token, mfa.PurposeEnroll)
	if err != nil {
		return nil, err
	}
	return s.newPendingSecret(ctx, u)
}

// CompleteMFAEnrollmentFromChallenge confirms the enrollment with a code,
// turns 2FA on and signs the user in. The recovery codes are returned once.
func (s *AuthService) CompleteMFAEnrollmentFromChallenge(ctx context.Context, input CompleteMFAEnrollmentInput) (*LoginResult, []string, error) {
	c, u, err := s.openChallenge(ctx, input.Token, mfa.PurposeEnroll)
	if err != nil {
		return nil, nil, err
	}
	codes, err := s.activatePending(ctx, u, input.Code)
	if err != nil {
		if errors.Is(err, ErrMFACodeInvalid) {
			s.recordSecondFactorFailure(ctx, c, u, input.IPAddress, input.UserAgent)
		}
		return nil, nil, err
	}
	if _, err := s.mfaRepo.ConsumeChallenge(ctx, c.ID); err != nil {
		return nil, nil, err
	}
	s.auditMFAEnabled(ctx, auditapp.AuditContext{ActorID: u.ID().String(), ActorEmail: u.Email(), ActorIP: input.IPAddress, UserAgent: input.UserAgent}, u, "organization_policy")

	s.recordLoginSuccess(ctx, u)
	res, err := s.completeLogin(ctx, u, input.IPAddress, input.UserAgent)
	if err != nil {
		return nil, nil, err
	}
	return res, codes, nil
}

// ---------------------------------------------------------------------------
// Self-service (My account)
// ---------------------------------------------------------------------------

// GetMFAStatus returns the user's 2FA state.
func (s *AuthService) GetMFAStatus(ctx context.Context, userID string) (*MFAStatus, error) {
	u, err := s.mfaUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	st := &MFAStatus{Supported: isPasswordAccount(u)}
	if !st.Supported {
		return st, nil
	}
	if !s.mfaEnabled() {
		st.Supported = false
		return st, nil
	}
	st.RequiredByOrganization = s.mfaRequiredByAnyOrganization(ctx, u.ID())
	f, err := s.mfaRepo.GetFactor(ctx, u.ID())
	if err != nil && !errors.Is(err, mfa.ErrFactorNotFound) {
		return nil, err
	}
	if f != nil && f.Enabled {
		st.Enabled = true
		st.EnabledAt = f.EnabledAt
		codes, err := s.mfaRepo.ListUnusedRecoveryCodes(ctx, u.ID())
		if err != nil {
			return nil, err
		}
		st.RecoveryCodesRemaining = len(codes)
	}
	return st, nil
}

// BeginMFASetup generates a new secret for the signed-in user. It does not
// change anything that authenticates until EnableMFA confirms a code.
func (s *AuthService) BeginMFASetup(ctx context.Context, userID string) (*MFASetup, error) {
	u, err := s.mfaUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !isPasswordAccount(u) {
		return nil, ErrMFANotSupported
	}
	if !s.mfaEnabled() {
		return nil, ErrMFAUnavailable
	}
	f, err := s.mfaRepo.GetFactor(ctx, u.ID())
	if err != nil && !errors.Is(err, mfa.ErrFactorNotFound) {
		return nil, err
	}
	if f != nil && f.Enabled {
		return nil, ErrMFAAlreadyEnabled
	}
	return s.newPendingSecret(ctx, u)
}

// EnableMFA confirms the pending secret with a code and turns 2FA on. It needs
// the current password: enabling signs out every other session, so with a
// stolen session alone an attacker could otherwise bind their own
// authenticator and lock the real user out (settings audit A-M1). Every
// other session of the user is signed out, so a session opened with a stolen
// password before 2FA was turned on does not survive it. The recovery codes
// are returned once and only their hashes are kept.
func (s *AuthService) EnableMFA(ctx context.Context, actx auditapp.AuditContext, userID, currentPassword, code string) ([]string, error) {
	u, err := s.mfaUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !isPasswordAccount(u) {
		return nil, ErrMFANotSupported
	}
	if !s.mfaEnabled() {
		return nil, ErrMFAUnavailable
	}
	if u.IsLocked() {
		return nil, ErrAccountLocked
	}
	if err := s.passwordHasher.Verify(currentPassword, *u.PasswordHash()); err != nil {
		s.recordPasswordFailure(ctx, u)
		return nil, ErrPasswordMismatch
	}
	codes, err := s.activatePending(ctx, u, code)
	if err != nil {
		return nil, err
	}
	except, _ := shared.IDFromString(actx.SessionID)
	s.revokeUserSessions(ctx, u.ID(), except)
	s.auditMFAEnabled(ctx, actx, u, "self_service")
	return codes, nil
}

// DisableMFA turns 2FA off. It needs the current password and a valid code
// (TOTP or an unused recovery code), so a hijacked session alone cannot
// strip the second factor.
func (s *AuthService) DisableMFA(ctx context.Context, actx auditapp.AuditContext, userID, currentPassword, code string) error {
	u, err := s.mfaUser(ctx, userID)
	if err != nil {
		return err
	}
	if !isPasswordAccount(u) {
		return ErrMFANotSupported
	}
	if !s.mfaEnabled() {
		return ErrMFAUnavailable
	}
	if u.IsLocked() {
		return ErrAccountLocked
	}
	if err := s.passwordHasher.Verify(currentPassword, *u.PasswordHash()); err != nil {
		s.recordPasswordFailure(ctx, u)
		return ErrPasswordMismatch
	}
	f, err := s.mfaRepo.GetFactor(ctx, u.ID())
	if err != nil || !f.Enabled {
		return ErrMFANotEnabled
	}
	ok, err := s.checkTOTPOrRecovery(ctx, f, code)
	if err != nil {
		return err
	}
	if !ok {
		return ErrMFACodeInvalid
	}
	if err := s.mfaRepo.Disable(ctx, u.ID()); err != nil {
		return err
	}
	s.audit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionAuthMFADisabled, auditdom.ResourceTypeUser, u.ID().String()).
		WithResourceName(u.Email()).
		WithMessage("Two-factor authentication disabled"))
	if s.securityNotifier != nil {
		s.securityNotifier.NotifyMFADisabled(ctx, u.Email(), u.Name(), actx.ActorIP)
	}
	return nil
}

// RegenerateRecoveryCodes replaces every recovery code. It needs a current
// TOTP code (not a recovery code) so it proves possession of the device.
func (s *AuthService) RegenerateRecoveryCodes(ctx context.Context, actx auditapp.AuditContext, userID, code string) ([]string, error) {
	u, err := s.mfaUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !isPasswordAccount(u) {
		return nil, ErrMFANotSupported
	}
	if !s.mfaEnabled() {
		return nil, ErrMFAUnavailable
	}
	f, err := s.mfaRepo.GetFactor(ctx, u.ID())
	if err != nil || !f.Enabled {
		return nil, ErrMFANotEnabled
	}
	ok, err := s.checkTOTP(ctx, f, code)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrMFACodeInvalid
	}
	codes, hashes, err := s.newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	if err := s.mfaRepo.ReplaceRecoveryCodes(ctx, u.ID(), hashes); err != nil {
		return nil, err
	}
	s.audit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionAuthMFARecoveryCodesRegenerated, auditdom.ResourceTypeUser, u.ID().String()).
		WithResourceName(u.Email()).
		WithMessage("Two-factor recovery codes regenerated"))
	return codes, nil
}

// LogSessionRevoked audits a user signing out one (or all other) sessions.
func (s *AuthService) LogSessionRevoked(ctx context.Context, actx auditapp.AuditContext, sessionID string, allOthers bool) {
	ev := auditapp.NewSuccessEvent(auditdom.ActionAuthSessionRevoked, auditdom.ResourceTypeToken, sessionID).
		WithMetadata("all_others", allOthers)
	if allOthers {
		ev = ev.WithMessage("Signed out all other sessions")
	} else {
		ev = ev.WithMessage("Signed out a session")
	}
	s.audit(ctx, actx, ev)
}

// ---------------------------------------------------------------------------
// Organization policy
// ---------------------------------------------------------------------------

// mfaRequiredByAnyOrganization reports whether any organization the user is
// an active member of requires 2FA. Lookup failures are treated as "not
// required" here because the token-mint gate (enforceMFAPolicy) re-checks
// per tenant and fails closed.
func (s *AuthService) mfaRequiredByAnyOrganization(ctx context.Context, userID shared.ID) bool {
	if s.tenantRepo == nil {
		return false
	}
	memberships, err := s.tenantRepo.GetUserMemberships(ctx, userID)
	if err != nil {
		s.logger.Warn("mfa policy: failed to load memberships", "user_id", userID.String(), "error", err)
		return false
	}
	for _, m := range memberships {
		tid, err := shared.IDFromString(m.TenantID)
		if err != nil {
			continue
		}
		t, err := s.tenantRepo.GetByID(ctx, tid)
		if err != nil || t == nil {
			continue
		}
		sec, serr := t.SecuritySettingsStrict()
		if serr != nil || sec.MFARequiredFor(m.Role) {
			// An unreadable security section counts as "2FA required".
			return true
		}
	}
	return false
}

// enforceMFAPolicy is the per-tenant 2FA gate at token mint (ExchangeToken and
// RefreshToken), next to enforceSSOPolicy.
//
//   - A session issued by THIS tenant's own SAML/OIDC provider passes: the
//     tenant chose that IdP, and it owns the second factor.
//   - A password session passes only when the user has 2FA on. The password
//     login verified the code (loginMFAChallenge), so an enabled factor means
//     this session went through the second step.
//   - Any other federated session (social OAuth, another organization's IdP)
//     never went through our second step, and its IdP is not one this tenant
//     chose, so it is refused whether or not the user has enrolled. The user
//     signs in again — with password and 2FA, or through this tenant's IdP.
func (s *AuthService) enforceMFAPolicy(ctx context.Context, sess *sessiondom.Session, userID shared.ID, tenantID string) error {
	if !s.mfaEnabled() || sess.FederatedFor(tenantID) {
		return nil
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	t, err := s.tenantRepo.GetByID(ctx, tid)
	if err != nil {
		return fmt.Errorf("failed to load tenant for 2FA policy: %w", err)
	}
	sec, err := t.SecuritySettingsStrict()
	if err != nil {
		// Fail closed: never mint a token on an unreadable 2FA policy.
		return fmt.Errorf("failed to read 2FA policy: %w", err)
	}
	if !sec.MFARequired {
		if !sec.MFARequiredForAdmins {
			return nil
		}
		// Owners and administrators only: look the role up (fail closed).
		m, merr := s.tenantRepo.GetMembership(ctx, userID, tid)
		if merr != nil || m == nil {
			return fmt.Errorf("failed to load membership for 2FA policy: %w", merr)
		}
		if !sec.MFARequiredFor(m.Role().String()) {
			return nil
		}
	}
	if sess.AuthMethod().IsFederated() {
		s.logger.Warn("blocked federated session not issued by this tenant's IdP from 2FA-required tenant",
			"tenant_id", tid.String(), "user_id", userID.String())
		return ErrMFAEnrollmentRequired
	}
	f, err := s.mfaRepo.GetFactor(ctx, userID)
	if err != nil && !errors.Is(err, mfa.ErrFactorNotFound) {
		return fmt.Errorf("failed to load mfa factor: %w", err)
	}
	if f != nil && f.Enabled {
		return nil
	}
	s.logger.Warn("blocked session without 2FA from 2FA-required tenant",
		"tenant_id", tid.String(), "user_id", userID.String())
	return ErrMFAEnrollmentRequired
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func isPasswordAccount(u *userdom.User) bool {
	return u.AuthProvider() == userdom.AuthProviderLocal && u.PasswordHash() != nil
}

func (s *AuthService) mfaUser(ctx context.Context, userID string) (*userdom.User, error) {
	id, err := shared.IDFromString(userID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid user id", shared.ErrValidation)
	}
	u, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return u, nil
}

func (s *AuthService) newPendingSecret(ctx context.Context, u *userdom.User) (*MFASetup, error) {
	secret, err := totp.GenerateSecret()
	if err != nil {
		return nil, err
	}
	enc, err := s.mfaEncryptor.EncryptString(secret)
	if err != nil {
		return nil, fmt.Errorf("encrypt mfa secret: %w", err)
	}
	if err := s.mfaRepo.SavePendingSecret(ctx, u.ID(), enc); err != nil {
		return nil, err
	}
	return &MFASetup{Secret: secret, OTPAuthURI: totp.URI(secret, s.mfaIssuer, u.Email())}, nil
}

// activatePending verifies code against the pending secret and turns 2FA on.
func (s *AuthService) activatePending(ctx context.Context, u *userdom.User, code string) ([]string, error) {
	f, err := s.mfaRepo.GetFactor(ctx, u.ID())
	if err != nil {
		if errors.Is(err, mfa.ErrFactorNotFound) {
			return nil, ErrMFANoPendingSetup
		}
		return nil, err
	}
	if f.Enabled {
		return nil, ErrMFAAlreadyEnabled
	}
	if f.PendingSecretEncrypted == "" {
		return nil, ErrMFANoPendingSetup
	}
	secret, err := s.mfaEncryptor.DecryptString(f.PendingSecretEncrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt mfa secret: %w", err)
	}
	step, ok := totp.Verify(secret, code, time.Now())
	if !ok {
		return nil, ErrMFACodeInvalid
	}
	codes, hashes, err := s.newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	activated, err := s.mfaRepo.Activate(ctx, u.ID(), step, hashes)
	if err != nil {
		return nil, err
	}
	if !activated {
		return nil, ErrMFANoPendingSetup
	}
	return codes, nil
}

// checkTOTP verifies a code against the active secret and records its time
// step; a code from a step already used is rejected (replay).
func (s *AuthService) checkTOTP(ctx context.Context, f *mfa.Factor, code string) (bool, error) {
	if f.SecretEncrypted == "" {
		return false, nil
	}
	secret, err := s.mfaEncryptor.DecryptString(f.SecretEncrypted)
	if err != nil {
		return false, fmt.Errorf("decrypt mfa secret: %w", err)
	}
	step, ok := totp.Verify(secret, normalizeTOTPCode(code), time.Now())
	if !ok {
		return false, nil
	}
	return s.mfaRepo.AdvanceStep(ctx, f.UserID, step)
}

// checkTOTPOrRecovery accepts either kind of code: a 6-digit value is checked
// as TOTP, anything else as a recovery code.
func (s *AuthService) checkTOTPOrRecovery(ctx context.Context, f *mfa.Factor, code string) (bool, error) {
	if len(normalizeTOTPCode(code)) == totp.Digits && isDigits(normalizeTOTPCode(code)) {
		return s.checkTOTP(ctx, f, code)
	}
	ok, _, err := s.useRecoveryCode(ctx, f.UserID, code)
	return ok, err
}

// useRecoveryCode consumes a matching unused recovery code. remaining is the
// number of unused codes left after this one.
func (s *AuthService) useRecoveryCode(ctx context.Context, userID shared.ID, code string) (ok bool, remaining int, err error) {
	norm := normalizeRecoveryCode(code)
	if len(norm) != recoveryCodeLength {
		return false, 0, nil
	}
	codes, err := s.mfaRepo.ListUnusedRecoveryCodes(ctx, userID)
	if err != nil {
		return false, 0, err
	}
	for _, c := range codes {
		if s.recoveryHasher.Verify(norm, c.CodeHash) != nil {
			continue
		}
		consumed, err := s.mfaRepo.ConsumeRecoveryCode(ctx, userID, c.ID)
		if err != nil {
			return false, 0, err
		}
		return consumed, len(codes) - 1, nil
	}
	return false, 0, nil
}

// newRecoveryCodes returns RecoveryCodeCount display codes and their hashes.
func (s *AuthService) newRecoveryCodes() (codes, hashes []string, err error) {
	codes = make([]string, 0, mfa.RecoveryCodeCount)
	hashes = make([]string, 0, mfa.RecoveryCodeCount)
	for i := 0; i < mfa.RecoveryCodeCount; i++ {
		raw, err := randomRecoveryCode()
		if err != nil {
			return nil, nil, err
		}
		h, err := s.recoveryHasher.Hash(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("hash recovery code: %w", err)
		}
		codes = append(codes, raw[:5]+"-"+raw[5:])
		hashes = append(hashes, h)
	}
	return codes, hashes, nil
}

func randomRecoveryCode() (string, error) {
	// Rejection sampling keeps every character equally likely.
	const n = len(recoveryCodeAlphabet)
	limit := 256 - (256 % n)
	out := make([]byte, 0, recoveryCodeLength)
	buf := make([]byte, 32)
	for len(out) < recoveryCodeLength {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("generate recovery code: %w", err)
		}
		for _, b := range buf {
			if int(b) >= limit {
				continue
			}
			out = append(out, recoveryCodeAlphabet[int(b)%n])
			if len(out) == recoveryCodeLength {
				break
			}
		}
	}
	return string(out), nil
}

func normalizeRecoveryCode(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	code = strings.ReplaceAll(code, "-", "")
	return strings.ReplaceAll(code, " ", "")
}

func normalizeTOTPCode(code string) string {
	return strings.ReplaceAll(strings.TrimSpace(code), " ", "")
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func (s *AuthService) auditMFAEnabled(ctx context.Context, actx auditapp.AuditContext, u *userdom.User, via string) {
	s.audit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionAuthMFAEnabled, auditdom.ResourceTypeUser, u.ID().String()).
		WithResourceName(u.Email()).
		WithMessage("Two-factor authentication enabled").
		WithMetadata("via", via))
}

func (s *AuthService) audit(ctx context.Context, actx auditapp.AuditContext, ev auditapp.AuditEvent) {
	if s.auditService == nil {
		return
	}
	if err := s.auditService.LogEvent(ctx, actx, ev); err != nil {
		s.logger.Error("failed to write audit event", "action", string(ev.Action), "error", err)
	}
}

// revocationTTL is how long a revoked session id must be remembered: as long
// as an access token minted for it can live, plus clock skew.
func (s *AuthService) revocationTTL() time.Duration {
	return s.config.AccessTokenDuration + time.Minute
}

// revokeUserSessions revokes every active session of the user except
// `except` (zero ID = revoke all), with their refresh tokens, and records the
// ids for immediate access-token rejection.
func (s *AuthService) revokeUserSessions(ctx context.Context, userID, except shared.ID) {
	revokeUserSessions(ctx, s.sessionRepo, s.refreshTokenRepo, s.revocations, s.revocationTTL(), userID, except, s.logger.Error)
}

// revokeUserSessions does the work behind AuthService.revokeUserSessions.
func revokeUserSessions(
	ctx context.Context,
	sessionRepo sessiondom.Repository,
	refreshTokenRepo sessiondom.RefreshTokenRepository,
	store SessionRevocationStore,
	ttl time.Duration,
	userID, except shared.ID,
	logError func(msg string, args ...any),
) {
	active, err := sessionRepo.GetActiveByUserID(ctx, userID)
	if err != nil {
		logError("failed to list sessions for revocation", "error", err)
	}
	if except.IsZero() {
		if err := sessionRepo.RevokeAllByUserID(ctx, userID); err != nil {
			logError("failed to revoke sessions", "error", err)
		}
		if err := refreshTokenRepo.RevokeByUserID(ctx, userID); err != nil {
			logError("failed to revoke refresh tokens", "error", err)
		}
	} else if err := sessionRepo.RevokeAllByUserIDExcept(ctx, userID, except); err != nil {
		logError("failed to revoke sessions", "error", err)
	}
	for _, sess := range active {
		if !except.IsZero() && sess.ID().Equals(except) {
			continue
		}
		if !except.IsZero() {
			if err := refreshTokenRepo.RevokeBySessionID(ctx, sess.ID()); err != nil {
				logError("failed to revoke refresh tokens for session", "error", err)
			}
		}
		markSessionRevoked(ctx, store, ttl, sess.ID().String(), logError)
	}
}

func markSessionRevoked(ctx context.Context, store SessionRevocationStore, ttl time.Duration, sessionID string, logError func(msg string, args ...any)) {
	if store == nil || sessionID == "" {
		return
	}
	if err := store.MarkSessionRevoked(ctx, sessionID, ttl); err != nil {
		logError("failed to record session revocation", "error", err)
	}
}
