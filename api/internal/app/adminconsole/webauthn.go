package adminconsole

// Console WebAuthn: security keys and passkeys as the console's second factor
// and step-up proof, one-time recovery codes, and the platform policy
// "require WebAuthn" (docs/rfcs/RFC-078-passkeys-and-security-notices.md).
//
// The relying party is the console's own origin (ADMIN_PUBLIC_URL): the
// browser binds every assertion to it, so a phishing proxy on another origin,
// or a script on the tenant site, cannot produce one the console accepts.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Audit actions of the console factors.
const (
	ActionWebAuthnRegistered     = "console.webauthn_registered"
	ActionWebAuthnRemoved        = "console.webauthn_removed"
	ActionWebAuthnRenamed        = "console.webauthn_renamed"
	ActionWebAuthnFailed         = "console.webauthn_failed"
	ActionWebAuthnCounterRegress = "console.webauthn_counter_regressed"
	ActionRecoveryCodesGenerated = "console.recovery_codes_generated"
	ActionRecoveryCodeUsed       = "console.recovery_code_used"
	ActionRecoveryCodeFailed     = "console.recovery_code_failed"
	ActionMFAPolicyChanged       = "console.mfa_policy_changed"
)

// Second-factor methods a sign-in may offer, in order of preference.
const (
	MethodWebAuthn     = "webauthn"
	MethodTOTP         = "totp"
	MethodRecoveryCode = "recovery_code"
)

// WebAuthnConfig is the console relying party.
type WebAuthnConfig struct {
	// PublicURL is the console's origin (scheme://host[:port]); the RP ID is
	// its host and it is the only origin accepted.
	PublicURL string
	// DisplayName is shown by the authenticator.
	DisplayName string
}

// NewConsoleWebAuthn builds the relying party from the console origin.
func NewConsoleWebAuthn(cfg WebAuthnConfig) (*webauthn.WebAuthn, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(cfg.PublicURL), "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("console origin %q: want scheme://host[:port]", cfg.PublicURL)
	}
	origin := u.Scheme + "://" + u.Host
	name := cfg.DisplayName
	if name == "" {
		name = Issuer
	}
	return webauthn.New(&webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: name,
		RPOrigins:     []string{origin},
		// No attestation: the console accepts any FIDO2 authenticator,
		// including synced passkeys, and keeps the AAGUID for display.
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationRequired,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: admin.CeremonyTTL, TimeoutUVD: admin.CeremonyTTL},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: admin.CeremonyTTL, TimeoutUVD: admin.CeremonyTTL},
		},
	})
}

// EnableWebAuthn turns on console WebAuthn. settings stores the policy.
func (s *Service) EnableWebAuthn(rp *webauthn.WebAuthn, factors admin.FactorRepository, settings platformsetting.Repository) {
	s.webauthn = rp
	s.factors = factors
	s.settings = settings
}

// WebAuthnEnabled reports whether the console relying party is configured.
func (s *Service) WebAuthnEnabled() bool { return s.webauthn != nil && s.factors != nil }

// waUser adapts an administrator to the WebAuthn user. The user handle is
// the administrator id (16 opaque bytes, no personal data).
type waUser struct {
	a     *admin.AdminUser
	creds []*admin.WebAuthnCredential
}

func (u waUser) WebAuthnID() []byte {
	id, err := uuid.Parse(u.a.ID().String())
	if err != nil {
		return []byte(u.a.ID().String())
	}
	return id[:]
}
func (u waUser) WebAuthnName() string { return u.a.Email() }
func (u waUser) WebAuthnDisplayName() string {
	if u.a.Name() != "" {
		return u.a.Name()
	}
	return u.a.Email()
}

func (u waUser) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(u.creds))
	for _, c := range u.creds {
		transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transports))
		for _, t := range c.Transports {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
		out = append(out, webauthn.Credential{
			ID:                c.CredentialID,
			PublicKey:         c.PublicKey,
			AttestationFormat: c.AttestationFmt,
			Transport:         transports,
			Flags: webauthn.CredentialFlags{
				UserPresent:    true,
				UserVerified:   c.UserVerified,
				BackupEligible: c.BackupEligible,
				BackupState:    c.BackupState,
			},
			Authenticator: webauthn.Authenticator{
				AAGUID:     c.AAGUID,
				SignCount:  c.SignCount,
				Attachment: protocol.AuthenticatorAttachment(c.Attachment),
			},
		})
	}
	return out
}

func (s *Service) loadUser(ctx context.Context, a *admin.AdminUser) (waUser, error) {
	creds, err := s.factors.ListWebAuthnCredentials(ctx, a.ID())
	if err != nil {
		return waUser{}, err
	}
	return waUser{a: a, creds: creds}, nil
}

// MFAPolicy returns the console MFA policy and its version (0: never stored).
func (s *Service) MFAPolicy(ctx context.Context) (admin.ConsoleMFAPolicy, int, error) {
	if s.settings == nil {
		return admin.ConsoleMFAPolicy{}, 0, nil
	}
	st, err := s.settings.Get(ctx, admin.ConsoleMFAPolicyKey)
	if errors.Is(err, platformsetting.ErrNotFound) {
		return admin.ConsoleMFAPolicy{}, 0, nil
	}
	if err != nil {
		return admin.ConsoleMFAPolicy{}, 0, fmt.Errorf("read console mfa policy: %w", err)
	}
	var p admin.ConsoleMFAPolicy
	if err := json.Unmarshal(st.Value, &p); err != nil {
		return admin.ConsoleMFAPolicy{}, 0, fmt.Errorf("decode console mfa policy: %w", err)
	}
	return p, st.Version, nil
}

// FactorStatus is the administrator's standing against the console MFA policy.
func (s *Service) FactorStatus(ctx context.Context, a *admin.AdminUser) (admin.FactorStatus, error) {
	st := admin.FactorStatus{BreakGlassExempted: a.IsBreakGlass()}
	if creds, err := s.console.GetCredentials(ctx, a.ID()); err == nil {
		st.TOTPEnabled = creds.MFAEnabled
	} else if !errors.Is(err, admin.ErrCredentialsNotFound) {
		return st, err
	}
	if !s.WebAuthnEnabled() {
		return st, nil
	}
	creds, err := s.factors.ListWebAuthnCredentials(ctx, a.ID())
	if err != nil {
		return st, err
	}
	st.WebAuthnCount = len(creds)
	if st.RecoveryCodesLeft, err = s.factors.CountRecoveryCodes(ctx, a.ID()); err != nil {
		return st, err
	}
	p, _, err := s.MFAPolicy(ctx)
	if err != nil {
		return st, err
	}
	st.PolicyRequires = p.RequireWebAuthn
	st.GraceUntil = p.GraceUntil
	st.GraceOver = p.GraceUntil == nil || !s.now().Before(*p.GraceUntil)
	return st, nil
}

// factorCacheTTL bounds how stale the per-request enrollment gate may be on
// another instance; this instance drops an administrator's entry the moment
// that administrator's factors or the policy change.
const factorCacheTTL = 30 * time.Second

type factorCacheEntry struct {
	st  admin.FactorStatus
	exp time.Time
}

// factorStatusCached is FactorStatus for the enrollment gate that runs on
// every console request (four queries otherwise). Decisions about a factor
// (step-up, sign-in, policy change) never use it.
func (s *Service) factorStatusCached(ctx context.Context, a *admin.AdminUser) (admin.FactorStatus, error) {
	now := s.now()
	key := a.ID().String()
	s.factorMu.Lock()
	e, ok := s.factorCache[key]
	s.factorMu.Unlock()
	if ok && now.Before(e.exp) {
		return e.st, nil
	}
	st, err := s.FactorStatus(ctx, a)
	if err != nil {
		return st, err
	}
	s.factorMu.Lock()
	if s.factorCache == nil {
		s.factorCache = map[string]factorCacheEntry{}
	}
	s.factorCache[key] = factorCacheEntry{st: st, exp: now.Add(factorCacheTTL)}
	s.factorMu.Unlock()
	return st, nil
}

// forgetFactors drops one administrator's cached standing, or everyone's
// (a == nil, the policy changed).
func (s *Service) forgetFactors(a *admin.AdminUser) {
	s.factorMu.Lock()
	defer s.factorMu.Unlock()
	if a == nil {
		s.factorCache = nil
		return
	}
	delete(s.factorCache, a.ID().String())
}

// signInMethods lists the second factors this administrator may use now,
// WebAuthn first.
func signInMethods(st admin.FactorStatus) []string {
	var m []string
	if st.WebAuthnCount > 0 {
		m = append(m, MethodWebAuthn)
	}
	if st.TOTPAllowed() {
		m = append(m, MethodTOTP)
	}
	if st.RecoveryCodesLeft > 0 {
		m = append(m, MethodRecoveryCode)
	}
	return m
}

// ---------------------------------------------------------------------------
// Sign-in (second step of a pending console session)
// ---------------------------------------------------------------------------

// pendingSession resolves the pending (second-step) console session and its
// administrator, applying the same checks as the TOTP step. It deletes the
// session when the administrator can no longer sign in.
func (s *Service) pendingSession(ctx context.Context, pendingToken string) (*admin.Session, *admin.AdminUser, error) {
	if pendingToken == "" {
		return nil, nil, admin.ErrInvalidMFACode
	}
	sess, err := s.console.GetSessionByTokenHash(ctx, hashToken(pendingToken))
	if err != nil {
		if errors.Is(err, admin.ErrSessionNotFound) {
			return nil, nil, admin.ErrInvalidMFACode
		}
		return nil, nil, err
	}
	if sess.MFAVerified || !s.now().Before(sess.ExpiresAt) {
		return nil, nil, admin.ErrInvalidMFACode
	}
	a, err := s.admins.GetByID(ctx, sess.AdminID)
	if err != nil {
		return nil, nil, admin.ErrInvalidMFACode
	}
	if !a.IsActive() || a.IsLocked() {
		_ = s.console.DeleteSession(ctx, sess.ID)
		return nil, nil, admin.ErrInvalidMFACode
	}
	if sessionAuthMethod(sess) == admin.AuthMethodPassword {
		if err := s.checkPasswordPathAllowed(ctx, a); err != nil {
			_ = s.console.DeleteSession(ctx, sess.ID)
			return nil, nil, err
		}
	}
	return sess, a, nil
}

// BeginWebAuthnLogin returns the assertion request for the pending session's
// administrator (their own authenticators only).
func (s *Service) BeginWebAuthnLogin(ctx context.Context, pendingToken string) (*protocol.CredentialAssertion, error) {
	if !s.WebAuthnEnabled() {
		return nil, admin.ErrWebAuthnUnavailable
	}
	sess, a, err := s.pendingSession(ctx, pendingToken)
	if err != nil {
		return nil, err
	}
	return s.beginAssertion(ctx, a, sess.ID, admin.CeremonyLogin)
}

func (s *Service) beginAssertion(ctx context.Context, a *admin.AdminUser, sessionID shared.ID, purpose string) (*protocol.CredentialAssertion, error) {
	u, err := s.loadUser(ctx, a)
	if err != nil {
		return nil, err
	}
	if len(u.creds) == 0 {
		return nil, admin.ErrWebAuthnUnavailable
	}
	assertion, data, err := s.webauthn.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, fmt.Errorf("begin webauthn assertion: %w", err)
	}
	if err := s.saveCeremony(ctx, sessionID, purpose, data); err != nil {
		return nil, err
	}
	return assertion, nil
}

func (s *Service) saveCeremony(ctx context.Context, sessionID shared.ID, purpose string, data *webauthn.SessionData) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encode webauthn ceremony: %w", err)
	}
	return s.factors.SaveCeremony(ctx, sessionID, purpose, raw, s.now().Add(admin.CeremonyTTL))
}

func (s *Service) takeCeremony(ctx context.Context, sessionID shared.ID, purpose string) (webauthn.SessionData, error) {
	raw, err := s.factors.TakeCeremony(ctx, sessionID, purpose, s.now())
	if err != nil {
		return webauthn.SessionData{}, err
	}
	var data webauthn.SessionData
	if err := json.Unmarshal(raw, &data); err != nil {
		return webauthn.SessionData{}, fmt.Errorf("decode webauthn ceremony: %w", err)
	}
	return data, nil
}

// verifyAssertion checks an assertion against the session's open ceremony
// and the administrator's own authenticators, and records the use. Every
// refusal is ErrInvalidAssertion (the cause is logged and audited).
func (s *Service) verifyAssertion(ctx context.Context, a *admin.AdminUser, sessionID shared.ID, purpose string, body []byte, client ClientInfo) error {
	data, err := s.takeCeremony(ctx, sessionID, purpose)
	if err != nil {
		if errors.Is(err, admin.ErrCeremonyNotFound) {
			return admin.ErrInvalidAssertion
		}
		return err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		s.log.Debug("console webauthn: unparsable assertion", "error", err)
		return admin.ErrInvalidAssertion
	}
	u, err := s.loadUser(ctx, a)
	if err != nil {
		return err
	}
	cred, err := s.webauthn.ValidateLogin(u, data, parsed)
	if err != nil {
		s.log.Info("console webauthn assertion refused", "admin_id", a.ID().String(), "purpose", purpose, "error", err)
		return admin.ErrInvalidAssertion
	}
	var stored *admin.WebAuthnCredential
	for _, c := range u.creds {
		if bytes.Equal(c.CredentialID, cred.ID) {
			stored = c
			break
		}
	}
	if stored == nil {
		return admin.ErrInvalidAssertion
	}
	if cred.Authenticator.CloneWarning {
		s.recordNote(ctx, a, ActionWebAuthnCounterRegress, client, stored.Name)
		return admin.ErrInvalidAssertion
	}
	ok, err := s.factors.RecordWebAuthnUse(ctx, a.ID(), stored.ID, cred.Authenticator.SignCount, cred.Flags.BackupState, s.now())
	if err != nil {
		return err
	}
	if !ok {
		// A concurrent assertion moved the counter first, or it went back.
		s.recordNote(ctx, a, ActionWebAuthnCounterRegress, client, stored.Name)
		return admin.ErrInvalidAssertion
	}
	return nil
}

// FinishWebAuthnLogin completes a sign-in with an assertion and opens a
// verified console session. A refused assertion counts toward the lockout,
// like a wrong code.
func (s *Service) FinishWebAuthnLogin(ctx context.Context, pendingToken string, body []byte, client ClientInfo) (string, *admin.AdminUser, error) {
	if !s.WebAuthnEnabled() {
		return "", nil, admin.ErrWebAuthnUnavailable
	}
	sess, a, err := s.pendingSession(ctx, pendingToken)
	if err != nil {
		return "", nil, err
	}
	if err := s.verifyAssertion(ctx, a, sess.ID, admin.CeremonyLogin, body, client); err != nil {
		if errors.Is(err, admin.ErrInvalidAssertion) {
			s.recordFailure(ctx, a, client, ActionWebAuthnFailed, "sign-in assertion refused")
		}
		return "", nil, err
	}
	return s.completeSecondFactor(ctx, sess, a, client, "webauthn")
}

// RecoveryLogin completes a sign-in with a one-time recovery code.
func (s *Service) RecoveryLogin(ctx context.Context, pendingToken, code string, client ClientInfo) (string, *admin.AdminUser, error) {
	if s.factors == nil {
		return "", nil, admin.ErrInvalidRecoveryCode
	}
	sess, a, err := s.pendingSession(ctx, pendingToken)
	if err != nil {
		if errors.Is(err, admin.ErrInvalidMFACode) {
			return "", nil, admin.ErrInvalidRecoveryCode
		}
		return "", nil, err
	}
	ok, err := s.factors.UseRecoveryCode(ctx, a.ID(), hashRecoveryCode(code), s.now())
	if err != nil {
		return "", nil, err
	}
	if !ok {
		s.recordFailure(ctx, a, client, ActionRecoveryCodeFailed, "wrong or used recovery code")
		return "", nil, admin.ErrInvalidRecoveryCode
	}
	s.forgetFactors(a)
	left, _ := s.factors.CountRecoveryCodes(ctx, a.ID())
	s.recordNote(ctx, a, ActionRecoveryCodeUsed, client, fmt.Sprintf("%d recovery codes left", left))
	return s.completeSecondFactor(ctx, sess, a, client, "recovery code")
}

// completeSecondFactor replaces a pending session with a verified one.
func (s *Service) completeSecondFactor(ctx context.Context, sess *admin.Session, a *admin.AdminUser, client ClientInfo, note string) (string, *admin.AdminUser, error) {
	if a.FailedLoginCount() > 0 {
		a.ResetFailedLogins()
		if err := s.admins.Update(ctx, a); err != nil {
			s.log.Warn("reset admin failed-login counter", "error", err)
		}
	}
	_ = s.console.DeleteSession(ctx, sess.ID)
	token, err := s.openVerifiedSession(ctx, a, sessionAuthMethod(sess), client, note)
	if err != nil {
		return "", nil, err
	}
	return token, a, nil
}

// ---------------------------------------------------------------------------
// Step-up with WebAuthn
// ---------------------------------------------------------------------------

// BeginWebAuthnStepUp returns an assertion request that, once answered,
// opens the step-up window of this verified console session.
func (s *Service) BeginWebAuthnStepUp(ctx context.Context, a *admin.AdminUser, sess *admin.Session) (*protocol.CredentialAssertion, error) {
	if !s.WebAuthnEnabled() {
		return nil, admin.ErrWebAuthnUnavailable
	}
	if a == nil || sess == nil || !sess.MFAVerified || sess.AdminID != a.ID() {
		return nil, admin.ErrStepUpRequired
	}
	return s.beginAssertion(ctx, a, sess.ID, admin.CeremonyStepUp)
}

// FinishWebAuthnStepUp verifies the assertion and opens the session's
// step-up window (admin.StepUpWindow): the protected action is then retried
// without a code. A refused assertion counts toward the lockout.
func (s *Service) FinishWebAuthnStepUp(ctx context.Context, a *admin.AdminUser, sess *admin.Session, body []byte, client ClientInfo) error {
	if !s.WebAuthnEnabled() {
		return admin.ErrWebAuthnUnavailable
	}
	if a == nil || sess == nil || !sess.MFAVerified || sess.AdminID != a.ID() {
		return admin.ErrStepUpRequired
	}
	if err := s.verifyAssertion(ctx, a, sess.ID, admin.CeremonyStepUp, body, client); err != nil {
		if errors.Is(err, admin.ErrInvalidAssertion) {
			s.recordFailure(ctx, a, client, ActionStepUpFailed, "step-up assertion refused")
		}
		return err
	}
	if err := s.console.MarkSessionStepUp(ctx, sess.ID, s.now()); err != nil {
		return fmt.Errorf("record console step-up window: %w", err)
	}
	s.recordNote(ctx, a, ActionStepUp, client, "webauthn")
	return nil
}

// ---------------------------------------------------------------------------
// Registration and management (signed in, route-level step-up)
// ---------------------------------------------------------------------------

// BeginWebAuthnRegistration returns the creation request for a new
// authenticator of the signed-in administrator.
func (s *Service) BeginWebAuthnRegistration(ctx context.Context, a *admin.AdminUser, sess *admin.Session) (*protocol.CredentialCreation, error) {
	if !s.WebAuthnEnabled() {
		return nil, admin.ErrWebAuthnUnavailable
	}
	if sess == nil || !sess.MFAVerified || sess.AdminID != a.ID() {
		return nil, admin.ErrSessionNotFound
	}
	u, err := s.loadUser(ctx, a)
	if err != nil {
		return nil, err
	}
	if len(u.creds) >= admin.MaxWebAuthnCredentials {
		return nil, admin.ErrTooManyWebAuthnCredentials
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(u.creds))
	for _, c := range u.WebAuthnCredentials() {
		exclude = append(exclude, c.Descriptor())
	}
	creation, data, err := s.webauthn.BeginRegistration(u, webauthn.WithExclusions(exclude))
	if err != nil {
		return nil, fmt.Errorf("begin webauthn registration: %w", err)
	}
	if err := s.saveCeremony(ctx, sess.ID, admin.CeremonyRegister, data); err != nil {
		return nil, err
	}
	return creation, nil
}

// FinishWebAuthnRegistration verifies the attestation response and stores
// the new authenticator.
func (s *Service) FinishWebAuthnRegistration(ctx context.Context, a *admin.AdminUser, sess *admin.Session, name string, body []byte, client ClientInfo) (*admin.WebAuthnCredential, error) {
	if !s.WebAuthnEnabled() {
		return nil, admin.ErrWebAuthnUnavailable
	}
	if sess == nil || !sess.MFAVerified || sess.AdminID != a.ID() {
		return nil, admin.ErrSessionNotFound
	}
	name, err := admin.NormalizeWebAuthnName(name)
	if err != nil {
		return nil, err
	}
	data, err := s.takeCeremony(ctx, sess.ID, admin.CeremonyRegister)
	if err != nil {
		if errors.Is(err, admin.ErrCeremonyNotFound) {
			return nil, admin.ErrInvalidAssertion
		}
		return nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		s.log.Debug("console webauthn: unparsable attestation", "error", err)
		return nil, admin.ErrInvalidAssertion
	}
	u, err := s.loadUser(ctx, a)
	if err != nil {
		return nil, err
	}
	cred, err := s.webauthn.CreateCredential(u, data, parsed)
	if err != nil {
		s.log.Info("console webauthn registration refused", "admin_id", a.ID().String(), "error", err)
		return nil, admin.ErrInvalidAssertion
	}
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	c := &admin.WebAuthnCredential{
		ID:             shared.NewID(),
		AdminID:        a.ID(),
		CredentialID:   cred.ID,
		PublicKey:      cred.PublicKey,
		SignCount:      cred.Authenticator.SignCount,
		AAGUID:         cred.Authenticator.AAGUID,
		Transports:     transports,
		Attachment:     string(cred.Authenticator.Attachment),
		AttestationFmt: cred.AttestationFormat,
		UserVerified:   cred.Flags.UserVerified,
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
		Name:           name,
		CreatedAt:      s.now(),
	}
	if err := s.factors.CreateWebAuthnCredential(ctx, c); err != nil {
		return nil, err
	}
	s.forgetFactors(a)
	s.recordNote(ctx, a, ActionWebAuthnRegistered, client, name)
	s.notifyFactorChange(ctx, a, FactorKeyAdded, name, client)
	return c, nil
}

// ListWebAuthn returns the signed-in administrator's authenticators.
func (s *Service) ListWebAuthn(ctx context.Context, a *admin.AdminUser) ([]*admin.WebAuthnCredential, error) {
	if !s.WebAuthnEnabled() {
		return nil, admin.ErrWebAuthnUnavailable
	}
	return s.factors.ListWebAuthnCredentials(ctx, a.ID())
}

// RenameWebAuthn relabels one of the administrator's own authenticators.
func (s *Service) RenameWebAuthn(ctx context.Context, a *admin.AdminUser, id shared.ID, name string, client ClientInfo) error {
	if !s.WebAuthnEnabled() {
		return admin.ErrWebAuthnUnavailable
	}
	name, err := admin.NormalizeWebAuthnName(name)
	if err != nil {
		return err
	}
	if err := s.factors.RenameWebAuthnCredential(ctx, a.ID(), id, name); err != nil {
		return err
	}
	s.recordNote(ctx, a, ActionWebAuthnRenamed, client, name)
	return nil
}

// RemoveWebAuthn deletes one of the administrator's own authenticators.
// While "require WebAuthn" binds this administrator, the last
// admin.MinWebAuthnCredentialsRequired are kept: register a replacement first.
func (s *Service) RemoveWebAuthn(ctx context.Context, a *admin.AdminUser, id shared.ID, client ClientInfo) error {
	if !s.WebAuthnEnabled() {
		return admin.ErrWebAuthnUnavailable
	}
	st, err := s.FactorStatus(ctx, a)
	if err != nil {
		return err
	}
	keep := 0
	if st.PolicyRequires && !st.BreakGlassExempted {
		keep = admin.MinWebAuthnCredentialsRequired
	}
	defer s.forgetFactors(a)
	if err := s.factors.DeleteWebAuthnCredential(ctx, a.ID(), id, keep); err != nil {
		return err
	}
	s.recordNote(ctx, a, ActionWebAuthnRemoved, client, id.String())
	return nil
}

// recoveryEncoding is Crockford-like base32 without padding, upper case.
var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateRecoveryCodes replaces the administrator's recovery codes with
// admin.RecoveryCodeCount new ones (60 bits each) and returns them once.
func (s *Service) GenerateRecoveryCodes(ctx context.Context, a *admin.AdminUser, client ClientInfo) ([]string, error) {
	if s.factors == nil {
		return nil, admin.ErrWebAuthnUnavailable
	}
	codes := make([]string, 0, admin.RecoveryCodeCount)
	hashes := make([]string, 0, admin.RecoveryCodeCount)
	for range admin.RecoveryCodeCount {
		buf := make([]byte, 8)
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("generate recovery code: %w", err)
		}
		raw := recoveryEncoding.EncodeToString(buf)[:12]
		code := raw[:4] + "-" + raw[4:8] + "-" + raw[8:]
		codes = append(codes, code)
		hashes = append(hashes, hashRecoveryCode(code))
	}
	if err := s.factors.ReplaceRecoveryCodes(ctx, a.ID(), hashes, s.now()); err != nil {
		return nil, err
	}
	s.forgetFactors(a)
	s.recordNote(ctx, a, ActionRecoveryCodesGenerated, client, "")
	s.notifyFactorChange(ctx, a, FactorRecoveryCodesRegenerated, "", client)
	return codes, nil
}

// RecoveryCodesLeft returns the administrator's unused recovery codes.
func (s *Service) RecoveryCodesLeft(ctx context.Context, a *admin.AdminUser) (int, error) {
	if s.factors == nil {
		return 0, nil
	}
	return s.factors.CountRecoveryCodes(ctx, a.ID())
}

// hashRecoveryCode normalizes (case, separators, spaces) and hashes a code.
func hashRecoveryCode(code string) string {
	norm := strings.Map(func(r rune) rune {
		switch {
		case r == '-' || r == ' ':
			return -1
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		}
		return r
	}, code)
	sum := sha256.Sum256([]byte("openctem-console-recovery:" + norm))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

// SetMFAPolicy changes "require WebAuthn" (a super admin, route-level
// step-up). Turning it on needs the console relying party and an actor who
// already complies, so the one turning it on can never lock themself out;
// other administrators keep signing in and are held on the enrollment pages
// until they comply.
func (s *Service) SetMFAPolicy(ctx context.Context, actor *admin.AdminUser, p admin.ConsoleMFAPolicy, expectedVersion int, client ClientInfo) (int, error) {
	if s.settings == nil {
		return 0, admin.ErrWebAuthnUnavailable
	}
	if p.RequireWebAuthn {
		if !s.WebAuthnEnabled() {
			return 0, admin.ErrWebAuthnUnavailable
		}
		st, err := s.FactorStatus(ctx, actor)
		if err != nil {
			return 0, err
		}
		if !st.Compliant() {
			return 0, admin.ErrPolicyActorNotCompliant
		}
	}
	now := s.now()
	if p.RequireWebAuthn {
		// The grace for TOTP-only administrators starts when the policy goes
		// from off to on; saving it again while on keeps the deadline.
		prev, _, err := s.MFAPolicy(ctx)
		if err != nil {
			return 0, err
		}
		if prev.RequireWebAuthn && prev.GraceUntil != nil {
			p.GraceUntil = prev.GraceUntil
		} else {
			until := now.Add(s.webauthnGrace())
			p.GraceUntil = &until
		}
	} else {
		p.GraceUntil = nil
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return 0, err
	}
	var version int
	if expectedVersion == 0 {
		created, err := s.settings.CreateIfAbsent(ctx, admin.ConsoleMFAPolicyKey, platformsetting.State{
			Value: raw, Version: 1, Source: platformsetting.SourceConsole, UpdatedBy: ptr(actor.ID()), UpdatedAt: now,
		})
		if err != nil {
			return 0, fmt.Errorf("store console mfa policy: %w", err)
		}
		if !created {
			return 0, admin.ErrConsoleMFAPolicyConflict
		}
		version = 1
	} else {
		st, err := s.settings.Update(ctx, admin.ConsoleMFAPolicyKey, raw, expectedVersion, actor.ID(), now)
		if errors.Is(err, platformsetting.ErrVersionConflict) || errors.Is(err, platformsetting.ErrNotFound) {
			return 0, admin.ErrConsoleMFAPolicyConflict
		}
		if err != nil {
			return 0, fmt.Errorf("store console mfa policy: %w", err)
		}
		version = st.Version
	}
	note := "require_webauthn=off"
	if p.RequireWebAuthn {
		note = "require_webauthn=on"
	}
	s.forgetFactors(nil)
	s.recordNote(ctx, actor, ActionMFAPolicyChanged, client, note)
	return version, nil
}

// webAuthnOverridesIdPMFA reports whether the console must still ask for
// WebAuthn after a platform IdP sign-in whose MFA is trusted: under "require
// WebAuthn" an administrator holding an authenticator proves it on the
// console origin itself.
func (s *Service) webAuthnOverridesIdPMFA(ctx context.Context, a *admin.AdminUser) bool {
	if !s.WebAuthnEnabled() {
		return false
	}
	st, err := s.FactorStatus(ctx, a)
	if err != nil {
		s.log.Warn("console mfa policy check", "error", err)
		return true // fail closed: ask for the console factor
	}
	return st.PolicyRequires && !st.BreakGlassExempted && st.WebAuthnCount > 0
}

// enrollmentRequired reports whether a verified session must stay on the
// enrollment pages. Errors fail closed.
func (s *Service) enrollmentRequired(ctx context.Context, a *admin.AdminUser) bool {
	if !s.WebAuthnEnabled() {
		return false
	}
	st, err := s.factorStatusCached(ctx, a)
	if err != nil {
		s.log.Warn("console mfa policy check", "error", err)
		return true
	}
	return st.EnrollmentRequired()
}
