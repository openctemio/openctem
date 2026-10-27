package auth

// Linking social sign-in identities (Google, GitHub, Microsoft) to an existing
// account. See docs/architecture/social-login-linking.md for the threat model.
//
// Two ways in:
//
//   - Explicit: a signed-in person links a provider from Account > Security.
//     The start needs a fresh step-up (route gate). The state token carries
//     the account and the session that started the link, signed, and is
//     accepted only by CompleteLink for that same account and session. The
//     provider's address does not have to match the account's: the person
//     proved both.
//   - Automatic, on a social sign-in whose address belongs to a password
//     account, only when all hold: the platform allows it (sign-up policy
//     social_auto_link, on by default), the provider is authoritative for the
//     address (emailAuthoritative: Google on gmail.com/googlemail.com or a
//     Workspace hd equal to the address domain, Microsoft with a domain-owner
//     verified address; never GitHub), the account's address is verified, the
//     account is active and holds no other identity of that provider. Every
//     session of the account is then revoked and a pending password reset
//     link is canceled, the link is audited and the account's mailbox is told.
//
// Either way, a password account signed in through a linked provider takes the
// same second step its password sign-in takes (linkedAccountChallenge): the
// provider replaces the password, never the second factor.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/config"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/domain/useridentity"
)

// Linking errors.
var (
	// ErrIdentityLinkedElsewhere: the provider account is already linked to
	// another account here.
	ErrIdentityLinkedElsewhere = errors.New("this provider account is already linked to another account")
	// ErrProviderAlreadyLinked: the account already has another account of
	// this provider linked; unlink it first.
	ErrProviderAlreadyLinked = errors.New("another account of this provider is already linked; unlink it first")
	// ErrLastSignInMethod: unlinking would leave the account with no way to
	// sign in.
	ErrLastSignInMethod = errors.New("this is the account's only sign-in method")
	// ErrIdentityNotUnlinkable: the identity belongs to an organization's
	// single sign-on and is managed there.
	ErrIdentityNotUnlinkable = errors.New("this sign-in method is managed by your organization")
	// ErrIdentityNotFound: the account has no identity with that id.
	ErrIdentityNotFound = errors.New("sign-in method not found")
)

// SecondFactorGate issues the second step of a sign-in to a password account
// (implemented by AuthService: the same rule as the password sign-in).
type SecondFactorGate interface {
	LinkedSignInChallenge(ctx context.Context, u *userdom.User, ip, ua string) (*MFAChallengeInfo, error)
}

// SessionRevoker revokes every session of an account (SessionService).
type SessionRevoker interface {
	RevokeAllSessions(ctx context.Context, userID, exceptSessionID string) error
}

// IdentityNotifier tells the account's mailbox that a sign-in method was
// linked or unlinked (EmailService). Sends in the background.
type IdentityNotifier interface {
	NotifyIdentityLinked(ctx context.Context, email, name, ipAddress, provider string, automatic bool)
	NotifyIdentityUnlinked(ctx context.Context, email, name, ipAddress, provider string)
}

// SetSecondFactorGate wires the second step for linked password accounts.
// Without it a password account is never signed in through a provider.
func (s *OAuthService) SetSecondFactorGate(g SecondFactorGate) { s.secondFactor = g }

// SetSessionRevoker wires the session revocation automatic linking needs.
// Without it nothing is linked automatically.
func (s *OAuthService) SetSessionRevoker(r SessionRevoker) { s.sessions = r }

// SetIdentityNotifier wires the link and unlink e-mails.
func (s *OAuthService) SetIdentityNotifier(n IdentityNotifier) { s.identityNotifier = n }

// LinkedSignInChallenge is the second step of a sign-in to a password account
// through a linked provider: exactly what its password sign-in would ask
// (loginMFAChallenge), nil when nothing is needed.
func (s *AuthService) LinkedSignInChallenge(ctx context.Context, u *userdom.User, ip, ua string) (*MFAChallengeInfo, error) {
	return s.loginMFAChallenge(ctx, u, ip, ua)
}

// linkedAccountChallenge runs the second-factor gate for a password account.
// Fail closed: without the gate the sign-in is refused.
func (s *OAuthService) linkedAccountChallenge(ctx context.Context, u *userdom.User) (*MFAChallengeInfo, error) {
	if s.secondFactor == nil {
		s.logger.Warn("OAuth sign-in to a password account refused: second-factor gate not wired", "user_id", u.ID().String())
		return nil, ErrOAuthAccountExists
	}
	ci := clientInfoFrom(ctx)
	c, err := s.secondFactor.LinkedSignInChallenge(ctx, u, ci.IP, ci.UserAgent)
	if err != nil {
		return nil, fmt.Errorf("second factor for linked sign-in: %w", err)
	}
	return c, nil
}

// providerOfKey names the social provider of a platform-wide identity, or ""
// for an organization's identity (SAML is scoped; any other OIDC issuer).
func providerOfKey(k useridentity.Key) OAuthProvider {
	if k.ScopeTenantID != nil {
		return ""
	}
	switch {
	case k.Issuer == googleIssuer:
		return OAuthProviderGoogle
	case k.Issuer == githubIssuer:
		return OAuthProviderGitHub
	case strings.HasPrefix(k.Issuer, "https://login.microsoftonline.com/"):
		return OAuthProviderMicrosoft
	}
	return ""
}

// autoLinkAllowed reports whether this sign-in may link itself to u, a
// password account holding the provider's address. Every condition is
// required; see the file comment.
func (s *OAuthService) autoLinkAllowed(ctx context.Context, u *userdom.User, info *OAuthUserInfo, provider OAuthProvider) bool {
	reason := ""
	switch {
	case s.sessions == nil:
		reason = "session revocation not wired"
	case !policyOrConfig(ctx, s.signupPolicy, s.authConfig).AutoLinkSocial():
		reason = "turned off by the platform"
	case !emailAuthoritative(provider, info):
		reason = "provider not authoritative for the address"
	case !u.EmailVerified():
		reason = "account address not verified"
	case !u.IsActive():
		reason = "account not active"
	case !strings.EqualFold(strings.TrimSpace(u.Email()), strings.TrimSpace(info.Email)):
		reason = "address mismatch"
	}
	if reason != "" {
		s.logger.Info("OAuth auto-link not applied", "user_id", u.ID().String(), "provider", provider, "reason", reason)
		return false
	}
	return true
}

// autoLink binds key to u after autoLinkAllowed, then revokes the account's
// sessions and cancels a pending reset link: whoever held them before the
// mailbox owner arrived through the provider loses them.
func (s *OAuthService) autoLink(ctx context.Context, u *userdom.User, key useridentity.Key, provider OAuthProvider) error {
	if err := s.checkLinkable(ctx, u, key, provider); err != nil {
		if errors.Is(err, ErrProviderAlreadyLinked) {
			return ErrOAuthAccountExists
		}
		return err
	}
	if err := s.accounts().bind(ctx, u, key); err != nil {
		return ErrOAuthAccountExists
	}
	if err := s.sessions.RevokeAllSessions(ctx, u.ID().String(), ""); err != nil {
		s.logger.Error("auto-link: revoking the account's sessions failed", "user_id", u.ID().String(), "error", err)
	}
	if u.PasswordResetToken() != nil {
		u.ClearPasswordResetToken()
	}
	s.recordLink(ctx, u, provider, true)
	s.logger.Info("OAuth identity linked automatically to a password account",
		"user_id", u.ID().String(), "provider", provider)
	return nil
}

// checkLinkable refuses a key bound to another account and a second identity
// of the same provider on u. nil means bind may proceed (or key is already
// u's, which bind accepts).
func (s *OAuthService) checkLinkable(ctx context.Context, u *userdom.User, key useridentity.Key, provider OAuthProvider) error {
	if s.identities == nil {
		return errIdentityStoreMissing
	}
	if got, err := s.identities.GetByKey(ctx, key); err == nil {
		if got.UserID != u.ID() {
			return ErrIdentityLinkedElsewhere
		}
		return nil
	} else if !errors.Is(err, useridentity.ErrNotFound) {
		return fmt.Errorf("look up identity: %w", err)
	}
	idents, err := s.identities.ListByUser(ctx, u.ID())
	if err != nil {
		return fmt.Errorf("list identities: %w", err)
	}
	for _, ident := range idents {
		if providerOfKey(ident.Key) == provider && ident.Key.Subject != key.Subject {
			return ErrProviderAlreadyLinked
		}
	}
	return nil
}

// recordLink audits a link and tells the account's mailbox.
func (s *OAuthService) recordLink(ctx context.Context, u *userdom.User, provider OAuthProvider, automatic bool) {
	ci := clientInfoFrom(ctx)
	how := "manual"
	msg := "Linked " + string(provider) + " sign-in to the account"
	if automatic {
		how = "automatic"
		msg = "Linked " + string(provider) + " sign-in to the account automatically on a sign-in with a verified address"
	}
	s.auditIdentity(ctx, u, auditdom.ActionAuthIdentityLinked, msg, provider, how)
	if s.identityNotifier != nil {
		s.identityNotifier.NotifyIdentityLinked(ctx, u.Email(), u.Name(), ci.IP, providerLabel(provider), automatic)
	}
}

func (s *OAuthService) auditIdentity(ctx context.Context, u *userdom.User, action auditdom.Action, msg string, provider OAuthProvider, how string) {
	if s.audit == nil {
		return
	}
	ci := clientInfoFrom(ctx)
	ev := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeUser, u.ID().String()).
		WithResourceName(u.Email()).
		WithMessage(msg).
		WithMetadata("provider", string(provider))
	if how != "" {
		ev = ev.WithMetadata("how", how)
	}
	actx := auditapp.AuditContext{ActorID: u.ID().String(), ActorEmail: u.Email(), ActorIP: ci.IP, UserAgent: ci.UserAgent}
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.logger.Error("failed to audit identity change", "action", string(action), "error", err)
	}
}

// providerLabel is the provider's display name for e-mails.
func providerLabel(p OAuthProvider) string {
	switch p {
	case OAuthProviderGoogle:
		return "Google"
	case OAuthProviderGitHub:
		return "GitHub"
	case OAuthProviderMicrosoft:
		return "Microsoft"
	}
	return string(p)
}

// SignInMethod is one way to sign in to the account, for Account > Security.
type SignInMethod struct {
	ID string `json:"id"`
	// Provider: google, github or microsoft; organization for an
	// organization's single sign-on (read only here).
	Provider   string     `json:"provider"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	// Unlinkable: the person may remove it now (a social identity that is not
	// the account's last sign-in method).
	Unlinkable bool `json:"unlinkable"`
}

// SignInMethods lists the account's sign-in methods.
type SignInMethods struct {
	// Password: the account signs in with a password.
	Password   bool           `json:"password"`
	Identities []SignInMethod `json:"identities"`
	// Available: social providers this platform offers for linking.
	Available []string `json:"available"`
}

// ListSignInMethods returns the account's sign-in methods. Only the caller's
// own account is ever read (userID comes from the session).
func (s *OAuthService) ListSignInMethods(ctx context.Context, userID string) (*SignInMethods, error) {
	u, idents, err := s.accountAndIdentities(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := &SignInMethods{Password: isPasswordAccount(u), Identities: []SignInMethod{}, Available: []string{}}
	total := len(idents)
	if out.Password {
		total++
	}
	for _, ident := range idents {
		p := providerOfKey(ident.Key)
		m := SignInMethod{ID: ident.ID.String(), Provider: string(p), CreatedAt: ident.CreatedAt, LastUsedAt: ident.LastUsedAt}
		if p == "" {
			m.Provider = "organization"
		} else {
			m.Unlinkable = total > 1
		}
		out.Identities = append(out.Identities, m)
	}
	if s.config.Enabled {
		for _, p := range []OAuthProvider{OAuthProviderGoogle, OAuthProviderGitHub, OAuthProviderMicrosoft} {
			if cfg := s.getProviderConfig(p); cfg != nil && cfg.IsConfigured() {
				out.Available = append(out.Available, string(p))
			}
		}
	}
	return out, nil
}

func (s *OAuthService) accountAndIdentities(ctx context.Context, userID string) (*userdom.User, []*useridentity.Identity, error) {
	if s.identities == nil {
		return nil, nil, errIdentityStoreMissing
	}
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: invalid user id", shared.ErrValidation)
	}
	u, err := s.userRepo.GetByID(ctx, uid)
	if err != nil {
		return nil, nil, fmt.Errorf("load account: %w", err)
	}
	idents, err := s.identities.ListByUser(ctx, uid)
	if err != nil {
		return nil, nil, fmt.Errorf("list identities: %w", err)
	}
	return u, idents, nil
}

// LinkStartInput starts linking a provider to the signed-in account.
type LinkStartInput struct {
	UserID      string
	SessionID   string
	Provider    OAuthProvider
	RedirectURI string
}

// StartLink returns the provider's authorization URL for a link. The caller
// already passed step-up (route gate).
func (s *OAuthService) StartLink(ctx context.Context, in LinkStartInput) (*AuthorizationURLResult, error) {
	cfg, err := s.readyProvider(in.Provider)
	if err != nil {
		return nil, err
	}
	if in.UserID == "" || in.SessionID == "" {
		return nil, ErrInvalidState
	}
	u, _, err := s.accountAndIdentities(ctx, in.UserID)
	if err != nil {
		return nil, err
	}
	if !u.IsActive() {
		return nil, ErrAccountSuspended
	}
	state, verifier, err := s.generateState(in.Provider, "", &linkBinding{UserID: in.UserID, SessionID: in.SessionID})
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}
	if err := s.pkceStore.Set(ctx, pkceStoreKey(state), verifier, s.stateTTL()); err != nil {
		return nil, fmt.Errorf("failed to store PKCE verifier: %w", err)
	}
	authURL, err := s.buildAuthorizationURL(in.Provider, cfg, in.RedirectURI, state, verifier)
	if err != nil {
		return nil, fmt.Errorf("failed to build authorization URL: %w", err)
	}
	return &AuthorizationURLResult{AuthorizationURL: authURL, State: state}, nil
}

// LinkCompleteInput finishes a link started by StartLink.
type LinkCompleteInput struct {
	UserID      string
	SessionID   string
	Provider    OAuthProvider
	Code        string
	State       string
	RedirectURI string
}

// CompleteLink binds the provider identity to the signed-in account. The
// state must be a link state minted for this account and this session.
func (s *OAuthService) CompleteLink(ctx context.Context, in LinkCompleteInput) (*SignInMethod, error) {
	cfg, err := s.readyProvider(in.Provider)
	if err != nil {
		return nil, err
	}
	claims, err := s.validateState(in.State, in.Provider)
	if err != nil || claims.Purpose != statePurposeLink ||
		claims.UserID == "" || claims.UserID != in.UserID ||
		claims.SessionID == "" || claims.SessionID != in.SessionID {
		return nil, ErrInvalidState
	}
	verifier, found, err := s.pkceStore.GetDel(ctx, pkceStoreKey(in.State))
	if err != nil || !found || verifier == "" {
		return nil, ErrInvalidState
	}
	tokens, err := s.exchangeCode(ctx, in.Provider, cfg, in.Code, in.RedirectURI, verifier)
	if err != nil {
		s.logger.Error("link: failed to exchange OAuth code", "provider", in.Provider, "error", err)
		return nil, ErrOAuthExchangeFailed
	}
	info, err := s.getUserInfo(ctx, in.Provider, tokens)
	if err != nil {
		s.logger.Error("link: failed to get user info", "provider", in.Provider, "error", err)
		return nil, ErrOAuthUserInfoFailed
	}
	return s.linkIdentity(ctx, in.UserID, info, in.Provider)
}

// linkIdentity binds a verified provider identity to the account userID
// (explicit link, after the provider round trip).
func (s *OAuthService) linkIdentity(ctx context.Context, userID string, info *OAuthUserInfo, provider OAuthProvider) (*SignInMethod, error) {
	key := useridentity.Key{Issuer: info.Issuer, Subject: info.Subject}
	if !key.Valid() {
		return nil, ErrOAuthUserInfoFailed
	}
	u, _, err := s.accountAndIdentities(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !u.IsActive() {
		return nil, ErrAccountSuspended
	}
	// A legacy subject (Entra sub before oid) is re-keyed by lookup.
	if owner, _, lerr := s.accounts().lookup(ctx, key, info.LegacySubject); lerr != nil {
		return nil, fmt.Errorf("resolve federated identity: %w", lerr)
	} else if owner != nil && owner.ID() != u.ID() {
		return nil, ErrIdentityLinkedElsewhere
	}
	if err := s.checkLinkable(ctx, u, key, provider); err != nil {
		return nil, err
	}
	if err := s.accounts().bind(ctx, u, key); err != nil {
		if errors.Is(err, ErrFederatedIdentityConflict) {
			return nil, ErrIdentityLinkedElsewhere
		}
		return nil, err
	}
	s.recordLink(ctx, u, provider, false)
	got, err := s.identities.GetByKey(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("read linked identity: %w", err)
	}
	return &SignInMethod{ID: got.ID.String(), Provider: string(provider), CreatedAt: got.CreatedAt, LastUsedAt: got.LastUsedAt}, nil
}

// Unlink removes a social identity from the signed-in account. The caller
// already passed step-up (route gate). The account's last sign-in method is
// never removed.
func (s *OAuthService) Unlink(ctx context.Context, userID, identityID string) error {
	u, idents, err := s.accountAndIdentities(ctx, userID)
	if err != nil {
		return err
	}
	var target *useridentity.Identity
	for _, ident := range idents {
		if ident.ID.String() == identityID {
			target = ident
		}
	}
	if target == nil {
		return ErrIdentityNotFound
	}
	provider := providerOfKey(target.Key)
	if provider == "" {
		return ErrIdentityNotUnlinkable
	}
	hasPassword := isPasswordAccount(u)
	if !hasPassword && len(idents) <= 1 {
		return ErrLastSignInMethod
	}
	if err := s.identities.DeleteForUser(ctx, u.ID(), target.ID, !hasPassword); err != nil {
		switch {
		case errors.Is(err, useridentity.ErrLastIdentity):
			return ErrLastSignInMethod
		case errors.Is(err, useridentity.ErrNotFound):
			return ErrIdentityNotFound
		}
		return fmt.Errorf("unlink identity: %w", err)
	}
	s.auditIdentity(ctx, u, auditdom.ActionAuthIdentityUnlinked, "Unlinked "+string(provider)+" sign-in from the account", provider, "")
	if s.identityNotifier != nil {
		s.identityNotifier.NotifyIdentityUnlinked(ctx, u.Email(), u.Name(), clientInfoFrom(ctx).IP, providerLabel(provider))
	}
	return nil
}

// readyProvider checks social sign-in is on and the provider configured.
func (s *OAuthService) readyProvider(p OAuthProvider) (*config.OAuthProviderConfig, error) {
	if !s.config.Enabled {
		return nil, ErrOAuthDisabled
	}
	if !p.IsValid() {
		return nil, ErrInvalidProvider
	}
	cfg := s.getProviderConfig(p)
	if cfg == nil || !cfg.IsConfigured() {
		return nil, ErrProviderDisabled
	}
	return cfg, nil
}
