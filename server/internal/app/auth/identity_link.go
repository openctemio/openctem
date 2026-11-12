package auth

// Linking social sign-in identities (Google, GitHub, Microsoft) to an existing
// account. See docs/architecture/social-login-linking.md for the threat model.
//
// Three ways in:
//
//   - Explicit: a signed-in person links a provider from Account > Security.
//     The start needs a proof typed for it (link_proof.go: an authenticator
//     code, else the password; a recent sign-in does not count), and so does
//     unlinking. The state token carries
//     the account and the session that started the link, signed, and is
//     accepted only by CompleteLink for that same account and session, once,
//     before it expires, and only from the browser that started the link: its
//     PKCE verifier is stored with the hash of a one-time browser-binding
//     secret (storeBoundVerifier, shared with sign-in) that the browser holds
//     in an HttpOnly cookie and presents at completion. The
//     provider's address does not have to match the account's: the person
//     proved both.
//   - After signing in (pending_link.go): a social sign-in whose address
//     belongs to an existing account changes nothing and is refused with
//     OAUTH_ACCOUNT_EXISTS, carrying a single-use pending link bound to that
//     provider identity and that account. The person signs in to the account
//     the usual way (password and second factor) and confirms the link
//     with a proof typed in the confirm dialog (link_proof.go).
//
// A collision with an existing account never links by itself: there is no
// setting that turns that on, because the provider's word about an address is
// not proof the person owns the account.
//
// A password account signed in through a linked provider takes the
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
	NotifyIdentityLinked(ctx context.Context, email, name, ipAddress, provider string)
	NotifyIdentityUnlinked(ctx context.Context, email, name, ipAddress, provider string)
}

// SetSecondFactorGate wires the second step for linked password accounts.
// Without it a password account is never signed in through a provider.
func (s *OAuthService) SetSecondFactorGate(g SecondFactorGate) { s.secondFactor = g }

// SetSessionRevoker wires the session revocation every link and unlink
// needs: the account's other sessions end. Without it CompleteLink and Unlink
// are refused.
func (s *OAuthService) SetSessionRevoker(r SessionRevoker) { s.sessions = r }

// SetLinkProofVerifier wires the proof every link and unlink needs
// (link_proof.go). Without it every link and unlink is refused.
func (s *OAuthService) SetLinkProofVerifier(v LinkProofVerifier) { s.linkProof = v }

// verifyLinkProof checks the proof typed for one change of u's sign-in
// methods. Fail closed: without a verifier nothing changes.
func (s *OAuthService) verifyLinkProof(ctx context.Context, u *userdom.User, sessionID string, proof StepUpProof, purpose string) (StepUpMethod, error) {
	if s.linkProof == nil {
		return stepUpNothingNeeded, ErrLinkProofUnavailable
	}
	ci := clientInfoFrom(ctx)
	actx := auditapp.AuditContext{ActorID: u.ID().String(), ActorEmail: u.Email(), ActorIP: ci.IP, UserAgent: ci.UserAgent}
	return s.linkProof.VerifyLinkProof(ctx, actx, u.ID().String(), sessionID, proof, purpose)
}

// linkProofMethod is what userID must type to change its sign-in methods
// ("" when it cannot, or when no verifier is wired).
func (s *OAuthService) linkProofMethod(ctx context.Context, userID string) string {
	if s.linkProof == nil {
		return ""
	}
	m, err := s.linkProof.LinkProofMethod(ctx, userID)
	if err != nil {
		return ""
	}
	return string(m)
}

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

// socialProviderOf names the social provider of an identity the person may
// manage from Account > Security, or "" for one an organization's single
// sign-on manages. An organization's Entra ID or Google Workspace sign-on
// stores the same unscoped issuer as the social button, so the issuer alone
// does not tell them apart: the identity's source does.
func socialProviderOf(ident *useridentity.Identity) OAuthProvider {
	if ident == nil || ident.ManagedBySSO() {
		return ""
	}
	return providerOfKey(ident.Key)
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
		if !ident.ManagedBySSO() && providerOfKey(ident.Key) == provider && ident.Key.Subject != key.Subject {
			return ErrProviderAlreadyLinked
		}
	}
	return nil
}

// How a provider identity came to be linked (audit metadata "how").
const (
	// linkHowManual: from Account > Security, after a step-up.
	linkHowManual = "manual"
	// linkHowAfterSignIn: confirmed right after signing in to the account,
	// from the pending link a refused social sign-in left (pending_link.go).
	linkHowAfterSignIn = "after_sign_in"
)

// recordLink audits a link and tells the account's mailbox.
func (s *OAuthService) recordLink(ctx context.Context, u *userdom.User, provider OAuthProvider, how string, factor StepUpMethod) {
	ci := clientInfoFrom(ctx)
	msg := "Linked " + string(provider) + " sign-in to the account"
	switch how {
	case linkHowAfterSignIn:
		msg = "Linked " + string(provider) + " sign-in to the account, confirmed after signing in"
	}
	s.auditIdentity(ctx, u, auditdom.ActionAuthIdentityLinked, msg, provider, how, factor)
	if s.identityNotifier != nil {
		s.identityNotifier.NotifyIdentityLinked(ctx, u.Email(), u.Name(), ci.IP, providerLabel(provider))
	}
}

func (s *OAuthService) auditIdentity(ctx context.Context, u *userdom.User, action auditdom.Action, msg string, provider OAuthProvider, how string, factor StepUpMethod) {
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
	// factor: what the person typed to confirm the change (totp or
	// password); empty for an automatic link.
	if factor != "" {
		ev = ev.WithMetadata("factor", string(factor))
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
	// Proof is what linking or unlinking asks for in the confirm dialog:
	// totp, password, or "" when the account has neither (it must turn on
	// two-factor authentication first).
	Proof string `json:"proof"`
}

// ListSignInMethods returns the account's sign-in methods. Only the caller's
// own account is ever read (userID comes from the session).
func (s *OAuthService) ListSignInMethods(ctx context.Context, userID string) (*SignInMethods, error) {
	u, idents, err := s.accountAndIdentities(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := &SignInMethods{Password: isPasswordAccount(u), Identities: []SignInMethod{}, Available: []string{}, Proof: s.linkProofMethod(ctx, userID)}
	total := len(idents)
	if out.Password {
		total++
	}
	for _, ident := range idents {
		p := socialProviderOf(ident)
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
			if cfg := s.getProviderConfig(ctx, p); cfg != nil && cfg.IsConfigured() {
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
	// Proof is the code or password typed in the confirm dialog
	// (link_proof.go).
	Proof StepUpProof
}

// StartLink returns the provider's authorization URL for a link after
// checking the proof typed for it. The factor is kept with the link's PKCE
// verifier, so CompleteLink audits it and refuses a link whose start was
// never proved.
func (s *OAuthService) StartLink(ctx context.Context, in LinkStartInput) (*AuthorizationURLResult, error) {
	cfg, err := s.readyProvider(ctx, in.Provider)
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
	factor, err := s.verifyLinkProof(ctx, u, in.SessionID, in.Proof, LinkProofLinkStart)
	if err != nil {
		return nil, err
	}
	state, verifier, err := s.generateState(in.Provider, "", &linkBinding{UserID: in.UserID, SessionID: in.SessionID})
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}
	binding, err := s.storeBoundVerifier(ctx, state, verifier)
	if err != nil {
		return nil, err
	}
	if err := s.pkceStore.Set(ctx, linkFactorKey(state), string(factor), s.stateTTL()); err != nil {
		return nil, fmt.Errorf("store link proof: %w", err)
	}
	authURL, err := s.buildAuthorizationURL(in.Provider, cfg, in.RedirectURI, state, verifier)
	if err != nil {
		return nil, fmt.Errorf("failed to build authorization URL: %w", err)
	}
	return &AuthorizationURLResult{AuthorizationURL: authURL, State: state, BrowserBinding: binding}, nil
}

// LinkCompleteInput finishes a link started by StartLink.
type LinkCompleteInput struct {
	UserID      string
	SessionID   string
	Provider    OAuthProvider
	Code        string
	State       string
	RedirectURI string
	// BrowserBinding is the secret StartLink returned to this browser.
	BrowserBinding string
}

// CompleteLink binds the provider identity to the signed-in account. The
// state must be a link state minted for this account and this session.
func (s *OAuthService) CompleteLink(ctx context.Context, in LinkCompleteInput) (*SignInMethod, error) {
	cfg, err := s.readyProvider(ctx, in.Provider)
	if err != nil {
		return nil, err
	}
	claims, err := s.validateState(in.State, in.Provider)
	if err != nil || claims.Purpose != statePurposeLink ||
		claims.UserID == "" || claims.UserID != in.UserID ||
		claims.SessionID == "" || claims.SessionID != in.SessionID {
		return nil, ErrInvalidState
	}
	verifier, ok := s.claimBoundVerifier(ctx, in.State, in.BrowserBinding, in.Provider)
	if !ok {
		return nil, ErrInvalidState
	}
	factor, ok := s.takeLinkFactor(ctx, in.State)
	if !ok {
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
	// The account's other sessions end before the new sign-in method exists;
	// the session that proved the link keeps going. Fail closed: when the
	// revoke fails nothing is linked.
	if err := s.revokeOtherSessions(ctx, in.UserID, in.SessionID, "link"); err != nil {
		return nil, err
	}
	return s.linkIdentity(ctx, in.UserID, info, in.Provider, linkHowManual, factor)
}

// errSessionRevokerMissing refuses a change of sign-in methods when the
// session revocation it needs is not wired.
var errSessionRevokerMissing = errors.New("session revocation not configured")

// revokeOtherSessions ends every session of userID but keepSessionID, before
// a change of the account's sign-in methods. An error means the change must
// not happen.
func (s *OAuthService) revokeOtherSessions(ctx context.Context, userID, keepSessionID, change string) error {
	if s.sessions == nil {
		s.logger.Error("sign-in method change refused: session revocation not wired", "change", change, "user_id", userID)
		return errSessionRevokerMissing
	}
	if err := s.sessions.RevokeAllSessions(ctx, userID, keepSessionID); err != nil {
		s.logger.Error("sign-in method change refused: revoking the account's other sessions failed",
			"change", change, "user_id", userID, "error", err)
		return fmt.Errorf("revoke other sessions before the %s: %w", change, err)
	}
	return nil
}

// linkFactorKey is where StartLink keeps the factor that proved a link start,
// under the hash of the state, until CompleteLink takes it.
func linkFactorKey(state string) string { return "oauth_link_factor:" + hashBinding(state) }

// takeLinkFactor removes and returns the factor StartLink verified for state.
// False when there is none (never proved, expired, or already used).
func (s *OAuthService) takeLinkFactor(ctx context.Context, state string) (StepUpMethod, bool) {
	raw, found, err := s.pkceStore.GetDel(ctx, linkFactorKey(state))
	if err != nil {
		s.logger.Error("link: failed to read the link proof", "error", err)
		return stepUpNothingNeeded, false
	}
	m := StepUpMethod(raw)
	if !found || (m != StepUpTOTP && m != StepUpPassword) {
		return stepUpNothingNeeded, false
	}
	return m, true
}

// linkIdentity binds a verified provider identity to the account userID
// (explicit link after the provider round trip, or a confirmed pending link).
// factor is the proof the person typed for it (audited).
func (s *OAuthService) linkIdentity(ctx context.Context, userID string, info *OAuthUserInfo, provider OAuthProvider, how string, factor StepUpMethod) (*SignInMethod, error) {
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
	s.recordLink(ctx, u, provider, how, factor)
	got, err := s.identities.GetByKey(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("read linked identity: %w", err)
	}
	return &SignInMethod{ID: got.ID.String(), Provider: string(provider), CreatedAt: got.CreatedAt, LastUsedAt: got.LastUsedAt}, nil
}

// UnlinkInput removes one social identity from the signed-in account.
type UnlinkInput struct {
	UserID     string
	SessionID  string
	IdentityID string
	// Proof is the code or password typed in the confirm dialog.
	Proof StepUpProof
}

// Unlink removes a social identity from the signed-in account after checking
// the proof typed for it. The account's last sign-in method is never removed.
func (s *OAuthService) Unlink(ctx context.Context, in UnlinkInput) error {
	userID, identityID := in.UserID, in.IdentityID
	if userID == "" || in.SessionID == "" {
		return ErrLinkProofUnavailable
	}
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
	provider := socialProviderOf(target)
	if provider == "" {
		return ErrIdentityNotUnlinkable
	}
	hasPassword := isPasswordAccount(u)
	if !hasPassword && len(idents) <= 1 {
		return ErrLastSignInMethod
	}
	factor, err := s.verifyLinkProof(ctx, u, in.SessionID, in.Proof, LinkProofUnlink)
	if err != nil {
		return err
	}
	// A session opened through the provider (perhaps by whoever made the
	// person unlink it) must not outlive the unlink. Revoke first and fail
	// closed: when the revoke fails the identity stays, so the person sees
	// the failure and can retry; a revoke followed by a failed delete only
	// signs the account's other devices out.
	if err := s.revokeOtherSessions(ctx, u.ID().String(), in.SessionID, "unlink"); err != nil {
		return err
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
	s.auditIdentity(ctx, u, auditdom.ActionAuthIdentityUnlinked, "Unlinked "+string(provider)+" sign-in from the account", provider, "", factor)
	if s.identityNotifier != nil {
		s.identityNotifier.NotifyIdentityUnlinked(ctx, u.Email(), u.Name(), clientInfoFrom(ctx).IP, providerLabel(provider))
	}
	return nil
}

// readyProvider checks social sign-in is on and the provider configured.
func (s *OAuthService) readyProvider(ctx context.Context, p OAuthProvider) (*config.OAuthProviderConfig, error) {
	if !s.config.Enabled {
		return nil, ErrOAuthDisabled
	}
	if !p.IsValid() {
		return nil, ErrInvalidProvider
	}
	cfg := s.getProviderConfig(ctx, p)
	if cfg == nil || !cfg.IsConfigured() {
		return nil, ErrProviderDisabled
	}
	return cfg, nil
}
