package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/config"
	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
	"github.com/openctemio/openctem/api/pkg/domain/signupevent"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/domain/useridentity"
	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/oidc"
)

// OAuth errors.
var (
	ErrOAuthDisabled       = errors.New("OAuth is disabled")
	ErrProviderDisabled    = errors.New("OAuth provider is disabled")
	ErrInvalidProvider     = errors.New("invalid OAuth provider")
	ErrInvalidState        = errors.New("invalid OAuth state")
	ErrOAuthExchangeFailed = errors.New("failed to exchange OAuth code")
	ErrOAuthUserInfoFailed = errors.New("failed to get user info from OAuth provider")
	// ErrOAuthAccountExists: the provider's email names an account that signs
	// in another way (a password, or another provider) and this provider
	// identity is not linked to it. Nothing was written. The person signs in
	// the usual way and links the provider from their account settings.
	ErrOAuthAccountExists = errors.New("an account with this email already exists; sign in to it and link this provider")
	// ErrOAuthUseOrgSSO: the provider identity is one an organization's single
	// sign-on created and manages. The social button never signs it in: the
	// person never confirmed that route. Nothing was written, no session opens.
	ErrOAuthUseOrgSSO = errors.New("this account signs in through your organization; use your organization's sign-in")
	// ErrOAuthNoEmail: the provider returned no email address.
	ErrOAuthNoEmail = errors.New("the OAuth provider did not return an email address")
)

// OAuthProvider represents a supported OAuth provider.
type OAuthProvider string

const (
	OAuthProviderGoogle    OAuthProvider = "google"
	OAuthProviderGitHub    OAuthProvider = "github"
	OAuthProviderMicrosoft OAuthProvider = "microsoft"
)

// IsValid checks if the provider is valid.
func (p OAuthProvider) IsValid() bool {
	switch p {
	case OAuthProviderGoogle, OAuthProviderGitHub, OAuthProviderMicrosoft:
		return true
	}
	return false
}

// ToAuthProvider converts OAuthProvider to userdom.AuthProvider.
func (p OAuthProvider) ToAuthProvider() userdom.AuthProvider {
	switch p {
	case OAuthProviderGoogle:
		return userdom.AuthProviderGoogle
	case OAuthProviderGitHub:
		return userdom.AuthProviderGitHub
	case OAuthProviderMicrosoft:
		return userdom.AuthProviderMicrosoft
	}
	return userdom.AuthProviderLocal
}

// OAuthService handles OAuth authentication.
type OAuthService struct {
	// signups records sign-up events for the platform console (optional).
	signups signupevent.Recorder
	// onSignIn runs after a sign-in created a session (signin_hook.go).
	onSignIn SignInHook
	// audit records each sign-in (auth.login), as the password sign-in does.
	audit            *auditapp.AuditService
	userRepo         userdom.Repository
	sessionRepo      sessiondom.Repository
	refreshTokenRepo sessiondom.RefreshTokenRepository
	tokenGenerator   *jwt.Generator
	config           config.OAuthConfig
	providers        ProviderSource
	authConfig       config.AuthConfig
	logger           *logger.Logger
	breakGlassGate   BreakGlassGate
	httpClient       *http.Client
	// oidcVerifier validates the signed id_token for providers that return one
	// (Microsoft/Entra), so identity is taken from verified claims rather than
	// a mutable directory attribute. See getMicrosoftUserInfo.
	oidcVerifier *oidc.Client
	// pkceStore holds each login's PKCE code_verifier server-side, keyed by
	// its state, until the callback consumes it.
	pkceStore PKCEVerifierStore
	// signupPolicy decides whether a social sign-in may create an account
	// (signup.Admit). Nil: SIGNUP_MODE from the config.
	signupPolicy signupdom.PolicySource
	// signupDomains: per-domain sign-up policy of claimed domains.
	signupDomains signupdom.DomainPolicySource
	// invitations answers whether a pending invitation is addressed to an
	// email (an invited person may sign up with Google/GitHub/Microsoft).
	invitations InvitationLookup
	// identities binds accounts to the provider's (issuer, subject); a login
	// finds the account by it first (federated_identity.go). Required.
	identities useridentity.Repository
	// claimMembers and claimDomains vouch for a claimable account before a
	// social sign-in adopts it (oauth_claim_guard.go). Unset: never adopted.
	claimMembers ClaimMembershipSource
	claimDomains DomainVerifier
	// secondFactor, sessions and identityNotifier serve linked identities
	// (identity_link.go): the second step of a linked password account, the
	// session revocation of an automatic link, and the link e-mails.
	secondFactor     SecondFactorGate
	sessions         SessionRevoker
	identityNotifier IdentityNotifier
	// linkProof checks the code or password typed to link or unlink a
	// sign-in method (link_proof.go). Unset: nothing is linked or unlinked.
	linkProof LinkProofVerifier
}

// InvitationLookup answers whether any organization has a pending invitation
// for an email. Implemented by the tenant repository.
type InvitationLookup interface {
	HasPendingInvitationForEmail(ctx context.Context, email string) (bool, error)
}

// SetSignupPolicy wires the platform sign-up policy (the console setting).
// SetAuditService wires the auth.login event for social sign-ins.
func (s *OAuthService) SetAuditService(a *auditapp.AuditService) { s.audit = a }

func (s *OAuthService) SetSignupPolicy(p signupdom.PolicySource) { s.signupPolicy = p }

// SetSignupDomainPolicy wires the per-domain sign-up policy of claimed
// domains.
func (s *OAuthService) SetSignupDomainPolicy(src signupdom.DomainPolicySource) { s.signupDomains = src }

// SetInvitationLookup wires the pending-invitation check.
func (s *OAuthService) SetInvitationLookup(l InvitationLookup) { s.invitations = l }

// invitedPending reports whether a pending invitation is addressed to email.
// A lookup error counts as not invited (fail-closed).
func (s *OAuthService) invitedPending(ctx context.Context, email string) bool {
	if s.invitations == nil {
		return false
	}
	ok, err := s.invitations.HasPendingInvitationForEmail(ctx, email)
	if err != nil {
		s.logger.Warn("pending-invitation lookup failed; treating as not invited", "error", err)
		return false
	}
	return ok
}

// SetIdentityRepo wires the federated identity store.
func (s *OAuthService) SetIdentityRepo(repo useridentity.Repository) {
	s.identities = repo
}

func (s *OAuthService) accounts() federatedAccounts {
	return federatedAccounts{identities: s.identities, users: s.userRepo, logger: s.logger, source: useridentity.SourceSocial}
}

// Canonical issuers of the social providers' account bindings. Google's
// identity comes from its verified id_token (either issuer spelling) and is
// stored under this one; GitHub has no id_token, so its identity comes from
// its own API over the access token.
const (
	googleIssuer = "https://accounts.google.com"
	githubIssuer = "https://github.com"
)

// SetPKCEStore replaces the PKCE verifier store. Production wires the Redis
// store so a login started on one replica can finish on another; the default
// is in-process.
func (s *OAuthService) SetPKCEStore(store PKCEVerifierStore) {
	if store != nil {
		s.pkceStore = store
	}
}

// pkceStoreKey derives the store key from the signed state.
func pkceStoreKey(state string) string {
	sum := sha256.Sum256([]byte(state))
	return "oauth_pkce:" + hex.EncodeToString(sum[:])
}

// NewOAuthService creates a new OAuthService.
func NewOAuthService(
	userRepo userdom.Repository,
	sessionRepo sessiondom.Repository,
	refreshTokenRepo sessiondom.RefreshTokenRepository,
	oauthCfg config.OAuthConfig,
	authCfg config.AuthConfig,
	log *logger.Logger,
) *OAuthService {
	tokenGen := jwt.NewGenerator(jwt.TokenConfig{
		Secret:               authCfg.JWTSecret,
		Issuer:               authCfg.JWTIssuer,
		AccessTokenDuration:  authCfg.AccessTokenDuration,
		RefreshTokenDuration: authCfg.RefreshTokenDuration,
	})

	return &OAuthService{
		userRepo:         userRepo,
		sessionRepo:      sessionRepo,
		refreshTokenRepo: refreshTokenRepo,
		tokenGenerator:   tokenGen,
		config:           oauthCfg,
		authConfig:       authCfg,
		logger:           log.With("service", "oauth"),
		// SSRF: OAuth userinfo + token endpoints for Google / GitHub /
		// Microsoft are hardcoded strings in this file, so no SSRF via
		// config. Using SafeHTTPClient remains valuable: if a follow-
		// redirect ever lands on a tenant-controlled host, the dialer
		// refuses the connection instead of silently following.
		httpClient:   httpsec.SafeHTTPClient(30 * time.Second),
		oidcVerifier: newOIDCClient(httpsec.SafeHTTPClient(30 * time.Second)),
		pkceStore:    NewMemoryPKCEStore(),
	}
}

// AuthorizationURLInput represents input for getting authorization URL.
type AuthorizationURLInput struct {
	Provider      OAuthProvider
	RedirectURI   string // Frontend callback URL
	FinalRedirect string // Where to redirect after successful auth
}

// AuthorizationURLResult represents the result of getting authorization URL.
type AuthorizationURLResult struct {
	AuthorizationURL string `json:"authorization_url"`
	State            string `json:"state"`
	// BrowserBinding is a one-time secret for the browser that started the
	// flow, returned with the callback to prove the state is its own.
	BrowserBinding string `json:"browser_binding"`
}

// GetAuthorizationURL returns the OAuth authorization URL for the specified provider.
func (s *OAuthService) GetAuthorizationURL(ctx context.Context, input AuthorizationURLInput) (*AuthorizationURLResult, error) {
	if !s.config.Enabled {
		return nil, ErrOAuthDisabled
	}

	if !input.Provider.IsValid() {
		return nil, ErrInvalidProvider
	}

	providerConfig := s.getProviderConfig(ctx, input.Provider)
	if providerConfig == nil || !providerConfig.IsConfigured() {
		return nil, ErrProviderDisabled
	}

	// Generate state token with PKCE for CSRF + code interception protection
	state, codeVerifier, err := s.generateState(input.Provider, input.FinalRedirect, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}
	binding, err := s.storeBoundVerifier(ctx, state, codeVerifier)
	if err != nil {
		return nil, err
	}

	// Build authorization URL with PKCE challenge
	authURL, err := s.buildAuthorizationURL(input.Provider, providerConfig, input.RedirectURI, state, codeVerifier)
	if err != nil {
		return nil, fmt.Errorf("failed to build authorization URL: %w", err)
	}

	return &AuthorizationURLResult{
		AuthorizationURL: authURL,
		State:            state,
		BrowserBinding:   binding,
	}, nil
}

// CallbackInput represents the OAuth callback input.
type CallbackInput struct {
	Provider    OAuthProvider
	Code        string
	State       string
	RedirectURI string
	// BrowserBinding is the secret the authorize call returned to this browser.
	BrowserBinding string
}

// CallbackResult represents the OAuth callback result.
type CallbackResult struct {
	AccessToken  string        `json:"access_token"`
	RefreshToken string        `json:"refresh_token"`
	ExpiresIn    int64         `json:"expires_in"`
	TokenType    string        `json:"token_type"`
	User         *userdom.User `json:"user"`
	// MFAChallenge is set when the account is a password account with a
	// second factor (or an organization requires one): no session was
	// issued, and the challenge opens the same second step a password
	// sign-in takes (POST /auth/mfa/verify or the enrollment steps).
	MFAChallenge *MFAChallengeInfo `json:"-"`
}

// HandleCallback handles the OAuth callback.
func (s *OAuthService) HandleCallback(ctx context.Context, input CallbackInput) (*CallbackResult, error) {
	if !s.config.Enabled {
		return nil, ErrOAuthDisabled
	}

	if !input.Provider.IsValid() {
		return nil, ErrInvalidProvider
	}

	providerConfig := s.getProviderConfig(ctx, input.Provider)
	if providerConfig == nil || !providerConfig.IsConfigured() {
		return nil, ErrProviderDisabled
	}

	// Validate state, then claim its PKCE verifier. Taking it is single use:
	// a replayed state finds nothing and is refused before any code exchange.
	claims, err := s.validateState(input.State, input.Provider)
	if err != nil {
		return nil, ErrInvalidState
	}
	// A link state signs nobody in: it belongs to CompleteLink.
	if claims.Purpose != "" {
		return nil, ErrInvalidState
	}
	finalRedirect := claims.FinalRedirect
	codeVerifier, ok := s.claimBoundVerifier(ctx, input.State, input.BrowserBinding, input.Provider)
	if !ok {
		return nil, ErrInvalidState
	}

	// Exchange code for tokens (includes PKCE code_verifier)
	tokens, err := s.exchangeCode(ctx, input.Provider, providerConfig, input.Code, input.RedirectURI, codeVerifier)
	if err != nil {
		s.logger.Error("failed to exchange OAuth code", "provider", input.Provider, "error", err)
		return nil, ErrOAuthExchangeFailed
	}

	// Get user info from provider
	userInfo, err := s.getUserInfo(ctx, input.Provider, tokens)
	if err != nil {
		if errors.Is(err, ErrEmailUnverifiedAtIDP) {
			s.logger.Warn("social sign-in refused: email not verified by the provider", "provider", input.Provider)
			return nil, ErrEmailUnverifiedAtIDP
		}
		s.logger.Error("failed to get user info", "provider", input.Provider, "error", err)
		return nil, ErrOAuthUserInfoFailed
	}

	// SECURITY: Require email from OAuth provider
	if userInfo.Email == "" {
		return nil, ErrOAuthNoEmail
	}

	return s.signIn(ctx, userInfo, input.Provider, finalRedirect)
}

// signIn finishes a social sign-in for a provider-verified identity: the
// account, the platform-administrator refusal, the second step of a linked
// password account, then the session.
func (s *OAuthService) signIn(ctx context.Context, userInfo *OAuthUserInfo, provider OAuthProvider, finalRedirect string) (*CallbackResult, error) {
	u, err := s.findOrCreateUser(ctx, userInfo, provider)
	if err != nil {
		return nil, fmt.Errorf("failed to find or create user: %w", err)
	}

	// A break-glass account signs in on the admin console only; the answer is
	// the generic provider failure.
	if refuseBreakGlass(ctx, s.breakGlassGate, s.logger, u, "oauth") {
		return nil, ErrOAuthExchangeFailed
	}

	// A password account reached through a linked provider takes the same
	// second step as its password sign-in (identity_link.go).
	if isPasswordAccount(u) {
		challenge, cerr := s.linkedAccountChallenge(ctx, u)
		if cerr != nil {
			return nil, cerr
		}
		if challenge != nil {
			s.logger.Info("OAuth sign-in to a linked password account waits for its second factor",
				"user_id", u.ID().String(), "provider", provider)
			return &CallbackResult{User: u, MFAChallenge: challenge}, nil
		}
	}

	// Create session
	sessionResult, err := s.createSession(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	s.logger.Info("OAuth login successful",
		"user_id", u.ID().String(),
		"email", u.Email(),
		"provider", provider,
		"final_redirect", finalRedirect,
	)

	return &CallbackResult{
		AccessToken:  sessionResult.AccessToken,
		RefreshToken: sessionResult.RefreshToken,
		ExpiresIn:    int64(s.authConfig.AccessTokenDuration.Seconds()),
		TokenType:    "Bearer",
		User:         u,
	}, nil
}

// ProviderInfo represents information about an OAuth provider.
type ProviderInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// GetAvailableProviders returns a list of available OAuth providers.
func (s *OAuthService) GetAvailableProviders() []ProviderInfo {
	on := func(p OAuthProvider) bool {
		c := s.getProviderConfig(context.Background(), p)
		return c != nil && c.IsConfigured()
	}
	return []ProviderInfo{
		{ID: "google", Name: "Google", Enabled: on(OAuthProviderGoogle)},
		{ID: "github", Name: "GitHub", Enabled: on(OAuthProviderGitHub)},
		{ID: "microsoft", Name: "Microsoft", Enabled: on(OAuthProviderMicrosoft)},
	}
}

// getProviderConfig returns the configuration for a provider.
//
// With a ProviderSource wired (the console's social login setting) the
// provider in force is read on every call, so a change applies without a
// restart; without one the start-up configuration is used.
func (s *OAuthService) getProviderConfig(ctx context.Context, provider OAuthProvider) *config.OAuthProviderConfig {
	if !provider.IsValid() {
		return nil
	}
	if s.providers != nil {
		cfg := s.providers.OAuthProvider(ctx, string(provider))
		return &cfg
	}
	switch provider {
	case OAuthProviderGoogle:
		return &s.config.Google
	case OAuthProviderGitHub:
		return &s.config.GitHub
	case OAuthProviderMicrosoft:
		return &s.config.Microsoft
	}
	return nil
}

// ProviderSource answers which configuration a social provider has right
// now. Implemented by the console's social login setting.
type ProviderSource interface {
	OAuthProvider(ctx context.Context, provider string) config.OAuthProviderConfig
}

// SetProviderSource makes the providers live: they are read from src on
// every authorize and callback instead of the start-up configuration.
func (s *OAuthService) SetProviderSource(src ProviderSource) { s.providers = src }

// generatePKCE generates a PKCE code verifier and challenge (RFC 7636).
func generatePKCE() (verifier, challenge string, err error) {
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(verifierBytes)

	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])
	return verifier, challenge, nil
}

// storeBoundVerifier keeps a flow's PKCE verifier server-side under its state,
// bound to the browser that started the flow: it mints a one-time browser
// binding secret, stores only its hash next to the verifier, and returns the
// secret for the caller to hand to that browser (an HttpOnly cookie). The
// record expires with the state. Sign-in and account linking both use it.
func (s *OAuthService) storeBoundVerifier(ctx context.Context, state, codeVerifier string) (string, error) {
	binding, err := newBrowserBinding()
	if err != nil {
		return "", fmt.Errorf("failed to create browser binding: %w", err)
	}
	if err := s.pkceStore.Set(ctx, pkceStoreKey(state), hashBinding(binding)+":"+codeVerifier, s.stateTTL()); err != nil {
		return "", fmt.Errorf("failed to store PKCE verifier: %w", err)
	}
	return binding, nil
}

// claimBoundVerifier takes the PKCE verifier stored for state. Taking it is
// single use: the record is deleted before the binding is checked, so a
// replayed state finds nothing and a wrong browser cannot retry. It reports
// false (the caller answers ErrInvalidState) when the record is missing or
// expired, malformed, or presented without the binding secret of the browser
// that started the flow.
func (s *OAuthService) claimBoundVerifier(ctx context.Context, state, browserBinding string, provider OAuthProvider) (string, bool) {
	stored, found, err := s.pkceStore.GetDel(ctx, pkceStoreKey(state))
	if err != nil {
		s.logger.Error("failed to read PKCE verifier", "provider", provider, "error", err)
		return "", false
	}
	bindHash, codeVerifier, split := strings.Cut(stored, ":")
	if !found || !split || codeVerifier == "" || !bindingMatches(browserBinding, bindHash) {
		return "", false
	}
	return codeVerifier, true
}

// stateTTL is how long a state (and its stored PKCE verifier) is valid.
func (s *OAuthService) stateTTL() time.Duration {
	if s.config.StateDuration > 0 {
		return s.config.StateDuration
	}
	return 10 * time.Minute
}

// generateState generates a signed state token and a fresh PKCE verifier.
// The verifier is returned to the caller to store server-side; it is not
// part of the state.
//
// link, when set, makes it a link state: it carries the signed-in account and
// session that started the link, and only CompleteLink accepts it.
func (s *OAuthService) generateState(provider OAuthProvider, finalRedirect string, link *linkBinding) (state string, codeVerifier string, err error) {
	// Generate random bytes
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", err
	}

	// Generate PKCE
	verifier, _, pkceErr := generatePKCE()
	if pkceErr != nil {
		return "", "", pkceErr
	}

	// Create state data. The PKCE verifier is deliberately NOT in here.
	stateData := map[string]interface{}{
		"provider":       string(provider),
		"final_redirect": finalRedirect,
		"random":         base64.URLEncoding.EncodeToString(randomBytes),
		"exp":            time.Now().Add(s.stateTTL()).Unix(),
	}
	if link != nil {
		stateData["purpose"] = statePurposeLink
		stateData["uid"] = link.UserID
		stateData["sid"] = link.SessionID
	}

	// Encode state data
	stateJSON, err := json.Marshal(stateData)
	if err != nil {
		return "", "", err
	}

	// Sign the state
	stateBase64 := base64.URLEncoding.EncodeToString(stateJSON)
	signature := s.signState(stateBase64)

	return stateBase64 + "." + signature, verifier, nil
}

// signState creates an HMAC signature for the state.
func (s *OAuthService) signState(data string) string {
	secret := s.config.StateSecret
	if secret == "" {
		secret = s.authConfig.JWTSecret // Fallback to JWT secret
	}
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

// stateClaims are the signed contents of a state token.
type stateClaims struct {
	FinalRedirect string
	// Purpose is empty for a sign-in and statePurposeLink for a link.
	Purpose   string
	UserID    string
	SessionID string
}

// statePurposeLink marks a state minted by StartLink.
const statePurposeLink = "link"

// linkBinding is the signed-in account and session a link state belongs to.
type linkBinding struct {
	UserID    string
	SessionID string
}

// validateState validates and decodes the state token.
func (s *OAuthService) validateState(state string, expectedProvider OAuthProvider) (*stateClaims, error) {
	parts := strings.SplitN(state, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("invalid state format")
	}

	stateData, signature := parts[0], parts[1]

	// Verify signature
	expectedSig := s.signState(stateData)
	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return nil, errors.New("invalid state signature")
	}

	// Decode state data
	stateJSON, err := base64.URLEncoding.DecodeString(stateData)
	if err != nil {
		return nil, errors.New("invalid state encoding")
	}

	var data map[string]interface{}
	if err := json.Unmarshal(stateJSON, &data); err != nil {
		return nil, errors.New("invalid state JSON")
	}

	// Check expiration
	expFloat, ok := data["exp"].(float64)
	if !ok {
		return nil, errors.New("invalid state expiration")
	}
	if time.Now().Unix() > int64(expFloat) {
		return nil, errors.New("state expired")
	}

	// Check provider
	provider, ok := data["provider"].(string)
	if !ok || provider != string(expectedProvider) {
		return nil, errors.New("provider mismatch")
	}

	c := &stateClaims{}
	c.FinalRedirect, _ = data["final_redirect"].(string)
	c.Purpose, _ = data["purpose"].(string)
	c.UserID, _ = data["uid"].(string)
	c.SessionID, _ = data["sid"].(string)
	return c, nil
}

// OAuth token response.
type oauthTokens struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// exchangeCode exchanges the authorization code for tokens.
func (s *OAuthService) exchangeCode(ctx context.Context, provider OAuthProvider, cfg *config.OAuthProviderConfig, code, redirectURI, codeVerifier string) (*oauthTokens, error) {
	tokenURL := s.getTokenURL(provider)

	data := url.Values{}
	data.Set("client_id", cfg.ClientID)
	data.Set("client_secret", cfg.ClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("grant_type", "authorization_code")

	// PKCE: Include code_verifier (RFC 7636)
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// SECURITY: Limit response body to 1MB to prevent memory exhaustion
	body, err := httpsec.ReadLimited(resp.Body, 1<<20)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: %w", httpsec.NewUpstreamStatusError(ctx, "oauth provider", resp.StatusCode, body))
	}

	var tokens oauthTokens
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, err
	}

	return &tokens, nil
}

// OAuthUserInfo represents user information from OAuth provider.
type OAuthUserInfo struct {
	ID        string
	Email     string
	Name      string
	AvatarURL string
	// Issuer + Subject are the provider's immutable user id: from the verified
	// id_token for Microsoft (keyed on oid), from the provider API for Google
	// (sub) and GitHub (numeric id). The account is found by this pair first;
	// the email is a mutable attribute (federated_identity.go).
	Issuer  string
	Subject string
	// HD is the Google Workspace (hosted) domain claim of the id_token; empty
	// for a consumer Google account.
	HD string
	// LegacySubject is the subject the identity was bound under before
	// (Microsoft: sub); a binding found under it is re-keyed to Subject.
	LegacySubject string
	// Login is the provider account's handle where it has one (GitHub);
	// empty otherwise. Shown when the person confirms a pending link.
	Login string
}

// getUserInfo fetches user information from the OAuth provider.
//
// The address comes back trimmed and lower-cased whatever the provider sent,
// so a provider spelling an existing account's address in another case finds
// that account (and its refusal or pending link) instead of creating a second
// one.
func (s *OAuthService) getUserInfo(ctx context.Context, provider OAuthProvider, tokens *oauthTokens) (*OAuthUserInfo, error) {
	info, err := s.providerUserInfo(ctx, provider, tokens)
	if err != nil {
		return nil, err
	}
	info.Email = userdom.NormalizeEmail(info.Email)
	return info, nil
}

func (s *OAuthService) providerUserInfo(ctx context.Context, provider OAuthProvider, tokens *oauthTokens) (*OAuthUserInfo, error) {
	switch provider {
	case OAuthProviderGoogle:
		return s.getGoogleUserInfo(ctx, tokens)
	case OAuthProviderGitHub:
		return s.getGitHubUserInfo(ctx, tokens.AccessToken)
	case OAuthProviderMicrosoft:
		// Identity comes from the signed id_token (verified below), NOT the
		// mutable Graph `mail` attribute — see getMicrosoftUserInfo.
		return s.getMicrosoftUserInfo(ctx, tokens.IDToken)
	}
	return nil, ErrInvalidProvider
}

// googleJWKSURL holds Google's id_token signing keys.
const googleJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"

// getGoogleUserInfo takes the identity (subject, verified email) from the
// signature-verified id_token: RS256/PS256/ES256 against Google's JWKS, our
// client id as the audience, Google's issuer. The userinfo API only supplies
// the display name and picture, and must describe the same subject. A login
// without an id_token (the "openid" scope was removed) is refused.
func (s *OAuthService) getGoogleUserInfo(ctx context.Context, tokens *oauthTokens) (*OAuthUserInfo, error) {
	if tokens == nil || strings.TrimSpace(tokens.IDToken) == "" {
		return nil, errors.New("google login returned no id_token (the 'openid' scope is required)")
	}
	cfg := s.getProviderConfig(ctx, OAuthProviderGoogle)
	if cfg == nil {
		return nil, ErrInvalidProvider
	}
	claims, err := s.oidcVerifier.VerifyIDToken(ctx, tokens.IDToken, oidc.Expectations{
		JWKSURI:    googleJWKSURL,
		ClientID:   cfg.ClientID,
		IssuerRule: oidc.GoogleIssuer,
		SkipNonce:  true, // code flow: id_token delivered server-to-server
	})
	if err != nil {
		return nil, fmt.Errorf("google id_token verification failed: %w", err)
	}
	info, err := googleUserInfoFromClaims(claims)
	if err != nil {
		return nil, err
	}
	profile, err := s.getGoogleProfile(ctx, tokens.AccessToken)
	if err != nil {
		return nil, err
	}
	if profile.ID != info.Subject {
		return nil, errors.New("google userinfo describes another account than the id_token")
	}
	info.Name = profile.Name
	if info.Name == "" {
		info.Name = claims.Name
	}
	info.AvatarURL = profile.AvatarURL
	return info, nil
}

// googleUserInfoFromClaims maps verified Google id_token claims: the email
// must be verified by Google, and the account is keyed on (Google issuer, sub).
func googleUserInfoFromClaims(claims *oidc.Claims) (*OAuthUserInfo, error) {
	if !bool(claims.EmailVerified) {
		return nil, fmt.Errorf("google: %w", ErrEmailUnverifiedAtIDP)
	}
	if strings.TrimSpace(claims.Email) == "" {
		return nil, errors.New("google id_token has no email claim")
	}
	return &OAuthUserInfo{
		ID:      claims.Subject,
		Email:   claims.Email,
		Name:    claims.Name,
		Issuer:  googleIssuer,
		Subject: claims.Subject,
		HD:      claims.HD,
	}, nil
}

// getGoogleProfile fetches the display name and picture from Google.
func (s *OAuthService) getGoogleProfile(ctx context.Context, accessToken string) (*OAuthUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// SECURITY: Limit response body to 1MB to prevent memory exhaustion
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("failed to get user info: %w", httpsec.NewUpstreamStatusError(ctx, "oauth provider", resp.StatusCode, body))
	}

	var data struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}
	if err := httpsec.DecodeJSON(resp.Body, httpsec.MaxResponseBytes, &data); err != nil {
		return nil, err
	}
	// The v2 userinfo id is the Google account id, the OIDC sub.
	return &OAuthUserInfo{ID: data.ID, Name: data.Name, AvatarURL: data.Picture}, nil
}

// getGitHubUserInfo fetches user info from GitHub.
func (s *OAuthService) getGitHubUserInfo(ctx context.Context, accessToken string) (*OAuthUserInfo, error) {
	// Get user profile
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// SECURITY: Limit response body to 1MB to prevent memory exhaustion
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("failed to get user info: %w", httpsec.NewUpstreamStatusError(ctx, "oauth provider", resp.StatusCode, body))
	}

	var userData struct {
		ID        int    `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := httpsec.DecodeJSON(resp.Body, httpsec.MaxResponseBytes, &userData); err != nil {
		return nil, err
	}

	// Always resolve a VERIFIED email via /user/emails. The public profile
	// email (userData.Email) is not guaranteed verified, and since accounts
	// are matched by email, accepting an unverified attacker-controlled email
	// could federate into a victim's account. Require a verified email.
	email, _ := s.getGitHubPrimaryEmail(ctx, accessToken)
	if email == "" {
		return nil, errors.New("github account has no verified email")
	}

	name := userData.Name
	if name == "" {
		name = userData.Login
	}

	ghID := ""
	if userData.ID > 0 {
		ghID = fmt.Sprintf("%d", userData.ID)
	}
	return &OAuthUserInfo{
		ID:        ghID,
		Email:     email,
		Name:      name,
		AvatarURL: userData.AvatarURL,
		Issuer:    githubIssuer,
		Subject:   ghID,
		Login:     userData.Login,
	}, nil
}

// getGitHubPrimaryEmail fetches the primary email from GitHub.
func (s *OAuthService) getGitHubPrimaryEmail(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("failed to fetch emails")
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := httpsec.DecodeJSON(resp.Body, httpsec.MaxResponseBytes, &emails); err != nil {
		return "", err
	}

	// Only the primary address, and only when GitHub verified it. Another
	// verified address is not the one the account is known by.
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}

	return "", errors.New("no primary verified email found")
}

// getMicrosoftUserInfo derives identity from the VERIFIED id_token, NOT the
// mutable Microsoft Graph `mail` attribute.
//
// SECURITY (nOAuth): with the multi-tenant `/common` authority, any Entra tenant
// can complete the flow, and a rogue tenant can set a user's `mail` to a
// victim's address without owning the domain. Matching accounts on that value
// was an account-takeover vector. We instead:
//   - verify the id_token signature (Entra JWKS) + audience + issuer(+tid), and
//   - require `xms_edov == true` ("email domain owner verified") before trusting
//     the email — parity with the verified-email requirement already enforced
//     for Google and GitHub. A domain can be verified in only one Entra tenant,
//     so a domain-verified email is a reliable identifier.
//
// NOTE: `xms_edov` must be emitted by the app registration (optional claim). If
// it is absent the login is refused, fail-closed, rather than trusting an
// unverified email. The immutable (issuer, subject) is also returned so the
// account can be bound to the IdP identity.
func (s *OAuthService) getMicrosoftUserInfo(ctx context.Context, idToken string) (*OAuthUserInfo, error) {
	if strings.TrimSpace(idToken) == "" {
		return nil, errors.New("microsoft login returned no id_token (the 'openid' scope is required)")
	}
	cfg := s.getProviderConfig(ctx, OAuthProviderMicrosoft)
	if cfg == nil {
		return nil, ErrInvalidProvider
	}

	claims, err := s.oidcVerifier.VerifyIDToken(ctx, idToken, oidc.Expectations{
		JWKSURI:    "https://login.microsoftonline.com/common/discovery/v2.0/keys",
		ClientID:   cfg.ClientID,
		IssuerRule: oidc.EntraIssuer("common"),
		SkipNonce:  true, // code flow: id_token delivered server-to-server
	})
	if err != nil {
		return nil, fmt.Errorf("microsoft id_token verification failed: %w", err)
	}

	info, err := microsoftUserInfoFromClaims(claims)
	if err != nil {
		s.logger.Warn("microsoft login blocked", "reason", err.Error(),
			"email", claims.Email, "tid", claims.TID, "subject", claims.Subject)
		return nil, err
	}
	return info, nil
}

// microsoftUserInfoFromClaims applies the nOAuth email-verification gate to
// already-verified Entra id_token claims and maps them to OAuthUserInfo. It is
// the security-critical mapping (the signature/issuer/audience checks are done
// by pkg/oidc), so it is a pure function to keep it unit-testable.
func microsoftUserInfoFromClaims(claims *oidc.Claims) (*OAuthUserInfo, error) {
	if !bool(claims.XMSEdov) {
		return nil, fmt.Errorf("microsoft (email domain not owner-verified): %w", ErrEmailUnverifiedAtIDP)
	}
	if strings.TrimSpace(claims.Email) == "" {
		return nil, errors.New("microsoft id_token has no email claim")
	}
	subject, legacy := entraSubject(claims)
	return &OAuthUserInfo{
		ID:            claims.Subject,
		Email:         claims.Email,
		Name:          claims.Name,
		Issuer:        claims.Issuer,
		Subject:       subject,
		LegacySubject: legacy,
	}, nil
}

// findOrCreateUser finds the account of a social login or creates one.
//
// The provider's (issuer, subject) finds a returning account first; the email
// it sends now replaces the old one when no other account holds it (the
// provider verified it). Only an unknown identity falls back to the email,
// under the takeover guards, and is then bound to the account.
func (s *OAuthService) findOrCreateUser(ctx context.Context, userInfo *OAuthUserInfo, provider OAuthProvider) (*userdom.User, error) {
	userInfo.Email = userdom.NormalizeEmail(userInfo.Email)
	acc := s.accounts()
	key := useridentity.Key{Issuer: userInfo.Issuer, Subject: userInfo.Subject}
	if key.Valid() {
		u, ident, err := acc.lookup(ctx, key, userInfo.LegacySubject)
		if err != nil {
			return nil, fmt.Errorf("resolve federated identity: %w", err)
		}
		if u != nil {
			// An identity an organization's single sign-on manages is signed
			// in through that sign-on only: a social sign-in that happens to
			// carry the same provider key is a route the person never
			// confirmed. Refused, audited, no session.
			if ident.ManagedBySSO() {
				auditSocialRefusedSSOIdentity(ctx, s.audit, s.logger, u, string(provider))
				return nil, ErrOAuthUseOrgSSO
			}
			// The provider's address moves the account only when the account
			// belongs to that provider. A provider linked to an account of
			// another kind (a password account) never changes its address.
			// An identity an organization's single sign-on manages keeps the
			// address that sign-on gave it: the organization changes it only
			// for a domain it proved (SSOService.returningFederatedUser), and
			// the social button must not skip that proof.
			var prev string
			var changed bool
			if u.AuthProvider() == provider.ToAuthProvider() && !ident.ManagedBySSO() {
				prev, changed = acc.adoptProviderEmail(ctx, u, userInfo.Email, nil)
				// The new address counts as verified only where the provider
				// runs its mailbox, as at account creation: a provider that
				// verified an address once (GitHub, a consumer Google account
				// on a company address) does not prove the mailbox now.
				if changed && !emailAuthoritative(provider, userInfo) {
					u.MarkEmailUnverified()
				}
			}
			u.UpdateLastLogin()
			acc.saveLogin(ctx, u, prev, changed)
			acc.markUsed(ctx, ident)
			return u, nil
		}
	}

	existingUser, err := s.userRepo.GetByEmail(ctx, userInfo.Email)
	if err == nil && existingUser != nil {
		// SECURITY: an account is bound to the auth provider that created it.
		// A verified email at one IdP does NOT prove ownership of an account
		// created at another. On a provider mismatch the ONLY safe adoption is
		// a CLAIMABLE LOCAL account (invited, no password yet) signing in via
		// its IdP for the first time. Block every other mismatch — a
		// password-backed local account AND a different federated provider
		// (e.g. account created via Google, login attempted via GitHub) —
		// otherwise it is a cross-IdP account takeover.
		existingProvider := existingUser.AuthProvider()
		expectedProvider := provider.ToAuthProvider()

		if existingProvider != expectedProvider {
			claimableLocal := existingProvider == userdom.AuthProviderLocal && existingUser.PasswordHash() == nil
			// A claimable account is adopted only when every organization it
			// belongs to has DNS-verified the email domain: otherwise an
			// organization that provisioned someone else's address without
			// that proof would capture the real owner's sign-in.
			if claimableLocal && !emailAuthoritative(provider, userInfo) {
				s.logger.Warn("OAuth login blocked: the provider is not authoritative for this email, so it cannot claim an account",
					"oauth_provider", expectedProvider)
				return nil, ErrEmailNotAuthoritative
			}
			if claimableLocal && !s.claimVouched(ctx, existingUser, userInfo.Email) {
				return nil, ErrOAuthAccountExists
			}
			if !claimableLocal {
				s.logger.Warn("OAuth login blocked: email registered with a different auth provider",
					"email", userInfo.Email,
					"existing_provider", existingProvider,
					"oauth_provider", expectedProvider,
				)
				// Nothing changes on the account. The person may sign in to
				// it and confirm the link (pending_link.go).
				return nil, s.offerPendingLink(ctx, existingUser, userInfo, provider)
			}
		}

		// An account of this provider with no bound identity (it predates
		// bindings) is bound by its email only when the provider is
		// authoritative for it. Otherwise the person signs in another way and
		// links the provider afterwards.
		if key.Valid() && !mayBindLegacyAccount(provider, userInfo) {
			s.logger.Warn("OAuth login blocked: the provider is not authoritative for this email and the account is not bound to it",
				"oauth_provider", expectedProvider)
			return nil, ErrEmailNotAuthoritative
		}

		// The identity was not found above. An account bound to another
		// subject at this provider, or to another issuer, belongs to a
		// different identity: refuse. Otherwise bind this one (the account
		// email matches the provider-verified email).
		if key.Valid() {
			sameIssuer, otherIssuer, berr := acc.boundIdentities(ctx, existingUser, key)
			if berr != nil {
				return nil, fmt.Errorf("check federated identities: %w", berr)
			}
			if sameIssuer || otherIssuer != nil {
				s.logger.Warn("OAuth login blocked: federated identity mismatch for email",
					"email", userInfo.Email, "oauth_provider", expectedProvider)
				return nil, ErrOAuthAccountExists
			}
			if berr := acc.bind(ctx, existingUser, key); berr != nil {
				return nil, ErrOAuthAccountExists
			}
		}

		existingUser.UpdateLastLogin()
		if err := s.userRepo.Update(ctx, existingUser); err != nil {
			s.logger.Warn("failed to update last login", "error", err)
		}
		return existingUser, nil
	}

	// SECURITY (FIX 4, sign-up policy): no account exists, so this sign-in
	// would create one. It may only when the sign-up policy admits it
	// (signup.Admit): self-service sign-up, or a pending invitation for this
	// verified email. Otherwise nothing is written (no orphan account).
	facts, err := signupdom.FactsForEmail(ctx, s.signupDomains, userInfo.Email)
	if err != nil {
		s.logger.Warn("domain sign-up policy unreadable; OAuth sign-up refused", "provider", provider, "error", err)
		return nil, ErrSignupNotAvailable
	}
	authoritative := emailAuthoritative(provider, userInfo)
	identity := facts.Apply(signupdom.Identity{
		Intent:          signupdom.IntentAccount,
		InvitedPending:  authoritative && s.invitedPending(ctx, userInfo.Email),
		DisposableEmail: disposableEmail(userInfo.Email),
	})
	if !authoritative {
		// The provider does not vouch for the mailbox: no domain join and no
		// invitation claim. A fresh account without those privileges is
		// possible only where sign-up is open.
		identity.DomainJoinable = false
	}
	switch signupdom.Admit(policyOrConfig(ctx, s.signupPolicy, s.authConfig), identity) {
	case signupdom.OutcomeSSORequired:
		s.logger.Info("OAuth sign-up refused: the domain requires its organization's SSO", "provider", provider)
		return nil, ErrSignupSSORequired
	case signupdom.OutcomeNotSetUp:
		s.logger.Warn("OAuth sign-up refused by the sign-up policy", "provider", provider)
		return nil, ErrSignupNotAvailable
	}

	newUser, err := userdom.NewOAuthUser(userInfo.Email, userInfo.Name, userInfo.AvatarURL, provider.ToAuthProvider())
	if err != nil {
		return nil, err
	}
	if !authoritative {
		newUser.MarkEmailUnverified()
	}
	if err := s.userRepo.Create(ctx, newUser); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	recordSignup(ctx, s.signups, signupevent.Event{Kind: signupevent.KindAccountCreated, Source: signupevent.SourceOAuth,
		Email: newUser.Email(), UserID: newUser.ID()})
	if key.Valid() {
		if err := acc.bind(ctx, newUser, key); err != nil {
			return nil, fmt.Errorf("bind new account: %w", err)
		}
	}

	s.logger.Info("created OAuth user", "user_id", newUser.ID().String(), "email", userInfo.Email, "provider", provider)

	// New OAuth users will be redirected to Create First Team page
	// via frontend flow (no auto-create tenant)

	return newUser, nil
}

// SessionResult represents session creation result.
type SessionResult struct {
	AccessToken  string
	RefreshToken string
}

// createSession creates a new session for the user.
func (s *OAuthService) createSession(ctx context.Context, u *userdom.User) (*SessionResult, error) {
	// A blocked or suspended account opens no session (it would only 401).
	if !u.IsActive() {
		return nil, ErrAccountSuspended
	}
	// Bind the token to its session: generate the session id first, embed it in
	// the JWT, then persist the session under the SAME id — so an OAuth session
	// is revocable (mirrors the password Login flow). Previously the token was
	// minted with an empty session id, leaving the token and session row
	// unlinked, so the OAuth access token could not be revoked.
	sessionID := shared.NewID()
	tokenPair, err := s.tokenGenerator.GenerateTokenPair(u.ID().String(), sessionID.String(), "user")
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Create session under the same id embedded in the token.
	ci := clientInfoFrom(ctx)
	newSession, err := sessiondom.NewWithID(
		sessionID,
		u.ID(),
		tokenPair.AccessToken,
		ci.IP,
		ci.UserAgent,
		s.authConfig.SessionDuration,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	// Social OAuth (GitHub/Google/personal Microsoft) is a federated login, so
	// it is stamped 'sso', but no organization's identity provider issued it:
	// no issuing tenant is recorded, so it is exempt from NO organization's SSO
	// enforcement or 2FA requirement (Session.FederatedFor).
	newSession.SetAuthMethod(sessiondom.AuthMethodSSO)

	if err := s.sessionRepo.Create(ctx, newSession); err != nil {
		return nil, fmt.Errorf("failed to save session: %w", err)
	}
	runSignInHook(ctx, s.onSignIn, u.ID())

	// Create refresh token entity
	refreshTokenEntity, err := sessiondom.NewRefreshToken(
		u.ID(),
		newSession.ID(),
		tokenPair.RefreshToken,
		s.authConfig.RefreshTokenDuration,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token: %w", err)
	}

	if err := s.refreshTokenRepo.Create(ctx, refreshTokenEntity); err != nil {
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}
	auditFederatedLogin(ctx, s.audit, s.logger, u, "", sessionID.String(), "oauth", string(u.AuthProvider()))

	return &SessionResult{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
	}, nil
}

// buildAuthorizationURL builds the OAuth authorization URL.
func (s *OAuthService) buildAuthorizationURL(provider OAuthProvider, cfg *config.OAuthProviderConfig, redirectURI, state, codeVerifier string) (string, error) {
	authURL := s.getAuthURL(provider)

	params := url.Values{}
	params.Set("client_id", cfg.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("state", state)
	params.Set("response_type", "code")

	if len(cfg.Scopes) > 0 {
		params.Set("scope", strings.Join(cfg.Scopes, " "))
	}

	// PKCE: Add code_challenge (RFC 7636)
	if codeVerifier != "" {
		challengeHash := sha256.Sum256([]byte(codeVerifier))
		codeChallenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", "S256")
	}

	// Provider-specific parameters
	switch provider {
	case OAuthProviderGoogle:
		params.Set("access_type", "offline")
		params.Set("prompt", "select_account")
	case OAuthProviderMicrosoft:
		params.Set("response_mode", "query")
	}

	return authURL + "?" + params.Encode(), nil
}

// getAuthURL returns the authorization endpoint URL for a provider.
func (s *OAuthService) getAuthURL(provider OAuthProvider) string {
	switch provider {
	case OAuthProviderGoogle:
		return "https://accounts.google.com/o/oauth2/v2/auth"
	case OAuthProviderGitHub:
		return "https://github.com/login/oauth/authorize"
	case OAuthProviderMicrosoft:
		return "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
	}
	return ""
}

// getTokenURL returns the token endpoint URL for a provider.
func (s *OAuthService) getTokenURL(provider OAuthProvider) string { return TokenEndpoint(provider) }

// TokenEndpoint is the fixed token endpoint of a social provider ("" for an
// unknown one). Nothing a request or a setting says changes it.
func TokenEndpoint(provider OAuthProvider) string {
	switch provider {
	case OAuthProviderGoogle:
		return "https://oauth2.googleapis.com/token"
	case OAuthProviderGitHub:
		return "https://github.com/login/oauth/access_token"
	case OAuthProviderMicrosoft:
		return "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	}
	return ""
}
