package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/crypto"
	identityproviderdom "github.com/openctemio/openctem/api/pkg/domain/identityprovider"
	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/domain/useridentity"
	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/oidc"
)

// SSO errors.
var (
	ErrSSOTenantNotFound      = errors.New("tenant not found")
	ErrSSONoActiveProviders   = errors.New("no active SSO providers for this tenant")
	ErrSSOProviderNotFound    = errors.New("SSO provider not configured for this tenant")
	ErrSSOProviderInactive    = errors.New("SSO provider is not active")
	ErrSSOInvalidState        = errors.New("invalid SSO state token")
	ErrSSOExchangeFailed      = errors.New("failed to exchange authorization code")
	ErrSSOUserInfoFailed      = errors.New("failed to get user info from SSO provider")
	ErrSSODomainNotAllowed    = errors.New("email domain not allowed for this SSO provider")
	ErrSSODecryptionFailed    = errors.New("failed to decrypt client secret")
	ErrSSOProviderUnsupported = errors.New("unsupported SSO provider type")
	ErrSSOInvalidRedirectURI  = errors.New("invalid redirect URI")
	ErrSSOInvalidDefaultRole  = errors.New("invalid default role")
	ErrSSONoEmail             = errors.New("SSO provider did not return an email address")
	ErrSSOInvalidIDToken      = errors.New("SSO id_token failed validation")
	// ErrSSONotAMember is returned when a federated login resolves to a user who
	// is not a member of the target tenant and does not qualify for JIT
	// auto-provisioning (FIX 2). The caller surfaces a generic "contact your
	// admin" outcome.
	ErrSSONotAMember = errors.New("not a member of this organization")
	// ErrSSORegistrationDisabled is returned when AUTH_ALLOW_REGISTRATION is
	// false and an SSO/social login would create a brand-new user (FIX 4).
	ErrSSORegistrationDisabled = errors.New("registration is disabled")
	// ErrAccountLinkRequiresVerification is the proof-before-link refusal: a
	// federated (SSO/OAuth) login whose email matches a PRE-EXISTING account is
	// never silently adopted. It is returned when a real password-backed local
	// account exists (Case 1 — the user must sign in with their existing password
	// first, then link the IdP from an authenticated session) AND when a claimable
	// passwordless account cannot prove ownership (Case 2 — unverified email or a
	// tenant domain that is not DNS-verified). Fail-closed: matching an email is
	// never, on its own, enough to bind a federated identity.
	ErrAccountLinkRequiresVerification = errors.New(
		"an account with this email already exists; sign in with your existing credentials first, then link this identity provider")
)

// ssoMaxRedirectURILength is the maximum length for redirect URIs.
const ssoMaxRedirectURILength = 2000

// SSOService handles per-tenant SSO authentication.
type SSOService struct {
	ipRepo           identityproviderdom.Repository
	tenantRepo       tenantdom.Repository
	userRepo         userdom.Repository
	sessionRepo      sessiondom.Repository
	refreshTokenRepo sessiondom.RefreshTokenRepository
	encryptor        crypto.Encryptor
	tokenGenerator   *jwt.Generator
	authConfig       config.AuthConfig
	logger           *logger.Logger
	httpClient       *http.Client
	// oidcVerifier verifies id_tokens and logout tokens (pkg/oidc).
	oidcVerifier *oidc.Client

	// For tenant membership creation
	tenantMemberRepo TenantMemberCreator

	// domainVerifier is the SSO P1 verified-domain gate. When wired, it is the
	// PRIMARY JIT auto-provisioning gate (a DNS-proven domain). When nil, the
	// flow falls back to the P0 config-AllowedDomains gate so nothing breaks
	// pre-wiring. Fail-closed: an unverified/unknown domain never JIT-provisions.
	domainVerifier DomainVerifier

	// revocations records back-channel-logged-out sessions so their access
	// tokens (and live WebSocket connections) stop at once rather than at
	// expiry. nil = they expire naturally.
	revocations   SessionRevocationStore
	revocationTTL time.Duration

	// identities binds accounts to the IdP's (issuer, subject); logins find
	// the account by it first (federated_identity.go). Required: a login that
	// carries an identity is refused when it is not wired.
	identities useridentity.Repository
	// jitApprovals tells administrators about newcomers waiting for approval.
	jitApprovals JITApprovalNotifier
}

// SetIdentityRepo wires the federated identity store.
func (s *SSOService) SetIdentityRepo(repo useridentity.Repository) {
	s.identities = repo
}

func (s *SSOService) accounts() federatedAccounts {
	return federatedAccounts{identities: s.identities, users: s.userRepo, logger: s.logger}
}

// SetSessionRevocationStore wires immediate revocation for sessions ended by
// an OIDC back-channel logout.
func (s *SSOService) SetSessionRevocationStore(store SessionRevocationStore, ttl time.Duration) {
	s.revocations = store
	s.revocationTTL = ttl
}

// TenantMemberCreator creates tenant memberships for auto-provisioned users and
// looks up existing membership (used to gate federated account binding).
type TenantMemberCreator interface {
	CreateMembership(ctx context.Context, m *tenantdom.Membership) error
	GetMembership(ctx context.Context, userID, tenantID shared.ID) (*tenantdom.Membership, error)
}

// DomainVerifier answers whether an email domain is DNS-verified for a tenant.
// It is the trust boundary that authorizes SSO JIT auto-provisioning: an IdP
// proves WHO a user is, a DNS-proven domain proves the tenant may CLAIM that
// domain's users.
type DomainVerifier interface {
	IsVerifiedDomain(ctx context.Context, tenantID, emailDomain string) (bool, error)
}

// NewSSOService creates a new SSOService.
func NewSSOService(
	ipRepo identityproviderdom.Repository,
	tenantRepo tenantdom.Repository,
	userRepo userdom.Repository,
	sessionRepo sessiondom.Repository,
	refreshTokenRepo sessiondom.RefreshTokenRepository,
	encryptor crypto.Encryptor,
	authCfg config.AuthConfig,
	log *logger.Logger,
) *SSOService {
	tokenGen := jwt.NewGenerator(jwt.TokenConfig{
		Secret:               authCfg.JWTSecret,
		Issuer:               authCfg.JWTIssuer,
		AccessTokenDuration:  authCfg.AccessTokenDuration,
		RefreshTokenDuration: authCfg.RefreshTokenDuration,
	})

	// SSRF: the SSO token-exchange, userinfo, and JWKS endpoints are
	// resolved from tenant-configured IdP records. SafeHTTPClient ensures the
	// dialer refuses to connect to loopback / RFC1918 / link-local / IPv6
	// private ranges at transport level, even if validateTenantIdentifier
	// (Okta whitelist) is bypassed by a future provider addition.
	httpClient := httpsec.SafeHTTPClient(30 * time.Second)

	return &SSOService{
		ipRepo:           ipRepo,
		tenantRepo:       tenantRepo,
		userRepo:         userRepo,
		sessionRepo:      sessionRepo,
		refreshTokenRepo: refreshTokenRepo,
		encryptor:        encryptor,
		tokenGenerator:   tokenGen,
		authConfig:       authCfg,
		logger:           log.With("service", "sso"),
		httpClient:       httpClient,
		oidcVerifier:     newOIDCClient(httpClient),
	}
}

// SetTenantMemberRepo sets the tenant membership creator for auto-provisioning.
func (s *SSOService) SetTenantMemberRepo(repo TenantMemberCreator) {
	s.tenantMemberRepo = repo
}

// SetDomainVerifier wires the verified-domain JIT gate (SSO P1). Nil-safe: when
// left unset, ensureTenantMembership falls back to the P0 AllowedDomains gate.
func (s *SSOService) SetDomainVerifier(v DomainVerifier) {
	s.domainVerifier = v
}

// SSOProviderInfo represents a public SSO provider for a tenant.
type SSOProviderInfo struct {
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	DisplayName string `json:"display_name"`
}

// HasUsableSSOPath reports whether the tenant has at least one way for members
// to sign in via SSO — an active per-tenant identity provider or the opted-in
// platform env fallback. It reuses the exact resolution the login page uses
// (GetProvidersForTenant), so "can enforce" matches "can actually sign in".
// Consumed by TenantService.UpdateSecuritySettings to gate enabling sso_enforced.
//
// Note: this covers OIDC/OAuth identity providers + env fallback. SAML-only
// tenants are not yet counted here (follow-up); the owner break-glass at the
// enforcement gate still prevents any permanent lock-out.
func (s *SSOService) HasUsableSSOPath(ctx context.Context, orgSlug string) (bool, error) {
	providers, err := s.GetProvidersForTenant(ctx, orgSlug)
	if err != nil {
		return false, err
	}
	return len(providers) > 0, nil
}

// GetProvidersForTenant returns active SSO providers for a tenant identified by slug.
//
// SECURITY (anti-enumeration): an unknown slug answers exactly like an
// organization without SSO, an empty list and no error, so the public
// providers endpoint does not tell whether an organization exists. The same
// provider query runs for an unknown slug (on a random id that matches
// nothing), so both answers cost the same.
func (s *SSOService) GetProvidersForTenant(ctx context.Context, orgSlug string) ([]SSOProviderInfo, error) {
	t, err := s.tenantRepo.GetBySlug(ctx, orgSlug)
	if err != nil {
		if _, lerr := s.ipRepo.ListActiveByTenant(ctx, shared.NewID().String()); lerr != nil {
			return nil, fmt.Errorf("list active providers: %w", lerr)
		}
		return []SSOProviderInfo{}, nil
	}

	providers, err := s.ipRepo.ListActiveByTenant(ctx, t.ID().String())
	if err != nil {
		return nil, fmt.Errorf("list active providers: %w", err)
	}

	result := make([]SSOProviderInfo, 0, len(providers))
	hasEntra := false
	for _, p := range providers {
		if p.Provider() == identityproviderdom.ProviderEntraID {
			hasEntra = true
		}
		result = append(result, SSOProviderInfo{
			ID:          p.ID(),
			Provider:    string(p.Provider()),
			DisplayName: p.DisplayName(),
		})
	}

	// Surface the platform-wide Entra fallback so the tenant's login page shows
	// the button even though it has no entra_id provider of its own. A tenant's
	// own active provider takes precedence and suppresses the fallback entry.
	// SECURITY (FIX 1): only tenants that opted in (and pass the env safety
	// gates) see the button — envProvider returns nil otherwise.
	if !hasEntra {
		if rp := s.envProvider(orgSlug, identityproviderdom.ProviderEntraID); rp != nil {
			result = append(result, SSOProviderInfo{
				ID:          "env:entra_id",
				Provider:    string(identityproviderdom.ProviderEntraID),
				DisplayName: rp.displayName,
			})
		}
	}
	return result, nil
}

// SSOAuthorizeInput is the input for generating an SSO authorization URL.
type SSOAuthorizeInput struct {
	OrgSlug     string
	Provider    string
	RedirectURI string // Frontend callback URL
	// ForceReauth asks the provider to authenticate the user again (step-up
	// re-authentication): prompt=login and max_age=0, and the callback
	// refuses an id_token whose auth_time is not fresh.
	ForceReauth bool
}

// SSOAuthorizeResult is the result of generating an SSO authorization URL.
type SSOAuthorizeResult struct {
	AuthorizationURL string `json:"authorization_url"`
	State            string `json:"state"`
}

// validateRedirectURI pins the caller-supplied redirect_uri to the configured
// exact-match allow-list (OAuth 2.1 / RFC 9700 open-redirect guard). Previously
// any syntactically valid http/https URL was accepted, so the SSO flow would
// return an authorization code to ANY host the IdP happened to have registered.
// Now the redirect_uri's ORIGIN (scheme+host+port) must match an allow-list
// entry exactly — no wildcard, no suffix match — and, when an entry pins a path
// prefix, the path must fall within it. Fail-closed: an empty allow-list rejects
// every URI.
func (s *SSOService) validateRedirectURI(uri string) error {
	if uri == "" {
		return fmt.Errorf("%w: empty", ErrSSOInvalidRedirectURI)
	}
	if len(uri) > ssoMaxRedirectURILength {
		return fmt.Errorf("%w: too long", ErrSSOInvalidRedirectURI)
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("%w: malformed URL", ErrSSOInvalidRedirectURI)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("%w: must use http or https scheme", ErrSSOInvalidRedirectURI)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%w: missing host", ErrSSOInvalidRedirectURI)
	}
	// Embedded credentials (user:pass@host) are a classic spoofing vector — the
	// real host can be pushed past a naive parser. Reject outright.
	if parsed.User != nil {
		return fmt.Errorf("%w: userinfo not allowed", ErrSSOInvalidRedirectURI)
	}
	for _, allowed := range s.authConfig.AllowedRedirectURIs {
		if redirectURIMatches(parsed, allowed) {
			return nil
		}
	}
	return fmt.Errorf("%w: not in allow-list", ErrSSOInvalidRedirectURI)
}

// redirectURIMatches reports whether parsed matches an allow-list entry. Scheme
// and host (incl. port) must be exactly equal (case-insensitive host). An entry
// with no path — or a bare "/" — authorizes any path on that exact origin; an
// entry with a path is an exact match or a strict single-segment path-prefix
// (entry ends in "/"), so path-traversal ("..") and extra "/segments" are
// rejected.
func redirectURIMatches(parsed *url.URL, allowed string) bool {
	a, err := url.Parse(strings.TrimSpace(allowed))
	if err != nil || a.Host == "" {
		return false
	}
	if !strings.EqualFold(parsed.Scheme, a.Scheme) || !strings.EqualFold(parsed.Host, a.Host) {
		return false
	}
	if a.Path == "" || a.Path == "/" {
		return true // origin-only entry: any path on this exact origin
	}
	if parsed.Path == a.Path {
		return true // exact path match
	}
	if strings.HasSuffix(a.Path, "/") && strings.HasPrefix(parsed.Path, a.Path) {
		rest := parsed.Path[len(a.Path):]
		return rest != "" && !strings.Contains(rest, "/") && !strings.Contains(rest, "..")
	}
	return false
}

// resolvedProvider is the effective SSO provider config for a tenant+provider,
// regardless of whether it came from the tenant's own DB record or the
// platform-wide env fallback. The client secret is already in plaintext (the
// DB path decrypts it; the env path carries it directly), so downstream code
// never decrypts again.
type resolvedProvider struct {
	provider         identityproviderdom.Provider
	displayName      string
	clientID         string
	clientSecret     string
	tenantIdentifier string
	scopes           []string
	allowedDomains   []string
	autoProvision    bool
	defaultRole      string
	source           string // "tenant" or "env" — for logging/telemetry
}

// isDomainAllowed mirrors IdentityProvider.IsDomainAllowed: empty allow-list
// means any domain is permitted.
func (r *resolvedProvider) isDomainAllowed(emailDomain string) bool {
	if len(r.allowedDomains) == 0 {
		return true
	}
	for _, d := range r.allowedDomains {
		if d == emailDomain {
			return true
		}
	}
	return false
}

// resolveProvider returns the effective SSO config for a tenant+provider. A
// tenant's own active provider always wins; when the tenant has none, it falls
// back to the platform-wide env config (currently Entra ID only). Returns
// ErrSSOProviderNotFound when neither is available.
func (s *SSOService) resolveProvider(ctx context.Context, tenantID, orgSlug string, provider identityproviderdom.Provider) (*resolvedProvider, error) {
	ip, err := s.ipRepo.GetByTenantAndProvider(ctx, tenantID, provider)
	if err == nil {
		if !ip.IsActive() {
			return nil, ErrSSOProviderInactive
		}
		secret, derr := s.encryptor.DecryptString(ip.ClientSecretEncrypted())
		if derr != nil {
			s.logger.Error("failed to decrypt client secret", "provider_id", ip.ID(), "error", derr)
			return nil, ErrSSODecryptionFailed
		}
		return &resolvedProvider{
			provider:         ip.Provider(),
			displayName:      ip.DisplayName(),
			clientID:         ip.ClientID(),
			clientSecret:     secret,
			tenantIdentifier: ip.TenantIdentifier(),
			scopes:           withOpenIDScope(ip.Scopes()),
			allowedDomains:   ip.AllowedDomains(),
			autoProvision:    ip.AutoProvision(),
			defaultRole:      ip.DefaultRole(),
			source:           "tenant",
		}, nil
	}
	if !errors.Is(err, identityproviderdom.ErrNotFound) {
		return nil, fmt.Errorf("get provider: %w", err)
	}

	// Tenant has no provider of its own — fall back to the platform env config,
	// but ONLY if this specific tenant has opted in (see envProvider).
	if rp := s.envProvider(orgSlug, provider); rp != nil {
		return rp, nil
	}
	return nil, ErrSSOProviderNotFound
}

// newOIDCClient is the token verifier for sign-in and logout tokens: the
// shared core (pkg/oidc) over the SSRF-safe client, with every URL checked
// by httpsec.ValidateURL before it is dialed.
func newOIDCClient(httpClient *http.Client) *oidc.Client {
	return oidc.NewClient(httpClient, func(raw string) error {
		_, err := httpsec.ValidateURL(raw)
		return err
	})
}

// envFallbackAllowedForTenant reports whether the given tenant slug has opted
// in to the platform-wide env SSO fallback (SSO_ENTRA_ALLOWED_TENANTS). It is
// fail-closed: an empty allow-list, or a slug not on it, returns false so the
// shared `/common` app registration cannot let any Microsoft account self-join
// an arbitrary organization.
func (s *SSOService) envFallbackAllowedForTenant(orgSlug string) bool {
	slug := strings.ToLower(strings.TrimSpace(orgSlug))
	if slug == "" {
		return false
	}
	for _, allowed := range s.authConfig.EntraSSO.AllowedTenants {
		if strings.EqualFold(strings.TrimSpace(allowed), slug) {
			return true
		}
	}
	return false
}

// envProvider builds a resolvedProvider from the platform-wide env config for
// the given provider+tenant, or nil when the env fallback is not configured, the
// tenant has not opted in, or the config is not safe to use for that tenant.
//
// SECURITY (FIX 1): two fail-closed gates guard the shared env credentials:
//  1. The tenant slug must be on SSO_ENTRA_ALLOWED_TENANTS (opt-in). Without it,
//     no env button and no env login for this tenant.
//  2. A non-specific directory (common/organizations/consumers/empty) accepts any
//     Microsoft directory, so auto-provisioning is FORCED off and a non-empty
//     AllowedDomains allow-list is REQUIRED — otherwise the fallback is refused
//     entirely. A pinned config (real directory GUID + AllowedDomains) may still
//     auto-provision.
func (s *SSOService) envProvider(orgSlug string, provider identityproviderdom.Provider) *resolvedProvider {
	if provider != identityproviderdom.ProviderEntraID || !s.authConfig.EntraSSO.IsConfigured() {
		return nil
	}
	if !s.envFallbackAllowedForTenant(orgSlug) {
		return nil
	}
	cfg := s.authConfig.EntraSSO
	role := cfg.DefaultRole
	if role == "" {
		role = string(tenantdom.RoleViewer)
	}
	autoProvision := cfg.AutoProvision
	if oidc.IsMultiTenantEntraAuthority(cfg.TenantID) {
		if len(cfg.AllowedDomains) == 0 {
			s.logger.Warn("env Entra fallback refused: non-specific directory requires SSO_ENTRA_ALLOWED_DOMAINS",
				"tenant_slug", logger.SanitizeValue(orgSlug), "directory", cfg.TenantID)
			return nil
		}
		autoProvision = false // never auto-provision from a multi-tenant authority
	}
	return &resolvedProvider{
		provider:         identityproviderdom.ProviderEntraID,
		displayName:      cfg.DisplayName,
		clientID:         cfg.ClientID,
		clientSecret:     cfg.ClientSecret,
		tenantIdentifier: cfg.TenantID,
		scopes:           []string{"openid", "email", "profile", "User.Read"},
		allowedDomains:   cfg.AllowedDomains,
		autoProvision:    autoProvision,
		defaultRole:      role,
		source:           "env",
	}
}

// GenerateAuthorizeURL builds the OAuth authorization URL for a tenant's SSO provider.
func (s *SSOService) GenerateAuthorizeURL(ctx context.Context, input SSOAuthorizeInput) (*SSOAuthorizeResult, error) {
	// SECURITY: Validate redirect URI against the exact-match allow-list to
	// prevent open redirect attacks (OAuth 2.1 / RFC 9700).
	if err := s.validateRedirectURI(input.RedirectURI); err != nil {
		return nil, err
	}

	t, err := s.tenantRepo.GetBySlug(ctx, input.OrgSlug)
	if err != nil {
		return nil, ErrSSOTenantNotFound
	}

	provider := identityproviderdom.Provider(input.Provider)
	rp, err := s.resolveProvider(ctx, t.ID().String(), input.OrgSlug, provider)
	if err != nil {
		return nil, err
	}

	// Generate state token with nonce (CSRF + replay) and a PKCE code_challenge
	// (RFC 7636). The verifier is carried, encrypted, inside the signed state and
	// recovered at callback — see generateState.
	state, nonce, codeChallenge, err := s.generateState(input.OrgSlug, input.Provider, input.ForceReauth)
	if err != nil {
		return nil, fmt.Errorf("generate state: %w", err)
	}

	// Get provider-specific auth endpoint
	authURL, _, _ := rp.provider.AuthEndpoints(rp.tenantIdentifier)
	if authURL == "" {
		return nil, ErrSSOProviderUnsupported
	}

	// Build authorization URL
	params := url.Values{}
	params.Set("client_id", rp.clientID)
	params.Set("redirect_uri", input.RedirectURI)
	params.Set("state", state)
	params.Set("response_type", "code")
	params.Set("nonce", nonce) // ID token replay prevention

	// PKCE (RFC 7636, S256). All supported OIDC providers (Entra ID, Okta,
	// Google Workspace) accept S256, so this is unconditional — it defends the
	// authorization code against interception even beyond the confidential
	// client_secret already used at token exchange.
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")

	if len(rp.scopes) > 0 {
		params.Set("scope", strings.Join(rp.scopes, " "))
	}

	// Provider-specific parameters
	switch rp.provider {
	case identityproviderdom.ProviderEntraID:
		params.Set("response_mode", "query")
	case identityproviderdom.ProviderGoogleWorkspace:
		params.Set("access_type", "offline")
		params.Set("prompt", "select_account")
		// Restrict to org domain
		if len(rp.allowedDomains) > 0 {
			params.Set("hd", rp.allowedDomains[0])
		}
	}
	if input.ForceReauth {
		// OIDC Core 3.1.2.1: max_age=0 makes the provider authenticate the
		// user again and return auth_time. Google keeps its own prompt
		// (it does not accept "login"); the others get prompt=login too.
		params.Set("max_age", "0")
		if rp.provider != identityproviderdom.ProviderGoogleWorkspace {
			params.Set("prompt", "login")
		}
	}

	return &SSOAuthorizeResult{
		AuthorizationURL: authURL + "?" + params.Encode(),
		State:            state,
	}, nil
}

// SSOCallbackInput is the input for handling an SSO callback.
type SSOCallbackInput struct {
	Provider    string
	Code        string
	State       string
	RedirectURI string
}

// SSOCallbackResult is the result of a successful SSO callback.
type SSOCallbackResult struct {
	AccessToken  string        `json:"access_token"`
	RefreshToken string        `json:"refresh_token"`
	ExpiresIn    int64         `json:"expires_in"`
	TokenType    string        `json:"token_type"`
	User         *userdom.User `json:"user"`
	TenantID     string        `json:"tenant_id"`
	TenantSlug   string        `json:"tenant_slug"`
}

// HandleCallback handles the SSO OAuth callback.
func (s *SSOService) HandleCallback(ctx context.Context, input SSOCallbackInput) (*SSOCallbackResult, error) {
	// Validate state and extract org slug + nonce + PKCE verifier
	st, err := s.validateState(input.State)
	if err != nil {
		return nil, ErrSSOInvalidState
	}
	orgSlug, stateProvider, nonce, codeVerifier := st.org, st.provider, st.nonce, st.codeVerifier

	if stateProvider != input.Provider {
		return nil, ErrSSOInvalidState
	}

	// PKCE: the authorize step always sent a code_challenge, so a verifier MUST
	// be present. A missing verifier means the state was tampered with or forged
	// (or predates PKCE) — fail closed rather than downgrade to a non-PKCE
	// exchange.
	if codeVerifier == "" {
		s.logger.Warn("SSO callback refused: missing PKCE verifier in state", "provider", input.Provider)
		return nil, ErrSSOInvalidState
	}

	// Look up tenant
	t, err := s.tenantRepo.GetBySlug(ctx, orgSlug)
	if err != nil {
		return nil, ErrSSOTenantNotFound
	}

	// Look up provider config (tenant's own, or the platform env fallback)
	provider := identityproviderdom.Provider(input.Provider)
	rp, err := s.resolveProvider(ctx, t.ID().String(), orgSlug, provider)
	if err != nil {
		return nil, err
	}

	// Exchange code for tokens (includes the PKCE code_verifier, RFC 7636)
	_, tokenURL, _ := rp.provider.AuthEndpoints(rp.tenantIdentifier)
	tokens, err := s.exchangeCode(ctx, rp.clientID, rp.clientSecret, input.Code, input.RedirectURI, tokenURL, codeVerifier)
	if err != nil {
		s.logger.Error("SSO code exchange failed", "provider", input.Provider, "error", err)
		return nil, ErrSSOExchangeFailed
	}

	// Every provider must return an id_token, and it is verified (signature,
	// nonce, audience, issuer) before any identity is taken from the flow. A
	// login without one is refused: the federated identity (issuer, subject)
	// that binds the account to this IdP, and the session binding used by
	// back-channel logout, come only from the verified id_token.
	var maxAuthAge time.Duration
	if st.reauth {
		maxAuthAge = freshAuthMaxAge
	}
	claims, err := s.verifyIDToken(ctx, rp, tokens.IDToken, nonce, maxAuthAge)
	if err != nil {
		s.logger.Warn("SSO id_token validation failed",
			"provider", input.Provider, "source", rp.source, "error", err)
		return nil, ErrSSOInvalidIDToken
	}

	// SECURITY: a Google Workspace login must come from an account of the
	// organization's Workspace. Only the verified id_token "hd" claim proves
	// that; the "hd" authorize parameter is a UI hint, and a consumer Google
	// account registered with a company address still passes email_verified.
	if rp.provider == identityproviderdom.ProviderGoogleWorkspace {
		if reason := s.googleWorkspaceDomainRefusal(ctx, t, rp, claims.HD); reason != "" {
			s.logger.Warn("google_workspace SSO refused", "reason", reason,
				"tenant_id", t.ID().String(), "subject", claims.Subject)
			return nil, ErrSSODomainNotAllowed
		}
	}

	var userInfo *SSOUserInfo
	if rp.provider == identityproviderdom.ProviderEntraID {
		// SECURITY (FIX 3, nOAuth): for Entra ID, identity comes ONLY from the
		// signature-verified id_token — never the mutable Microsoft Graph /me
		// `mail`. A rogue directory on a multi-tenant authority can set a user's
		// `mail` to a victim's address without owning the domain, so we require
		// `xms_edov == true` (email domain owner-verified) and take the email +
		// immutable (issuer, subject) from the token. If the provider returned no
		// verifiable id_token (e.g. missing "openid" scope) we fail closed rather
		// than trusting Graph mail.
		if claims == nil {
			s.logger.Warn("entra_id SSO refused: no verifiable id_token (the 'openid' scope is required)",
				"provider", input.Provider, "source", rp.source)
			return nil, ErrSSOInvalidIDToken
		}
		info, cerr := entraUserInfoFromClaims(claims)
		if cerr != nil {
			s.logger.Warn("entra_id SSO refused", "reason", cerr.Error(),
				"source", rp.source, "tid", claims.TID, "subject", claims.Subject)
			return nil, ErrSSOInvalidIDToken
		}
		userInfo = info
	} else {
		// Other providers (Okta, Google) go through the OIDC userinfo endpoint,
		// which emits the standard email_verified claim enforced in the parsers.
		_, _, userInfoURL := rp.provider.AuthEndpoints(rp.tenantIdentifier)
		userInfo, err = s.getUserInfo(ctx, rp.provider, tokens.AccessToken, userInfoURL)
		if err != nil {
			s.logger.Error("SSO user info failed", "provider", input.Provider, "error", err)
			return nil, ErrSSOUserInfoFailed
		}
		// Carry the verified id_token identity into account binding when present.
		// These come from the signature-verified, JWKS-pinned id_token (not the
		// userinfo body), so they are authoritative for distinguishing IdPs.
		if claims != nil {
			userInfo.Issuer = canonicalIssuer(claims.Issuer)
			userInfo.Subject = claims.Subject
		}
	}

	// SECURITY: Require email from SSO provider
	if userInfo.Email == "" {
		return nil, ErrSSONoEmail
	}

	// Validate email domain restriction
	parts := strings.SplitN(userInfo.Email, "@", 2)
	if len(parts) == 2 && !rp.isDomainAllowed(parts[1]) {
		return nil, ErrSSODomainNotAllowed
	}

	// Find or create user and provision into tenant. The tenant is passed so the
	// proof-before-link guard can require a DNS-verified tenant domain before a
	// federated login may CLAIM a pre-existing passwordless account (Case 2).
	u, err := s.findOrCreateUser(ctx, t, userInfo, rp)
	if err != nil {
		return nil, fmt.Errorf("find or create user: %w", err)
	}

	// SECURITY (FIX 2): a session must be tied to a real membership in THIS
	// tenant. Existing members are unaffected; a non-member is JIT-provisioned
	// ONLY when the provider auto-provisions AND the verified email domain is on
	// a NON-EMPTY AllowedDomains allow-list. Otherwise the login is refused
	// (fail-closed — no silent member grant).
	if s.tenantMemberRepo != nil {
		if err := s.ensureTenantMembership(ctx, u, t, rp, userInfo.Email); err != nil {
			return nil, err
		}
	}

	// Create session (federated OIDC → stamped 'sso', issued by this tenant's
	// IdP: exempt from THIS tenant's SSO enforcement and 2FA requirement only).
	// The platform env fallback counts as the tenant's IdP: it is used only for
	// a tenant the operator opted in (envFallbackAllowedForTenant) and in place
	// of a provider of its own.
	// Capture the IdP session binding from the verified id_token (when present) so
	// an OIDC Back-Channel Logout can later revoke this exact session. issuer/sid/
	// sub come ONLY from the signature-verified id_token, never the userinfo body.
	var fed federatedBinding
	if claims != nil {
		fed = federatedBinding{issuer: claims.Issuer, sid: claims.SID, sub: claims.Subject, mfa: oidcMFAEvidence(claims)}
		if claims.AuthTime != nil {
			fed.authTime = claims.AuthTime.Time
		}
	}
	sessionResult, err := s.createSession(ctx, u, sessiondom.AuthMethodSSO, t.ID(), fed)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	s.logger.Info("SSO login successful",
		"user_id", u.ID().String(),
		"email", u.Email(),
		"provider", input.Provider,
		"tenant_id", t.ID().String(),
		"org_slug", orgSlug,
	)

	return &SSOCallbackResult{
		AccessToken:  sessionResult.AccessToken,
		RefreshToken: sessionResult.RefreshToken,
		ExpiresIn:    int64(s.authConfig.AccessTokenDuration.Seconds()),
		TokenType:    "Bearer",
		User:         u,
		TenantID:     t.ID().String(),
		TenantSlug:   t.Slug(),
	}, nil
}

// ensureTenantMembership enforces that a federated login lands on a real
// membership in the target tenant. Existing members pass through untouched. A
// non-member is auto-provisioned (JIT) ONLY when the provider auto-provisions
// AND the verified email's domain is on a NON-EMPTY AllowedDomains allow-list;
// otherwise the login is refused with ErrSSONotAMember (fail-closed). Callers
// must have a non-nil tenantMemberRepo.
func (s *SSOService) ensureTenantMembership(ctx context.Context, u *userdom.User, t *tenantdom.Tenant, rp *resolvedProvider, email string) error {
	// Already a member? Nothing to do (existing members are unaffected).
	// An offboarded tombstone is not a membership: only JIT may re-admit the
	// person (from zero), under the same rules as a newcomer.
	if m, err := s.tenantMemberRepo.GetMembership(ctx, u.ID(), t.ID()); err == nil && m != nil && !m.IsOffboarded() {
		if m.AwaitsApproval() {
			return ErrSSOAwaitingApproval
		}
		return nil
	}

	if !s.jitProvisioningAllowed(ctx, t, rp, email) {
		s.logger.Warn("SSO login refused: not a member and JIT provisioning not permitted",
			"user_id", u.ID().String(), "tenant_id", t.ID().String(),
			"source", rp.source, "auto_provision", rp.autoProvision)
		return ErrSSONotAMember
	}

	membership, err := tenantdom.NewMembership(u.ID(), t.ID(), s.jitRoleFor(ctx, t, email, rp.defaultRole), nil)
	if err != nil {
		return fmt.Errorf("build membership: %w", err)
	}
	held, err := holdIfApprovalRequired(t, membership)
	if err != nil {
		return err
	}
	if err := s.tenantMemberRepo.CreateMembership(ctx, membership); err != nil {
		// A concurrent login may have created the membership between our lookup
		// and here — re-check before failing (fail-closed on genuine failure).
		if m, gErr := s.tenantMemberRepo.GetMembership(ctx, u.ID(), t.ID()); gErr == nil && m != nil && !m.IsOffboarded() {
			return nil
		}
		s.logger.Warn("SSO auto-provision membership failed",
			"user_id", u.ID().String(), "tenant_id", t.ID().String(), "error", err)
		return ErrSSONotAMember
	}
	s.logger.Info("SSO auto-provisioned tenant membership",
		"user_id", u.ID().String(), "tenant_id", t.ID().String(), "role", membership.Role().String(), "held", held)
	if held {
		s.notifyAwaitingApproval(ctx, t, email)
		return ErrSSOAwaitingApproval
	}
	return nil
}

// googleWorkspaceDomainRefusal decides whether a Google id_token's hosted
// domain (the "hd" claim) may sign in to the organization. It returns "" when
// it may, otherwise the reason it may not (for the log). Fail-closed:
//   - no "hd" claim: a consumer Google account, never admitted;
//   - the provider narrows domains (AllowedDomains): "hd" must be on that list;
//   - otherwise "hd" must be DNS-verified for this organization (no verifier
//     wired or a lookup error refuses).
func (s *SSOService) googleWorkspaceDomainRefusal(ctx context.Context, t *tenantdom.Tenant, rp *resolvedProvider, hd string) string {
	hd = strings.ToLower(strings.TrimSpace(hd))
	if hd == "" {
		return "id_token has no hd claim (not a Google Workspace account)"
	}
	if len(rp.allowedDomains) > 0 {
		for _, d := range rp.allowedDomains {
			if strings.EqualFold(strings.TrimSpace(d), hd) {
				return ""
			}
		}
		return "hd claim is not one of the provider's allowed domains"
	}
	if s.domainVerifier == nil {
		return "no verified-domain checker wired (fail-closed)"
	}
	verified, err := s.domainVerifier.IsVerifiedDomain(ctx, t.ID().String(), hd)
	if err != nil {
		return "verified-domain lookup failed (fail-closed)"
	}
	if !verified {
		return "hd claim is not a verified domain of the organization"
	}
	return ""
}

// jitMembershipRole is the membership role of a user admitted by SSO
// just-in-time provisioning: the organization's configured default when it is
// member or viewer, otherwise viewer (least privilege). Owner is never
// granted by SSO.
//
// Admin is never granted this way (owner decision B18), including for
// providers stored before the rule or SSO_ENTRA_DEFAULT_ROLE=admin: such a
// configuration provisions viewers.
func jitMembershipRole(configured string) tenantdom.Role {
	switch r := tenantdom.Role(strings.ToLower(strings.TrimSpace(configured))); r {
	case tenantdom.RoleMember, tenantdom.RoleViewer:
		return r
	default:
		return tenantdom.RoleViewer
	}
}

// jitProvisioningAllowed decides whether SSO may admit someone who is not yet a
// member (and, for a first login, create their account): "for an organization,
// SSO decides whether a user is admitted". Fail-closed at every
// branch. All of the following must hold:
//   - the organization's SSO provider opts in to auto-provisioning;
//   - the email's domain is DNS-verified for the organization (the verified
//     domains a platform administrator set up); no verifier wired, a lookup
//     error, or an unverified domain refuses;
//   - when the provider narrows domains (AllowedDomains), the domain is on it;
//   - the organization's own Security.AllowedDomains admits the email.
func (s *SSOService) jitProvisioningAllowed(ctx context.Context, t *tenantdom.Tenant, rp *resolvedProvider, email string) bool {
	if t == nil || rp == nil || !rp.autoProvision {
		return false
	}
	emailDomain := ""
	if at := strings.LastIndex(email, "@"); at >= 0 {
		emailDomain = strings.ToLower(strings.TrimSpace(email[at+1:]))
	}
	if emailDomain == "" {
		return false
	}
	if s.domainVerifier == nil {
		s.logger.Warn("SSO JIT refused: no verified-domain checker wired (fail-closed)",
			"tenant_id", t.ID().String())
		return false
	}
	verified, err := s.domainVerifier.IsVerifiedDomain(ctx, t.ID().String(), emailDomain)
	if err != nil {
		s.logger.Warn("verified-domain check failed; refusing JIT (fail-closed)",
			"tenant_id", t.ID().String(), "error", err)
		return false
	}
	if !verified {
		return false
	}
	// Per-domain JIT (RFC-058): a domain may admit its people without
	// provisioning newcomers.
	if on, _ := s.domainJIT(ctx, t, emailDomain); !on {
		return false
	}
	if len(rp.allowedDomains) > 0 && !rp.isDomainAllowed(emailDomain) {
		return false
	}
	return t.TypedSettings().Security.EmailDomainAllowed(email)
}

// DomainJITPolicy is the per-domain just-in-time provisioning a domain
// verifier may offer (domainverify.Service.DomainJITPolicy).
type DomainJITPolicy interface {
	DomainJITPolicy(ctx context.Context, tenantID, emailDomain string) (enabled bool, role string, err error)
}

// domainJIT returns whether the domain provisions newcomers and their role
// ("" = the provider default). A verifier without per-domain settings keeps
// the provider default behavior; a lookup error refuses (fail closed).
func (s *SSOService) domainJIT(ctx context.Context, t *tenantdom.Tenant, emailDomain string) (bool, string) {
	p, ok := s.domainVerifier.(DomainJITPolicy)
	if !ok {
		return true, ""
	}
	on, role, err := p.DomainJITPolicy(ctx, t.ID().String(), emailDomain)
	if err != nil {
		s.logger.Warn("per-domain JIT lookup failed; refusing JIT (fail-closed)", "tenant_id", t.ID().String(), "error", err)
		return false, ""
	}
	return on, role
}

// jitRoleFor is the role a newcomer admitted on email's domain gets: the
// domain's own JIT role when set, otherwise the provider default.
func (s *SSOService) jitRoleFor(ctx context.Context, t *tenantdom.Tenant, email, providerDefault string) tenantdom.Role {
	if at := strings.LastIndex(email, "@"); at >= 0 {
		if _, role := s.domainJIT(ctx, t, strings.ToLower(email[at+1:])); role != "" {
			return jitMembershipRole(role)
		}
	}
	return jitMembershipRole(providerDefault)
}

// verifyIDToken validates the provider's id_token against its JWKS, the flow
// nonce, our client_id (audience), and a provider-specific issuer check.
//
// The id_token is required for every provider: a provider without signing
// keys, or a token response without an id_token (a provider configured
// without the "openid" scope), is an error. Returns the verified claims so the
// caller can bind the account to the IdP identity (issuer/subject) and, for
// Entra, read the domain-verified email. The returned claims are never nil
// when the error is nil.
func (s *SSOService) verifyIDToken(ctx context.Context, rp *resolvedProvider, idToken, nonce string, maxAuthAge time.Duration) (*oidc.Claims, error) {
	jwksURL := rp.provider.JWKSURL(rp.tenantIdentifier)
	if jwksURL == "" {
		return nil, fmt.Errorf("%s provider has no id_token signing keys (is the organization URL configured?)", rp.provider)
	}
	if strings.TrimSpace(idToken) == "" {
		return nil, errors.New(`token response carried no id_token: the provider must grant the "openid" scope`)
	}

	exp := oidc.Expectations{
		JWKSURI:    jwksURL,
		ClientID:   rp.clientID,
		Nonce:      nonce,
		MaxAuthAge: maxAuthAge,
	}
	switch rp.provider {
	case identityproviderdom.ProviderEntraID:
		exp.IssuerRule = oidc.EntraIssuer(rp.tenantIdentifier)
	case identityproviderdom.ProviderOkta:
		exp.IssuerRule = oidc.OktaIssuer(rp.tenantIdentifier)
	case identityproviderdom.ProviderGoogleWorkspace:
		exp.IssuerRule = oidc.GoogleIssuer
	default:
		// No issuer rule: VerifyIDToken refuses incomplete expectations.
	}

	claims, err := s.oidcVerifier.VerifyIDToken(ctx, idToken, exp)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// entraUserInfoFromClaims maps a signature-verified Entra id_token to SSOUserInfo,
// enforcing the nOAuth email-verification gate (mirrors oauth.go's Path A). The
// email is trusted ONLY when `xms_edov == true`; identity is keyed on the
// immutable (issuer, subject). It is a pure function to keep the security-critical
// gate unit-testable (the signature/issuer/audience checks live in pkg/oidc).
func entraUserInfoFromClaims(claims *oidc.Claims) (*SSOUserInfo, error) {
	if !bool(claims.XMSEdov) {
		return nil, errors.New("entra id_token email not domain-owner-verified (xms_edov absent or false)")
	}
	if strings.TrimSpace(claims.Email) == "" {
		return nil, errors.New("entra id_token has no email claim")
	}
	subject, legacy := entraSubject(claims)
	return &SSOUserInfo{
		Email:         claims.Email,
		Name:          claims.Name,
		Issuer:        claims.Issuer,
		Subject:       subject,
		LegacySubject: legacy,
		EmailVerified: true, // gated on xms_edov==true above (domain-owner verified)
	}, nil
}

// generateState generates a signed state token containing org slug, provider,
// nonce, and the PKCE verifier (stored ENCRYPTED), and returns the matching
// S256 code_challenge for the authorize URL.
//
// PKCE verifier storage — the crux: (Path A, oauth.go, keeps its verifier in
// Redis keyed by state and never sends it.) This state round-trips
// through the browser AND is sent to the IdP as the `state` param, so anything
// stored in the clear there is exposed to a redirect interceptor — which would
// defeat PKCE. We instead ENCRYPT the verifier (AES-256-GCM via s.encryptor,
// the same encryptor used for client secrets) before placing it in the state.
// An interceptor sees only opaque ciphertext; only this server (holding
// APP_ENCRYPTION_KEY) can recover the verifier at callback. This is stateless
// (works across replicas, unlike an in-memory store) and needs no cookie/proxy
// changes — the verifier rides inside the existing `state` the UI already
// round-trips. (In dev without APP_ENCRYPTION_KEY the encryptor is a no-op, so
// the verifier is plaintext — acceptable for dev only.)
func (s *SSOService) generateState(orgSlug, provider string, reauth bool) (state, nonce, codeChallenge string, err error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", "", err
	}

	// Generate nonce for ID token replay prevention
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", "", "", err
	}
	nonce = base64.RawURLEncoding.EncodeToString(nonceBytes)

	// PKCE (RFC 7636): random verifier + S256 challenge.
	verifier, challenge, pkceErr := generatePKCE()
	if pkceErr != nil {
		return "", "", "", pkceErr
	}
	encVerifier, encErr := s.encryptor.EncryptString(verifier)
	if encErr != nil {
		return "", "", "", fmt.Errorf("encrypt pkce verifier: %w", encErr)
	}

	stateData := map[string]interface{}{
		"org":      orgSlug,
		"provider": provider,
		"nonce":    nonce,
		"pkce":     encVerifier,
		"random":   base64.URLEncoding.EncodeToString(randomBytes),
		"exp":      time.Now().Add(10 * time.Minute).Unix(),
	}
	if reauth {
		stateData["reauth"] = true
	}

	stateJSON, marshalErr := json.Marshal(stateData)
	if marshalErr != nil {
		return "", "", "", marshalErr
	}

	stateBase64 := base64.URLEncoding.EncodeToString(stateJSON)
	signature := s.signState(stateBase64)

	return stateBase64 + "." + signature, nonce, challenge, nil
}

// signState creates an HMAC signature for the state.
func (s *SSOService) signState(data string) string {
	h := hmac.New(sha256.New, []byte(s.authConfig.JWTSecret))
	h.Write([]byte(data))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

// ssoState is a verified SSO state: the org slug, provider, the nonce embedded
// at authorize time (compared against the id_token nonce), the decrypted PKCE
// code_verifier (RFC 7636) for the token exchange, and whether the flow asked
// the provider to authenticate the user again.
type ssoState struct {
	org, provider, nonce, codeVerifier string
	reauth                             bool
}

// validateState validates the signed state token and returns its contents.
func (s *SSOService) validateState(state string) (ssoState, error) {
	orgSlug, provider, nonce, codeVerifier, reauth, err := s.parseState(state)
	return ssoState{org: orgSlug, provider: provider, nonce: nonce, codeVerifier: codeVerifier, reauth: reauth}, err
}

func (s *SSOService) parseState(state string) (orgSlug, provider, nonce, codeVerifier string, reauth bool, err error) {
	parts := strings.SplitN(state, ".", 2)
	if len(parts) != 2 {
		return "", "", "", "", false, errors.New("invalid state format")
	}

	stateData, signature := parts[0], parts[1]

	// Verify signature
	expectedSig := s.signState(stateData)
	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return "", "", "", "", false, errors.New("invalid state signature")
	}

	// Decode state data
	stateJSON, err := base64.URLEncoding.DecodeString(stateData)
	if err != nil {
		return "", "", "", "", false, errors.New("invalid state encoding")
	}

	var data map[string]interface{}
	if err := json.Unmarshal(stateJSON, &data); err != nil {
		return "", "", "", "", false, errors.New("invalid state JSON")
	}

	// Check expiration
	expFloat, ok := data["exp"].(float64)
	if !ok {
		return "", "", "", "", false, errors.New("invalid state expiration")
	}
	if time.Now().Unix() > int64(expFloat) {
		return "", "", "", "", false, errors.New("state expired")
	}

	orgSlug, _ = data["org"].(string)
	provider, _ = data["provider"].(string)
	nonce, _ = data["nonce"].(string)
	if orgSlug == "" || provider == "" {
		return "", "", "", "", false, errors.New("missing state fields")
	}

	// Recover the PKCE verifier: it was AES-GCM-encrypted at authorize time (see
	// generateState). A decryption failure means the ciphertext was tampered with
	// — fail closed.
	if enc, encOK := data["pkce"].(string); encOK && enc != "" {
		v, decErr := s.encryptor.DecryptString(enc)
		if decErr != nil {
			return "", "", "", "", false, errors.New("invalid state pkce")
		}
		codeVerifier = v
	}

	reauth, _ = data["reauth"].(bool)
	return orgSlug, provider, nonce, codeVerifier, reauth, nil
}

// ssoTokens represents OAuth token response.
type ssoTokens struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
}

// exchangeCode exchanges authorization code for tokens, sending the PKCE
// code_verifier (RFC 7636) so the IdP can bind the code to the earlier
// code_challenge.
func (s *SSOService) exchangeCode(ctx context.Context, clientID, clientSecret, code, redirectURI, tokenURL, codeVerifier string) (*ssoTokens, error) {
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("grant_type", "authorization_code")

	// PKCE: proves possession of the verifier whose S256 hash was sent as the
	// code_challenge at authorize time.
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

	// SECURITY: Limit response body to 1MB
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed (status %d): %s", resp.StatusCode, string(body))
	}

	var tokens ssoTokens
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, err
	}

	return &tokens, nil
}

// SSOUserInfo represents user info from SSO provider.
type SSOUserInfo struct {
	Email     string
	Name      string
	AvatarURL string

	// Issuer + Subject are the verified id_token's federated identity, the
	// key the account is found by (federated_identity.go). Empty when the
	// provider returned no id_token to verify: the email then finds the
	// account, under the adoption guards, and nothing is bound.
	Issuer  string
	Subject string
	// LegacySubject is the subject the issuer used for this identity before
	// (Entra: `sub`, now keyed on `oid`); an identity bound under it is
	// re-keyed to Subject.
	LegacySubject string

	// EmailVerified records that the IdP proved ownership of Email (Entra
	// xms_edov==true, or the OIDC email_verified claim). Producers set it true
	// ONLY after that check passes. It gates the proof-before-link claim of a
	// pre-existing passwordless account (Case 2); its zero value (false) is
	// fail-closed, so any producer that forgets to set it refuses the claim.
	EmailVerified bool
}

// getUserInfo fetches user information from the SSO provider.
func (s *SSOService) getUserInfo(ctx context.Context, provider identityproviderdom.Provider, accessToken, userInfoURL string) (*SSOUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
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
		// SECURITY: Limit response body to 1MB
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("user info failed (status %d): %s", resp.StatusCode, string(body))
	}

	switch provider {
	case identityproviderdom.ProviderEntraID:
		return s.parseEntraIDUserInfo(resp.Body)
	case identityproviderdom.ProviderOkta:
		return s.parseOktaUserInfo(resp.Body)
	case identityproviderdom.ProviderGoogleWorkspace:
		return s.parseGoogleUserInfo(resp.Body)
	default:
		return nil, ErrSSOProviderUnsupported
	}
}

func (s *SSOService) parseEntraIDUserInfo(body io.Reader) (*SSOUserInfo, error) {
	var data struct {
		Mail              string `json:"mail"`
		UserPrincipalName string `json:"userPrincipalName"`
		DisplayName       string `json:"displayName"`
	}
	if err := json.NewDecoder(body).Decode(&data); err != nil {
		return nil, err
	}

	// SECURITY: Entra ID (via Microsoft Graph /me) does NOT emit an
	// email_verified claim — Graph is a directory API, not an OIDC
	// userinfo endpoint. The trust model is: the tenant-admin
	// configured this IdP, and Azure AD enforces email verification at
	// directory-entry time. Both `mail` and `userPrincipalName` are
	// directory-bound verified identifiers. Account-takeover defence
	// lives in findOrCreateUser's provider-match + PasswordHash check.
	email := data.Mail
	if email == "" {
		email = data.UserPrincipalName
	}

	return &SSOUserInfo{
		Email: email,
		Name:  data.DisplayName,
	}, nil
}

func (s *SSOService) parseOktaUserInfo(body io.Reader) (*SSOUserInfo, error) {
	var data struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"` // OIDC standard claim
		Name          string `json:"name"`
	}
	if err := json.NewDecoder(body).Decode(&data); err != nil {
		return nil, err
	}
	// SECURITY: reject unverified emails. Okta's OIDC userinfo emits the
	// standard email_verified claim; a rogue/misconfigured provider that
	// returns email_verified=false would otherwise let an attacker claim
	// any email address and federate into existing accounts.
	if !data.EmailVerified {
		return nil, fmt.Errorf("okta identity provider did not mark email as verified")
	}
	return &SSOUserInfo{
		Email:         data.Email,
		Name:          data.Name,
		EmailVerified: true, // gated on the OIDC email_verified claim above
	}, nil
}

func (s *SSOService) parseGoogleUserInfo(body io.Reader) (*SSOUserInfo, error) {
	var data struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"` // OIDC; Workspace also emits this
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}
	if err := json.NewDecoder(body).Decode(&data); err != nil {
		return nil, err
	}
	// SECURITY: reject unverified emails from Google Workspace. See
	// parseOktaUserInfo for the rationale.
	if !data.EmailVerified {
		return nil, fmt.Errorf("google workspace identity provider did not mark email as verified")
	}
	return &SSOUserInfo{
		Email:         data.Email,
		Name:          data.Name,
		AvatarURL:     data.Picture,
		EmailVerified: true, // gated on the OIDC email_verified claim above
	}, nil
}

// findOrCreateUser finds an existing user or creates a new SSO user.
// Handles race condition: if two concurrent SSO logins create the same user,
// the second attempt will retry the lookup after a duplicate key error.
func (s *SSOService) findOrCreateUser(ctx context.Context, t *tenantdom.Tenant, userInfo *SSOUserInfo, rp *resolvedProvider) (*userdom.User, error) {
	if userInfo.Email == "" {
		return nil, ErrSSONoEmail
	}
	if rp == nil {
		return nil, ErrSSOProviderNotFound
	}
	provider := rp.provider

	// The IdP's (issuer, subject) finds a returning account first, whatever
	// email the IdP now sends for it.
	key := useridentity.Key{Issuer: userInfo.Issuer, Subject: userInfo.Subject}
	if key.Valid() {
		u, ident, err := s.accounts().lookup(ctx, key, userInfo.LegacySubject)
		if err != nil {
			return nil, fmt.Errorf("resolve federated identity: %w", err)
		}
		if u != nil {
			return s.returningFederatedUser(ctx, t, u, ident, userInfo), nil
		}
	}

	// Unknown identity: the email may name an existing account, adopted only
	// under the proof-before-link guards.
	existingUser, err := s.userRepo.GetByEmail(ctx, userInfo.Email)
	if err == nil && existingUser != nil {
		return s.adoptExistingUser(ctx, t, existingUser, userInfo, provider)
	}

	// No account yet. The organization's SSO is what admits new people,
	// independent of public self-registration
	// (AUTH_ALLOW_REGISTRATION): the account is created only when this login
	// would be just-in-time provisioned into the organization (auto-provision
	// on, DNS-verified email domain, allowed domains). Checking BEFORE creating
	// the account means a refused login leaves no orphan account behind.
	if !s.jitProvisioningAllowed(ctx, t, rp, userInfo.Email) {
		s.logger.Warn("SSO login refused: no account and just-in-time provisioning not permitted",
			"provider", provider, "source", rp.source)
		return nil, ErrSSONotAMember
	}

	// Map identity provider to auth provider
	authProvider := s.mapAuthProvider(provider)

	// Create new user
	// NewFederatedUser (not NewOAuthUser) so Okta / generic-OIDC providers —
	// which mapAuthProvider maps to AuthProviderOIDC — can actually create an
	// account; NewOAuthUser rejects OIDC and broke first-login for those IdPs.
	newUser, err := userdom.NewFederatedUser(userInfo.Email, userInfo.Name, userInfo.AvatarURL, authProvider)
	if err != nil {
		return nil, err
	}
	if err := s.userRepo.Create(ctx, newUser); err != nil {
		// Handle race condition: another concurrent request may have created
		// the user between our GetByEmail and Create calls.
		// Retry the lookup if creation fails (likely unique constraint violation).
		retryUser, retryErr := s.userRepo.GetByEmail(ctx, userInfo.Email)
		if retryErr == nil && retryUser != nil {
			// SECURITY: the concurrently-created (or previously-missed) account
			// must pass the SAME adoption guard as the normal path — otherwise a
			// login whose initial GetByEmail errored/missed could adopt a
			// different-provider or password-backed local account here without
			// any provider/issuer check (takeover via the race/error path).
			s.logger.Debug("user created by concurrent request, using existing", "email", userInfo.Email)
			return s.adoptExistingUser(ctx, t, retryUser, userInfo, provider)
		}
		return nil, fmt.Errorf("create user: %w", err)
	}
	if key.Valid() {
		if err := s.accounts().bind(ctx, newUser, key); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrSSODomainNotAllowed, err)
		}
	}

	s.logger.Info("created SSO user", "user_id", newUser.ID().String(), "email", userInfo.Email, "provider", provider)
	return newUser, nil
}

// returningFederatedUser completes the login of an account found by its
// (issuer, subject). The email the IdP sends now is adopted only when this
// organization DNS-verified its domain and no other account holds it;
// otherwise the account keeps its email and the login still succeeds.
func (s *SSOService) returningFederatedUser(ctx context.Context, t *tenantdom.Tenant, u *userdom.User,
	ident *useridentity.Identity, userInfo *SSOUserInfo) *userdom.User {
	acc := s.accounts()
	prev, changed := acc.adoptProviderEmail(ctx, u, userInfo.Email, func(ctx context.Context, email string) error {
		return s.requireFederatedDomainProof(ctx, t, email)
	})
	syncFederatedProfile(u, userInfo.Name)
	u.UpdateLastLogin()
	acc.saveLogin(ctx, u, prev, changed)
	acc.markUsed(ctx, ident)
	return u
}

// adoptExistingUser applies the proof-before-link / account-takeover guard
// before returning an existing account for a federated login, then records the
// login. It is the SINGLE place adoption is authorized, so BOTH the normal
// lookup path and the create-race retry path enforce the same checks. Matching
// an email is NEVER, on its own, enough to bind a federated identity — the four
// pre-existing-account cases are handled as follows (fail-closed):
//
//	Case 4 (same IdP identity already bound): never reaches here — the
//	   returning user is found by (issuer, subject) in findOrCreateUser.
//	Case 3 (a DIFFERENT federated identity bound): a different auth provider,
//	   another issuer, or another subject at the same issuer — rejected
//	   (cross-IdP takeover). The provider enum is coarse (every Okta org /
//	   generic OIDC IdP collapse to AuthProviderOIDC), so the identity check
//	   below is what actually distinguishes IdPs and people.
//	Case 1 (a real password-backed local account, no federated identity): never
//	   silently linked. Refused with ErrAccountLinkRequiresVerification so the
//	   user signs in with their existing password first, then links the IdP from
//	   an authenticated session (proof of ownership).
//	Case 2 (a claimable PASSWORDLESS local account — invited / SCIM-provisioned,
//	   the classic pre-hijack target): only claimable when ownership is provable
//	   WITHOUT a password — the IdP verified the email AND the email domain is a
//	   DNS-verified domain of THIS tenant (see requireClaimableOwnershipProof).
//	   Otherwise refused, so an attacker cannot claim an invited seat.
func (s *SSOService) adoptExistingUser(ctx context.Context, t *tenantdom.Tenant, existingUser *userdom.User, userInfo *SSOUserInfo, provider identityproviderdom.Provider) (*userdom.User, error) {
	existingProvider := existingUser.AuthProvider()
	expectedProvider := s.mapAuthProvider(provider)

	if existingProvider != expectedProvider {
		// The federated login's provider does not match the one that created the
		// account. A non-local existing account is bound to a DIFFERENT federated
		// provider (Case 3) — reject outright.
		if existingProvider != userdom.AuthProviderLocal {
			s.logger.Warn("SSO login blocked: email registered with a different auth provider",
				"email", userInfo.Email,
				"existing_provider", existingProvider,
				"sso_provider", expectedProvider,
			)
			return nil, fmt.Errorf("%w: this email is registered with a different login method", ErrSSODomainNotAllowed)
		}

		// The existing account is LOCAL. A password-backed local account is a real,
		// activated account (Case 1) — proof-before-link: never adopt it on the
		// strength of a matching federated email. The user must authenticate with
		// their password first and link the IdP explicitly.
		if existingUser.PasswordHash() != nil {
			s.logger.Warn("SSO login blocked: email owns a password account; proof-before-link required",
				"email", userInfo.Email, "sso_provider", expectedProvider)
			return nil, ErrAccountLinkRequiresVerification
		}

		// The existing account is a claimable, passwordless local account (Case 2 —
		// invited / SCIM-provisioned). Require provable ownership before binding.
		if err := s.requireClaimableOwnershipProof(ctx, t, userInfo); err != nil {
			return nil, err
		}
	}

	// The IdP's identity was not found (findOrCreateUser looks it up first),
	// so the account holds no binding for it. An account bound to another
	// subject at the same IdP, or to another IdP, is a different person's
	// account: refused (Case 3). Matching the email is never enough.
	key := useridentity.Key{Issuer: userInfo.Issuer, Subject: userInfo.Subject}
	if key.Valid() {
		sameIssuer, otherIssuer, err := s.accounts().boundIdentities(ctx, existingUser, key)
		if err != nil {
			return nil, fmt.Errorf("check federated identities: %w", err)
		}
		if sameIssuer {
			s.logger.Warn("SSO login blocked: email bound to another subject at this identity provider",
				"email", userInfo.Email, "issuer", userInfo.Issuer)
			return nil, fmt.Errorf("%w: %w", ErrSSODomainNotAllowed, ErrFederatedIdentityConflict)
		}
		if otherIssuer != nil {
			s.logger.Warn("SSO login blocked: email bound to a different identity provider",
				"email", userInfo.Email,
				"bound_issuer", otherIssuer.Key.Issuer,
				"login_issuer", userInfo.Issuer,
			)
			return nil, fmt.Errorf("%w: this email is registered with a different identity provider", ErrSSODomainNotAllowed)
		}
	}

	// Same provider type and no binding to match: every Okta/generic OIDC IdP
	// collapses to the same provider type, so the type match proves nothing
	// and any organization's IdP could assert this email. Require the
	// organization to have DNS-proven the email domain before adopting (and,
	// below, binding) the account.
	if existingProvider == expectedProvider {
		if err := s.requireFederatedDomainProof(ctx, t, userInfo.Email); err != nil {
			s.logger.Warn("SSO login blocked: account has no matching IdP binding and the email domain is not DNS-verified for this organization",
				"sso_provider", expectedProvider)
			return nil, fmt.Errorf("%w: %w", ErrAccountLinkRequiresVerification, err)
		}
	}

	if key.Valid() {
		if err := s.accounts().bind(ctx, existingUser, key); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrSSODomainNotAllowed, err)
		}
	}

	syncFederatedProfile(existingUser, userInfo.Name)
	existingUser.UpdateLastLogin()
	if updateErr := s.userRepo.Update(ctx, existingUser); updateErr != nil {
		s.logger.Warn("failed to update last login", "error", updateErr)
	}
	return existingUser, nil
}

// syncFederatedProfile re-syncs, on each SSO login, the only attribute that is
// safe to take from the identity provider: the display name. Email (the
// account key), password, roles and memberships are never changed by a login;
// role changes go through the organization's administrators or SCIM.
func syncFederatedProfile(u *userdom.User, idpName string) {
	name := strings.TrimSpace(idpName)
	if name == "" || name == u.Name() || len(name) > 255 {
		return
	}
	u.UpdateProfile(name, u.Phone(), u.AvatarURL())
}

// requireClaimableOwnershipProof authorizes a federated login to CLAIM a
// pre-existing PASSWORDLESS local account (Case 2 — an invited / SCIM seat).
// Because such an account has no password, the only safe proof of ownership is:
//
//  1. the IdP verified the email (xms_edov / email_verified — captured on
//     userInfo.EmailVerified by the producers), AND
//  2. the email's domain is a DNS-verified domain of THIS tenant.
//
// Together these prove both that the IdP vouches for the address and that the
// tenant owns the domain the seat belongs to — so the claim cannot be forged by
// an attacker who merely presents a matching email. Fail-closed at every branch:
// a missing tenant, missing/unverified email, unparseable domain, an unwired or
// erroring domain verifier, or an unverified domain all refuse the claim.
func (s *SSOService) requireClaimableOwnershipProof(ctx context.Context, t *tenantdom.Tenant, userInfo *SSOUserInfo) error {
	if t == nil {
		s.logger.Warn("account claim refused: no tenant context (fail-closed)", "email", userInfo.Email)
		return ErrAccountLinkRequiresVerification
	}
	// (1) The IdP must have proven the email. Upstream producers already refuse an
	// unverified email, so this is a defense-in-depth assertion local to the gate.
	if !userInfo.EmailVerified {
		s.logger.Warn("account claim refused: email not IdP-verified",
			"email", userInfo.Email, "tenant_id", t.ID().String())
		return ErrAccountLinkRequiresVerification
	}
	emailDomain := ""
	if parts := strings.SplitN(userInfo.Email, "@", 2); len(parts) == 2 {
		emailDomain = strings.ToLower(strings.TrimSpace(parts[1]))
	}
	if emailDomain == "" {
		return ErrAccountLinkRequiresVerification
	}
	// (2) The tenant must have DNS-proven it owns the domain. Without the verifier
	// wired we cannot establish ownership → refuse (fail-closed), rather than fall
	// back to the weaker AllowedDomains list, which is admin-asserted not DNS-proven.
	if s.domainVerifier == nil {
		s.logger.Warn("account claim refused: domain verifier not wired (fail-closed)",
			"email", userInfo.Email, "tenant_id", t.ID().String())
		return ErrAccountLinkRequiresVerification
	}
	verified, err := s.domainVerifier.IsVerifiedDomain(ctx, t.ID().String(), emailDomain)
	if err != nil {
		s.logger.Warn("account claim refused: verified-domain check failed (fail-closed)",
			"email", userInfo.Email, "tenant_id", t.ID().String(), "error", err)
		return ErrAccountLinkRequiresVerification
	}
	if !verified {
		s.logger.Warn("account claim refused: email domain is not DNS-verified for this tenant",
			"email", userInfo.Email, "tenant_id", t.ID().String(), "domain", emailDomain)
		return ErrAccountLinkRequiresVerification
	}
	s.logger.Info("federated login claimed a passwordless account (verified email + DNS-verified domain)",
		"email", userInfo.Email, "tenant_id", t.ID().String(), "domain", emailDomain)
	return nil
}

// mapAuthProvider maps identity provider to user auth provider.
func (s *SSOService) mapAuthProvider(provider identityproviderdom.Provider) userdom.AuthProvider {
	switch provider {
	case identityproviderdom.ProviderEntraID:
		return userdom.AuthProviderMicrosoft
	case identityproviderdom.ProviderGoogleWorkspace:
		return userdom.AuthProviderGoogle
	case identityproviderdom.ProviderOkta:
		return userdom.AuthProviderOIDC
	default:
		return userdom.AuthProviderOIDC
	}
}

// createSession creates a new session for the user. authMethod records how the
// identity was federated (AuthMethodSSO for OIDC/OAuth, AuthMethodSAML for a
// SAML assertion) and idpTenant the organization whose identity provider
// issued it. Together they make the session an SSO sign-in OF that
// organization only: it is exempt from that organization's SSO enforcement and
// 2FA requirement (an SSO-enforced organization must admit the very login
// method it requires), but users are global, so for every other organization
// the account belongs to it is treated as a password session
// (Session.FederatedFor).
// federatedBinding carries the IdP session identifiers captured from a verified
// id_token so createSession can persist them for OIDC Back-Channel Logout. All
// fields may be empty (a provider may omit sid or return no id_token).
type federatedBinding struct {
	issuer string
	sid    string
	sub    string
	// authTime is when the provider last authenticated the user (id_token
	// auth_time, SAML AuthnInstant); zero when the provider did not say.
	authTime time.Time
	// mfa: the provider proved a second factor for this sign-in (OIDC amr
	// "mfa", SAML multi-factor AuthnContext). Recorded on the session.
	mfa bool
}

// freshAuthMaxAge is how old the provider's authentication may be when a
// flow asked for a fresh one (prompt=login / ForceAuthn): the user signed in
// at the provider and was sent straight back.
const freshAuthMaxAge = 5 * time.Minute

func (s *SSOService) createSession(ctx context.Context, u *userdom.User, authMethod sessiondom.AuthMethod, idpTenant shared.ID, fed federatedBinding) (*SessionResult, error) {
	// Bind the token to its session: generate the session id first, embed it in
	// the JWT, then persist the session under the SAME id — so an SSO session is
	// revocable (mirrors the password Login flow). Previously the token was
	// minted with an empty session id, leaving the token and session row
	// unlinked, so the SSO access token could not be revoked.
	sessionID := shared.NewID()
	tokenPair, err := s.tokenGenerator.GenerateTokenPair(u.ID().String(), sessionID.String(), "user")
	if err != nil {
		return nil, fmt.Errorf("generate tokens: %w", err)
	}

	newSession, err := sessiondom.NewWithID(
		sessionID,
		u.ID(),
		tokenPair.AccessToken,
		"", // IP address from request context
		"", // User agent from request context
		s.authConfig.SessionDuration,
	)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	// Stamp the session as federated, issued by idpTenant's identity provider.
	// Default to SSO for any unspecified/invalid federated method.
	if !authMethod.IsFederated() {
		authMethod = sessiondom.AuthMethodSSO
	}
	newSession.SetAuthMethod(authMethod)
	newSession.SetIDPTenant(idpTenant)
	newSession.SetMFAEvidence(fed.mfa)

	// Persist the IdP session binding (issuer/sid/sub) so an OIDC Back-Channel
	// Logout from this provider can revoke exactly this session. Only stamped
	// when an issuer is present (a verified id_token was seen).
	if fed.issuer != "" {
		newSession.SetFederatedBinding(fed.issuer, fed.sid, fed.sub)
	}

	if err := s.sessionRepo.Create(ctx, newSession); err != nil {
		return nil, fmt.Errorf("save session: %w", err)
	}
	s.stampProviderAuthentication(ctx, newSession, fed.authTime)

	refreshTokenEntity, err := sessiondom.NewRefreshToken(
		u.ID(),
		newSession.ID(),
		tokenPair.RefreshToken,
		s.authConfig.RefreshTokenDuration,
	)
	if err != nil {
		return nil, fmt.Errorf("create refresh token: %w", err)
	}

	if err := s.refreshTokenRepo.Create(ctx, refreshTokenEntity); err != nil {
		return nil, fmt.Errorf("save refresh token: %w", err)
	}

	return &SessionResult{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
	}, nil
}

// ErrSSOFederatedTakeover is returned when a federated (e.g. SAML) login
// resolves to an existing password-backed local account — logging into it from
// an external assertion would be account takeover.
var ErrSSOFederatedTakeover = errors.New("email is registered with a password; federated login not allowed")

// ErrSSOFederatedNotMember is returned when a federated login matches an
// existing global user who is not a member of the target tenant — blocking a
// malicious tenant from forging an assertion for another tenant's user.
var ErrSSOFederatedNotMember = errors.New("federated login not permitted: user is not a member of this organization")

// ErrSSOFederatedDomainUnverified is returned when a federated login matches an
// existing account whose email domain the organization has not DNS-verified:
// the organization's IdP cannot vouch for an identity on a domain it does not
// own.
var ErrSSOFederatedDomainUnverified = errors.New("federated login not permitted: email domain is not verified for this organization")

// requireFederatedDomainProof reports whether the organization t has DNS-proven
// the domain of email. Fail-closed: an unparseable email, an unwired or failing
// verifier, or an unverified domain all refuse.
func (s *SSOService) requireFederatedDomainProof(ctx context.Context, t *tenantdom.Tenant, email string) error {
	at := strings.LastIndex(email, "@")
	if t == nil || at < 0 {
		return ErrSSOFederatedDomainUnverified
	}
	emailDomain := strings.ToLower(strings.TrimSpace(email[at+1:]))
	if emailDomain == "" || s.domainVerifier == nil {
		return ErrSSOFederatedDomainUnverified
	}
	verified, err := s.domainVerifier.IsVerifiedDomain(ctx, t.ID().String(), emailDomain)
	if err != nil || !verified {
		return ErrSSOFederatedDomainUnverified
	}
	return nil
}

// CompleteFederatedLogin issues an OpenCTEM session for an externally
// authenticated identity (e.g. a validated SAML assertion). It finds-or-creates
// a claimable passwordless user, blocks takeover of password-backed local
// accounts, auto-provisions tenant membership when requested, and creates the
// session. Reused by the SAML SP flow so it shares the SSO session machinery.
func (s *SSOService) CompleteFederatedLogin(ctx context.Context, t *tenantdom.Tenant, email, name, defaultRole string, autoProvision bool) (*SSOCallbackResult, error) {
	return s.completeFederatedLogin(ctx, t, email, name, defaultRole, autoProvision, federatedBinding{}, useridentity.Key{})
}

// completeFederatedLogin is CompleteFederatedLogin with the time the
// provider authenticated the user (SAML AuthnInstant), which opens the
// step-up window when it is recent, and the assertion's identity (issuer +
// persistent NameID, scoped to t; empty when the IdP sent no persistent id).
//
//nolint:cyclop // one decision tree: returning identity, existing email, new account
func (s *SSOService) completeFederatedLogin(ctx context.Context, t *tenantdom.Tenant, email, name, defaultRole string,
	autoProvision bool, fed federatedBinding, key useridentity.Key) (*SSOCallbackResult, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return nil, ErrSSONoEmail
	}

	// The identity is trusted only inside the organization whose IdP
	// certificate signed it: never look it up, or bind it, platform-wide.
	if key.Valid() && (key.ScopeTenantID == nil || *key.ScopeTenantID != t.ID()) {
		return nil, ErrSSOFederatedNotMember
	}

	newUser := false
	var u *userdom.User
	if key.Valid() {
		found, ident, lerr := s.accounts().lookup(ctx, key, "")
		if lerr != nil {
			return nil, fmt.Errorf("resolve federated identity: %w", lerr)
		}
		if found != nil {
			// Bound earlier in this organization; the person must still be a
			// member of it (an offboarded member's identity row survives).
			if err := s.requireFederatedMembership(ctx, found, t); err != nil {
				return nil, err
			}
			acc := s.accounts()
			prev, changed := acc.adoptProviderEmail(ctx, found, email, func(ctx context.Context, e string) error {
				return s.requireFederatedDomainProof(ctx, t, e)
			})
			syncFederatedProfile(found, name)
			found.UpdateLastLogin()
			acc.saveLogin(ctx, found, prev, changed)
			acc.markUsed(ctx, ident)
			return s.federatedSessionResult(ctx, found, t, fed)
		}
	}

	existing, err := s.userRepo.GetByEmail(ctx, email)
	if err == nil && existing != nil {
		u = existing
		if err := s.admitExistingSAMLAccount(ctx, u, t, email, name, key); err != nil {
			return nil, err
		}
	} else {
		// No account yet: the organization's SSO admits new people only through
		// just-in-time provisioning (auto-provision on, DNS-verified email
		// domain, allowed domains). Refuse before creating anything, so a
		// refused login leaves no orphan account and no tenant-less session.
		if !s.jitProvisioningAllowed(ctx, t, &resolvedProvider{autoProvision: autoProvision, source: "saml"}, email) {
			s.logger.Warn("federated login refused: no account and just-in-time provisioning not permitted",
				"tenant_id", t.ID().String())
			return nil, ErrSSONotAMember
		}
		newUser = true
		// Create a claimable passwordless local user (same shape as an invite).
		newU, cerr := userdom.New(email, name)
		if cerr != nil {
			return nil, fmt.Errorf("%w: %v", shared.ErrValidation, cerr)
		}
		if cerr := s.userRepo.Create(ctx, newU); cerr != nil {
			if retry, rerr := s.userRepo.GetByEmail(ctx, email); rerr == nil && retry != nil {
				newU = retry
			} else {
				return nil, fmt.Errorf("create user: %w", cerr)
			}
		} else if key.Valid() {
			if berr := s.accounts().bind(ctx, newU, key); berr != nil {
				return nil, berr
			}
		}
		u = newU
	}

	if newUser && s.tenantMemberRepo != nil {
		held := false
		membership, memErr := tenantdom.NewMembership(u.ID(), t.ID(), s.jitRoleFor(ctx, t, email, defaultRole), nil)
		if memErr == nil {
			held, memErr = holdIfApprovalRequired(t, membership)
		}
		if memErr == nil {
			memErr = s.tenantMemberRepo.CreateMembership(ctx, membership)
		}
		if memErr != nil {
			// A concurrent login may have provisioned it; otherwise refuse
			// rather than issue a session with no membership.
			if m, gErr := s.tenantMemberRepo.GetMembership(ctx, u.ID(), t.ID()); gErr != nil || m == nil {
				s.logger.Warn("federated auto-provision membership failed", "user_id", u.ID().String(), "error", memErr)
				return nil, ErrSSONotAMember
			}
		} else if held {
			s.notifyAwaitingApproval(ctx, t, email)
		}
	}
	// A membership that waits for an administrator's approval gets no
	// session in the organization (RFC-058).
	if s.tenantMemberRepo != nil {
		if m, gErr := s.tenantMemberRepo.GetMembership(ctx, u.ID(), t.ID()); gErr == nil && m != nil && m.AwaitsApproval() {
			return nil, ErrSSOAwaitingApproval
		}
	}

	return s.federatedSessionResult(ctx, u, t, fed)
}

// admitExistingSAMLAccount lets t's SAML IdP sign in an existing account
// found by email: never a password account, only a member of t, only on a
// domain t DNS-verified; the assertion's identity is then bound.
func (s *SSOService) admitExistingSAMLAccount(ctx context.Context, u *userdom.User, t *tenantdom.Tenant,
	email, name string, key useridentity.Key) error {
	// Account-takeover guard: a password-backed local account must not be
	// accessible via an external assertion.
	if u.AuthProvider() == userdom.AuthProviderLocal && u.PasswordHash() != nil {
		return ErrSSOFederatedTakeover
	}
	// Cross-tenant takeover guard: users are global, so GetByEmail can match a
	// user who belongs to a DIFFERENT tenant. A federated assertion (SAML in
	// particular, where the tenant admin holds the IdP signing key) must not
	// bind to a pre-existing user unless they are already a member of THIS
	// tenant — otherwise a malicious tenant could forge an assertion for any
	// global email and mint a session as that victim. Brand-new users (no
	// match) are created + auto-provisioned below; existing users must have
	// been invited (membership) first. Fail closed on lookup error.
	if err := s.requireFederatedMembership(ctx, u, t); err != nil {
		return err
	}
	// Membership alone does not let this organization's IdP speak for the
	// account. Users are global: an organization can make someone a member
	// (an accepted invitation, SCIM, an admin add) without owning their
	// identity, and a session minted here is exchangeable for every other
	// organization the account belongs to. So the organization must have
	// DNS-proven the email domain — the same proof the OIDC path demands
	// before it claims an existing passwordless account
	// (requireClaimableOwnershipProof) and that JIT demands for new users.
	if err := s.requireFederatedDomainProof(ctx, t, email); err != nil {
		s.logger.Warn("federated login refused: email domain is not DNS-verified for this organization",
			"user_id", u.ID().String(), "tenant_id", t.ID().String())
		return err
	}
	if err := s.bindSAMLIdentity(ctx, u, t, key); err != nil {
		return err
	}
	syncFederatedProfile(u, name)
	u.UpdateLastLogin()
	if uerr := s.userRepo.Update(ctx, u); uerr != nil {
		s.logger.Warn("federated login: update last login", "error", uerr)
	}
	return nil
}

// bindSAMLIdentity binds the assertion's identity to an existing account
// that passed the membership and domain checks. The identity was not found
// by lookup, so an account already bound to another subject at this IdP is
// someone else's: refused. No identity (no persistent NameID): nothing to do.
func (s *SSOService) bindSAMLIdentity(ctx context.Context, u *userdom.User, t *tenantdom.Tenant, key useridentity.Key) error {
	if !key.Valid() {
		return nil
	}
	sameIssuer, _, err := s.accounts().boundIdentities(ctx, u, key)
	if err != nil {
		return fmt.Errorf("check federated identities: %w", err)
	}
	if sameIssuer {
		s.logger.Warn("federated login refused: email bound to another subject at this identity provider",
			"user_id", u.ID().String(), "tenant_id", t.ID().String())
		return ErrFederatedIdentityConflict
	}
	return s.accounts().bind(ctx, u, key)
}

// requireFederatedMembership admits an existing account through t's SAML IdP
// only when it is a member of t (not offboarded). Fail closed on lookup error.
func (s *SSOService) requireFederatedMembership(ctx context.Context, u *userdom.User, t *tenantdom.Tenant) error {
	if s.tenantMemberRepo == nil {
		return nil
	}
	m, mErr := s.tenantMemberRepo.GetMembership(ctx, u.ID(), t.ID())
	if mErr != nil || m == nil || m.IsOffboarded() {
		s.logger.Warn("federated login refused: user is not a member of the target tenant",
			"user_id", u.ID().String(), "tenant_id", t.ID().String())
		return ErrSSOFederatedNotMember
	}
	return nil
}

// federatedSessionResult issues the session of a SAML login.
func (s *SSOService) federatedSessionResult(ctx context.Context, u *userdom.User, t *tenantdom.Tenant, fed federatedBinding) (*SSOCallbackResult, error) {
	// Federated via a validated SAML assertion → stamped 'saml', issued by this
	// tenant's IdP (exempt from this tenant's enforcement only — it IS this
	// tenant's SSO login). No OIDC id_token binding — SAML single
	// logout is out of scope for the OIDC back-channel path.
	sessionResult, err := s.createSession(ctx, u, sessiondom.AuthMethodSAML, t.ID(), federatedBinding{authTime: fed.authTime, mfa: fed.mfa})
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	return &SSOCallbackResult{
		AccessToken:  sessionResult.AccessToken,
		RefreshToken: sessionResult.RefreshToken,
		ExpiresIn:    int64(s.authConfig.AccessTokenDuration.Seconds()),
		TokenType:    "Bearer",
		User:         u,
		TenantID:     t.ID().String(),
		TenantSlug:   t.Slug(),
	}, nil
}

// === Admin CRUD operations for identity provider configurations ===

// CreateProviderInput is the input for creating an identity provider config.
type CreateProviderInput struct {
	TenantID         string
	Provider         string
	DisplayName      string
	ClientID         string
	ClientSecret     string // Plaintext - will be encrypted
	IssuerURL        string
	TenantIdentifier string
	Scopes           []string
	AllowedDomains   []string
	AutoProvision    bool
	DefaultRole      string
	CreatedBy        string
}

// validSSODefaultRoles are the roles allowed for auto-provisioned SSO users.
// Owner and admin are excluded (owner decision B18): an IdP misconfiguration
// must not provision administrators; admins are promoted explicitly.
var validSSODefaultRoles = map[string]bool{
	"member": true,
	"viewer": true,
}

// validateDefaultRole checks that the default role is a valid non-owner role.
func validateDefaultRole(role string) error {
	if role == "" {
		return nil // Will use entity default ("member")
	}
	if !validSSODefaultRoles[role] {
		return fmt.Errorf("%w: must be member or viewer", ErrSSOInvalidDefaultRole)
	}
	return nil
}

// validateTenantIdentifier validates the tenant identifier to prevent SSRF.
// For Okta, this must be a valid https URL. For Entra ID, it's a directory/tenant ID.
func validateTenantIdentifier(provider identityproviderdom.Provider, tid string) error {
	if tid == "" {
		return nil
	}
	switch provider {
	case identityproviderdom.ProviderOkta:
		// Okta tenant identifier is the org URL (e.g., https://dev-123456.okta.com)
		parsed, err := url.Parse(tid)
		if err != nil {
			return fmt.Errorf("%w: invalid Okta org URL", identityproviderdom.ErrInvalidConfig)
		}
		if parsed.Scheme != "https" {
			return fmt.Errorf("%w: Okta org URL must use https", identityproviderdom.ErrInvalidConfig)
		}
		if parsed.Host == "" {
			return fmt.Errorf("%w: Okta org URL missing host", identityproviderdom.ErrInvalidConfig)
		}
		// Prevent SSRF: only allow known Okta domains
		host := strings.ToLower(parsed.Host)
		if !strings.HasSuffix(host, ".okta.com") && !strings.HasSuffix(host, ".oktapreview.com") {
			return fmt.Errorf("%w: Okta org URL must end with .okta.com or .oktapreview.com", identityproviderdom.ErrInvalidConfig)
		}
	case identityproviderdom.ProviderEntraID:
		// Entra ID tenant identifier is a GUID or domain — no URL, so no SSRF risk.
		// Just prevent overly long or suspicious values.
		if len(tid) > 128 {
			return fmt.Errorf("%w: tenant identifier too long", identityproviderdom.ErrInvalidConfig)
		}
	}
	return nil
}

// validateScopes validates that requested scopes are reasonable. A non-empty
// scope list must include "openid": sign-in verifies the provider's id_token,
// which the provider issues only for that scope. An empty list means the
// defaults, which include it.
func validateScopes(scopes []string) error {
	if len(scopes) > 20 {
		return fmt.Errorf("%w: too many scopes (max 20)", identityproviderdom.ErrInvalidConfig)
	}
	for _, scope := range scopes {
		if len(scope) > 128 {
			return fmt.Errorf("%w: scope too long (max 128 chars)", identityproviderdom.ErrInvalidConfig)
		}
	}
	if len(scopes) > 0 && !hasOpenIDScope(scopes) {
		return fmt.Errorf(`%w: scopes must include "openid" (sign-in verifies the provider's id_token)`, identityproviderdom.ErrInvalidConfig)
	}
	return nil
}

func hasOpenIDScope(scopes []string) bool {
	for _, sc := range scopes {
		if strings.TrimSpace(sc) == "openid" {
			return true
		}
	}
	return false
}

// withOpenIDScope returns scopes with "openid" first if it is missing. A
// provider saved before "openid" was required keeps working: its authorize
// request asks for the id_token that the callback now requires.
func withOpenIDScope(scopes []string) []string {
	if hasOpenIDScope(scopes) {
		return scopes
	}
	return append([]string{"openid"}, scopes...)
}

// validateAllowedDomains validates allowed email domains.
func validateAllowedDomains(domains []string) error {
	if len(domains) > 100 {
		return fmt.Errorf("%w: too many allowed domains (max 100)", identityproviderdom.ErrInvalidConfig)
	}
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			return fmt.Errorf("%w: empty domain not allowed", identityproviderdom.ErrInvalidConfig)
		}
		if len(domain) > 255 {
			return fmt.Errorf("%w: domain too long (max 255 chars)", identityproviderdom.ErrInvalidConfig)
		}
		if strings.Contains(domain, "*") {
			return fmt.Errorf("%w: wildcards not allowed in domain", identityproviderdom.ErrInvalidConfig)
		}
		if strings.ContainsAny(domain, " \t\n\r") {
			return fmt.Errorf("%w: domain contains whitespace", identityproviderdom.ErrInvalidConfig)
		}
	}
	return nil
}

// CreateProvider creates a new identity provider configuration for a tenant.
func (s *SSOService) CreateProvider(ctx context.Context, input CreateProviderInput) (*identityproviderdom.IdentityProvider, error) {
	ip, err := s.BuildProvider(input)
	if err != nil {
		return nil, err
	}
	if err := s.ipRepo.Create(ctx, ip); err != nil {
		return nil, err
	}
	return ip, nil
}

// BuildProvider validates input and returns the identity provider it
// describes (client secret encrypted), without storing it.
func (s *SSOService) BuildProvider(input CreateProviderInput) (*identityproviderdom.IdentityProvider, error) {
	provider := identityproviderdom.Provider(input.Provider)
	if !provider.IsValid() {
		return nil, identityproviderdom.ErrInvalidProvider
	}

	// Validate default role (prevent setting "owner" via SSO auto-provision)
	if err := validateDefaultRole(input.DefaultRole); err != nil {
		return nil, err
	}

	// Validate tenant identifier to prevent SSRF
	if err := validateTenantIdentifier(provider, input.TenantIdentifier); err != nil {
		return nil, err
	}

	// Validate scopes
	if err := validateScopes(input.Scopes); err != nil {
		return nil, err
	}

	// Validate allowed domains
	if err := validateAllowedDomains(input.AllowedDomains); err != nil {
		return nil, err
	}

	// Encrypt client secret
	encryptedSecret, err := s.encryptor.EncryptString(input.ClientSecret)
	if err != nil {
		return nil, fmt.Errorf("encrypt client secret: %w", err)
	}

	ip := identityproviderdom.New(
		shared.NewID().String(),
		input.TenantID,
		provider,
		input.DisplayName,
		input.ClientID,
		encryptedSecret,
	)

	if input.IssuerURL != "" {
		ip.SetIssuerURL(input.IssuerURL)
	}
	if input.TenantIdentifier != "" {
		ip.SetTenantIdentifier(input.TenantIdentifier)
	}
	if len(input.Scopes) > 0 {
		ip.SetScopes(input.Scopes)
	}
	if len(input.AllowedDomains) > 0 {
		ip.SetAllowedDomains(input.AllowedDomains)
	}
	ip.SetAutoProvision(input.AutoProvision)
	if input.DefaultRole != "" {
		ip.SetDefaultRole(input.DefaultRole)
	}
	if input.CreatedBy != "" {
		ip.SetCreatedBy(input.CreatedBy)
	}
	return ip, nil
}

// UpdateProviderInput is the input for updating an identity provider config.
type UpdateProviderInput struct {
	ID               string
	TenantID         string // For authorization check
	DisplayName      *string
	ClientID         *string
	ClientSecret     *string // Plaintext - will be encrypted if provided
	IssuerURL        *string
	TenantIdentifier *string
	Scopes           []string
	AllowedDomains   []string
	AutoProvision    *bool
	DefaultRole      *string
	IsActive         *bool
}

// UpdateProvider updates an identity provider configuration.
func (s *SSOService) UpdateProvider(ctx context.Context, input UpdateProviderInput) (*identityproviderdom.IdentityProvider, error) {
	ip, err := s.BuildProviderUpdate(ctx, input)
	if err != nil {
		return nil, err
	}
	if err := s.ipRepo.Update(ctx, ip); err != nil {
		return nil, err
	}
	return ip, nil
}

// BuildProviderUpdate validates input and returns the tenant's identity
// provider with the update applied, without storing it.
func (s *SSOService) BuildProviderUpdate(ctx context.Context, input UpdateProviderInput) (*identityproviderdom.IdentityProvider, error) {
	ip, err := s.ipRepo.GetByID(ctx, input.TenantID, input.ID)
	if err != nil {
		return nil, err
	}

	// Validate default role if being updated
	if input.DefaultRole != nil {
		if err := validateDefaultRole(*input.DefaultRole); err != nil {
			return nil, err
		}
	}

	// Validate tenant identifier if being updated
	if input.TenantIdentifier != nil {
		if err := validateTenantIdentifier(ip.Provider(), *input.TenantIdentifier); err != nil {
			return nil, err
		}
	}

	// Validate allowed domains if being updated
	if input.AllowedDomains != nil {
		if err := validateAllowedDomains(input.AllowedDomains); err != nil {
			return nil, err
		}
	}

	// Validate scopes if being updated
	if input.Scopes != nil {
		if err := validateScopes(input.Scopes); err != nil {
			return nil, err
		}
	}

	if input.DisplayName != nil {
		ip.SetDisplayName(*input.DisplayName)
	}
	if input.ClientID != nil {
		ip.SetClientID(*input.ClientID)
	}
	if input.ClientSecret != nil {
		encryptedSecret, encErr := s.encryptor.EncryptString(*input.ClientSecret)
		if encErr != nil {
			return nil, fmt.Errorf("encrypt client secret: %w", encErr)
		}
		ip.SetClientSecretEncrypted(encryptedSecret)
	}
	if input.IssuerURL != nil {
		ip.SetIssuerURL(*input.IssuerURL)
	}
	if input.TenantIdentifier != nil {
		ip.SetTenantIdentifier(*input.TenantIdentifier)
	}
	if input.Scopes != nil {
		ip.SetScopes(input.Scopes)
	}
	if input.AllowedDomains != nil {
		ip.SetAllowedDomains(input.AllowedDomains)
	}
	if input.AutoProvision != nil {
		ip.SetAutoProvision(*input.AutoProvision)
	}
	if input.DefaultRole != nil {
		ip.SetDefaultRole(*input.DefaultRole)
	}
	if input.IsActive != nil {
		ip.SetActive(*input.IsActive)
	}
	return ip, nil
}

// GetProvider retrieves a provider configuration by ID.
func (s *SSOService) GetProvider(ctx context.Context, tenantID, id string) (*identityproviderdom.IdentityProvider, error) {
	return s.ipRepo.GetByID(ctx, tenantID, id)
}

// GetProviderByType returns the tenant's identity provider of one type (a
// tenant has at most one per type).
func (s *SSOService) GetProviderByType(ctx context.Context, tenantID, provider string) (*identityproviderdom.IdentityProvider, error) {
	return s.ipRepo.GetByTenantAndProvider(ctx, tenantID, identityproviderdom.Provider(provider))
}

// ListProviders lists all identity provider configurations for a tenant.
func (s *SSOService) ListProviders(ctx context.Context, tenantID string) ([]*identityproviderdom.IdentityProvider, error) {
	return s.ipRepo.ListByTenant(ctx, tenantID)
}

// DeleteProvider deletes an identity provider configuration.
func (s *SSOService) DeleteProvider(ctx context.Context, tenantID, id string) error {
	// Verify provider exists and belongs to tenant (tenant isolation enforced at query level)
	if _, err := s.ipRepo.GetByID(ctx, tenantID, id); err != nil {
		return err
	}

	return s.ipRepo.Delete(ctx, tenantID, id)
}
