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

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/crypto"
	identityproviderdom "github.com/openctemio/api/pkg/domain/identityprovider"
	sessiondom "github.com/openctemio/api/pkg/domain/session"
	"github.com/openctemio/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/api/pkg/domain/tenant"
	userdom "github.com/openctemio/api/pkg/domain/user"
	"github.com/openctemio/api/pkg/httpsec"
	"github.com/openctemio/api/pkg/jwt"
	"github.com/openctemio/api/pkg/logger"
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
	oidcVerifier     *oidcVerifier

	// For tenant membership creation
	tenantMemberRepo TenantMemberCreator
}

// TenantMemberCreator creates tenant memberships for auto-provisioned users and
// looks up existing membership (used to gate federated account binding).
type TenantMemberCreator interface {
	CreateMembership(ctx context.Context, m *tenantdom.Membership) error
	GetMembership(ctx context.Context, userID, tenantID shared.ID) (*tenantdom.Membership, error)
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
		oidcVerifier:     newOIDCVerifier(httpClient, log.With("service", "sso-oidc")),
	}
}

// SetTenantMemberRepo sets the tenant membership creator for auto-provisioning.
func (s *SSOService) SetTenantMemberRepo(repo TenantMemberCreator) {
	s.tenantMemberRepo = repo
}

// SSOProviderInfo represents a public SSO provider for a tenant.
type SSOProviderInfo struct {
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	DisplayName string `json:"display_name"`
}

// GetProvidersForTenant returns active SSO providers for a tenant identified by slug.
func (s *SSOService) GetProvidersForTenant(ctx context.Context, orgSlug string) ([]SSOProviderInfo, error) {
	t, err := s.tenantRepo.GetBySlug(ctx, orgSlug)
	if err != nil {
		return nil, ErrSSOTenantNotFound
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
}

// SSOAuthorizeResult is the result of generating an SSO authorization URL.
type SSOAuthorizeResult struct {
	AuthorizationURL string `json:"authorization_url"`
	State            string `json:"state"`
}

// validateRedirectURI validates the redirect URI for security.
func validateRedirectURI(uri string) error {
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
	return nil
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

// isDomainAllowedForProvisioning is the STRICT gate for creating a NEW tenant
// membership (JIT). Unlike isDomainAllowed (empty allow-list = allow any), an
// empty/nil allow-list here means NO auto-provisioning at all (fail-closed) —
// so a provider that never configured AllowedDomains cannot silently grant
// membership to any authenticated identity.
func (r *resolvedProvider) isDomainAllowedForProvisioning(emailDomain string) bool {
	if len(r.allowedDomains) == 0 {
		return false
	}
	return r.isDomainAllowed(emailDomain)
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
			scopes:           ip.Scopes(),
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

// isNonSpecificEntraTenant reports whether an Entra directory id is a
// multi-tenant / non-pinned authority ("", common, organizations, consumers).
// Such authorities let ANY Microsoft account complete the flow, so the env
// fallback treats them as fail-closed (no auto-provision, domains required).
func isNonSpecificEntraTenant(tid string) bool {
	switch strings.ToLower(strings.TrimSpace(tid)) {
	case "", "common", "organizations", "consumers":
		return true
	default:
		return false
	}
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
		role = "member"
	}
	autoProvision := cfg.AutoProvision
	if isNonSpecificEntraTenant(cfg.TenantID) {
		if len(cfg.AllowedDomains) == 0 {
			s.logger.Warn("env Entra fallback refused: non-specific directory requires SSO_ENTRA_ALLOWED_DOMAINS",
				"tenant_slug", orgSlug, "directory", cfg.TenantID)
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
	// SECURITY: Validate redirect URI to prevent open redirect attacks
	if err := validateRedirectURI(input.RedirectURI); err != nil {
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

	// Generate state token with nonce for CSRF + replay protection
	state, nonce, err := s.generateState(input.OrgSlug, input.Provider)
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
	// Validate state and extract org slug + nonce
	orgSlug, stateProvider, nonce, err := s.validateState(input.State)
	if err != nil {
		return nil, ErrSSOInvalidState
	}

	if stateProvider != input.Provider {
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

	// Exchange code for tokens
	_, tokenURL, _ := rp.provider.AuthEndpoints(rp.tenantIdentifier)
	tokens, err := s.exchangeCode(ctx, rp.clientID, rp.clientSecret, input.Code, input.RedirectURI, tokenURL)
	if err != nil {
		s.logger.Error("SSO code exchange failed", "provider", input.Provider, "error", err)
		return nil, ErrSSOExchangeFailed
	}

	// Verify the id_token (signature + nonce + issuer/audience) when the
	// provider returns one. The token endpoint response is server-to-server
	// over TLS, so a missing id_token (provider configured without the
	// "openid" scope) is not attacker-controllable — verify when present,
	// skip otherwise to stay backward compatible with such configs.
	claims, err := s.verifyIDToken(ctx, rp, tokens.IDToken, nonce)
	if err != nil {
		s.logger.Warn("SSO id_token validation failed",
			"provider", input.Provider, "source", rp.source, "error", err)
		return nil, ErrSSOInvalidIDToken
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
			userInfo.Issuer = claims.Issuer
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

	// Find or create user and provision into tenant
	u, err := s.findOrCreateUser(ctx, userInfo, rp.provider)
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

	// Create session
	sessionResult, err := s.createSession(ctx, u)
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
	if m, err := s.tenantMemberRepo.GetMembership(ctx, u.ID(), t.ID()); err == nil && m != nil {
		return nil
	}

	emailDomain := ""
	if parts := strings.SplitN(email, "@", 2); len(parts) == 2 {
		emailDomain = parts[1]
	}

	if !rp.autoProvision || !rp.isDomainAllowedForProvisioning(emailDomain) {
		s.logger.Warn("SSO login refused: not a member and JIT provisioning not permitted",
			"user_id", u.ID().String(), "tenant_id", t.ID().String(),
			"source", rp.source, "auto_provision", rp.autoProvision)
		return ErrSSONotAMember
	}

	membership, err := tenantdom.NewMembership(u.ID(), t.ID(), tenantdom.Role(rp.defaultRole), nil)
	if err != nil {
		return fmt.Errorf("build membership: %w", err)
	}
	if err := s.tenantMemberRepo.CreateMembership(ctx, membership); err != nil {
		// A concurrent login may have created the membership between our lookup
		// and here — re-check before failing (fail-closed on genuine failure).
		if m, gErr := s.tenantMemberRepo.GetMembership(ctx, u.ID(), t.ID()); gErr == nil && m != nil {
			return nil
		}
		s.logger.Warn("SSO auto-provision membership failed",
			"user_id", u.ID().String(), "tenant_id", t.ID().String(), "error", err)
		return ErrSSONotAMember
	}
	s.logger.Info("SSO auto-provisioned tenant membership",
		"user_id", u.ID().String(), "tenant_id", t.ID().String(), "role", rp.defaultRole)
	return nil
}

// verifyIDToken validates the provider's id_token against its JWKS, the flow
// nonce, our client_id (audience), and a provider-specific issuer check.
//
// It is a no-op (returns nil, nil) when the provider publishes no JWKS or the
// token response carried no id_token — see the call site for why a missing
// id_token is safe to skip for non-Entra providers. When an id_token IS present,
// every check is enforced. Returns the verified claims so the caller can bind
// the account to the IdP identity (issuer/subject) and, for Entra, read the
// domain-verified email. Returns nil claims when there is nothing to verify.
func (s *SSOService) verifyIDToken(ctx context.Context, rp *resolvedProvider, idToken, nonce string) (*oidcClaims, error) {
	jwksURL := rp.provider.JWKSURL(rp.tenantIdentifier)
	if jwksURL == "" {
		return nil, nil // provider has no id_token to verify
	}
	if strings.TrimSpace(idToken) == "" {
		s.logger.Debug("SSO provider returned no id_token; skipping id_token validation",
			"provider", rp.provider, "source", rp.source)
		return nil, nil
	}

	exp := idTokenExpectations{
		jwksURL:  jwksURL,
		audience: rp.clientID,
		nonce:    nonce,
	}
	if rp.provider == identityproviderdom.ProviderEntraID {
		exp.validateIssuer = entraIssuerValidator(rp.tenantIdentifier)
	}

	claims, err := s.oidcVerifier.verify(ctx, idToken, exp)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// entraUserInfoFromClaims maps a signature-verified Entra id_token to SSOUserInfo,
// enforcing the nOAuth email-verification gate (mirrors oauth.go's Path A). The
// email is trusted ONLY when `xms_edov == true`; identity is keyed on the
// immutable (issuer, subject). It is a pure function to keep the security-critical
// gate unit-testable (the signature/issuer/audience checks live in oidcVerifier).
func entraUserInfoFromClaims(claims *oidcClaims) (*SSOUserInfo, error) {
	if claims.XMSEdov == nil || !*claims.XMSEdov {
		return nil, errors.New("entra id_token email not domain-owner-verified (xms_edov absent or false)")
	}
	if strings.TrimSpace(claims.Email) == "" {
		return nil, errors.New("entra id_token has no email claim")
	}
	return &SSOUserInfo{
		Email:   claims.Email,
		Name:    claims.Name,
		Issuer:  claims.Issuer,
		Subject: claims.Subject,
	}, nil
}

// generateState generates a signed state token containing org slug, provider, and nonce.
func (s *SSOService) generateState(orgSlug, provider string) (state string, nonce string, err error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", err
	}

	// Generate nonce for ID token replay prevention
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", "", err
	}
	nonce = base64.RawURLEncoding.EncodeToString(nonceBytes)

	stateData := map[string]interface{}{
		"org":      orgSlug,
		"provider": provider,
		"nonce":    nonce,
		"random":   base64.URLEncoding.EncodeToString(randomBytes),
		"exp":      time.Now().Add(10 * time.Minute).Unix(),
	}

	stateJSON, marshalErr := json.Marshal(stateData)
	if marshalErr != nil {
		return "", "", marshalErr
	}

	stateBase64 := base64.URLEncoding.EncodeToString(stateJSON)
	signature := s.signState(stateBase64)

	return stateBase64 + "." + signature, nonce, nil
}

// signState creates an HMAC signature for the state.
func (s *SSOService) signState(data string) string {
	h := hmac.New(sha256.New, []byte(s.authConfig.JWTSecret))
	h.Write([]byte(data))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

// validateState validates the state token and returns org slug, provider, and
// the nonce embedded at authorize time (compared against the id_token nonce).
func (s *SSOService) validateState(state string) (orgSlug, provider, nonce string, err error) {
	parts := strings.SplitN(state, ".", 2)
	if len(parts) != 2 {
		return "", "", "", errors.New("invalid state format")
	}

	stateData, signature := parts[0], parts[1]

	// Verify signature
	expectedSig := s.signState(stateData)
	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return "", "", "", errors.New("invalid state signature")
	}

	// Decode state data
	stateJSON, err := base64.URLEncoding.DecodeString(stateData)
	if err != nil {
		return "", "", "", errors.New("invalid state encoding")
	}

	var data map[string]interface{}
	if err := json.Unmarshal(stateJSON, &data); err != nil {
		return "", "", "", errors.New("invalid state JSON")
	}

	// Check expiration
	expFloat, ok := data["exp"].(float64)
	if !ok {
		return "", "", "", errors.New("invalid state expiration")
	}
	if time.Now().Unix() > int64(expFloat) {
		return "", "", "", errors.New("state expired")
	}

	orgSlug, _ = data["org"].(string)
	provider, _ = data["provider"].(string)
	nonce, _ = data["nonce"].(string)
	if orgSlug == "" || provider == "" {
		return "", "", "", errors.New("missing state fields")
	}

	return orgSlug, provider, nonce, nil
}

// ssoTokens represents OAuth token response.
type ssoTokens struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
}

// exchangeCode exchanges authorization code for tokens.
func (s *SSOService) exchangeCode(ctx context.Context, clientID, clientSecret, code, redirectURI, tokenURL string) (*ssoTokens, error) {
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("grant_type", "authorization_code")

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

	// Issuer + Subject are the verified id_token's federated identity (OIDC
	// iss/sub), used to bind the account to the IdP that owns it. Empty when
	// the provider returned no id_token to verify — binding is then skipped.
	Issuer  string
	Subject string
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
		Email: data.Email,
		Name:  data.Name,
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
		Email:     data.Email,
		Name:      data.Name,
		AvatarURL: data.Picture,
	}, nil
}

// findOrCreateUser finds an existing user or creates a new SSO user.
// Handles race condition: if two concurrent SSO logins create the same user,
// the second attempt will retry the lookup after a duplicate key error.
func (s *SSOService) findOrCreateUser(ctx context.Context, userInfo *SSOUserInfo, provider identityproviderdom.Provider) (*userdom.User, error) {
	if userInfo.Email == "" {
		return nil, ErrSSONoEmail
	}

	// Try to find existing user by email
	existingUser, err := s.userRepo.GetByEmail(ctx, userInfo.Email)
	if err == nil && existingUser != nil {
		return s.adoptExistingUser(ctx, existingUser, userInfo, provider)
	}

	// SECURITY (FIX 4): when public registration is disabled, a federated login
	// may only bind to an existing/pre-invited account (handled above) — it must
	// NOT create a brand-new user. Reaching here means no account exists, so
	// refuse rather than self-provisioning an identity into the platform.
	if !s.authConfig.AllowRegistration {
		s.logger.Warn("SSO login refused: registration disabled and no account exists",
			"email", userInfo.Email, "provider", provider)
		return nil, ErrSSORegistrationDisabled
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
	// Record the IdP identity on first federation (no-op if no id_token issuer).
	newUser.BindFederatedIdentity(userInfo.Issuer, userInfo.Subject)

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
			return s.adoptExistingUser(ctx, retryUser, userInfo, provider)
		}
		return nil, fmt.Errorf("create user: %w", err)
	}

	s.logger.Info("created SSO user", "user_id", newUser.ID().String(), "email", userInfo.Email, "provider", provider)
	return newUser, nil
}

// adoptExistingUser applies the account-takeover guard before returning an
// existing account for a federated login, then records the login. It is the
// SINGLE place adoption is authorized, so BOTH the normal lookup path and the
// create-race retry path enforce the same checks:
//
//  1. Provider match — an account is bound to the auth provider that created
//     it; the only safe cross-provider adoption is a claimable LOCAL account
//     (invited, no password) being claimed via its IdP for the first time.
//  2. IdP issuer binding — the provider enum is coarse (every Okta org and
//     every generic OIDC IdP collapse to AuthProviderOIDC), so a recorded
//     verified id_token issuer must match; a pre-tracking/claimable account is
//     bound trust-on-first-use.
func (s *SSOService) adoptExistingUser(ctx context.Context, existingUser *userdom.User, userInfo *SSOUserInfo, provider identityproviderdom.Provider) (*userdom.User, error) {
	existingProvider := existingUser.AuthProvider()
	expectedProvider := s.mapAuthProvider(provider)

	if existingProvider != expectedProvider {
		claimableLocal := existingProvider == userdom.AuthProviderLocal && existingUser.PasswordHash() == nil
		if !claimableLocal {
			s.logger.Warn("SSO login blocked: email registered with a different auth provider",
				"email", userInfo.Email,
				"existing_provider", existingProvider,
				"sso_provider", expectedProvider,
			)
			return nil, fmt.Errorf("%w: this email is registered with a different login method", ErrSSODomainNotAllowed)
		}
	}

	if userInfo.Issuer != "" {
		if bound := existingUser.FederatedIssuer(); bound != nil && *bound != "" {
			if *bound != userInfo.Issuer {
				s.logger.Warn("SSO login blocked: email bound to a different identity provider",
					"email", userInfo.Email,
					"bound_issuer", *bound,
					"login_issuer", userInfo.Issuer,
				)
				return nil, fmt.Errorf("%w: this email is registered with a different identity provider", ErrSSODomainNotAllowed)
			}
		} else {
			existingUser.BindFederatedIdentity(userInfo.Issuer, userInfo.Subject)
			s.logger.Info("bound federated identity to existing account",
				"email", userInfo.Email, "issuer", userInfo.Issuer)
		}
	}

	existingUser.UpdateLastLogin()
	if updateErr := s.userRepo.Update(ctx, existingUser); updateErr != nil {
		s.logger.Warn("failed to update last login", "error", updateErr)
	}
	return existingUser, nil
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

// createSession creates a new session for the user.
func (s *SSOService) createSession(ctx context.Context, u *userdom.User) (*SessionResult, error) {
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

	if err := s.sessionRepo.Create(ctx, newSession); err != nil {
		return nil, fmt.Errorf("save session: %w", err)
	}

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

// CompleteFederatedLogin issues an OpenCTEM session for an externally
// authenticated identity (e.g. a validated SAML assertion). It finds-or-creates
// a claimable passwordless user, blocks takeover of password-backed local
// accounts, auto-provisions tenant membership when requested, and creates the
// session. Reused by the SAML SP flow so it shares the SSO session machinery.
func (s *SSOService) CompleteFederatedLogin(ctx context.Context, t *tenantdom.Tenant, email, name, defaultRole string, autoProvision bool) (*SSOCallbackResult, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return nil, ErrSSONoEmail
	}

	u, err := s.userRepo.GetByEmail(ctx, email)
	if err == nil && u != nil {
		// Account-takeover guard: a password-backed local account must not be
		// accessible via an external assertion.
		if u.AuthProvider() == userdom.AuthProviderLocal && u.PasswordHash() != nil {
			return nil, ErrSSOFederatedTakeover
		}
		// Cross-tenant takeover guard: users are global, so GetByEmail can match a
		// user who belongs to a DIFFERENT tenant. A federated assertion (SAML in
		// particular, where the tenant admin holds the IdP signing key) must not
		// bind to a pre-existing user unless they are already a member of THIS
		// tenant — otherwise a malicious tenant could forge an assertion for any
		// global email and mint a session as that victim. Brand-new users (no
		// match) are created + auto-provisioned below; existing users must have
		// been invited (membership) first. Fail closed on lookup error.
		if s.tenantMemberRepo != nil {
			m, mErr := s.tenantMemberRepo.GetMembership(ctx, u.ID(), t.ID())
			if mErr != nil || m == nil {
				s.logger.Warn("federated login refused: user is not a member of the target tenant",
					"user_id", u.ID().String(), "tenant_id", t.ID().String())
				return nil, ErrSSOFederatedNotMember
			}
		}
		u.UpdateLastLogin()
		if uerr := s.userRepo.Update(ctx, u); uerr != nil {
			s.logger.Warn("federated login: update last login", "error", uerr)
		}
	} else {
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
		}
		u = newU
	}

	if autoProvision && s.tenantMemberRepo != nil {
		role := tenantdom.Role(defaultRole)
		if !role.IsValid() || role == tenantdom.RoleOwner {
			role = tenantdom.RoleMember
		}
		membership, memErr := tenantdom.NewMembership(u.ID(), t.ID(), role, nil)
		if memErr == nil {
			memErr = s.tenantMemberRepo.CreateMembership(ctx, membership)
		}
		if memErr != nil {
			s.logger.Debug("federated auto-provision membership", "user_id", u.ID().String(), "error", memErr)
		}
	}

	sessionResult, err := s.createSession(ctx, u)
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
// Owner is excluded — owners must be explicitly promoted.
var validSSODefaultRoles = map[string]bool{
	"admin":  true,
	"member": true,
	"viewer": true,
}

// validateDefaultRole checks that the default role is a valid non-owner role.
func validateDefaultRole(role string) error {
	if role == "" {
		return nil // Will use entity default ("member")
	}
	if !validSSODefaultRoles[role] {
		return fmt.Errorf("%w: must be admin, member, or viewer", ErrSSOInvalidDefaultRole)
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

// validateScopes validates that requested scopes are reasonable.
func validateScopes(scopes []string) error {
	if len(scopes) > 20 {
		return fmt.Errorf("%w: too many scopes (max 20)", identityproviderdom.ErrInvalidConfig)
	}
	for _, scope := range scopes {
		if len(scope) > 128 {
			return fmt.Errorf("%w: scope too long (max 128 chars)", identityproviderdom.ErrInvalidConfig)
		}
	}
	return nil
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

	if err := s.ipRepo.Create(ctx, ip); err != nil {
		return nil, err
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

	if err := s.ipRepo.Update(ctx, ip); err != nil {
		return nil, err
	}

	return ip, nil
}

// GetProvider retrieves a provider configuration by ID.
func (s *SSOService) GetProvider(ctx context.Context, tenantID, id string) (*identityproviderdom.IdentityProvider, error) {
	return s.ipRepo.GetByID(ctx, tenantID, id)
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
