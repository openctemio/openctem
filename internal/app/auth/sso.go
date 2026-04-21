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

	// For tenant membership creation
	tenantMemberRepo TenantMemberCreator
}

// TenantMemberCreator creates tenant memberships for auto-provisioned users.
type TenantMemberCreator interface {
	CreateMembership(ctx context.Context, m *tenantdom.Membership) error
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
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
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
	for _, p := range providers {
		result = append(result, SSOProviderInfo{
			ID:          p.ID(),
			Provider:    string(p.Provider()),
			DisplayName: p.DisplayName(),
		})
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
	ip, err := s.ipRepo.GetByTenantAndProvider(ctx, t.ID().String(), provider)
	if err != nil {
		if errors.Is(err, identityproviderdom.ErrNotFound) {
			return nil, ErrSSOProviderNotFound
		}
		return nil, fmt.Errorf("get provider: %w", err)
	}

	if !ip.IsActive() {
		return nil, ErrSSOProviderInactive
	}

	// Decrypt client secret to verify config is valid
	clientSecret, err := s.encryptor.DecryptString(ip.ClientSecretEncrypted())
	if err != nil {
		s.logger.Error("failed to decrypt client secret", "provider_id", ip.ID(), "error", err)
		return nil, ErrSSODecryptionFailed
	}
	_ = clientSecret // Just validating decryption works

	// Generate state token with nonce for CSRF + replay protection
	state, nonce, err := s.generateState(input.OrgSlug, input.Provider)
	if err != nil {
		return nil, fmt.Errorf("generate state: %w", err)
	}

	// Get provider-specific auth endpoint
	authURL, _, _ := ip.Provider().AuthEndpoints(ip.TenantIdentifier())
	if authURL == "" {
		return nil, ErrSSOProviderUnsupported
	}

	// Build authorization URL
	params := url.Values{}
	params.Set("client_id", ip.ClientID())
	params.Set("redirect_uri", input.RedirectURI)
	params.Set("state", state)
	params.Set("response_type", "code")
	params.Set("nonce", nonce) // ID token replay prevention

	if len(ip.Scopes()) > 0 {
		params.Set("scope", strings.Join(ip.Scopes(), " "))
	}

	// Provider-specific parameters
	switch ip.Provider() {
	case identityproviderdom.ProviderEntraID:
		params.Set("response_mode", "query")
	case identityproviderdom.ProviderGoogleWorkspace:
		params.Set("access_type", "offline")
		params.Set("prompt", "select_account")
		// Restrict to org domain
		if len(ip.AllowedDomains()) > 0 {
			params.Set("hd", ip.AllowedDomains()[0])
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
	// Validate state and extract org slug
	orgSlug, stateProvider, err := s.validateState(input.State)
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

	// Look up provider config
	provider := identityproviderdom.Provider(input.Provider)
	ip, err := s.ipRepo.GetByTenantAndProvider(ctx, t.ID().String(), provider)
	if err != nil {
		if errors.Is(err, identityproviderdom.ErrNotFound) {
			return nil, ErrSSOProviderNotFound
		}
		return nil, fmt.Errorf("get provider: %w", err)
	}

	if !ip.IsActive() {
		return nil, ErrSSOProviderInactive
	}

	// Decrypt client secret
	clientSecret, err := s.encryptor.DecryptString(ip.ClientSecretEncrypted())
	if err != nil {
		s.logger.Error("failed to decrypt client secret", "provider_id", ip.ID(), "error", err)
		return nil, ErrSSODecryptionFailed
	}

	// Exchange code for tokens
	_, tokenURL, _ := ip.Provider().AuthEndpoints(ip.TenantIdentifier())
	tokens, err := s.exchangeCode(ctx, ip.ClientID(), clientSecret, input.Code, input.RedirectURI, tokenURL)
	if err != nil {
		s.logger.Error("SSO code exchange failed", "provider", input.Provider, "error", err)
		return nil, ErrSSOExchangeFailed
	}

	// Get user info
	_, _, userInfoURL := ip.Provider().AuthEndpoints(ip.TenantIdentifier())
	userInfo, err := s.getUserInfo(ctx, ip.Provider(), tokens.AccessToken, userInfoURL)
	if err != nil {
		s.logger.Error("SSO user info failed", "provider", input.Provider, "error", err)
		return nil, ErrSSOUserInfoFailed
	}

	// SECURITY: Require email from SSO provider
	if userInfo.Email == "" {
		return nil, ErrSSONoEmail
	}

	// Validate email domain restriction
	parts := strings.SplitN(userInfo.Email, "@", 2)
	if len(parts) == 2 && !ip.IsDomainAllowed(parts[1]) {
		return nil, ErrSSODomainNotAllowed
	}

	// Find or create user and provision into tenant
	u, err := s.findOrCreateUser(ctx, userInfo, ip.Provider())
	if err != nil {
		return nil, fmt.Errorf("find or create user: %w", err)
	}

	// Auto-provision into tenant if enabled
	if ip.AutoProvision() && s.tenantMemberRepo != nil {
		membership, memErr := tenantdom.NewMembership(u.ID(), t.ID(), tenantdom.Role(ip.DefaultRole()), nil)
		if memErr == nil {
			memErr = s.tenantMemberRepo.CreateMembership(ctx, membership)
		}
		if memErr != nil {
			// Ignore "already exists" errors - user may already be a member
			s.logger.Debug("auto-provision membership", "user_id", u.ID().String(), "tenant_id", t.ID().String(), "error", memErr)
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

// validateState validates the state token and returns org slug and provider.
func (s *SSOService) validateState(state string) (orgSlug, provider string, err error) {
	parts := strings.SplitN(state, ".", 2)
	if len(parts) != 2 {
		return "", "", errors.New("invalid state format")
	}

	stateData, signature := parts[0], parts[1]

	// Verify signature
	expectedSig := s.signState(stateData)
	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return "", "", errors.New("invalid state signature")
	}

	// Decode state data
	stateJSON, err := base64.URLEncoding.DecodeString(stateData)
	if err != nil {
		return "", "", errors.New("invalid state encoding")
	}

	var data map[string]interface{}
	if err := json.Unmarshal(stateJSON, &data); err != nil {
		return "", "", errors.New("invalid state JSON")
	}

	// Check expiration
	expFloat, ok := data["exp"].(float64)
	if !ok {
		return "", "", errors.New("invalid state expiration")
	}
	if time.Now().Unix() > int64(expFloat) {
		return "", "", errors.New("state expired")
	}

	orgSlug, _ = data["org"].(string)
	provider, _ = data["provider"].(string)
	if orgSlug == "" || provider == "" {
		return "", "", errors.New("missing state fields")
	}

	return orgSlug, provider, nil
}

// ssoTokens represents OAuth token response.
type ssoTokens struct {
	AccessToken string `json:"access_token"`
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
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(body).Decode(&data); err != nil {
		return nil, err
	}
	return &SSOUserInfo{
		Email: data.Email,
		Name:  data.Name,
	}, nil
}

func (s *SSOService) parseGoogleUserInfo(body io.Reader) (*SSOUserInfo, error) {
	var data struct {
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}
	if err := json.NewDecoder(body).Decode(&data); err != nil {
		return nil, err
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
		// SECURITY: Verify auth provider matches to prevent account takeover.
		// A local user cannot be logged in via SSO (and vice versa) unless
		// the auth provider matches or the user was created by this SSO provider.
		existingProvider := existingUser.AuthProvider()
		expectedProvider := s.mapAuthProvider(provider)

		if existingProvider != expectedProvider && existingProvider != userdom.AuthProviderOIDC {
			// Allow local users to be "upgraded" to SSO only if they have no password set
			// (i.e., they were invited but haven't set a password yet).
			if existingProvider == userdom.AuthProviderLocal && existingUser.PasswordHash() != nil {
				s.logger.Warn("SSO login blocked: email exists with different auth provider",
					"email", userInfo.Email,
					"existing_provider", existingProvider,
					"sso_provider", expectedProvider,
				)
				return nil, fmt.Errorf("%w: this email is registered with a different login method", ErrSSODomainNotAllowed)
			}
		}

		existingUser.UpdateLastLogin()
		if updateErr := s.userRepo.Update(ctx, existingUser); updateErr != nil {
			s.logger.Warn("failed to update last login", "error", updateErr)
		}
		return existingUser, nil
	}

	// Map identity provider to auth provider
	authProvider := s.mapAuthProvider(provider)

	// Create new user
	newUser, err := userdom.NewOAuthUser(userInfo.Email, userInfo.Name, userInfo.AvatarURL, authProvider)
	if err != nil {
		return nil, err
	}

	if err := s.userRepo.Create(ctx, newUser); err != nil {
		// Handle race condition: another concurrent request may have created
		// the user between our GetByEmail and Create calls.
		// Retry the lookup if creation fails (likely unique constraint violation).
		retryUser, retryErr := s.userRepo.GetByEmail(ctx, userInfo.Email)
		if retryErr == nil && retryUser != nil {
			s.logger.Debug("user created by concurrent request, using existing", "email", userInfo.Email)
			return retryUser, nil
		}
		return nil, fmt.Errorf("create user: %w", err)
	}

	s.logger.Info("created SSO user", "user_id", newUser.ID().String(), "email", userInfo.Email, "provider", provider)
	return newUser, nil
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
	tokenPair, err := s.tokenGenerator.GenerateTokenPair(u.ID().String(), "", "user")
	if err != nil {
		return nil, fmt.Errorf("generate tokens: %w", err)
	}

	newSession, err := sessiondom.New(
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
