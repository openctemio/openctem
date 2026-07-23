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
	sessiondom "github.com/openctemio/api/pkg/domain/session"
	"github.com/openctemio/api/pkg/domain/shared"
	userdom "github.com/openctemio/api/pkg/domain/user"
	"github.com/openctemio/api/pkg/httpsec"
	"github.com/openctemio/api/pkg/jwt"
	"github.com/openctemio/api/pkg/logger"
)

// OAuth errors.
var (
	ErrOAuthDisabled       = errors.New("OAuth is disabled")
	ErrProviderDisabled    = errors.New("OAuth provider is disabled")
	ErrInvalidProvider     = errors.New("invalid OAuth provider")
	ErrInvalidState        = errors.New("invalid OAuth state")
	ErrOAuthExchangeFailed = errors.New("failed to exchange OAuth code")
	ErrOAuthUserInfoFailed = errors.New("failed to get user info from OAuth provider")
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
	userRepo         userdom.Repository
	sessionRepo      sessiondom.Repository
	refreshTokenRepo sessiondom.RefreshTokenRepository
	tokenGenerator   *jwt.Generator
	config           config.OAuthConfig
	authConfig       config.AuthConfig
	logger           *logger.Logger
	httpClient       *http.Client
	// oidcVerifier validates the signed id_token for providers that return one
	// (Microsoft/Entra), so identity is taken from verified claims rather than
	// a mutable directory attribute. See getMicrosoftUserInfo.
	oidcVerifier *oidcVerifier
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
		oidcVerifier: newOIDCVerifier(httpsec.SafeHTTPClient(30*time.Second), log),
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
}

// GetAuthorizationURL returns the OAuth authorization URL for the specified provider.
func (s *OAuthService) GetAuthorizationURL(ctx context.Context, input AuthorizationURLInput) (*AuthorizationURLResult, error) {
	if !s.config.Enabled {
		return nil, ErrOAuthDisabled
	}

	if !input.Provider.IsValid() {
		return nil, ErrInvalidProvider
	}

	providerConfig := s.getProviderConfig(input.Provider)
	if providerConfig == nil || !providerConfig.IsConfigured() {
		return nil, ErrProviderDisabled
	}

	// Generate state token with PKCE for CSRF + code interception protection
	state, codeVerifier, err := s.generateState(input.Provider, input.FinalRedirect)
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	// Build authorization URL with PKCE challenge
	authURL, err := s.buildAuthorizationURL(input.Provider, providerConfig, input.RedirectURI, state, codeVerifier)
	if err != nil {
		return nil, fmt.Errorf("failed to build authorization URL: %w", err)
	}

	return &AuthorizationURLResult{
		AuthorizationURL: authURL,
		State:            state,
	}, nil
}

// CallbackInput represents the OAuth callback input.
type CallbackInput struct {
	Provider    OAuthProvider
	Code        string
	State       string
	RedirectURI string
}

// CallbackResult represents the OAuth callback result.
type CallbackResult struct {
	AccessToken  string        `json:"access_token"`
	RefreshToken string        `json:"refresh_token"`
	ExpiresIn    int64         `json:"expires_in"`
	TokenType    string        `json:"token_type"`
	User         *userdom.User `json:"user"`
}

// HandleCallback handles the OAuth callback.
func (s *OAuthService) HandleCallback(ctx context.Context, input CallbackInput) (*CallbackResult, error) {
	if !s.config.Enabled {
		return nil, ErrOAuthDisabled
	}

	if !input.Provider.IsValid() {
		return nil, ErrInvalidProvider
	}

	providerConfig := s.getProviderConfig(input.Provider)
	if providerConfig == nil || !providerConfig.IsConfigured() {
		return nil, ErrProviderDisabled
	}

	// Validate state and extract PKCE verifier
	finalRedirect, codeVerifier, err := s.validateState(input.State, input.Provider)
	if err != nil {
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
		s.logger.Error("failed to get user info", "provider", input.Provider, "error", err)
		return nil, ErrOAuthUserInfoFailed
	}

	// SECURITY: Require email from OAuth provider
	if userInfo.Email == "" {
		return nil, fmt.Errorf("OAuth provider did not return an email address")
	}

	// Find or create user
	u, err := s.findOrCreateUser(ctx, userInfo, input.Provider)
	if err != nil {
		return nil, fmt.Errorf("failed to find or create user: %w", err)
	}

	// Create session
	sessionResult, err := s.createSession(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	s.logger.Info("OAuth login successful",
		"user_id", u.ID().String(),
		"email", u.Email(),
		"provider", input.Provider,
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
	providers := []ProviderInfo{
		{ID: "google", Name: "Google", Enabled: s.config.Google.IsConfigured()},
		{ID: "github", Name: "GitHub", Enabled: s.config.GitHub.IsConfigured()},
		{ID: "microsoft", Name: "Microsoft", Enabled: s.config.Microsoft.IsConfigured()},
	}
	return providers
}

// getProviderConfig returns the configuration for a provider.
func (s *OAuthService) getProviderConfig(provider OAuthProvider) *config.OAuthProviderConfig {
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

// generateState generates a signed state token with PKCE verifier.
func (s *OAuthService) generateState(provider OAuthProvider, finalRedirect string) (state string, codeVerifier string, err error) {
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

	// Create state data (includes PKCE verifier for callback verification)
	stateData := map[string]interface{}{
		"provider":       string(provider),
		"final_redirect": finalRedirect,
		"code_verifier":  verifier,
		"random":         base64.URLEncoding.EncodeToString(randomBytes),
		"exp":            time.Now().Add(s.config.StateDuration).Unix(),
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

// validateState validates and decodes the state token. Returns finalRedirect and codeVerifier.
func (s *OAuthService) validateState(state string, expectedProvider OAuthProvider) (string, string, error) {
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

	// Check provider
	provider, ok := data["provider"].(string)
	if !ok || provider != string(expectedProvider) {
		return "", "", errors.New("provider mismatch")
	}

	finalRedirect, _ := data["final_redirect"].(string)
	verifier, _ := data["code_verifier"].(string)
	return finalRedirect, verifier, nil
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
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
	// Issuer + Subject are the immutable federated identity from a verified
	// id_token (set for Microsoft). When present, the account is bound to and
	// matched by this pair rather than the mutable email alone.
	Issuer  string
	Subject string
}

// getUserInfo fetches user information from the OAuth provider.
func (s *OAuthService) getUserInfo(ctx context.Context, provider OAuthProvider, tokens *oauthTokens) (*OAuthUserInfo, error) {
	switch provider {
	case OAuthProviderGoogle:
		return s.getGoogleUserInfo(ctx, tokens.AccessToken)
	case OAuthProviderGitHub:
		return s.getGitHubUserInfo(ctx, tokens.AccessToken)
	case OAuthProviderMicrosoft:
		// Identity comes from the signed id_token (verified below), NOT the
		// mutable Graph `mail` attribute — see getMicrosoftUserInfo.
		return s.getMicrosoftUserInfo(ctx, tokens.IDToken)
	}
	return nil, ErrInvalidProvider
}

// getGoogleUserInfo fetches user info from Google.
func (s *OAuthService) getGoogleUserInfo(ctx context.Context, accessToken string) (*OAuthUserInfo, error) {
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
		return nil, fmt.Errorf("failed to get user info: %s", string(body))
	}

	var data struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
		EmailVerified bool   `json:"verified_email"` // Google uses "verified_email" in v2
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	// SECURITY: Only accept verified emails from Google
	if !data.EmailVerified {
		return nil, fmt.Errorf("email not verified by Google")
	}

	return &OAuthUserInfo{
		ID:        data.ID,
		Email:     data.Email,
		Name:      data.Name,
		AvatarURL: data.Picture,
	}, nil
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
		return nil, fmt.Errorf("failed to get user info: %s", string(body))
	}

	var userData struct {
		ID        int    `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
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

	return &OAuthUserInfo{
		ID:        fmt.Sprintf("%d", userData.ID),
		Email:     email,
		Name:      name,
		AvatarURL: userData.AvatarURL,
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
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}

	// Find primary verified email
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}

	// Fallback to first verified email
	for _, e := range emails {
		if e.Verified {
			return e.Email, nil
		}
	}

	return "", errors.New("no verified email found")
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
	cfg := s.getProviderConfig(OAuthProviderMicrosoft)
	if cfg == nil {
		return nil, ErrInvalidProvider
	}

	claims, err := s.oidcVerifier.verify(ctx, idToken, idTokenExpectations{
		jwksURL:        "https://login.microsoftonline.com/common/discovery/v2.0/keys",
		audience:       cfg.ClientID,
		validateIssuer: entraIssuerValidator("common"),
		skipNonce:      true, // code flow: id_token delivered server-to-server
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
// by oidcVerifier.verify), so it is a pure function to keep it unit-testable.
func microsoftUserInfoFromClaims(claims *oidcClaims) (*OAuthUserInfo, error) {
	if claims.XMSEdov == nil || !*claims.XMSEdov {
		return nil, errors.New("email not verified by Microsoft (email domain not owner-verified)")
	}
	if strings.TrimSpace(claims.Email) == "" {
		return nil, errors.New("microsoft id_token has no email claim")
	}
	return &OAuthUserInfo{
		ID:      claims.Subject,
		Email:   claims.Email,
		Name:    claims.Name,
		Issuer:  claims.Issuer,
		Subject: claims.Subject,
	}, nil
}

// findOrCreateUser finds an existing user or creates a new one.
func (s *OAuthService) findOrCreateUser(ctx context.Context, userInfo *OAuthUserInfo, provider OAuthProvider) (*userdom.User, error) {
	// Try to find existing user by email
	existingUser, err := s.userRepo.GetByEmail(ctx, userInfo.Email)
	if err == nil && existingUser != nil {
		// SECURITY: an account is bound to the auth provider that created it.
		// Users are matched by email, but a verified email at one IdP does NOT
		// prove ownership of an account created at another. On a provider
		// mismatch the ONLY safe adoption is a CLAIMABLE LOCAL account (invited,
		// no password yet) signing in via its IdP for the first time. Block
		// every other mismatch — a password-backed local account AND a different
		// federated provider (e.g. account created via Google, login attempted
		// via GitHub) — otherwise it is a cross-IdP account takeover.
		existingProvider := existingUser.AuthProvider()
		expectedProvider := provider.ToAuthProvider()

		if existingProvider != expectedProvider {
			claimableLocal := existingProvider == userdom.AuthProviderLocal && existingUser.PasswordHash() == nil
			if !claimableLocal {
				s.logger.Warn("OAuth login blocked: email registered with a different auth provider",
					"email", userInfo.Email,
					"existing_provider", existingProvider,
					"oauth_provider", expectedProvider,
				)
				return nil, fmt.Errorf("this email is registered with a different login method")
			}
		}

		// Defense-in-depth: when the provider supplied a verified federated
		// identity (issuer+subject from a signed id_token, e.g. Microsoft), pin
		// the account to it. If already pinned, a DIFFERENT identity presenting
		// the same email is rejected; otherwise bind it now (safe here — the
		// email was domain-verified before we reached this point).
		if userInfo.Issuer != "" && userInfo.Subject != "" {
			if boundIss, boundSub := existingUser.FederatedIssuer(), existingUser.FederatedSubject(); boundIss != nil && boundSub != nil {
				if *boundIss != userInfo.Issuer || *boundSub != userInfo.Subject {
					s.logger.Warn("OAuth login blocked: federated identity mismatch for email",
						"email", userInfo.Email, "oauth_provider", expectedProvider)
					return nil, fmt.Errorf("this email is registered with a different login method")
				}
			} else {
				existingUser.BindFederatedIdentity(userInfo.Issuer, userInfo.Subject)
			}
		}

		// Update last login
		existingUser.UpdateLastLogin()
		if err := s.userRepo.Update(ctx, existingUser); err != nil {
			s.logger.Warn("failed to update last login", "error", err)
		}
		return existingUser, nil
	}

	// SECURITY (FIX 4): when public registration is disabled, social login may
	// only bind to an existing/pre-invited account (handled above) — it must NOT
	// create a brand-new user. Reaching here means no account exists, so refuse.
	if !s.authConfig.AllowRegistration {
		s.logger.Warn("OAuth login refused: registration disabled and no account exists",
			"email", userInfo.Email, "provider", provider)
		return nil, ErrRegistrationDisabled
	}

	// Create new user
	newUser, err := userdom.NewOAuthUser(userInfo.Email, userInfo.Name, userInfo.AvatarURL, provider.ToAuthProvider())
	if err != nil {
		return nil, err
	}
	if userInfo.Issuer != "" && userInfo.Subject != "" {
		newUser.BindFederatedIdentity(userInfo.Issuer, userInfo.Subject)
	}

	if err := s.userRepo.Create(ctx, newUser); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
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
	newSession, err := sessiondom.NewWithID(
		sessionID,
		u.ID(),
		tokenPair.AccessToken,
		"", // IP address - can be set from request context
		"", // User agent - can be set from request context
		s.authConfig.SessionDuration,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	if err := s.sessionRepo.Create(ctx, newSession); err != nil {
		return nil, fmt.Errorf("failed to save session: %w", err)
	}

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
func (s *OAuthService) getTokenURL(provider OAuthProvider) string {
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
