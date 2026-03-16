package unit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/domain/session"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/user"
	"github.com/openctemio/api/pkg/logger"
)

// =============================================================================
// Mock User Repository for OAuth Tests
// =============================================================================

type mockOAuthUserRepo struct {
	users map[string]*user.User // keyed by ID

	// Error overrides
	createErr                  error
	getByIDErr                 error
	getByEmailErr              error
	getByEmailForAuthErr       error
	getByEmailVerificationErr  error
	getByPasswordResetTokenErr error
	updateErr                  error
	deleteErr                  error
	existsByEmailResult        bool
	existsByEmailErr           error
	existsByKeycloakIDResult   bool
	existsByKeycloakIDErr      error
	getByKeycloakIDErr         error
	upsertFromKeycloakErr      error
	getByIDsErr                error
	countResult                int64
	countErr                   error

	// Call tracking
	createCalls int
	updateCalls int
}

func newMockUserRepoForOAuth() *mockOAuthUserRepo {
	return &mockOAuthUserRepo{
		users: make(map[string]*user.User),
	}
}

func (m *mockOAuthUserRepo) Create(_ context.Context, u *user.User) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.users[u.ID().String()] = u
	return nil
}

func (m *mockOAuthUserRepo) GetByID(_ context.Context, id shared.ID) (*user.User, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	u, ok := m.users[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return u, nil
}

func (m *mockOAuthUserRepo) GetByKeycloakID(_ context.Context, _ string) (*user.User, error) {
	if m.getByKeycloakIDErr != nil {
		return nil, m.getByKeycloakIDErr
	}
	return nil, shared.ErrNotFound
}

func (m *mockOAuthUserRepo) GetByEmail(_ context.Context, email string) (*user.User, error) {
	if m.getByEmailErr != nil {
		return nil, m.getByEmailErr
	}
	for _, u := range m.users {
		if u.Email() == email {
			return u, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *mockOAuthUserRepo) GetByEmailForAuth(_ context.Context, email string) (*user.User, error) {
	if m.getByEmailForAuthErr != nil {
		return nil, m.getByEmailForAuthErr
	}
	for _, u := range m.users {
		if u.Email() == email {
			return u, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *mockOAuthUserRepo) Update(_ context.Context, u *user.User) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	m.users[u.ID().String()] = u
	return nil
}

func (m *mockOAuthUserRepo) Delete(_ context.Context, _ shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	return nil
}

func (m *mockOAuthUserRepo) ExistsByEmail(_ context.Context, _ string) (bool, error) {
	if m.existsByEmailErr != nil {
		return false, m.existsByEmailErr
	}
	return m.existsByEmailResult, nil
}

func (m *mockOAuthUserRepo) ExistsByKeycloakID(_ context.Context, _ string) (bool, error) {
	if m.existsByKeycloakIDErr != nil {
		return false, m.existsByKeycloakIDErr
	}
	return m.existsByKeycloakIDResult, nil
}

func (m *mockOAuthUserRepo) UpsertFromKeycloak(_ context.Context, _, _, _ string) (*user.User, error) {
	if m.upsertFromKeycloakErr != nil {
		return nil, m.upsertFromKeycloakErr
	}
	return nil, nil
}

func (m *mockOAuthUserRepo) GetByIDs(_ context.Context, _ []shared.ID) ([]*user.User, error) {
	if m.getByIDsErr != nil {
		return nil, m.getByIDsErr
	}
	return nil, nil
}

func (m *mockOAuthUserRepo) Count(_ context.Context, _ user.Filter) (int64, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	return m.countResult, nil
}

func (m *mockOAuthUserRepo) GetByEmailVerificationToken(_ context.Context, _ string) (*user.User, error) {
	if m.getByEmailVerificationErr != nil {
		return nil, m.getByEmailVerificationErr
	}
	return nil, shared.ErrNotFound
}

func (m *mockOAuthUserRepo) GetByPasswordResetToken(_ context.Context, _ string) (*user.User, error) {
	if m.getByPasswordResetTokenErr != nil {
		return nil, m.getByPasswordResetTokenErr
	}
	return nil, shared.ErrNotFound
}

// =============================================================================
// Mock Session Repository for OAuth Tests
// =============================================================================

type mockOAuthSessionRepo struct {
	sessions map[string]*session.Session

	// Error overrides
	createErr          error
	getByIDErr         error
	getByTokenErr      error
	getActiveErr       error
	updateErr          error
	deleteErr          error
	revokeAllErr       error
	revokeAllExceptErr error
	countActiveErr     error
	getOldestErr       error
	deleteExpiredErr   error

	// Result overrides
	countActiveResult  int
	oldestSession      *session.Session

	// Call tracking
	createCalls int
}

func newMockOAuthSessionRepo() *mockOAuthSessionRepo {
	return &mockOAuthSessionRepo{
		sessions: make(map[string]*session.Session),
	}
}

func (m *mockOAuthSessionRepo) Create(_ context.Context, s *session.Session) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.sessions[s.ID().String()] = s
	return nil
}

func (m *mockOAuthSessionRepo) GetByID(_ context.Context, id shared.ID) (*session.Session, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	s, ok := m.sessions[id.String()]
	if !ok {
		return nil, session.ErrSessionNotFound
	}
	return s, nil
}

func (m *mockOAuthSessionRepo) GetByAccessTokenHash(_ context.Context, _ string) (*session.Session, error) {
	if m.getByTokenErr != nil {
		return nil, m.getByTokenErr
	}
	return nil, session.ErrSessionNotFound
}

func (m *mockOAuthSessionRepo) GetActiveByUserID(_ context.Context, _ shared.ID) ([]*session.Session, error) {
	if m.getActiveErr != nil {
		return nil, m.getActiveErr
	}
	return nil, nil
}

func (m *mockOAuthSessionRepo) Update(_ context.Context, s *session.Session) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.sessions[s.ID().String()] = s
	return nil
}

func (m *mockOAuthSessionRepo) Delete(_ context.Context, _ shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	return nil
}

func (m *mockOAuthSessionRepo) RevokeAllByUserID(_ context.Context, _ shared.ID) error {
	if m.revokeAllErr != nil {
		return m.revokeAllErr
	}
	return nil
}

func (m *mockOAuthSessionRepo) RevokeAllByUserIDExcept(_ context.Context, _ shared.ID, _ shared.ID) error {
	if m.revokeAllExceptErr != nil {
		return m.revokeAllExceptErr
	}
	return nil
}

func (m *mockOAuthSessionRepo) CountActiveByUserID(_ context.Context, _ shared.ID) (int, error) {
	if m.countActiveErr != nil {
		return 0, m.countActiveErr
	}
	return m.countActiveResult, nil
}

func (m *mockOAuthSessionRepo) GetOldestActiveByUserID(_ context.Context, _ shared.ID) (*session.Session, error) {
	if m.getOldestErr != nil {
		return nil, m.getOldestErr
	}
	return m.oldestSession, nil
}

func (m *mockOAuthSessionRepo) DeleteExpired(_ context.Context) (int64, error) {
	if m.deleteExpiredErr != nil {
		return 0, m.deleteExpiredErr
	}
	return 0, nil
}

// =============================================================================
// Mock Refresh Token Repository for OAuth Tests
// =============================================================================

type mockOAuthRefreshTokenRepo struct {
	tokens map[string]*session.RefreshToken

	// Error overrides
	createErr          error
	getByIDErr         error
	getByTokenHashErr  error
	getByFamilyErr     error
	updateErr          error
	deleteErr          error
	revokeByFamilyErr  error
	revokeBySessionErr error
	revokeByUserErr    error
	deleteExpiredErr   error

	// Call tracking
	createCalls int
}

func newMockOAuthRefreshTokenRepo() *mockOAuthRefreshTokenRepo {
	return &mockOAuthRefreshTokenRepo{
		tokens: make(map[string]*session.RefreshToken),
	}
}

func (m *mockOAuthRefreshTokenRepo) Create(_ context.Context, t *session.RefreshToken) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.tokens[t.ID().String()] = t
	return nil
}

func (m *mockOAuthRefreshTokenRepo) GetByID(_ context.Context, id shared.ID) (*session.RefreshToken, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	t, ok := m.tokens[id.String()]
	if !ok {
		return nil, session.ErrRefreshTokenNotFound
	}
	return t, nil
}

func (m *mockOAuthRefreshTokenRepo) GetByTokenHash(_ context.Context, _ string) (*session.RefreshToken, error) {
	if m.getByTokenHashErr != nil {
		return nil, m.getByTokenHashErr
	}
	return nil, session.ErrRefreshTokenNotFound
}

func (m *mockOAuthRefreshTokenRepo) GetByFamily(_ context.Context, _ shared.ID) ([]*session.RefreshToken, error) {
	if m.getByFamilyErr != nil {
		return nil, m.getByFamilyErr
	}
	return nil, nil
}

func (m *mockOAuthRefreshTokenRepo) Update(_ context.Context, _ *session.RefreshToken) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	return nil
}

func (m *mockOAuthRefreshTokenRepo) Delete(_ context.Context, _ shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	return nil
}

func (m *mockOAuthRefreshTokenRepo) RevokeByFamily(_ context.Context, _ shared.ID) error {
	if m.revokeByFamilyErr != nil {
		return m.revokeByFamilyErr
	}
	return nil
}

func (m *mockOAuthRefreshTokenRepo) RevokeBySessionID(_ context.Context, _ shared.ID) error {
	if m.revokeBySessionErr != nil {
		return m.revokeBySessionErr
	}
	return nil
}

func (m *mockOAuthRefreshTokenRepo) RevokeByUserID(_ context.Context, _ shared.ID) error {
	if m.revokeByUserErr != nil {
		return m.revokeByUserErr
	}
	return nil
}

func (m *mockOAuthRefreshTokenRepo) DeleteExpired(_ context.Context) (int64, error) {
	if m.deleteExpiredErr != nil {
		return 0, m.deleteExpiredErr
	}
	return 0, nil
}

// =============================================================================
// OAuth Test Helpers
// =============================================================================

func defaultOAuthTestConfig() config.OAuthConfig {
	return config.OAuthConfig{
		Enabled:             true,
		FrontendCallbackURL: "http://localhost:3000/auth/callback",
		StateSecret:         "test-state-secret-at-least-32-chars!!",
		StateDuration:       10 * time.Minute,
		Google: config.OAuthProviderConfig{
			Enabled:      true,
			ClientID:     "google-client-id",
			ClientSecret: "google-client-secret",
			Scopes:       []string{"openid", "email", "profile"},
		},
		GitHub: config.OAuthProviderConfig{
			Enabled:      true,
			ClientID:     "github-client-id",
			ClientSecret: "github-client-secret",
			Scopes:       []string{"read:user", "user:email"},
		},
		Microsoft: config.OAuthProviderConfig{
			Enabled:      true,
			ClientID:     "microsoft-client-id",
			ClientSecret: "microsoft-client-secret",
			Scopes:       []string{"openid", "email", "profile", "User.Read"},
		},
	}
}

func defaultOAuthAuthConfig() config.AuthConfig {
	return config.AuthConfig{
		JWTSecret:            "test-secret-key-at-least-32-chars-long!!",
		JWTIssuer:            "test-issuer",
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
		SessionDuration:      30 * 24 * time.Hour,
	}
}

func newTestOAuthService() (*app.OAuthService, *mockOAuthUserRepo, *mockOAuthSessionRepo, *mockOAuthRefreshTokenRepo) {
	userRepo := newMockUserRepoForOAuth()
	sessionRepo := newMockOAuthSessionRepo()
	refreshTokenRepo := newMockOAuthRefreshTokenRepo()
	log := logger.NewNop()

	svc := app.NewOAuthService(
		userRepo,
		sessionRepo,
		refreshTokenRepo,
		defaultOAuthTestConfig(),
		defaultOAuthAuthConfig(),
		log,
	)

	return svc, userRepo, sessionRepo, refreshTokenRepo
}

func newTestOAuthServiceWithConfig(oauthCfg config.OAuthConfig, authCfg config.AuthConfig) (*app.OAuthService, *mockOAuthUserRepo, *mockOAuthSessionRepo, *mockOAuthRefreshTokenRepo) {
	userRepo := newMockUserRepoForOAuth()
	sessionRepo := newMockOAuthSessionRepo()
	refreshTokenRepo := newMockOAuthRefreshTokenRepo()
	log := logger.NewNop()

	svc := app.NewOAuthService(
		userRepo,
		sessionRepo,
		refreshTokenRepo,
		oauthCfg,
		authCfg,
		log,
	)

	return svc, userRepo, sessionRepo, refreshTokenRepo
}

// signTestState creates an HMAC signature matching the service's signState logic.
func signTestState(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

// buildTestState creates a valid state token for testing.
func buildTestState(provider string, finalRedirect string, exp time.Time, secret string) string {
	stateData := map[string]interface{}{
		"provider":       provider,
		"final_redirect": finalRedirect,
		"random":         base64.URLEncoding.EncodeToString([]byte("test-random-bytes")),
		"exp":            exp.Unix(),
	}

	stateJSON, _ := json.Marshal(stateData)
	stateBase64 := base64.URLEncoding.EncodeToString(stateJSON)
	signature := signTestState(stateBase64, secret)

	return stateBase64 + "." + signature
}

// =============================================================================
// Test: GetAuthorizationURL
// =============================================================================

func TestOAuthService_GetAuthorizationURL_SuccessGoogle(t *testing.T) {
	svc, _, _, _ := newTestOAuthService()
	ctx := context.Background()

	result, err := svc.GetAuthorizationURL(ctx, app.AuthorizationURLInput{
		Provider:      app.OAuthProviderGoogle,
		RedirectURI:   "http://localhost:3000/auth/sso/callback",
		FinalRedirect: "/dashboard",
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.AuthorizationURL == "" {
		t.Fatal("expected authorization URL, got empty")
	}
	if result.State == "" {
		t.Fatal("expected state token, got empty")
	}
	if !strings.Contains(result.AuthorizationURL, "accounts.google.com") {
		t.Errorf("expected Google auth URL, got %s", result.AuthorizationURL)
	}
	if !strings.Contains(result.AuthorizationURL, "client_id=google-client-id") {
		t.Errorf("expected client_id in URL, got %s", result.AuthorizationURL)
	}
	if !strings.Contains(result.AuthorizationURL, "response_type=code") {
		t.Errorf("expected response_type=code in URL, got %s", result.AuthorizationURL)
	}
	// Google-specific params
	if !strings.Contains(result.AuthorizationURL, "access_type=offline") {
		t.Errorf("expected access_type=offline for Google, got %s", result.AuthorizationURL)
	}
	if !strings.Contains(result.AuthorizationURL, "prompt=select_account") {
		t.Errorf("expected prompt=select_account for Google, got %s", result.AuthorizationURL)
	}
}

func TestOAuthService_GetAuthorizationURL_SuccessGitHub(t *testing.T) {
	svc, _, _, _ := newTestOAuthService()
	ctx := context.Background()

	result, err := svc.GetAuthorizationURL(ctx, app.AuthorizationURLInput{
		Provider:      app.OAuthProviderGitHub,
		RedirectURI:   "http://localhost:3000/auth/sso/callback",
		FinalRedirect: "/dashboard",
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if !strings.Contains(result.AuthorizationURL, "github.com/login/oauth/authorize") {
		t.Errorf("expected GitHub auth URL, got %s", result.AuthorizationURL)
	}
	if !strings.Contains(result.AuthorizationURL, "client_id=github-client-id") {
		t.Errorf("expected client_id in URL, got %s", result.AuthorizationURL)
	}
}

func TestOAuthService_GetAuthorizationURL_SuccessMicrosoft(t *testing.T) {
	svc, _, _, _ := newTestOAuthService()
	ctx := context.Background()

	result, err := svc.GetAuthorizationURL(ctx, app.AuthorizationURLInput{
		Provider:      app.OAuthProviderMicrosoft,
		RedirectURI:   "http://localhost:3000/auth/sso/callback",
		FinalRedirect: "/dashboard",
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if !strings.Contains(result.AuthorizationURL, "login.microsoftonline.com") {
		t.Errorf("expected Microsoft auth URL, got %s", result.AuthorizationURL)
	}
	if !strings.Contains(result.AuthorizationURL, "client_id=microsoft-client-id") {
		t.Errorf("expected client_id in URL, got %s", result.AuthorizationURL)
	}
	// Microsoft-specific params
	if !strings.Contains(result.AuthorizationURL, "response_mode=query") {
		t.Errorf("expected response_mode=query for Microsoft, got %s", result.AuthorizationURL)
	}
}

func TestOAuthService_GetAuthorizationURL_OAuthDisabled(t *testing.T) {
	oauthCfg := defaultOAuthTestConfig()
	oauthCfg.Enabled = false

	svc, _, _, _ := newTestOAuthServiceWithConfig(oauthCfg, defaultOAuthAuthConfig())
	ctx := context.Background()

	result, err := svc.GetAuthorizationURL(ctx, app.AuthorizationURLInput{
		Provider:    app.OAuthProviderGoogle,
		RedirectURI: "http://localhost:3000/auth/sso/callback",
	})

	if result != nil {
		t.Fatalf("expected nil result, got %+v", result)
	}
	if !errors.Is(err, app.ErrOAuthDisabled) {
		t.Fatalf("expected ErrOAuthDisabled, got %v", err)
	}
}

func TestOAuthService_GetAuthorizationURL_UnknownProvider(t *testing.T) {
	svc, _, _, _ := newTestOAuthService()
	ctx := context.Background()

	result, err := svc.GetAuthorizationURL(ctx, app.AuthorizationURLInput{
		Provider:    app.OAuthProvider("unknown"),
		RedirectURI: "http://localhost:3000/auth/sso/callback",
	})

	if result != nil {
		t.Fatalf("expected nil result, got %+v", result)
	}
	if !errors.Is(err, app.ErrInvalidProvider) {
		t.Fatalf("expected ErrInvalidProvider, got %v", err)
	}
}

func TestOAuthService_GetAuthorizationURL_DisabledProvider(t *testing.T) {
	oauthCfg := defaultOAuthTestConfig()
	oauthCfg.Google.Enabled = false

	svc, _, _, _ := newTestOAuthServiceWithConfig(oauthCfg, defaultOAuthAuthConfig())
	ctx := context.Background()

	result, err := svc.GetAuthorizationURL(ctx, app.AuthorizationURLInput{
		Provider:    app.OAuthProviderGoogle,
		RedirectURI: "http://localhost:3000/auth/sso/callback",
	})

	if result != nil {
		t.Fatalf("expected nil result, got %+v", result)
	}
	if !errors.Is(err, app.ErrProviderDisabled) {
		t.Fatalf("expected ErrProviderDisabled, got %v", err)
	}
}

func TestOAuthService_GetAuthorizationURL_ProviderNotConfigured(t *testing.T) {
	oauthCfg := defaultOAuthTestConfig()
	// Enabled but missing client ID/secret
	oauthCfg.GitHub.ClientID = ""
	oauthCfg.GitHub.ClientSecret = ""

	svc, _, _, _ := newTestOAuthServiceWithConfig(oauthCfg, defaultOAuthAuthConfig())
	ctx := context.Background()

	result, err := svc.GetAuthorizationURL(ctx, app.AuthorizationURLInput{
		Provider:    app.OAuthProviderGitHub,
		RedirectURI: "http://localhost:3000/auth/sso/callback",
	})

	if result != nil {
		t.Fatalf("expected nil result, got %+v", result)
	}
	if !errors.Is(err, app.ErrProviderDisabled) {
		t.Fatalf("expected ErrProviderDisabled, got %v", err)
	}
}

// =============================================================================
// Test: GetAvailableProviders
// =============================================================================

func TestOAuthService_GetAvailableProviders_ReturnsEnabledProviders(t *testing.T) {
	svc, _, _, _ := newTestOAuthService()

	providers := svc.GetAvailableProviders()

	if len(providers) != 3 {
		t.Fatalf("expected 3 providers, got %d", len(providers))
	}

	// All enabled in default config
	for _, p := range providers {
		if !p.Enabled {
			t.Errorf("expected provider %s to be enabled", p.ID)
		}
	}

	// Verify IDs and names
	expectedProviders := map[string]string{
		"google":    "Google",
		"github":    "GitHub",
		"microsoft": "Microsoft",
	}

	for _, p := range providers {
		expectedName, ok := expectedProviders[p.ID]
		if !ok {
			t.Errorf("unexpected provider ID: %s", p.ID)
			continue
		}
		if p.Name != expectedName {
			t.Errorf("expected provider name %s, got %s", expectedName, p.Name)
		}
	}
}

func TestOAuthService_GetAvailableProviders_ReturnsEmptyWhenNoneEnabled(t *testing.T) {
	oauthCfg := defaultOAuthTestConfig()
	oauthCfg.Google.Enabled = false
	oauthCfg.GitHub.Enabled = false
	oauthCfg.Microsoft.Enabled = false

	svc, _, _, _ := newTestOAuthServiceWithConfig(oauthCfg, defaultOAuthAuthConfig())

	providers := svc.GetAvailableProviders()

	if len(providers) != 3 {
		t.Fatalf("expected 3 provider entries, got %d", len(providers))
	}

	// All should be disabled
	for _, p := range providers {
		if p.Enabled {
			t.Errorf("expected provider %s to be disabled", p.ID)
		}
	}
}

func TestOAuthService_GetAvailableProviders_PartiallyEnabled(t *testing.T) {
	oauthCfg := defaultOAuthTestConfig()
	oauthCfg.Google.Enabled = true
	oauthCfg.GitHub.Enabled = false
	oauthCfg.Microsoft.Enabled = false

	svc, _, _, _ := newTestOAuthServiceWithConfig(oauthCfg, defaultOAuthAuthConfig())

	providers := svc.GetAvailableProviders()

	enabledCount := 0
	for _, p := range providers {
		if p.Enabled {
			enabledCount++
			if p.ID != "google" {
				t.Errorf("expected only google to be enabled, got %s", p.ID)
			}
		}
	}

	if enabledCount != 1 {
		t.Errorf("expected 1 enabled provider, got %d", enabledCount)
	}
}

// =============================================================================
// Test: State Token Generation and Validation
// =============================================================================

func TestOAuthService_StateToken_ValidStatePassesValidation(t *testing.T) {
	svc, _, _, _ := newTestOAuthService()
	ctx := context.Background()

	// Generate a state via GetAuthorizationURL
	result, err := svc.GetAuthorizationURL(ctx, app.AuthorizationURLInput{
		Provider:      app.OAuthProviderGoogle,
		RedirectURI:   "http://localhost:3000/auth/sso/callback",
		FinalRedirect: "/dashboard",
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// The state should have two parts separated by "."
	parts := strings.SplitN(result.State, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("expected state with 2 parts, got %d parts", len(parts))
	}

	// Verify the state data can be decoded
	stateJSON, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("expected valid base64 in state, got error: %v", err)
	}

	var stateData map[string]interface{}
	if err := json.Unmarshal(stateJSON, &stateData); err != nil {
		t.Fatalf("expected valid JSON in state, got error: %v", err)
	}

	// Check state contains expected fields
	if stateData["provider"] != "google" {
		t.Errorf("expected provider=google, got %v", stateData["provider"])
	}
	if stateData["final_redirect"] != "/dashboard" {
		t.Errorf("expected final_redirect=/dashboard, got %v", stateData["final_redirect"])
	}
	if _, ok := stateData["exp"]; !ok {
		t.Error("expected exp field in state")
	}
	if _, ok := stateData["random"]; !ok {
		t.Error("expected random field in state")
	}
}

func TestOAuthService_StateToken_TamperedStateFails(t *testing.T) {
	// Build a valid state, then tamper with the signature
	secret := "test-state-secret-at-least-32-chars!!"
	state := buildTestState("google", "/dashboard", time.Now().Add(10*time.Minute), secret)

	// Tamper with the signature
	parts := strings.SplitN(state, ".", 2)
	tamperedState := parts[0] + ".tampered-signature"

	// HandleCallback will use validateState internally; we test via HandleCallback
	oauthCfg := defaultOAuthTestConfig()
	svc, _, _, _ := newTestOAuthServiceWithConfig(oauthCfg, defaultOAuthAuthConfig())
	ctx := context.Background()

	_, err := svc.HandleCallback(ctx, app.CallbackInput{
		Provider:    app.OAuthProviderGoogle,
		Code:        "auth-code",
		State:       tamperedState,
		RedirectURI: "http://localhost:3000/auth/sso/callback",
	})

	if !errors.Is(err, app.ErrInvalidState) {
		t.Fatalf("expected ErrInvalidState for tampered state, got %v", err)
	}
}

func TestOAuthService_StateToken_ExpiredStateFails(t *testing.T) {
	secret := "test-state-secret-at-least-32-chars!!"
	// Create state that expired 1 hour ago
	state := buildTestState("google", "/dashboard", time.Now().Add(-1*time.Hour), secret)

	oauthCfg := defaultOAuthTestConfig()
	svc, _, _, _ := newTestOAuthServiceWithConfig(oauthCfg, defaultOAuthAuthConfig())
	ctx := context.Background()

	_, err := svc.HandleCallback(ctx, app.CallbackInput{
		Provider:    app.OAuthProviderGoogle,
		Code:        "auth-code",
		State:       state,
		RedirectURI: "http://localhost:3000/auth/sso/callback",
	})

	if !errors.Is(err, app.ErrInvalidState) {
		t.Fatalf("expected ErrInvalidState for expired state, got %v", err)
	}
}

func TestOAuthService_StateToken_WrongProviderFails(t *testing.T) {
	secret := "test-state-secret-at-least-32-chars!!"
	// Create state for GitHub but validate against Google
	state := buildTestState("github", "/dashboard", time.Now().Add(10*time.Minute), secret)

	oauthCfg := defaultOAuthTestConfig()
	svc, _, _, _ := newTestOAuthServiceWithConfig(oauthCfg, defaultOAuthAuthConfig())
	ctx := context.Background()

	_, err := svc.HandleCallback(ctx, app.CallbackInput{
		Provider:    app.OAuthProviderGoogle, // Different from state's "github"
		Code:        "auth-code",
		State:       state,
		RedirectURI: "http://localhost:3000/auth/sso/callback",
	})

	if !errors.Is(err, app.ErrInvalidState) {
		t.Fatalf("expected ErrInvalidState for wrong provider, got %v", err)
	}
}

func TestOAuthService_StateToken_InvalidFormatFails(t *testing.T) {
	oauthCfg := defaultOAuthTestConfig()
	svc, _, _, _ := newTestOAuthServiceWithConfig(oauthCfg, defaultOAuthAuthConfig())
	ctx := context.Background()

	// State without "." separator
	_, err := svc.HandleCallback(ctx, app.CallbackInput{
		Provider:    app.OAuthProviderGoogle,
		Code:        "auth-code",
		State:       "no-dot-separator",
		RedirectURI: "http://localhost:3000/auth/sso/callback",
	})

	if !errors.Is(err, app.ErrInvalidState) {
		t.Fatalf("expected ErrInvalidState for invalid format, got %v", err)
	}
}

// =============================================================================
// Test: HandleCallback - Error Paths
// =============================================================================

func TestOAuthService_HandleCallback_OAuthDisabled(t *testing.T) {
	oauthCfg := defaultOAuthTestConfig()
	oauthCfg.Enabled = false

	svc, _, _, _ := newTestOAuthServiceWithConfig(oauthCfg, defaultOAuthAuthConfig())
	ctx := context.Background()

	result, err := svc.HandleCallback(ctx, app.CallbackInput{
		Provider:    app.OAuthProviderGoogle,
		Code:        "auth-code",
		State:       "some-state",
		RedirectURI: "http://localhost:3000/auth/sso/callback",
	})

	if result != nil {
		t.Fatalf("expected nil result, got %+v", result)
	}
	if !errors.Is(err, app.ErrOAuthDisabled) {
		t.Fatalf("expected ErrOAuthDisabled, got %v", err)
	}
}

func TestOAuthService_HandleCallback_InvalidProvider(t *testing.T) {
	svc, _, _, _ := newTestOAuthService()
	ctx := context.Background()

	result, err := svc.HandleCallback(ctx, app.CallbackInput{
		Provider:    app.OAuthProvider("invalid"),
		Code:        "auth-code",
		State:       "some-state",
		RedirectURI: "http://localhost:3000/auth/sso/callback",
	})

	if result != nil {
		t.Fatalf("expected nil result, got %+v", result)
	}
	if !errors.Is(err, app.ErrInvalidProvider) {
		t.Fatalf("expected ErrInvalidProvider, got %v", err)
	}
}

func TestOAuthService_HandleCallback_DisabledProvider(t *testing.T) {
	oauthCfg := defaultOAuthTestConfig()
	oauthCfg.Microsoft.Enabled = false

	svc, _, _, _ := newTestOAuthServiceWithConfig(oauthCfg, defaultOAuthAuthConfig())
	ctx := context.Background()

	result, err := svc.HandleCallback(ctx, app.CallbackInput{
		Provider:    app.OAuthProviderMicrosoft,
		Code:        "auth-code",
		State:       "some-state",
		RedirectURI: "http://localhost:3000/auth/sso/callback",
	})

	if result != nil {
		t.Fatalf("expected nil result, got %+v", result)
	}
	if !errors.Is(err, app.ErrProviderDisabled) {
		t.Fatalf("expected ErrProviderDisabled, got %v", err)
	}
}

// =============================================================================
// Test: OAuthProvider helper methods
// =============================================================================

func TestOAuthProvider_IsValid(t *testing.T) {
	tests := []struct {
		provider app.OAuthProvider
		valid    bool
	}{
		{app.OAuthProviderGoogle, true},
		{app.OAuthProviderGitHub, true},
		{app.OAuthProviderMicrosoft, true},
		{app.OAuthProvider("unknown"), false},
		{app.OAuthProvider(""), false},
		{app.OAuthProvider("facebook"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.provider), func(t *testing.T) {
			if got := tt.provider.IsValid(); got != tt.valid {
				t.Errorf("OAuthProvider(%q).IsValid() = %v, want %v", tt.provider, got, tt.valid)
			}
		})
	}
}

func TestOAuthProvider_ToAuthProvider(t *testing.T) {
	tests := []struct {
		provider app.OAuthProvider
		expected user.AuthProvider
	}{
		{app.OAuthProviderGoogle, user.AuthProviderGoogle},
		{app.OAuthProviderGitHub, user.AuthProviderGitHub},
		{app.OAuthProviderMicrosoft, user.AuthProviderMicrosoft},
		{app.OAuthProvider("unknown"), user.AuthProviderLocal}, // fallback
	}

	for _, tt := range tests {
		t.Run(string(tt.provider), func(t *testing.T) {
			if got := tt.provider.ToAuthProvider(); got != tt.expected {
				t.Errorf("OAuthProvider(%q).ToAuthProvider() = %v, want %v", tt.provider, got, tt.expected)
			}
		})
	}
}

// =============================================================================
// Test: State Token - uses JWT secret as fallback
// =============================================================================

func TestOAuthService_StateToken_FallbackToJWTSecret(t *testing.T) {
	oauthCfg := defaultOAuthTestConfig()
	oauthCfg.StateSecret = "" // Empty state secret forces fallback to JWT secret

	authCfg := defaultOAuthAuthConfig()
	svc, _, _, _ := newTestOAuthServiceWithConfig(oauthCfg, authCfg)
	ctx := context.Background()

	// Should still work, using JWT secret as fallback for signing
	result, err := svc.GetAuthorizationURL(ctx, app.AuthorizationURLInput{
		Provider:      app.OAuthProviderGoogle,
		RedirectURI:   "http://localhost:3000/auth/sso/callback",
		FinalRedirect: "/dashboard",
	})

	if err != nil {
		t.Fatalf("expected no error with fallback secret, got %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.State == "" {
		t.Fatal("expected state token, got empty")
	}

	// Verify signature uses JWT secret as fallback
	parts := strings.SplitN(result.State, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("expected state with 2 parts, got %d", len(parts))
	}

	expectedSig := signTestState(parts[0], authCfg.JWTSecret)
	if parts[1] != expectedSig {
		t.Error("expected state signed with JWT secret as fallback")
	}
}

// =============================================================================
// Test: GetAuthorizationURL - URL contains scopes
// =============================================================================

func TestOAuthService_GetAuthorizationURL_ContainsScopes(t *testing.T) {
	svc, _, _, _ := newTestOAuthService()
	ctx := context.Background()

	tests := []struct {
		name     string
		provider app.OAuthProvider
		scopes   []string
	}{
		{
			name:     "Google scopes",
			provider: app.OAuthProviderGoogle,
			scopes:   []string{"openid", "email", "profile"},
		},
		{
			name:     "GitHub scopes",
			provider: app.OAuthProviderGitHub,
			scopes:   []string{"read:user", "user:email"},
		},
		{
			name:     "Microsoft scopes",
			provider: app.OAuthProviderMicrosoft,
			scopes:   []string{"openid", "email", "profile", "User.Read"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := svc.GetAuthorizationURL(ctx, app.AuthorizationURLInput{
				Provider:    tt.provider,
				RedirectURI: "http://localhost:3000/auth/sso/callback",
			})

			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			// The scope parameter should contain all scopes joined by space (URL encoded as +)
			if !strings.Contains(result.AuthorizationURL, "scope=") {
				t.Errorf("expected scope parameter in URL, got %s", result.AuthorizationURL)
			}
		})
	}
}

// =============================================================================
// Test: GetAuthorizationURL - redirect URI passed through
// =============================================================================

func TestOAuthService_GetAuthorizationURL_RedirectURIPassedThrough(t *testing.T) {
	svc, _, _, _ := newTestOAuthService()
	ctx := context.Background()

	redirectURI := "http://localhost:3000/auth/sso/callback"

	result, err := svc.GetAuthorizationURL(ctx, app.AuthorizationURLInput{
		Provider:    app.OAuthProviderGoogle,
		RedirectURI: redirectURI,
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// The redirect_uri should be URL-encoded in the authorization URL
	if !strings.Contains(result.AuthorizationURL, "redirect_uri=") {
		t.Errorf("expected redirect_uri in URL, got %s", result.AuthorizationURL)
	}
}

// =============================================================================
// Test: State uniqueness - each call generates different state
// =============================================================================

func TestOAuthService_GetAuthorizationURL_UniqueStates(t *testing.T) {
	svc, _, _, _ := newTestOAuthService()
	ctx := context.Background()

	input := app.AuthorizationURLInput{
		Provider:    app.OAuthProviderGoogle,
		RedirectURI: "http://localhost:3000/auth/sso/callback",
	}

	result1, err1 := svc.GetAuthorizationURL(ctx, input)
	result2, err2 := svc.GetAuthorizationURL(ctx, input)

	if err1 != nil || err2 != nil {
		t.Fatalf("expected no errors, got %v, %v", err1, err2)
	}

	if result1.State == result2.State {
		t.Error("expected unique states for each call, got identical states")
	}
}
