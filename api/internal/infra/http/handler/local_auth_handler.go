package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/password"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// LocalAuthHandler handles local authentication requests.
type LocalAuthHandler struct {
	authService    *auth.AuthService
	sessionService *auth.SessionService
	emailService   *auth.EmailService
	platformAdmin  PlatformAdminChecker
	authConfig     config.AuthConfig
	cookieConfig   CookieConfig
	csrfConfig     middleware.CSRFConfig
	validator      *validator.Validator
	logger         *logger.Logger
	// signupPolicy answers registration_enabled on /auth/info (the console
	// sign-up setting). Nil: TENANT_CREATION_MODE from the config.
	signupPolicy signupdom.PolicySource
}

// SetSignupPolicy wires the platform sign-up policy.
func (h *LocalAuthHandler) SetSignupPolicy(p signupdom.PolicySource) { h.signupPolicy = p }

// registrationEnabled reports whether anyone may create an account: the
// self_service sign-up mode.
func (h *LocalAuthHandler) registrationEnabled(r *http.Request) bool {
	if h.signupPolicy != nil {
		return h.signupPolicy.Current(r.Context()).AllowsSelfService()
	}
	return h.authConfig.SelfServiceTenantCreation()
}

// CodeSignupNotAvailable is the error code of every sign-up refusal; the web
// shows the "not set up" page for it.
const CodeSignupNotAvailable apierror.Code = "SIGNUP_NOT_AVAILABLE"

// writeSignupNotAvailable is the one answer of every refused sign-up path
// (register, social sign-in): the same status, code and text whatever the
// reason, so it says nothing about the email or the organization.
func writeSignupNotAvailable(w http.ResponseWriter) {
	apierror.New(http.StatusForbidden, CodeSignupNotAvailable,
		"Your organization isn't set up yet. Ask your administrator to invite you.").WriteJSON(w)
}

// NewLocalAuthHandler creates a new LocalAuthHandler.
func NewLocalAuthHandler(
	authService *auth.AuthService,
	sessionService *auth.SessionService,
	emailService *auth.EmailService,
	platformAdmin PlatformAdminChecker,
	authConfig config.AuthConfig,
	log *logger.Logger,
) *LocalAuthHandler {
	return &LocalAuthHandler{
		authService:    authService,
		sessionService: sessionService,
		emailService:   emailService,
		platformAdmin:  platformAdmin,
		authConfig:     authConfig,
		cookieConfig:   NewCookieConfig(authConfig),
		csrfConfig:     middleware.NewCSRFConfig(authConfig, log),
		validator:      validator.New(),
		logger:         log.With("handler", "local_auth"),
	}
}

// RegisterRequest is the request body for user registration.
type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email,max=255"`
	Password string `json:"password" validate:"required,min=8,max=128"`
	Name     string `json:"name" validate:"required,max=255"`
	// InvitationToken is optional: when present, the register flow
	// resolves the target tenant from the invitation and uses that
	// tenant's email-verification rule. Without this, registrations via
	// invitation links would fall back to the platform default and
	// silently ignore an admin's per-tenant "never" setting.
	InvitationToken string `json:"invitation_token,omitempty" validate:"omitempty,max=200"`
}

// RegisterResponse is the response body for user registration.
type RegisterResponse struct {
	ID                   string `json:"id"`
	Email                string `json:"email"`
	Name                 string `json:"name"`
	RequiresVerification bool   `json:"requires_verification"`
	Message              string `json:"message"`
}

// Register handles user registration.
// @Summary      Register user
// @Description  Registers a new user with email and password
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request  body      RegisterRequest  true  "Registration data"
// @Success      201  {object}  RegisterResponse
// @Failure      400  {object}  map[string]string
// @Failure      409  {object}  map[string]string
// @Router       /auth/register [post]
func (h *LocalAuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		apierror.ValidationFailed("Validation failed", err).WriteJSON(w)
		return
	}

	result, err := h.authService.Register(r.Context(), auth.RegisterInput{
		Email:           req.Email,
		Password:        req.Password,
		Name:            req.Name,
		InvitationToken: req.InvitationToken,
	})
	if err != nil {
		h.handleAuthError(w, err)
		return
	}

	// SECURITY (anti-enumeration): a new and an already registered email get
	// byte-identical responses. The body never carries the account id, echoes
	// the submitted email and name (normalized the same way), and states the
	// verification rule that applies to a new account either way. The
	// verification email is sent after the response, so its latency does not
	// tell the two apart either.
	resp := RegisterResponse{
		Email:                strings.TrimSpace(strings.ToLower(req.Email)),
		Name:                 strings.TrimSpace(req.Name),
		RequiresVerification: result.RequiresVerification,
		Message:              registerMessage(result.RequiresVerification),
	}

	if !result.EmailExisted && result.User != nil && result.RequiresVerification &&
		result.VerificationToken != "" && h.emailService != nil {
		u := result.User
		token := result.VerificationToken
		duration := h.authConfig.EmailVerificationDuration
		go func() {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
			defer cancel()
			if err := h.emailService.SendVerificationEmail(ctx, u.Email(), u.Name(), token, duration); err != nil {
				// The user can request another email.
				h.logger.Error("failed to send verification email",
					"email", logger.SanitizeValue(u.Email()),
					"error", logger.SanitizeError(err),
				)
			}
		}()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// registerMessage is the one message a registration answers with, whether or
// not the email already had an account.
func registerMessage(requiresVerification bool) string {
	if requiresVerification {
		return "Registration received. Please check your email to verify your account."
	}
	return "Registration received. You can now sign in."
}

// LoginRequest is the request body for login.
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// TenantInfo represents tenant membership info in login response.
type TenantInfo struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
	Role string `json:"role"`
}

// LoginResponse is the response body for login.
// Returns a global refresh token and list of tenants.
// Client must call POST /api/v1/auth/token to get tenant-scoped access token.
// Note: refresh_token is also set as httpOnly cookie for security (XSS protection).
type LoginResponse struct {
	RefreshToken string       `json:"refresh_token,omitempty"` // Also set in httpOnly cookie
	TokenType    string       `json:"token_type"`
	ExpiresIn    int64        `json:"expires_in"`
	User         UserInfo     `json:"user"`
	Tenants      []TenantInfo `json:"tenants"`
	// SuspendedTenants is non-empty when the user has memberships that
	// are currently suspended. The client uses this to show a clear
	// "your access to X is suspended" notice instead of bouncing the
	// user to /onboarding/create-team. Suspended tenants are NOT
	// accessible — the user cannot pick one and exchange a token.
	SuspendedTenants []TenantInfo `json:"suspended_tenants,omitempty"`
	// PlatformAdmin is true when the account is a platform administrator
	// (RFC-022). Such an account belongs to no organization; the client sends
	// it to the admin console rather than organization onboarding.
	PlatformAdmin bool `json:"platform_admin,omitempty"`
	// RecoveryCodes is present only on the response that completes a forced
	// 2FA enrollment (POST /auth/mfa/enroll/confirm). Shown once.
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
}

// UserInfo contains basic user information.
type UserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// Login handles user login.
// @Summary      User login
// @Description  Authenticates a user and returns refresh token and tenant list
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request  body      LoginRequest  true  "Login credentials"
// @Success      200  {object}  LoginResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /auth/login [post]
func (h *LocalAuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		apierror.ValidationFailed("Validation failed", err).WriteJSON(w)
		return
	}

	// Get client info
	ipAddress := getClientIP(r)
	userAgent := r.UserAgent()

	result, err := h.authService.Login(r.Context(), auth.LoginInput{
		Email:     req.Email,
		Password:  req.Password,
		IPAddress: ipAddress,
		UserAgent: userAgent,
	})
	if err != nil {
		h.handleAuthError(w, err)
		return
	}

	// Password was right but a second factor is needed: answer with the
	// challenge only. No cookie is set and no session exists yet.
	if result.MFAChallenge != nil {
		writeMFAChallenge(w, result.MFAChallenge)
		return
	}

	h.writeLoginSuccess(w, r, result, nil)
}

// writeLoginSuccess sets the session cookies and writes the login response
// shared by password login and the second-factor steps. recoveryCodes is set
// only when the login just completed a forced 2FA enrollment.
func (h *LocalAuthHandler) writeLoginSuccess(w http.ResponseWriter, r *http.Request, result *auth.LoginResult, recoveryCodes []string) {
	// Convert tenant memberships to response format
	tenants := make([]TenantInfo, len(result.Tenants))
	for i, t := range result.Tenants {
		tenants[i] = TenantInfo{
			ID:   t.TenantID,
			Slug: t.TenantSlug,
			Name: t.TenantName,
			Role: t.Role,
		}
	}

	// Convert suspended memberships (may be nil — that's fine, omitempty
	// keeps the response clean for the typical case).
	var suspendedTenants []TenantInfo
	if len(result.SuspendedTenants) > 0 {
		suspendedTenants = make([]TenantInfo, len(result.SuspendedTenants))
		for i, t := range result.SuspendedTenants {
			suspendedTenants[i] = TenantInfo{
				ID:   t.TenantID,
				Slug: t.TenantSlug,
				Name: t.TenantName,
				Role: t.Role,
			}
		}
	}

	// Calculate expires_in in seconds (for refresh token)
	expiresIn := int64(h.authConfig.RefreshTokenDuration.Seconds())

	// Set refresh token as httpOnly cookie (XSS protection)
	SetRefreshTokenCookie(w, result.RefreshToken, result.ExpiresAt, h.cookieConfig)

	// Generate and set CSRF token (readable by JavaScript for double-submit pattern)
	csrfToken, err := middleware.GenerateCSRFToken()
	if err != nil {
		h.logger.Error("failed to generate CSRF token", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	middleware.SetCSRFTokenCookie(w, csrfToken, h.csrfConfig)

	// SECURITY (S-3): Do NOT include refresh_token in the response body.
	// It is set as an httpOnly cookie above (SetRefreshTokenCookie) which is
	// the only place a browser-bound client should read it from. Returning
	// it in the body lets any XSS / browser extension / analytics middleware
	// capture the long-lived credential, enabling persistent ATO.
	resp := LoginResponse{
		TokenType: "Bearer",
		ExpiresIn: expiresIn,
		User: UserInfo{
			ID:    result.User.ID().String(),
			Email: result.User.Email(),
			Name:  result.User.Name(),
		},
		Tenants:          tenants,
		SuspendedTenants: suspendedTenants,
		RecoveryCodes:    recoveryCodes,
	}
	if h.platformAdmin != nil {
		resp.PlatformAdmin = h.platformAdmin.IsPlatformAdmin(r.Context(), result.User.ID())
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// Logout handles user logout.
// @Summary      User logout
// @Description  Logs out the current user and invalidates the session
// @Tags         Authentication
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]string
// @Failure      400  {object}  map[string]string
// @Router       /auth/logout [post]
func (h *LocalAuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	sessionID := middleware.GetSessionID(r.Context())
	if sessionID == "" {
		// Try to get from local claims
		if claims := middleware.GetLocalClaims(r.Context()); claims != nil {
			sessionID = claims.SessionID
		}
	}

	if sessionID == "" {
		apierror.BadRequest("Session ID not found").WriteJSON(w)
		return
	}

	if err := h.authService.Logout(r.Context(), sessionID); err != nil {
		h.logger.Error("logout failed", "error", err)
		// Don't return error - logout should be idempotent
	}

	// Clear all auth cookies
	ClearRefreshTokenCookie(w, h.cookieConfig)
	ClearTenantCookie(w, h.cookieConfig)

	// Clear the CSRF token cookie
	middleware.ClearCSRFTokenCookie(w, h.csrfConfig)

	h.logger.Info("logout successful", "session_id", sessionID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Logged out successfully",
	})
}

// refreshTokenFrom returns the refresh token that authenticates a
// refresh-token route (/auth/token, /auth/refresh, /auth/create-first-team,
// /invitations/accept-with-refresh). A token sent in the body is a
// deliberate, non-ambient credential (server-to-server callers such as the
// UI's Next routes use it) and needs nothing else. A token taken from the
// refresh_token cookie is ambient - the browser attaches it to any request -
// so it is accepted only with the double-submit CSRF pair (csrf_token cookie
// + X-CSRF-Token header), like every other cookie-authenticated write. On a
// failed check it writes the 403 and returns ok=false. An empty token with
// ok=true means the request carried none.
func (h *LocalAuthHandler) refreshTokenFrom(w http.ResponseWriter, r *http.Request, bodyToken string) (string, bool) {
	if bodyToken != "" {
		return bodyToken, true
	}
	cookieToken := GetRefreshTokenFromCookie(r, h.cookieConfig)
	if cookieToken == "" {
		return "", true
	}
	if !middleware.CheckDoubleSubmit(w, r, h.logger) {
		return "", false
	}
	return cookieToken, true
}

// ExchangeTokenRequest is the request body for token exchange.
// refresh_token can be omitted if sent via httpOnly cookie.
type ExchangeTokenRequest struct {
	RefreshToken string `json:"refresh_token"` // Optional if cookie is present
	TenantID     string `json:"tenant_id" validate:"required"`
}

// ExchangeTokenResponse is the response body for token exchange.
type ExchangeTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	TenantID    string `json:"tenant_id"`
	TenantSlug  string `json:"tenant_slug"`
	Role        string `json:"role"`
}

// ExchangeToken exchanges a global refresh token for a tenant-scoped access token.
// @Summary      Exchange token
// @Description  Exchanges refresh token for tenant-scoped access token
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request  body      ExchangeTokenRequest  true  "Token exchange data"
// @Success      200  {object}  ExchangeTokenResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /auth/token [post]
func (h *LocalAuthHandler) ExchangeToken(w http.ResponseWriter, r *http.Request) {
	var req ExchangeTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		apierror.ValidationFailed("Validation failed", err).WriteJSON(w)
		return
	}

	refreshToken, ok := h.refreshTokenFrom(w, r, req.RefreshToken)
	if !ok {
		return
	}
	if refreshToken == "" {
		apierror.BadRequest("refresh_token is required (in body or cookie)").WriteJSON(w)
		return
	}

	result, err := h.authService.ExchangeToken(r.Context(), auth.ExchangeTokenInput{
		RefreshToken: refreshToken,
		TenantID:     req.TenantID,
	})
	if err != nil {
		h.handleAuthError(w, err)
		return
	}

	expiresIn := int64(h.authConfig.AccessTokenDuration.Seconds())

	// S-3-rotate: ExchangeToken now rotates the refresh token. Persist the
	// NEW refresh token to the httpOnly cookie so the next call works.
	// Body intentionally OMITS the refresh token — it lives in cookie only
	// (matches S-3 hardening: never echo refresh tokens in JSON bodies).
	if result.RefreshToken != "" {
		refreshExpiresAt := time.Now().Add(h.authConfig.RefreshTokenDuration)
		SetRefreshTokenCookie(w, result.RefreshToken, refreshExpiresAt, h.cookieConfig)
	}

	resp := ExchangeTokenResponse{
		AccessToken: result.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		TenantID:    result.TenantID,
		TenantSlug:  result.TenantSlug,
		Role:        result.Role,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// RefreshTokenRequest is the request body for token refresh.
// refresh_token can be omitted if sent via httpOnly cookie.
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"` // Optional if cookie is present
	TenantID     string `json:"tenant_id" validate:"required"`
}

// RefreshTokenResponse is the response body for token refresh.
// Returns both new access token and rotated refresh token.
// Note: new refresh_token is also set in httpOnly cookie.
type RefreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"` // Also set in httpOnly cookie
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	TenantID     string `json:"tenant_id"`
	TenantSlug   string `json:"tenant_slug"`
	Role         string `json:"role"`
}

// RefreshToken handles token refresh with rotation.
// @Summary      Refresh token
// @Description  Refreshes access token and rotates refresh token
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request  body      RefreshTokenRequest  true  "Refresh token data"
// @Success      200  {object}  RefreshTokenResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /auth/refresh [post]
func (h *LocalAuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		apierror.ValidationFailed("Validation failed", err).WriteJSON(w)
		return
	}

	refreshToken, ok := h.refreshTokenFrom(w, r, req.RefreshToken)
	if !ok {
		return
	}
	if refreshToken == "" {
		apierror.BadRequest("refresh_token is required (in body or cookie)").WriteJSON(w)
		return
	}

	ipAddress := getClientIP(r)
	userAgent := r.UserAgent()

	result, err := h.authService.RefreshToken(r.Context(), auth.RefreshTokenInput{
		RefreshToken: refreshToken,
		TenantID:     req.TenantID,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
	})
	if err != nil {
		h.handleAuthError(w, err)
		return
	}

	expiresIn := int64(h.authConfig.AccessTokenDuration.Seconds())

	// Set rotated refresh token in httpOnly cookie
	refreshExpiresAt := result.RefreshExpiresAt
	SetRefreshTokenCookie(w, result.RefreshToken, refreshExpiresAt, h.cookieConfig)

	// Rotate CSRF token as well for additional security
	csrfToken, err := middleware.GenerateCSRFToken()
	if err != nil {
		h.logger.Error("failed to generate CSRF token", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	middleware.SetCSRFTokenCookie(w, csrfToken, h.csrfConfig)

	// SECURITY (S-3): omit refresh_token from response body — set in httpOnly
	// cookie above. Browser clients never need it in JS.
	resp := RefreshTokenResponse{
		AccessToken: result.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		TenantID:    result.TenantID,
		TenantSlug:  result.TenantSlug,
		Role:        result.Role,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// CreateFirstTeamRequest is the request body for creating first team.
type CreateFirstTeamRequest struct {
	TeamName string `json:"team_name" validate:"required,min=2,max=100"`
	TeamSlug string `json:"team_slug" validate:"required,min=3,max=50"`
	// RefreshToken authenticates the call when sent server-to-server; a
	// browser uses the refresh_token cookie plus the CSRF pair instead.
	RefreshToken string `json:"refresh_token,omitempty"`
}

// CreateFirstTeamResponse is the response body for creating first team.
type CreateFirstTeamResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	TenantID     string `json:"tenant_id"`
	TenantSlug   string `json:"tenant_slug"`
	TenantName   string `json:"tenant_name"`
	Role         string `json:"role"`
}

// CreateFirstTeam handles creating the first team for a new user.
// POST /api/v1/auth/create-first-team
// This endpoint uses refresh_token for authentication since user has no access_token yet.
// The refresh token can be provided in the request body OR via httpOnly cookie.
func (h *LocalAuthHandler) CreateFirstTeam(w http.ResponseWriter, r *http.Request) {
	var req CreateFirstTeamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		apierror.ValidationFailed("Validation failed", err).WriteJSON(w)
		return
	}

	refreshToken, ok := h.refreshTokenFrom(w, r, req.RefreshToken)
	if !ok {
		return
	}
	if refreshToken == "" {
		apierror.Unauthorized("refresh_token is required (in body or cookie)").WriteJSON(w)
		return
	}

	result, err := h.authService.CreateFirstTeam(r.Context(), auth.CreateFirstTeamInput{
		RefreshToken: refreshToken,
		TeamName:     req.TeamName,
		TeamSlug:     req.TeamSlug,
		IPAddress:    getClientIP(r),
		UserAgent:    r.UserAgent(),
	})
	if err != nil {
		h.handleAuthError(w, err)
		return
	}

	expiresIn := int64(h.authConfig.AccessTokenDuration.Seconds())

	// Set new refresh token in httpOnly cookie
	refreshExpiresAt := result.ExpiresAt.Add(h.authConfig.RefreshTokenDuration)
	SetRefreshTokenCookie(w, result.RefreshToken, refreshExpiresAt, h.cookieConfig)

	// Set tenant cookie so frontend knows user now has a tenant (JSON format with id, slug, role)
	SetTenantCookie(w, result.Tenant.TenantID, result.Tenant.TenantSlug, result.Tenant.Role, h.cookieConfig)

	// Generate CSRF token
	csrfToken, err := middleware.GenerateCSRFToken()
	if err != nil {
		h.logger.Error("failed to generate CSRF token", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	middleware.SetCSRFTokenCookie(w, csrfToken, h.csrfConfig)

	resp := CreateFirstTeamResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		TenantID:     result.Tenant.TenantID,
		TenantSlug:   result.Tenant.TenantSlug,
		TenantName:   result.Tenant.TenantName,
		Role:         result.Tenant.Role,
	}

	h.logger.Info("first team created via API",
		"tenant_id", result.Tenant.TenantID,
		"tenant_name", result.Tenant.TenantName,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// AcceptInvitationWithRefreshResponse is the response body for accepting invitation with refresh token.
type AcceptInvitationWithRefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	TenantID     string `json:"tenant_id"`
	TenantSlug   string `json:"tenant_slug"`
	TenantName   string `json:"tenant_name"`
	Role         string `json:"role"`
}

// AcceptInvitationWithRefreshRequest is the body of
// POST /api/v1/invitations/accept-with-refresh. refresh_token may be omitted
// when the browser sends the refresh_token cookie (with the CSRF pair).
type AcceptInvitationWithRefreshRequest struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// AcceptInvitationWithRefreshBody handles
// POST /api/v1/invitations/accept-with-refresh: accept an invitation with a
// refresh token, for an invited user who has no organization yet (so no
// tenant-scoped access token). The invitation token travels in the body.
// @Summary      Accept an invitation with a refresh token
// @Description  For an invited user without an organization yet: accepts the invitation and issues an access token for the new organization. The refresh token comes from the body or the httpOnly cookie (cookie requires the CSRF pair). The invitation token travels in the body, never in the URL.
// @Tags         Invitations
// @Accept       json
// @Produce      json
// @Param        request  body      AcceptInvitationWithRefreshRequest  true  "Invitation token and optional refresh token"
// @Success      200  {object}  AcceptInvitationWithRefreshResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Router       /invitations/accept-with-refresh [post]
func (h *LocalAuthHandler) AcceptInvitationWithRefreshBody(w http.ResponseWriter, r *http.Request) {
	var body AcceptInvitationWithRefreshRequest
	if !decodeInvitationBody(w, r, &body) {
		return
	}
	if !validInvitationToken(body.Token) {
		apierror.BadRequest("Invalid invitation token").WriteJSON(w)
		return
	}
	h.acceptInvitationWithRefresh(w, r, body.Token, body.RefreshToken)
}

// AcceptInvitationWithRefresh handles
// POST /api/v1/invitations/{token}/accept-with-refresh (deprecated; the
// successor is POST /api/v1/invitations/accept-with-refresh).
// The refresh token is obtained from the body or the httpOnly cookie.
func (h *LocalAuthHandler) AcceptInvitationWithRefresh(w http.ResponseWriter, r *http.Request) {
	invitationToken, ok := invitationTokenFromPath(w, r)
	if !ok {
		return
	}

	// Optional body: {"refresh_token": "..."} for server-to-server callers.
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body)
	}
	h.acceptInvitationWithRefresh(w, r, invitationToken, body.RefreshToken)
}

func (h *LocalAuthHandler) acceptInvitationWithRefresh(w http.ResponseWriter, r *http.Request, invitationToken, bodyRefreshToken string) {
	refreshToken, ok := h.refreshTokenFrom(w, r, bodyRefreshToken)
	if !ok {
		return
	}
	if refreshToken == "" {
		apierror.Unauthorized("refresh_token is required (in body or cookie)").WriteJSON(w)
		return
	}

	result, err := h.authService.AcceptInvitationWithRefreshToken(r.Context(), auth.AcceptInvitationWithRefreshTokenInput{
		RefreshToken:    refreshToken,
		InvitationToken: invitationToken,
	})
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			apierror.NotFound("Invitation").WriteJSON(w)
			return
		}
		h.handleAuthError(w, err)
		return
	}

	expiresIn := int64(h.authConfig.AccessTokenDuration.Seconds())

	// Set access token in httpOnly cookie (so browser has it for subsequent requests)
	SetAccessTokenCookie(w, result.AccessToken, result.ExpiresAt, h.cookieConfig)

	// Set new refresh token in httpOnly cookie
	refreshExpiresAt := result.ExpiresAt.Add(h.authConfig.RefreshTokenDuration)
	SetRefreshTokenCookie(w, result.RefreshToken, refreshExpiresAt, h.cookieConfig)

	// Set tenant cookie so frontend knows user now has a tenant (JSON format with id, slug, role)
	SetTenantCookie(w, result.Tenant.TenantID, result.Tenant.TenantSlug, result.Role, h.cookieConfig)

	// Generate CSRF token
	csrfToken, err := middleware.GenerateCSRFToken()
	if err != nil {
		h.logger.Error("failed to generate CSRF token", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	middleware.SetCSRFTokenCookie(w, csrfToken, h.csrfConfig)

	resp := AcceptInvitationWithRefreshResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		TenantID:     result.Tenant.TenantID,
		TenantSlug:   result.Tenant.TenantSlug,
		TenantName:   result.Tenant.TenantName,
		Role:         result.Role,
	}

	h.logger.Info("invitation accepted with refresh token",
		"tenant_id", result.Tenant.TenantID,
		"tenant_name", result.Tenant.TenantName,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// VerifyEmailRequest is the request body for email verification.
type VerifyEmailRequest struct {
	Token string `json:"token" validate:"required"`
}

// VerifyEmail handles email verification.
// @Summary      Verify email
// @Description  Verifies user email with token
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request  body      VerifyEmailRequest  true  "Verification token"
// @Success      200  {object}  map[string]string
// @Failure      400  {object}  map[string]string
// @Router       /auth/verify-email [post]
func (h *LocalAuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req VerifyEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		apierror.ValidationFailed("Validation failed", err).WriteJSON(w)
		return
	}

	if err := h.authService.VerifyEmail(r.Context(), req.Token); err != nil {
		h.handleAuthError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Email verified successfully",
	})
}

// ForgotPasswordRequest is the request body for forgot password.
type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// ForgotPassword handles forgot password request.
// @Summary      Forgot password
// @Description  Sends password reset email
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request  body      ForgotPasswordRequest  true  "Email address"
// @Success      200  {object}  map[string]string
// @Router       /auth/forgot-password [post]
func (h *LocalAuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		apierror.ValidationFailed("Validation failed", err).WriteJSON(w)
		return
	}

	// SECURITY (anti-enumeration, AUTHZ-6): the answer is the same whether or
	// not the email has an account, and so is its latency: the whole lookup,
	// the token write and the email run after the response, detached from
	// the request.
	ipAddress := getClientIP(r)
	email := req.Email
	resetDuration := h.authConfig.PasswordResetDuration
	go func() {
		// Detach from the request context (which is canceled once we
		// respond) but keep request-scoped values for tracing.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
		defer cancel()
		result, err := h.authService.ForgotPassword(ctx, auth.ForgotPasswordInput{Email: email})
		if err != nil {
			h.logger.Error("password reset request failed", "error", logger.SanitizeError(err))
			return
		}
		if result == nil || result.Token == "" || h.emailService == nil {
			return
		}
		if err := h.emailService.SendPasswordResetEmail(
			ctx,
			email,
			"", // empty name for privacy
			result.Token,
			resetDuration,
			ipAddress,
		); err != nil {
			h.logger.Error("failed to send password reset email",
				"email", logger.SanitizeValue(email),
				"error", logger.SanitizeError(err),
			)
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "If the email exists, a password reset link has been sent",
	})
}

// ResetPasswordRequest is the request body for password reset.
type ResetPasswordRequest struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8,max=128"`
}

// ResetPassword handles password reset.
// @Summary      Reset password
// @Description  Resets password using token
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request  body      ResetPasswordRequest  true  "Reset token and new password"
// @Success      200  {object}  map[string]string
// @Failure      400  {object}  map[string]string
// @Router       /auth/reset-password [post]
func (h *LocalAuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		apierror.ValidationFailed("Validation failed", err).WriteJSON(w)
		return
	}

	if err := h.authService.ResetPassword(r.Context(), auth.ResetPasswordInput{
		Token:       req.Token,
		NewPassword: req.NewPassword,
	}); err != nil {
		h.handleAuthError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password reset successfully",
	})
}

// ChangePasswordRequest is the request body for changing password.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8,max=128"`
}

// ChangePassword handles password change for authenticated users.
// @Summary      Change password
// @Description  Changes password for authenticated user
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body      ChangePasswordRequest  true  "Current and new password"
// @Success      200  {object}  map[string]string
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /users/me/change-password [post]
func (h *LocalAuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		apierror.ValidationFailed("Validation failed", err).WriteJSON(w)
		return
	}

	if err := h.authService.ChangePassword(r.Context(), userID, auth.ChangePasswordInput{
		CurrentPassword:  req.CurrentPassword,
		NewPassword:      req.NewPassword,
		CurrentSessionID: middleware.GetSessionID(r.Context()),
		IPAddress:        getClientIP(r),
		UserAgent:        r.UserAgent(),
	}); err != nil {
		h.handleAuthError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password changed successfully. Your other sessions have been signed out.",
	})
}

// SessionsResponse is the response body for listing sessions.
type SessionsResponse struct {
	Sessions []auth.SessionInfo `json:"sessions"`
}

// ListSessions lists all active sessions for the authenticated user.
// @Summary      List sessions
// @Description  Lists all active sessions
// @Tags         Authentication
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  SessionsResponse
// @Failure      401  {object}  map[string]string
// @Router       /users/me/sessions [get]
func (h *LocalAuthHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}

	currentSessionID := middleware.GetSessionID(r.Context())

	sessions, err := h.sessionService.ListUserSessions(r.Context(), userID, currentSessionID)
	if err != nil {
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(SessionsResponse{Sessions: sessions})
}

// RevokeSession revokes a specific session.
// @Summary      Revoke session
// @Description  Revokes a specific session by ID
// @Tags         Authentication
// @Produce      json
// @Security     BearerAuth
// @Param        sessionId  path      string  true  "Session ID"
// @Success      200  {object}  map[string]string
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /users/me/sessions/{sessionId} [delete]
func (h *LocalAuthHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}

	// Get session ID from URL path
	sessionID := r.PathValue("sessionId")
	if sessionID == "" {
		apierror.BadRequest("Session ID is required").WriteJSON(w)
		return
	}

	if err := h.sessionService.RevokeSession(r.Context(), userID, sessionID); err != nil {
		h.handleAuthError(w, err)
		return
	}
	h.authService.LogSessionRevoked(r.Context(), selfAuditContext(r), sessionID, false)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Session revoked successfully",
	})
}

// RevokeAllSessions revokes all sessions except the current one.
// @Summary      Revoke all sessions
// @Description  Revokes all sessions except current
// @Tags         Authentication
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /users/me/sessions [delete]
func (h *LocalAuthHandler) RevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}

	currentSessionID := middleware.GetSessionID(r.Context())

	if err := h.sessionService.RevokeAllSessions(r.Context(), userID, currentSessionID); err != nil {
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	h.authService.LogSessionRevoked(r.Context(), selfAuditContext(r), "", true)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "All other sessions revoked successfully",
	})
}

// AuthInfoResponse is the response body for auth info.
type AuthInfoResponse struct {
	Provider             string `json:"provider"`
	RegistrationEnabled  bool   `json:"registration_enabled"`
	EmailVerificationReq bool   `json:"email_verification_required"`
}

// Info returns authentication provider information.
// @Summary      Auth info
// @Description  Returns authentication provider information
// @Tags         Authentication
// @Produce      json
// @Success      200  {object}  AuthInfoResponse
// @Router       /auth/info [get]
func (h *LocalAuthHandler) Info(w http.ResponseWriter, r *http.Request) {
	resp := AuthInfoResponse{
		Provider:             string(h.authConfig.Provider),
		RegistrationEnabled:  h.registrationEnabled(r),
		EmailVerificationReq: h.authConfig.RequireEmailVerification,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// minPasswordLength is the configured minimum (the default when unset).
func (h *LocalAuthHandler) minPasswordLength() int {
	if h.authConfig.PasswordMinLength > 0 {
		return h.authConfig.PasswordMinLength
	}
	return password.MinLengthDefault
}

// handleAuthError handles authentication errors and returns appropriate HTTP responses.
func (h *LocalAuthHandler) handleAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		apierror.Unauthorized("Invalid email or password").WriteJSON(w)
	case errors.Is(err, auth.ErrAccountLocked):
		apierror.Forbidden("Account is locked due to too many failed attempts").WriteJSON(w)
	case errors.Is(err, auth.ErrAccountSuspended):
		apierror.Forbidden("Account is suspended").WriteJSON(w)
	case errors.Is(err, auth.ErrEmailNotVerified):
		apierror.Forbidden("Email is not verified").WriteJSON(w)
	case WritePlanLimitError(w, err):
	case errors.Is(err, auth.ErrRegistrationDisabled), errors.Is(err, auth.ErrSignupNotAvailable):
		writeSignupNotAvailable(w)
	case errors.Is(err, auth.ErrTenantCreationDisabled):
		apierror.Forbidden("Organizations are created by the application administrator").WriteJSON(w)
	case errors.Is(err, tenantdom.ErrPlatformAdminMembership):
		apierror.Conflict("Platform administrators cannot belong to an organization. Use the admin console, or a separate account.").WriteJSON(w)
	case errors.Is(err, auth.ErrEmailAlreadyExists):
		apierror.Conflict("Email already exists").WriteJSON(w)
	case errors.Is(err, auth.ErrInvalidResetToken):
		apierror.BadRequest("Invalid or expired reset token").WriteJSON(w)
	case errors.Is(err, auth.ErrInvalidVerificationToken):
		apierror.BadRequest("Invalid or expired verification token").WriteJSON(w)
	case errors.Is(err, auth.ErrPasswordMismatch):
		// 400, not 401: the caller IS authenticated. Clients treat a 401 as an
		// expired session and sign the user out, which is wrong for a typo.
		apierror.BadRequest("Current password is incorrect").WriteJSON(w)
	case errors.Is(err, auth.ErrSessionLimitReached):
		apierror.Forbidden("Maximum number of active sessions reached").WriteJSON(w)
	case errors.Is(err, auth.ErrTenantAccessDenied):
		apierror.Forbidden("User does not have access to this tenant").WriteJSON(w)
	case errors.Is(err, auth.ErrSSORequired):
		apierror.Forbidden("This organization requires SSO sign-in. Please sign in through your identity provider.").WriteJSON(w)
	case errors.Is(err, auth.ErrTenantRequired):
		apierror.BadRequest("tenant_id is required").WriteJSON(w)
	// Two-factor authentication
	case errors.Is(err, auth.ErrMFAChallengeInvalid):
		apierror.Unauthorized("Your sign-in verification expired or is no longer valid. Please sign in again.").WriteJSON(w)
	case errors.Is(err, auth.ErrMFACodeInvalid):
		apierror.Unauthorized("Invalid verification code").WriteJSON(w)
	case errors.Is(err, auth.ErrMFAEnrollmentRequired):
		apierror.New(http.StatusForbidden, apierror.CodeMFAEnrollmentRequired,
			"This organization requires two-factor authentication. Sign in again to complete it.").WriteJSON(w)
	case errors.Is(err, auth.ErrMFANotSupported):
		apierror.BadRequest("Two-factor authentication for this account is managed by your identity provider").WriteJSON(w)
	case errors.Is(err, auth.ErrMFAAlreadyEnabled):
		apierror.Conflict("Two-factor authentication is already enabled").WriteJSON(w)
	case errors.Is(err, auth.ErrMFANotEnabled):
		apierror.BadRequest("Two-factor authentication is not enabled").WriteJSON(w)
	case errors.Is(err, auth.ErrMFANoPendingSetup):
		apierror.BadRequest("Start two-factor setup first").WriteJSON(w)
	case errors.Is(err, auth.ErrMFAUnavailable):
		apierror.ServiceUnavailable("Two-factor authentication is not available on this server").WriteJSON(w)
	// Session/Token errors. A malformed, forged or expired refresh JWT (or
	// anything else presented as one, e.g. a 2FA challenge token) is a 401,
	// not a server error.
	case errors.Is(err, jwt.ErrInvalidToken), errors.Is(err, jwt.ErrExpiredToken),
		errors.Is(err, jwt.ErrInvalidTokenType):
		apierror.Unauthorized("Invalid or expired refresh token").WriteJSON(w)
	case errors.Is(err, session.ErrRefreshTokenNotFound):
		apierror.Unauthorized("Invalid or expired refresh token").WriteJSON(w)
	case errors.Is(err, session.ErrRefreshTokenExpired):
		apierror.Unauthorized("Refresh token has expired").WriteJSON(w)
	case errors.Is(err, session.ErrRefreshTokenUsed):
		apierror.Unauthorized("Refresh token has already been used (possible security breach)").WriteJSON(w)
	case errors.Is(err, session.ErrRefreshTokenRevoked):
		apierror.Unauthorized("Refresh token has been revoked").WriteJSON(w)
	case errors.Is(err, session.ErrSessionExpired):
		apierror.Unauthorized("Session has expired, please login again").WriteJSON(w)
	case errors.Is(err, session.ErrSessionRevoked):
		apierror.Unauthorized("Session has been revoked").WriteJSON(w)
	case errors.Is(err, session.ErrSessionNotFound):
		// Unknown session id, or one that belongs to another user. 404 (not
		// 500), and identical for both so a caller can't probe others' ids.
		apierror.NotFound("Session").WriteJSON(w)
	case errors.Is(err, session.ErrTokenFamilyMismatch):
		apierror.Unauthorized("Invalid token (possible replay attack detected)").WriteJSON(w)
	// Password validation errors
	case errors.Is(err, password.ErrPasswordTooShort):
		apierror.BadRequest(fmt.Sprintf("Password is too short (minimum %d characters)", h.minPasswordLength())).WriteJSON(w)
	case errors.Is(err, password.ErrPasswordCommon):
		apierror.BadRequest("This password appears in lists of breached passwords. Choose another one.").WriteJSON(w)
	case errors.Is(err, password.ErrPasswordNoUppercase):
		apierror.BadRequest("Password must contain at least one uppercase letter").WriteJSON(w)
	case errors.Is(err, password.ErrPasswordNoLowercase):
		apierror.BadRequest("Password must contain at least one lowercase letter").WriteJSON(w)
	case errors.Is(err, password.ErrPasswordNoNumber):
		apierror.BadRequest("Password must contain at least one number").WriteJSON(w)
	case errors.Is(err, password.ErrPasswordNoSpecial):
		apierror.BadRequest("Password must contain at least one special character").WriteJSON(w)
	// Generic validation and conflict errors
	// Use safe error messages to prevent information leakage
	case errors.Is(err, shared.ErrConflict):
		apierror.SafeConflict(err).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.SafeBadRequest(err).WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		// A lookup miss (e.g. an unknown invitation token) is a client
		// error, not a server one.
		apierror.NotFound("").WriteJSON(w)
	default:
		h.logger.Error("auth error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// getClientIP extracts the client IP address from the request.
//
// SECURITY (S-4): Forwarding headers are honored only when the immediate
// TCP peer sits in the trusted-proxy CIDR allowlist. Without this guard
// attackers could spoof X-Forwarded-For to attribute brute-force / abuse
// attempts to fake IPs in the audit log.
//
// trustedProxiesForAuth is set during server bootstrap. If nil (tests,
// direct-Internet deployments) only r.RemoteAddr is honored.
func getClientIP(r *http.Request) string {
	return httpsec.ClientIP(r, trustedProxiesForAuth)
}

// trustedProxiesForAuth is the package-level proxy allowlist used by
// auth-handler audit code. Wired once at startup via SetAuthTrustedProxies.
var trustedProxiesForAuth *httpsec.TrustedProxySet //nolint:gochecknoglobals // set once at startup

// SetAuthTrustedProxies configures the trusted-proxy set used by the
// auth handler's IP attribution. Call once during server bootstrap.
func SetAuthTrustedProxies(set *httpsec.TrustedProxySet) {
	trustedProxiesForAuth = set
}
