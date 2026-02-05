package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/session"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/password"
	"github.com/openctemio/api/pkg/validator"
)

// LocalAuthHandler handles local authentication requests.
type LocalAuthHandler struct {
	authService    *app.AuthService
	sessionService *app.SessionService
	emailService   *app.EmailService
	authConfig     config.AuthConfig
	cookieConfig   CookieConfig
	csrfConfig     middleware.CSRFConfig
	validator      *validator.Validator
	logger         *logger.Logger
}

// NewLocalAuthHandler creates a new LocalAuthHandler.
func NewLocalAuthHandler(
	authService *app.AuthService,
	sessionService *app.SessionService,
	emailService *app.EmailService,
	authConfig config.AuthConfig,
	log *logger.Logger,
) *LocalAuthHandler {
	return &LocalAuthHandler{
		authService:    authService,
		sessionService: sessionService,
		emailService:   emailService,
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

	result, err := h.authService.Register(r.Context(), app.RegisterInput{
		Email:    req.Email,
		Password: req.Password,
		Name:     req.Name,
	})
	if err != nil {
		h.handleAuthError(w, err)
		return
	}

	// Security: Always show the same generic message to prevent email enumeration
	// The message "check your email" is shown whether the email existed or not
	message := "Registration successful. Please check your email to verify your account."

	// Handle case where email already existed (anti-enumeration)
	if result.EmailExisted {
		// Return a generic response that looks identical to a successful registration
		// to prevent attackers from discovering which emails are registered
		resp := RegisterResponse{
			ID:                   "", // Don't reveal any info
			Email:                req.Email,
			Name:                 req.Name,
			RequiresVerification: true,
			Message:              message,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Send verification email if required (only for new users)
	if result.RequiresVerification && result.VerificationToken != "" {
		if h.emailService != nil {
			if err := h.emailService.SendVerificationEmail(
				r.Context(),
				result.User.Email(),
				result.User.Name(),
				result.VerificationToken,
				h.authConfig.EmailVerificationDuration,
			); err != nil {
				h.logger.Error("failed to send verification email",
					"email", result.User.Email(),
					"error", err,
				)
				// Don't fail registration if email fails - user can request resend
			}
		}
	} else if !result.RequiresVerification {
		message = "Registration successful"
	}

	resp := RegisterResponse{
		ID:                   result.User.ID().String(),
		Email:                result.User.Email(),
		Name:                 result.User.Name(),
		RequiresVerification: result.RequiresVerification,
		Message:              message,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
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

	result, err := h.authService.Login(r.Context(), app.LoginInput{
		Email:     req.Email,
		Password:  req.Password,
		IPAddress: ipAddress,
		UserAgent: userAgent,
	})
	if err != nil {
		h.handleAuthError(w, err)
		return
	}

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

	resp := LoginResponse{
		RefreshToken: result.RefreshToken, // Also in body for backward compatibility
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		User: UserInfo{
			ID:    result.User.ID().String(),
			Email: result.User.Email(),
			Name:  result.User.Name(),
		},
		Tenants: tenants,
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

	// Get refresh token from cookie if not in body (httpOnly cookie takes precedence)
	refreshToken := GetRefreshTokenFromCookie(r, h.cookieConfig)
	if refreshToken == "" {
		refreshToken = req.RefreshToken
	}
	if refreshToken == "" {
		apierror.BadRequest("refresh_token is required (in body or cookie)").WriteJSON(w)
		return
	}

	result, err := h.authService.ExchangeToken(r.Context(), app.ExchangeTokenInput{
		RefreshToken: refreshToken,
		TenantID:     req.TenantID,
	})
	if err != nil {
		h.handleAuthError(w, err)
		return
	}

	expiresIn := int64(h.authConfig.AccessTokenDuration.Seconds())

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

	// Get refresh token from cookie if not in body (httpOnly cookie takes precedence)
	refreshToken := GetRefreshTokenFromCookie(r, h.cookieConfig)
	if refreshToken == "" {
		refreshToken = req.RefreshToken
	}
	if refreshToken == "" {
		apierror.BadRequest("refresh_token is required (in body or cookie)").WriteJSON(w)
		return
	}

	ipAddress := getClientIP(r)
	userAgent := r.UserAgent()

	result, err := h.authService.RefreshToken(r.Context(), app.RefreshTokenInput{
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

	resp := RefreshTokenResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken, // Also in body for backward compatibility
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		TenantID:     result.TenantID,
		TenantSlug:   result.TenantSlug,
		Role:         result.Role,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// CreateFirstTeamRequest is the request body for creating first team.
type CreateFirstTeamRequest struct {
	TeamName string `json:"team_name" validate:"required,min=2,max=100"`
	TeamSlug string `json:"team_slug" validate:"required,min=3,max=50"`
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

	// Get refresh token from cookie (httpOnly cookie)
	refreshToken := GetRefreshTokenFromCookie(r, h.cookieConfig)
	if refreshToken == "" {
		apierror.Unauthorized("refresh_token is required (in cookie)").WriteJSON(w)
		return
	}

	result, err := h.authService.CreateFirstTeam(r.Context(), app.CreateFirstTeamInput{
		RefreshToken: refreshToken,
		TeamName:     req.TeamName,
		TeamSlug:     req.TeamSlug,
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

// AcceptInvitationWithRefreshRequest is the request body for accepting invitation with refresh token.
type AcceptInvitationWithRefreshRequest struct {
	InvitationToken string `json:"invitation_token" validate:"required"`
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

// AcceptInvitationWithRefresh handles accepting an invitation using refresh token.
// POST /api/v1/invitations/{token}/accept-with-refresh
// This endpoint is for users who were invited but don't have a tenant yet,
// so they only have a refresh token (no access token).
// The refresh token is obtained from the httpOnly cookie.
func (h *LocalAuthHandler) AcceptInvitationWithRefresh(w http.ResponseWriter, r *http.Request) {
	// Get invitation token from URL path
	invitationToken := r.PathValue("token")
	if invitationToken == "" {
		apierror.BadRequest("Invitation token is required").WriteJSON(w)
		return
	}

	// Get refresh token from cookie (httpOnly cookie)
	refreshToken := GetRefreshTokenFromCookie(r, h.cookieConfig)
	if refreshToken == "" {
		apierror.Unauthorized("refresh_token is required (in cookie)").WriteJSON(w)
		return
	}

	result, err := h.authService.AcceptInvitationWithRefreshToken(r.Context(), app.AcceptInvitationWithRefreshTokenInput{
		RefreshToken:    refreshToken,
		InvitationToken: invitationToken,
	})
	if err != nil {
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

	// Always return success to prevent email enumeration
	ipAddress := getClientIP(r)
	result, _ := h.authService.ForgotPassword(r.Context(), app.ForgotPasswordInput{
		Email: req.Email,
	})

	// Send password reset email if we got a token
	if result != nil && result.Token != "" && h.emailService != nil {
		// Get user name for email (we don't expose errors)
		userName := "" // Default to empty name for privacy
		if err := h.emailService.SendPasswordResetEmail(
			r.Context(),
			req.Email,
			userName,
			result.Token,
			h.authConfig.PasswordResetDuration,
			ipAddress,
		); err != nil {
			h.logger.Error("failed to send password reset email",
				"email", req.Email,
				"error", err,
			)
			// Don't reveal the error to prevent enumeration
		}
	}

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

	if err := h.authService.ResetPassword(r.Context(), app.ResetPasswordInput{
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

	if err := h.authService.ChangePassword(r.Context(), userID, app.ChangePasswordInput{
		CurrentPassword: req.CurrentPassword,
		NewPassword:     req.NewPassword,
	}); err != nil {
		h.handleAuthError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password changed successfully",
	})
}

// SessionsResponse is the response body for listing sessions.
type SessionsResponse struct {
	Sessions []app.SessionInfo `json:"sessions"`
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

// WSTokenResponse is the response body for WebSocket token.
type WSTokenResponse struct {
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expires_in"` // Seconds until expiration
}

// GetWSToken returns a short-lived token for WebSocket authentication.
// This is needed because WebSocket connections cannot use httpOnly cookies
// when the connection is cross-origin (different port in development).
// The token is valid for 30 seconds - just enough time to establish the connection.
// @Summary      Get WebSocket token
// @Description  Returns a short-lived token for WebSocket authentication
// @Tags         Authentication
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  WSTokenResponse
// @Failure      401  {object}  map[string]string
// @Router       /auth/ws-token [get]
func (h *LocalAuthHandler) GetWSToken(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	tenantID := middleware.GetTenantID(r.Context())

	if userID == "" || tenantID == "" {
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}

	// Generate a short-lived token (30 seconds) for WebSocket authentication
	// This token will be passed as a query parameter during WebSocket handshake
	token, err := h.authService.GenerateWSToken(r.Context(), userID, tenantID)
	if err != nil {
		h.logger.Error("failed to generate WS token", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	resp := WSTokenResponse{
		Token:     token,
		ExpiresIn: 30, // 30 seconds
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
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
		RegistrationEnabled:  h.authConfig.AllowRegistration,
		EmailVerificationReq: h.authConfig.RequireEmailVerification,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// handleAuthError handles authentication errors and returns appropriate HTTP responses.
func (h *LocalAuthHandler) handleAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, app.ErrInvalidCredentials):
		apierror.Unauthorized("Invalid email or password").WriteJSON(w)
	case errors.Is(err, app.ErrAccountLocked):
		apierror.Forbidden("Account is locked due to too many failed attempts").WriteJSON(w)
	case errors.Is(err, app.ErrAccountSuspended):
		apierror.Forbidden("Account is suspended").WriteJSON(w)
	case errors.Is(err, app.ErrEmailNotVerified):
		apierror.Forbidden("Email is not verified").WriteJSON(w)
	case errors.Is(err, app.ErrRegistrationDisabled):
		apierror.Forbidden("Registration is disabled").WriteJSON(w)
	case errors.Is(err, app.ErrEmailAlreadyExists):
		apierror.Conflict("Email already exists").WriteJSON(w)
	case errors.Is(err, app.ErrInvalidResetToken):
		apierror.BadRequest("Invalid or expired reset token").WriteJSON(w)
	case errors.Is(err, app.ErrInvalidVerificationToken):
		apierror.BadRequest("Invalid or expired verification token").WriteJSON(w)
	case errors.Is(err, app.ErrPasswordMismatch):
		apierror.Unauthorized("Current password is incorrect").WriteJSON(w)
	case errors.Is(err, app.ErrSessionLimitReached):
		apierror.Forbidden("Maximum number of active sessions reached").WriteJSON(w)
	case errors.Is(err, app.ErrTenantAccessDenied):
		apierror.Forbidden("User does not have access to this tenant").WriteJSON(w)
	case errors.Is(err, app.ErrTenantRequired):
		apierror.BadRequest("tenant_id is required").WriteJSON(w)
	// Session/Token errors
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
	case errors.Is(err, session.ErrTokenFamilyMismatch):
		apierror.Unauthorized("Invalid token (possible replay attack detected)").WriteJSON(w)
	// Password validation errors
	case errors.Is(err, password.ErrPasswordTooShort):
		apierror.BadRequest("Password is too short (minimum 8 characters)").WriteJSON(w)
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
	default:
		h.logger.Error("auth error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// getClientIP extracts the client IP address from the request.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxied requests)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first IP in the list
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		return ip[:idx]
	}
	return ip
}
