package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/domain/session"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/domain/user"
	"github.com/openctemio/api/pkg/jwt"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/password"
)

// AuthService errors.
var (
	ErrInvalidCredentials       = errors.New("invalid email or password")
	ErrAccountLocked            = errors.New("account is locked due to too many failed attempts")
	ErrAccountSuspended         = errors.New("account is suspended")
	ErrEmailNotVerified         = errors.New("email is not verified")
	ErrRegistrationDisabled     = errors.New("registration is disabled")
	ErrEmailAlreadyExists       = errors.New("email already exists")
	ErrInvalidResetToken        = errors.New("invalid or expired reset token")
	ErrInvalidVerificationToken = errors.New("invalid or expired verification token")
	ErrPasswordMismatch         = errors.New("current password is incorrect")
	ErrSessionLimitReached      = errors.New("maximum number of active sessions reached")
	ErrTenantAccessDenied       = errors.New("user does not have access to this tenant")
	ErrTenantRequired           = errors.New("tenant_id is required")
)

// AuthService handles authentication operations.
type AuthService struct {
	userRepo         user.Repository
	sessionRepo      session.Repository
	refreshTokenRepo session.RefreshTokenRepository
	tenantRepo       tenant.Repository
	passwordHasher   *password.Hasher
	tokenGenerator   *jwt.Generator
	config           config.AuthConfig
	logger           *logger.Logger
	auditService     *AuditService
	roleService      *RoleService // Optional: for database-driven role permissions
}

// NewAuthService creates a new AuthService.
func NewAuthService(
	userRepo user.Repository,
	sessionRepo session.Repository,
	refreshTokenRepo session.RefreshTokenRepository,
	tenantRepo tenant.Repository,
	auditService *AuditService,
	cfg config.AuthConfig,
	log *logger.Logger,
) *AuthService {
	// Create password hasher with policy from config
	hasher := password.New(password.WithPolicy(password.Policy{
		MinLength:      cfg.PasswordMinLength,
		RequireUpper:   cfg.PasswordRequireUpper,
		RequireLower:   cfg.PasswordRequireLower,
		RequireNumber:  cfg.PasswordRequireNumber,
		RequireSpecial: cfg.PasswordRequireSpecial,
	}))

	// Create token generator
	tokenGen := jwt.NewGenerator(jwt.TokenConfig{
		Secret:               cfg.JWTSecret,
		Issuer:               cfg.JWTIssuer,
		AccessTokenDuration:  cfg.AccessTokenDuration,
		RefreshTokenDuration: cfg.RefreshTokenDuration,
	})

	return &AuthService{
		userRepo:         userRepo,
		sessionRepo:      sessionRepo,
		refreshTokenRepo: refreshTokenRepo,
		tenantRepo:       tenantRepo,
		passwordHasher:   hasher,
		tokenGenerator:   tokenGen,
		config:           cfg,
		logger:           log.With("service", "auth"),
		auditService:     auditService,
	}
}

// SetRoleService sets the role service for database-driven permissions.
// When set, the auth service will fetch permissions from the database
// instead of using hardcoded role-permission mappings.
func (s *AuthService) SetRoleService(roleService *RoleService) {
	s.roleService = roleService
}

// RegisterInput represents the input for user registration.
type RegisterInput struct {
	Email    string `json:"email" validate:"required,email,max=255"`
	Password string `json:"password" validate:"required,min=8,max=128"`
	Name     string `json:"name" validate:"required,max=255"`
}

// RegisterResult represents the result of registration.
type RegisterResult struct {
	User                 *user.User
	VerificationToken    string // Only returned if email verification is required
	RequiresVerification bool
	EmailExisted         bool // Set to true if email already exists (for anti-enumeration)
}

// Register creates a new local user account.
// Security note: To prevent email enumeration attacks, this method returns
// a success result even if the email already exists. The caller should always
// display a generic "check your email" message regardless of the result.
func (s *AuthService) Register(ctx context.Context, input RegisterInput) (*RegisterResult, error) {
	if !s.config.AllowRegistration {
		return nil, ErrRegistrationDisabled
	}

	// Normalize email
	email := strings.TrimSpace(strings.ToLower(input.Email))

	// Check if email already exists
	// Security: Return success-like result to prevent email enumeration
	existingUser, err := s.userRepo.GetByEmail(ctx, email)
	if err == nil && existingUser != nil {
		s.logger.Info("registration attempt for existing email", "email", email)
		// Return a fake successful result to prevent email enumeration
		// The UI should always show "Check your email for verification"
		return &RegisterResult{
			User:                 nil, // Signal to handler that no actual registration happened
			VerificationToken:    "",
			RequiresVerification: true,
			EmailExisted:         true, // New field to indicate this case
		}, nil
	}
	if err != nil && !shared.IsNotFound(err) {
		return nil, fmt.Errorf("failed to check email: %w", err)
	}

	// Validate password against policy
	if err := s.passwordHasher.Validate(input.Password); err != nil {
		return nil, fmt.Errorf("password validation failed: %w", err)
	}

	// Hash password
	passwordHash, err := s.passwordHasher.Hash(input.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	name := strings.TrimSpace(input.Name)
	newUser, err := user.NewLocalUser(email, name, passwordHash)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Generate verification token if required
	var verificationToken string
	if s.config.RequireEmailVerification {
		token, err := password.GenerateVerificationToken()
		if err != nil {
			return nil, fmt.Errorf("failed to generate verification token: %w", err)
		}
		verificationToken = token
		expiresAt := time.Now().Add(s.config.EmailVerificationDuration)
		newUser.SetEmailVerificationToken(token, expiresAt)
	} else {
		// Auto-verify email if verification not required
		newUser.VerifyEmail()
	}

	// Save user
	if err := s.userRepo.Create(ctx, newUser); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	s.logger.Info("user registered", "user_id", newUser.ID().String(), "email", email)

	// Log audit event
	actx := AuditContext{
		ActorEmail: email,
		ActorIP:    "", // Not available in RegisterInput, would need context or expansion
		UserAgent:  "",
	}
	if err := s.auditService.LogUserRegistered(ctx, actx, newUser.ID().String(), email); err != nil {
		s.logger.Error("failed to log user registration", "error", err)
	}

	return &RegisterResult{
		User:                 newUser,
		VerificationToken:    verificationToken,
		RequiresVerification: s.config.RequireEmailVerification,
	}, nil
}

// LoginInput represents the input for login.
type LoginInput struct {
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required"`
	IPAddress string `json:"-"`
	UserAgent string `json:"-"`
}

// TenantMembershipInfo represents a tenant membership for API responses.
type TenantMembershipInfo struct {
	TenantID   string `json:"tenant_id"`
	TenantSlug string `json:"tenant_slug"`
	TenantName string `json:"tenant_name"`
	Role       string `json:"role"`
}

// LoginResult represents the result of login.
// Returns a global refresh token and list of tenant memberships.
// Client must call ExchangeToken to get a tenant-scoped access token.
type LoginResult struct {
	User         *user.User
	RefreshToken string // Global refresh token (no tenant context)
	ExpiresAt    time.Time
	SessionID    string
	Tenants      []TenantMembershipInfo // List of tenants user belongs to
}

// Login authenticates a user and creates a session.
// Returns a global refresh token and list of tenant memberships.
// Client should call ExchangeToken to get a tenant-scoped access token.
func (s *AuthService) Login(ctx context.Context, input LoginInput) (*LoginResult, error) {
	// Normalize email
	email := strings.TrimSpace(strings.ToLower(input.Email))

	// Get user by email
	u, err := s.userRepo.GetByEmailForAuth(ctx, email)
	if err != nil {
		if shared.IsNotFound(err) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Check if account is locked
	if u.IsLocked() {
		return nil, ErrAccountLocked
	}

	// Check if account is suspended
	if u.Status() == user.StatusSuspended {
		return nil, ErrAccountSuspended
	}

	// Check if user is a local user
	if u.AuthProvider() != user.AuthProviderLocal {
		return nil, ErrInvalidCredentials
	}

	// Verify password
	passwordHash := u.PasswordHash()
	if passwordHash == nil {
		return nil, ErrInvalidCredentials
	}
	if err := s.passwordHasher.Verify(input.Password, *passwordHash); err != nil {
		// Record failed login attempt
		u.RecordFailedLogin(s.config.MaxLoginAttempts, s.config.LockoutDuration)
		if updateErr := s.userRepo.Update(ctx, u); updateErr != nil {
			s.logger.Error("failed to update user after failed login", "error", updateErr)
		}

		// Audit failed login
		actx := AuditContext{
			ActorEmail: email,
			ActorIP:    input.IPAddress,
			UserAgent:  input.UserAgent,
		}
		_ = s.auditService.LogAuthFailed(ctx, actx, "invalid credentials")

		return nil, ErrInvalidCredentials
	}

	// Check if email is verified
	if s.config.RequireEmailVerification && !u.EmailVerified() {
		return nil, ErrEmailNotVerified
	}

	// Reset failed login attempts on successful login
	u.RecordSuccessfulLogin()
	if err := s.userRepo.Update(ctx, u); err != nil {
		s.logger.Error("failed to reset failed login attempts", "error", err)
	}

	// Check session limit
	activeCount, err := s.sessionRepo.CountActiveByUserID(ctx, u.ID())
	if err != nil {
		return nil, fmt.Errorf("failed to count active sessions: %w", err)
	}
	if activeCount >= s.config.MaxActiveSessions {
		// Auto-revoke the oldest session to make room for new one
		oldestSession, err := s.sessionRepo.GetOldestActiveByUserID(ctx, u.ID())
		if err != nil {
			return nil, fmt.Errorf("failed to get oldest session: %w", err)
		}
		if oldestSession != nil {
			if err := oldestSession.Revoke(); err != nil {
				s.logger.Error("failed to revoke oldest session", "error", err)
			} else if err := s.sessionRepo.Update(ctx, oldestSession); err != nil {
				s.logger.Error("failed to update revoked session", "error", err)
			} else {
				// Also revoke refresh tokens for the old session
				if err := s.refreshTokenRepo.RevokeBySessionID(ctx, oldestSession.ID()); err != nil {
					s.logger.Error("failed to revoke refresh tokens for oldest session", "error", err)
				}
				s.logger.Info("auto-revoked oldest session due to session limit",
					"user_id", u.ID().String(),
					"revoked_session_id", oldestSession.ID().String(),
				)
			}
		}
	}

	// Generate session ID first so we can include it in the JWT
	sessionID := shared.NewID()

	// Query user's tenant memberships
	memberships, err := s.tenantRepo.GetUserMemberships(ctx, u.ID())
	if err != nil {
		s.logger.Error("failed to get user memberships", "error", err)
		// Continue without memberships - user can still login but won't have tenant access
		memberships = nil
	}

	// Convert to TenantMembershipInfo for response
	tenantInfos := make([]TenantMembershipInfo, 0, len(memberships))
	for _, m := range memberships {
		tenantInfos = append(tenantInfos, TenantMembershipInfo{
			TenantID:   m.TenantID,
			TenantSlug: m.TenantSlug,
			TenantName: m.TenantName,
			Role:       m.Role,
		})
	}

	// Generate GLOBAL refresh token (no tenant context)
	refreshTokenStr, refreshExpiresAt, err := s.tokenGenerator.GenerateGlobalRefreshToken(
		u.ID().String(),
		u.Email(),
		u.Name(),
		sessionID.String(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Create session (we use refresh token hash as access token hash for now,
	// since access tokens will be generated per-tenant via ExchangeToken)
	sess, err := session.NewWithID(
		sessionID,
		u.ID(),
		refreshTokenStr, // Use refresh token for session tracking
		input.IPAddress,
		input.UserAgent,
		s.config.SessionDuration,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	if err := s.sessionRepo.Create(ctx, sess); err != nil {
		return nil, fmt.Errorf("failed to save session: %w", err)
	}

	// Store refresh token in database
	refreshToken, err := session.NewRefreshToken(
		u.ID(),
		sess.ID(),
		refreshTokenStr,
		s.config.RefreshTokenDuration,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token: %w", err)
	}

	if err := s.refreshTokenRepo.Create(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	s.logger.Info("user logged in", "user_id", u.ID().String(), "session_id", sess.ID().String())

	// Audit successful login
	actx := AuditContext{
		ActorID:    u.ID().String(),
		ActorEmail: u.Email(),
		ActorIP:    input.IPAddress,
		UserAgent:  input.UserAgent,
		SessionID:  sess.ID().String(),
	}
	if err := s.auditService.LogUserLogin(ctx, actx, u.ID().String(), u.Email()); err != nil {
		s.logger.Error("failed to log user login", "error", err)
	}

	return &LoginResult{
		User:         u,
		RefreshToken: refreshTokenStr,
		ExpiresAt:    refreshExpiresAt,
		SessionID:    sess.ID().String(),
		Tenants:      tenantInfos,
	}, nil
}

// ExchangeTokenInput represents the input for token exchange.
type ExchangeTokenInput struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
	TenantID     string `json:"tenant_id" validate:"required"`
}

// ExchangeTokenResult represents the result of token exchange.
type ExchangeTokenResult struct {
	AccessToken string
	TenantID    string
	TenantSlug  string
	Role        string
	ExpiresAt   time.Time
}

// ExchangeToken exchanges a global refresh token for a tenant-scoped access token.
// This is the main method for getting access tokens after login.
func (s *AuthService) ExchangeToken(ctx context.Context, input ExchangeTokenInput) (*ExchangeTokenResult, error) {
	if input.TenantID == "" {
		return nil, ErrTenantRequired
	}

	// Validate the refresh token JWT
	claims, err := s.tokenGenerator.ValidateRefreshToken(input.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Get the refresh token hash and verify it exists in database
	tokenHash := session.HashToken(input.RefreshToken)
	storedToken, err := s.refreshTokenRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, session.ErrRefreshTokenNotFound) {
			return nil, session.ErrRefreshTokenNotFound
		}
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	// Check if token is valid (not used, not revoked, not expired)
	if !storedToken.IsValid() {
		return nil, session.ErrRefreshTokenRevoked
	}

	// Get the session and verify it's still active
	sess, err := s.sessionRepo.GetByID(ctx, storedToken.SessionID())
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	if !sess.IsActive() {
		return nil, session.ErrSessionExpired
	}

	// Get user
	userID, err := shared.IDFromString(claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user id in token: %w", err)
	}

	u, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Verify user has access to the requested tenant
	memberships, err := s.tenantRepo.GetUserMemberships(ctx, u.ID())
	if err != nil {
		return nil, fmt.Errorf("failed to get user memberships: %w", err)
	}

	var targetMembership *tenant.UserMembership
	for _, m := range memberships {
		if m.TenantID == input.TenantID {
			targetMembership = &m
			break
		}
	}

	if targetMembership == nil {
		return nil, ErrTenantAccessDenied
	}

	// Determine if user is admin (owner or admin role)
	// Owner/Admin: isAdmin=true → bypass permission checks, no permissions in JWT
	// Member/Viewer/Custom: isAdmin=false → permissions fetched from DB on each request
	// This keeps JWT small (< 4KB cookie limit) for all users
	isAdminRole := targetMembership.Role == "owner" || targetMembership.Role == "admin"

	// Generate tenant-scoped access token (with database-driven permissions if available)
	accessToken, err := s.generateTenantScopedAccessToken(
		ctx,
		u.ID().String(),
		u.Email(),
		u.Name(),
		sess.ID().String(),
		jwt.TenantMembership{
			TenantID:   targetMembership.TenantID,
			TenantSlug: targetMembership.TenantSlug,
			Role:       targetMembership.Role,
		},
		isAdminRole,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Update session activity
	sess.UpdateActivity()
	if err := s.sessionRepo.Update(ctx, sess); err != nil {
		s.logger.Error("failed to update session activity", "error", err)
	}

	s.logger.Debug("token exchanged",
		"user_id", u.ID().String(),
		"tenant_id", input.TenantID,
		"session_id", sess.ID().String(),
	)

	return &ExchangeTokenResult{
		AccessToken: accessToken.AccessToken,
		TenantID:    accessToken.TenantID,
		TenantSlug:  accessToken.TenantSlug,
		Role:        accessToken.Role,
		ExpiresAt:   accessToken.ExpiresAt,
	}, nil
}

// Logout revokes a session.
func (s *AuthService) Logout(ctx context.Context, sessionID string) error {
	id, err := shared.IDFromString(sessionID)
	if err != nil {
		return fmt.Errorf("invalid session id: %w", err)
	}

	sess, err := s.sessionRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			return nil // Already logged out
		}
		return fmt.Errorf("failed to get session: %w", err)
	}

	// Revoke session
	if err := sess.Revoke(); err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	if err := s.sessionRepo.Update(ctx, sess); err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	// Revoke all refresh tokens for this session
	if err := s.refreshTokenRepo.RevokeBySessionID(ctx, id); err != nil {
		s.logger.Error("failed to revoke refresh tokens", "error", err)
	}

	s.logger.Info("user logged out", "session_id", sessionID)

	// Audit logout (best effort, as we only have session ID here)
	// Ideally we should look up user from session before revoking to get full context
	// For now, simple log
	actx := AuditContext{
		ActorID:   sess.UserID().String(),
		SessionID: sessionID,
	}
	// Try to get user email if possible, or just log ID
	_ = s.auditService.LogUserLogout(ctx, actx, sess.UserID().String(), "")

	return nil
}

// RefreshTokenInput represents the input for token refresh.
// Requires tenant_id to generate tenant-scoped access token.
type RefreshTokenInput struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
	TenantID     string `json:"tenant_id" validate:"required"`
	IPAddress    string `json:"-"`
	UserAgent    string `json:"-"`
}

// RefreshTokenResult represents the result of token refresh.
// Returns a new global refresh token and tenant-scoped access token.
type RefreshTokenResult struct {
	AccessToken      string    // Tenant-scoped access token
	RefreshToken     string    // New global refresh token (rotated)
	TenantID         string    // Tenant ID the access token is scoped to
	TenantSlug       string    // Tenant slug
	Role             string    // User's role in this tenant
	ExpiresAt        time.Time // Access token expiration
	RefreshExpiresAt time.Time // Refresh token expiration (for cookie)
}

// RefreshToken rotates the refresh token and issues new tenant-scoped access token.
// This implements token rotation for security while providing tenant-scoped access.
func (s *AuthService) RefreshToken(ctx context.Context, input RefreshTokenInput) (*RefreshTokenResult, error) {
	if input.TenantID == "" {
		return nil, ErrTenantRequired
	}

	// Validate the refresh token JWT
	claims, err := s.tokenGenerator.ValidateRefreshToken(input.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Get the refresh token hash
	tokenHash := session.HashToken(input.RefreshToken)

	// Find the refresh token in database
	storedToken, err := s.refreshTokenRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, session.ErrRefreshTokenNotFound) {
			return nil, session.ErrRefreshTokenNotFound
		}
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	// Check if token has been used (replay attack detection)
	if storedToken.IsUsed() {
		// Possible replay attack - revoke entire token family
		s.logger.Warn("possible replay attack detected", "family", storedToken.Family().String())
		if err := s.refreshTokenRepo.RevokeByFamily(ctx, storedToken.Family()); err != nil {
			s.logger.Error("failed to revoke token family", "error", err)
		}
		return nil, session.ErrRefreshTokenUsed
	}

	// Check if token is valid
	if !storedToken.IsValid() {
		return nil, session.ErrRefreshTokenRevoked
	}

	// Get the session
	sess, err := s.sessionRepo.GetByID(ctx, storedToken.SessionID())
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	if !sess.IsActive() {
		return nil, session.ErrSessionExpired
	}

	// Get user
	userID, err := shared.IDFromString(claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user id in token: %w", err)
	}

	u, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Mark old token as used (token rotation)
	if err := storedToken.MarkUsed(); err != nil {
		return nil, err
	}
	if err := s.refreshTokenRepo.Update(ctx, storedToken); err != nil {
		return nil, fmt.Errorf("failed to update refresh token: %w", err)
	}

	// Verify user has access to the requested tenant
	memberships, err := s.tenantRepo.GetUserMemberships(ctx, u.ID())
	if err != nil {
		return nil, fmt.Errorf("failed to get user memberships: %w", err)
	}

	var targetMembership *tenant.UserMembership
	for _, m := range memberships {
		if m.TenantID == input.TenantID {
			targetMembership = &m
			break
		}
	}

	if targetMembership == nil {
		return nil, ErrTenantAccessDenied
	}

	// Generate new GLOBAL refresh token (token rotation)
	newRefreshTokenStr, refreshExpiresAt, err := s.tokenGenerator.GenerateGlobalRefreshToken(
		u.ID().String(),
		u.Email(),
		u.Name(),
		sess.ID().String(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Create new refresh token in the same family (for rotation tracking)
	newRefreshToken, err := session.NewRefreshTokenInFamily(
		u.ID(),
		sess.ID(),
		newRefreshTokenStr,
		storedToken.Family(),
		s.config.RefreshTokenDuration,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create new refresh token: %w", err)
	}

	if err := s.refreshTokenRepo.Create(ctx, newRefreshToken); err != nil {
		return nil, fmt.Errorf("failed to save new refresh token: %w", err)
	}

	// Determine if user is admin (owner or admin role)
	// Owner/Admin: isAdmin=true → bypass permission checks, no permissions in JWT
	// Member/Viewer/Custom: isAdmin=false → permissions fetched from DB on each request
	isRefreshAdminRole := targetMembership.Role == "owner" || targetMembership.Role == "admin"

	// Generate TENANT-SCOPED access token (with database-driven permissions if available)
	accessToken, err := s.generateTenantScopedAccessToken(
		ctx,
		u.ID().String(),
		u.Email(),
		u.Name(),
		sess.ID().String(),
		jwt.TenantMembership{
			TenantID:   targetMembership.TenantID,
			TenantSlug: targetMembership.TenantSlug,
			Role:       targetMembership.Role,
		},
		isRefreshAdminRole,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Update session activity
	sess.UpdateActivity()
	if err := s.sessionRepo.Update(ctx, sess); err != nil {
		s.logger.Error("failed to update session activity", "error", err)
	}

	s.logger.Debug("token refreshed",
		"user_id", u.ID().String(),
		"tenant_id", input.TenantID,
		"session_id", sess.ID().String(),
	)

	return &RefreshTokenResult{
		AccessToken:      accessToken.AccessToken,
		RefreshToken:     newRefreshTokenStr,
		TenantID:         accessToken.TenantID,
		TenantSlug:       accessToken.TenantSlug,
		Role:             accessToken.Role,
		ExpiresAt:        accessToken.ExpiresAt,
		RefreshExpiresAt: refreshExpiresAt,
	}, nil
}

// VerifyEmail verifies a user's email with the verification token.
func (s *AuthService) VerifyEmail(ctx context.Context, token string) error {
	u, err := s.userRepo.GetByEmailVerificationToken(ctx, token)
	if err != nil {
		if shared.IsNotFound(err) {
			return ErrInvalidVerificationToken
		}
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Check if token is expired
	if u.EmailVerificationExpiresAt() != nil && time.Now().After(*u.EmailVerificationExpiresAt()) {
		return ErrInvalidVerificationToken
	}

	// Verify email
	u.VerifyEmail()

	if err := s.userRepo.Update(ctx, u); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	s.logger.Info("email verified", "user_id", u.ID().String())
	return nil
}

// ForgotPasswordInput represents the input for password reset request.
type ForgotPasswordInput struct {
	Email string `json:"email" validate:"required,email"`
}

// ForgotPasswordResult represents the result of password reset request.
type ForgotPasswordResult struct {
	Token string // Reset token (should be sent via email in production)
}

// ForgotPassword initiates a password reset.
func (s *AuthService) ForgotPassword(ctx context.Context, input ForgotPasswordInput) (*ForgotPasswordResult, error) {
	email := strings.TrimSpace(strings.ToLower(input.Email))

	u, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		if shared.IsNotFound(err) {
			// Don't reveal if email exists
			return &ForgotPasswordResult{}, nil
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Only allow password reset for local users
	if u.AuthProvider() != user.AuthProviderLocal {
		return &ForgotPasswordResult{}, nil
	}

	// Generate reset token
	token, err := password.GenerateResetToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate reset token: %w", err)
	}

	expiresAt := time.Now().Add(s.config.PasswordResetDuration)
	u.SetPasswordResetToken(token, expiresAt)

	if err := s.userRepo.Update(ctx, u); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	s.logger.Info("password reset requested", "user_id", u.ID().String())

	return &ForgotPasswordResult{Token: token}, nil
}

// ResetPasswordInput represents the input for password reset.
type ResetPasswordInput struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8,max=128"`
}

// ResetPassword resets a user's password using the reset token.
func (s *AuthService) ResetPassword(ctx context.Context, input ResetPasswordInput) error {
	u, err := s.userRepo.GetByPasswordResetToken(ctx, input.Token)
	if err != nil {
		if shared.IsNotFound(err) {
			return ErrInvalidResetToken
		}
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Check if token is expired
	if u.PasswordResetExpiresAt() != nil && time.Now().After(*u.PasswordResetExpiresAt()) {
		return ErrInvalidResetToken
	}

	// Validate new password
	if err := s.passwordHasher.Validate(input.NewPassword); err != nil {
		return fmt.Errorf("password validation failed: %w", err)
	}

	// Hash new password
	passwordHash, err := s.passwordHasher.Hash(input.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password and clear reset token
	if err := u.SetPasswordHash(passwordHash); err != nil {
		return fmt.Errorf("failed to set password hash: %w", err)
	}
	u.ClearPasswordResetToken()

	// Revoke all sessions for security
	if err := s.sessionRepo.RevokeAllByUserID(ctx, u.ID()); err != nil {
		s.logger.Error("failed to revoke sessions after password reset", "error", err)
	}

	// Revoke all refresh tokens
	if err := s.refreshTokenRepo.RevokeByUserID(ctx, u.ID()); err != nil {
		s.logger.Error("failed to revoke refresh tokens after password reset", "error", err)
	}

	if err := s.userRepo.Update(ctx, u); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	s.logger.Info("password reset completed", "user_id", u.ID().String())
	return nil
}

// ChangePasswordInput represents the input for changing password.
type ChangePasswordInput struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8,max=128"`
}

// ChangePassword changes a user's password (requires authentication).
func (s *AuthService) ChangePassword(ctx context.Context, userID string, input ChangePasswordInput) error {
	id, err := shared.IDFromString(userID)
	if err != nil {
		return fmt.Errorf("invalid user id: %w", err)
	}

	u, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Only allow password change for local users
	if u.AuthProvider() != user.AuthProviderLocal {
		return errors.New("password change not supported for this auth provider")
	}

	// Verify current password
	passwordHash := u.PasswordHash()
	if passwordHash == nil {
		return errors.New("no password set for this user")
	}
	if err := s.passwordHasher.Verify(input.CurrentPassword, *passwordHash); err != nil {
		return ErrPasswordMismatch
	}

	// Validate new password
	if err := s.passwordHasher.Validate(input.NewPassword); err != nil {
		return fmt.Errorf("password validation failed: %w", err)
	}

	// Hash new password
	newPasswordHash, err := s.passwordHasher.Hash(input.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	if err := u.SetPasswordHash(newPasswordHash); err != nil {
		return fmt.Errorf("failed to set password: %w", err)
	}

	if err := s.userRepo.Update(ctx, u); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	s.logger.Info("password changed", "user_id", userID)
	return nil
}

// ValidateAccessToken validates an access token and returns the claims.
func (s *AuthService) ValidateAccessToken(tokenString string) (*jwt.Claims, error) {
	return s.tokenGenerator.ValidateAccessToken(tokenString)
}

// CreateFirstTeamInput represents the input for creating first team.
type CreateFirstTeamInput struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
	TeamName     string `json:"team_name" validate:"required,min=2,max=100"`
	TeamSlug     string `json:"team_slug" validate:"required,min=3,max=50"`
}

// CreateFirstTeamResult represents the result of creating first team.
type CreateFirstTeamResult struct {
	AccessToken  string               `json:"access_token"`
	RefreshToken string               `json:"refresh_token"` // Rotated refresh token
	ExpiresAt    time.Time            `json:"expires_at"`
	Tenant       TenantMembershipInfo `json:"tenant"`
}

// CreateFirstTeam creates the first team for a user who has no tenants.
// This endpoint uses refresh_token for authentication since user has no access_token yet.
func (s *AuthService) CreateFirstTeam(ctx context.Context, input CreateFirstTeamInput) (*CreateFirstTeamResult, error) {
	// Validate the refresh token JWT
	claims, err := s.tokenGenerator.ValidateRefreshToken(input.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Verify refresh token exists in database
	tokenHash := session.HashToken(input.RefreshToken)
	storedToken, err := s.refreshTokenRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, session.ErrRefreshTokenNotFound) {
			return nil, session.ErrRefreshTokenNotFound
		}
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	if !storedToken.IsValid() {
		return nil, session.ErrRefreshTokenRevoked
	}

	// Get the session
	sess, err := s.sessionRepo.GetByID(ctx, storedToken.SessionID())
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	if !sess.IsActive() {
		return nil, session.ErrSessionExpired
	}

	// Get user
	userID, err := shared.IDFromString(claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user id in token: %w", err)
	}

	u, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Check if user already has tenants
	existingMemberships, err := s.tenantRepo.GetUserMemberships(ctx, u.ID())
	if err != nil {
		return nil, fmt.Errorf("failed to check existing memberships: %w", err)
	}
	if len(existingMemberships) > 0 {
		return nil, fmt.Errorf("%w: user already has teams, use regular create team API", shared.ErrValidation)
	}

	// Validate slug format
	if !tenant.IsValidSlug(input.TeamSlug) {
		return nil, fmt.Errorf("%w: invalid slug format (use lowercase letters, numbers, and hyphens)", shared.ErrValidation)
	}

	// Check if slug already exists
	slugExists, err := s.tenantRepo.ExistsBySlug(ctx, input.TeamSlug)
	if err != nil {
		return nil, fmt.Errorf("failed to check slug existence: %w", err)
	}
	if slugExists {
		return nil, fmt.Errorf("%w: team URL '%s' is already taken", shared.ErrValidation, input.TeamSlug)
	}

	// Create tenant
	newTenant, err := tenant.NewTenant(input.TeamName, input.TeamSlug, u.ID().String())
	if err != nil {
		return nil, fmt.Errorf("failed to create tenant: %w", err)
	}

	if err := s.tenantRepo.Create(ctx, newTenant); err != nil {
		return nil, fmt.Errorf("failed to save tenant: %w", err)
	}

	// Create owner membership
	membership, err := tenant.NewOwnerMembership(u.ID(), newTenant.ID())
	if err != nil {
		_ = s.tenantRepo.Delete(ctx, newTenant.ID())
		return nil, fmt.Errorf("failed to create membership: %w", err)
	}

	if err := s.tenantRepo.CreateMembership(ctx, membership); err != nil {
		_ = s.tenantRepo.Delete(ctx, newTenant.ID())
		return nil, fmt.Errorf("failed to save membership: %w", err)
	}

	s.logger.Info("first team created",
		"user_id", u.ID().String(),
		"tenant_id", newTenant.ID().String(),
		"tenant_name", newTenant.Name(),
	)

	// Mark old refresh token as used (token rotation)
	if err := storedToken.MarkUsed(); err != nil {
		s.logger.Error("failed to mark refresh token as used", "error", err)
	} else {
		if err := s.refreshTokenRepo.Update(ctx, storedToken); err != nil {
			s.logger.Error("failed to update refresh token", "error", err)
		}
	}

	// Generate new refresh token
	newRefreshTokenStr, _, err := s.tokenGenerator.GenerateGlobalRefreshToken(
		u.ID().String(),
		u.Email(),
		u.Name(),
		sess.ID().String(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Save new refresh token
	newRefreshToken, err := session.NewRefreshTokenInFamily(
		u.ID(),
		sess.ID(),
		newRefreshTokenStr,
		storedToken.Family(),
		s.config.RefreshTokenDuration,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token: %w", err)
	}
	if err := s.refreshTokenRepo.Create(ctx, newRefreshToken); err != nil {
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	// Generate tenant-scoped access token (with database-driven permissions if available)
	// Owner gets isAdmin=true to bypass permission checks and keep JWT small (< 4KB cookie limit)
	accessToken, err := s.generateTenantScopedAccessToken(
		ctx,
		u.ID().String(),
		u.Email(),
		u.Name(),
		sess.ID().String(),
		jwt.TenantMembership{
			TenantID:   newTenant.ID().String(),
			TenantSlug: newTenant.Slug(),
			Role:       tenant.RoleOwner.String(),
		},
		true, // Owner is always admin - bypasses permission checks, keeps JWT small
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	return &CreateFirstTeamResult{
		AccessToken:  accessToken.AccessToken,
		RefreshToken: newRefreshTokenStr,
		ExpiresAt:    accessToken.ExpiresAt,
		Tenant: TenantMembershipInfo{
			TenantID:   newTenant.ID().String(),
			TenantSlug: newTenant.Slug(),
			TenantName: newTenant.Name(),
			Role:       tenant.RoleOwner.String(),
		},
	}, nil
}

// AcceptInvitationWithRefreshTokenInput represents the input for accepting an invitation.
type AcceptInvitationWithRefreshTokenInput struct {
	RefreshToken    string `json:"refresh_token" validate:"required"`
	InvitationToken string `json:"invitation_token" validate:"required"`
}

// AcceptInvitationWithRefreshTokenResult represents the result of accepting an invitation.
type AcceptInvitationWithRefreshTokenResult struct {
	AccessToken  string               `json:"access_token"`
	RefreshToken string               `json:"refresh_token"` // Rotated refresh token
	ExpiresAt    time.Time            `json:"expires_at"`
	Tenant       TenantMembershipInfo `json:"tenant"`
	Role         string               `json:"role"`
}

// AcceptInvitationWithRefreshToken accepts an invitation using a refresh token.
// This endpoint is for users who were invited but don't have a tenant yet,
// so they only have a refresh token (no access token).
func (s *AuthService) AcceptInvitationWithRefreshToken(ctx context.Context, input AcceptInvitationWithRefreshTokenInput) (*AcceptInvitationWithRefreshTokenResult, error) {
	// Validate the refresh token JWT
	claims, err := s.tokenGenerator.ValidateRefreshToken(input.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Verify refresh token exists in database
	tokenHash := session.HashToken(input.RefreshToken)
	storedToken, err := s.refreshTokenRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, session.ErrRefreshTokenNotFound) {
			return nil, session.ErrRefreshTokenNotFound
		}
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	if !storedToken.IsValid() {
		return nil, session.ErrRefreshTokenRevoked
	}

	// Get the session
	sess, err := s.sessionRepo.GetByID(ctx, storedToken.SessionID())
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	if !sess.IsActive() {
		return nil, session.ErrSessionExpired
	}

	// Get user
	userID, err := shared.IDFromString(claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user id in token: %w", err)
	}

	u, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Get the invitation by token
	invitation, err := s.tenantRepo.GetInvitationByToken(ctx, input.InvitationToken)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil, fmt.Errorf("%w: invitation not found or expired", shared.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get invitation: %w", err)
	}

	// Verify the invitation is for this user's email (case-insensitive)
	if !strings.EqualFold(invitation.Email(), u.Email()) {
		return nil, fmt.Errorf("%w: this invitation was sent to a different email address", shared.ErrValidation)
	}

	if !invitation.IsPending() {
		if invitation.IsExpired() {
			return nil, fmt.Errorf("%w: invitation has expired", shared.ErrValidation)
		}
		if invitation.IsAccepted() {
			return nil, fmt.Errorf("%w: invitation has already been accepted", shared.ErrValidation)
		}
	}

	// Check if user is already a member
	_, err = s.tenantRepo.GetMembership(ctx, u.ID(), invitation.TenantID())
	if err == nil {
		return nil, fmt.Errorf("%w: you are already a member of this team", shared.ErrValidation)
	}
	if !errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("failed to check membership: %w", err)
	}

	// Accept the invitation
	if err := invitation.Accept(); err != nil {
		return nil, err
	}

	// Create membership
	invitedBy := invitation.InvitedBy()
	membership, err := tenant.NewMembership(u.ID(), invitation.TenantID(), invitation.Role(), &invitedBy)
	if err != nil {
		return nil, err
	}

	// Use transaction to ensure atomicity
	if err := s.tenantRepo.AcceptInvitationTx(ctx, invitation, membership); err != nil {
		return nil, fmt.Errorf("failed to accept invitation: %w", err)
	}

	// Get the tenant info
	t, err := s.tenantRepo.GetByID(ctx, invitation.TenantID())
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}

	s.logger.Info("invitation accepted with refresh token",
		"invitation_id", invitation.ID().String(),
		"user_id", u.ID().String(),
		"tenant_id", t.ID().String(),
	)

	// Mark old refresh token as used (token rotation)
	if err := storedToken.MarkUsed(); err != nil {
		s.logger.Error("failed to mark refresh token as used", "error", err)
	} else {
		if err := s.refreshTokenRepo.Update(ctx, storedToken); err != nil {
			s.logger.Error("failed to update refresh token", "error", err)
		}
	}

	// Generate new refresh token
	newRefreshTokenStr, _, err := s.tokenGenerator.GenerateGlobalRefreshToken(
		u.ID().String(),
		u.Email(),
		u.Name(),
		sess.ID().String(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Save new refresh token
	newRefreshToken, err := session.NewRefreshTokenInFamily(
		u.ID(),
		sess.ID(),
		newRefreshTokenStr,
		storedToken.Family(),
		s.config.RefreshTokenDuration,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token: %w", err)
	}
	if err := s.refreshTokenRepo.Create(ctx, newRefreshToken); err != nil {
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	// Determine if user is admin (only owner/admin bypass permissions)
	isAdminRole := membership.Role() == tenant.RoleOwner || membership.Role() == tenant.RoleAdmin

	// Generate tenant-scoped access token
	accessToken, err := s.generateTenantScopedAccessToken(
		ctx,
		u.ID().String(),
		u.Email(),
		u.Name(),
		sess.ID().String(),
		jwt.TenantMembership{
			TenantID:   t.ID().String(),
			TenantSlug: t.Slug(),
			Role:       membership.Role().String(),
		},
		isAdminRole,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	return &AcceptInvitationWithRefreshTokenResult{
		AccessToken:  accessToken.AccessToken,
		RefreshToken: newRefreshTokenStr,
		ExpiresAt:    accessToken.ExpiresAt,
		Tenant: TenantMembershipInfo{
			TenantID:   t.ID().String(),
			TenantSlug: t.Slug(),
			TenantName: t.Name(),
			Role:       membership.Role().String(),
		},
		Role: membership.Role().String(),
	}, nil
}

// generateTenantScopedAccessToken generates an access token for a user in a tenant.
// If roleService is available and user has roles in user_roles table, it fetches permissions from the database.
// Otherwise, it falls back to hardcoded role-permission mappings based on membership.Role.
func (s *AuthService) generateTenantScopedAccessToken(
	ctx context.Context,
	userID, email, name, sessionID string,
	membership jwt.TenantMembership,
	isAdmin bool,
) (*jwt.TenantScopedAccessToken, error) {
	// If roleService is available, try to get permissions from database
	if s.roleService != nil {
		permissions, err := s.roleService.GetUserPermissions(ctx, membership.TenantID, userID)
		//nolint:gocritic // if-else chain is clearer for error handling with fallthrough
		if err != nil {
			s.logger.Warn("failed to get user permissions from database, falling back to role mapping",
				"error", err,
				"user_id", userID,
				"tenant_id", membership.TenantID,
			)
			// Fall through to use hardcoded mapping
		} else if len(permissions) > 0 {
			// Only use database permissions if we actually have some
			// Get user's roles for JWT claims
			roles, err := s.roleService.GetUserRoles(ctx, membership.TenantID, userID)
			if err != nil {
				s.logger.Warn("failed to get user roles",
					"error", err,
					"user_id", userID,
					"tenant_id", membership.TenantID,
				)
			}

			var roleSlugs []string
			for _, r := range roles {
				roleSlugs = append(roleSlugs, r.Slug()) // Use Slug() for lowercase (owner, admin, member, viewer)
			}

			// Use the first role slug for backward compatibility
			// Frontend expects lowercase: 'owner', 'admin', 'member', 'viewer'
			if len(roleSlugs) > 0 {
				membership.Role = roleSlugs[0]
			}

			s.logger.Debug("using database permissions",
				"user_id", userID,
				"tenant_id", membership.TenantID,
				"permissions_count", len(permissions),
				"roles", roleSlugs,
			)

			return s.tokenGenerator.GenerateTenantScopedAccessTokenWithPermissions(
				userID, email, name, sessionID,
				membership,
				permissions,
				roleSlugs,
				isAdmin,
			)
		} else {
			s.logger.Debug("no permissions found in database, falling back to role mapping",
				"user_id", userID,
				"tenant_id", membership.TenantID,
				"role", membership.Role,
			)
		}
	}

	// Fallback to hardcoded role-permission mapping
	s.logger.Debug("using hardcoded role-permission mapping",
		"user_id", userID,
		"tenant_id", membership.TenantID,
		"role", membership.Role,
	)
	return s.tokenGenerator.GenerateTenantScopedAccessToken(
		userID, email, name, sessionID,
		membership,
		isAdmin,
	)
}

// GenerateWSToken generates a short-lived token for WebSocket authentication.
// This is needed because WebSocket connections cannot use httpOnly cookies
// when the connection is cross-origin (different port in development).
// The token is valid for 30 seconds - just enough time to establish the connection.
func (s *AuthService) GenerateWSToken(ctx context.Context, userID, tenantID string) (string, error) {
	return s.tokenGenerator.GenerateShortLivedToken(userID, tenantID, 30*time.Second)
}
