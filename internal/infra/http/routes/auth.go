package routes

import (
	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
)

// registerAuthRoutes registers authentication endpoints based on provider.
func registerAuthRoutes(router Router, h Handlers, authCfg AuthConfig, authMiddleware Middleware) {
	// Create auth-specific rate limiter for brute-force protection
	// SECURITY: These endpoints are critical attack vectors and need stricter limits
	authRateLimiter := middleware.NewAuthRateLimiter(middleware.DefaultAuthRateLimitConfig(), nil)
	loginRL := authRateLimiter.LoginMiddleware()
	registerRL := authRateLimiter.RegisterMiddleware()
	passwordRL := authRateLimiter.PasswordMiddleware()

	// Public auth routes
	router.Group("/api/v1/auth", func(r Router) {
		// Provider info endpoint
		if authCfg.Provider.SupportsLocal() && h.LocalAuth != nil {
			r.GET("/info", h.LocalAuth.Info)
		} else if h.Auth != nil {
			r.GET("/info", h.Auth.Info)
		}

		// Local auth endpoints - public (no auth required)
		// SECURITY: Rate limited to prevent brute-force and credential stuffing attacks
		if authCfg.Provider.SupportsLocal() && h.LocalAuth != nil {
			// Registration - strict rate limit (3/min)
			registerHandler := ChainFunc(h.LocalAuth.Register, registerRL)
			r.POST("/register", registerHandler.ServeHTTP)

			// Login - strict rate limit (5/min)
			loginHandler := ChainFunc(h.LocalAuth.Login, loginRL)
			r.POST("/login", loginHandler.ServeHTTP)

			// Token operations - login rate limit
			tokenHandler := ChainFunc(h.LocalAuth.ExchangeToken, loginRL)
			r.POST("/token", tokenHandler.ServeHTTP)

			refreshHandler := ChainFunc(h.LocalAuth.RefreshToken, loginRL)
			r.POST("/refresh", refreshHandler.ServeHTTP)

			// Email verification - password rate limit
			verifyHandler := ChainFunc(h.LocalAuth.VerifyEmail, passwordRL)
			r.POST("/verify-email", verifyHandler.ServeHTTP)

			// Password operations - very strict rate limit (3/min)
			forgotHandler := ChainFunc(h.LocalAuth.ForgotPassword, passwordRL)
			r.POST("/forgot-password", forgotHandler.ServeHTTP)

			resetHandler := ChainFunc(h.LocalAuth.ResetPassword, passwordRL)
			r.POST("/reset-password", resetHandler.ServeHTTP)

			// First team creation - registration rate limit
			firstTeamHandler := ChainFunc(h.LocalAuth.CreateFirstTeam, registerRL)
			r.POST("/create-first-team", firstTeamHandler.ServeHTTP)

			// Protected: logout requires authentication
			logoutHandler := ChainFunc(h.LocalAuth.Logout, authMiddleware)
			r.POST("/logout", logoutHandler.ServeHTTP)

			// Protected: WebSocket token requires authentication
			// This endpoint returns a short-lived token for WebSocket connections
			// when cookies cannot be used (cross-origin development)
			wsTokenHandler := ChainFunc(h.LocalAuth.GetWSToken, authMiddleware)
			r.GET("/ws-token", wsTokenHandler.ServeHTTP)
		}

		// OIDC token endpoint (deprecated - returns Keycloak redirect info)
		if authCfg.Provider.SupportsOIDC() && h.Auth != nil {
			r.POST("/token", h.Auth.GenerateToken)
		}

		// OAuth endpoints (social login) - login rate limit
		if h.OAuth != nil {
			r.GET("/oauth/providers", h.OAuth.ListProviders)
			r.GET("/oauth/{provider}/authorize", h.OAuth.Authorize)
			callbackHandler := ChainFunc(h.OAuth.Callback, loginRL)
			r.POST("/oauth/{provider}/callback", callbackHandler.ServeHTTP)
		}
	})
}

// registerUserRoutes registers user profile management endpoints.
func registerUserRoutes(
	router Router,
	h *handler.UserHandler,
	localAuthHandler *handler.LocalAuthHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	provider config.AuthProvider,
) {
	// Build middleware chain - UserSync for both local and OIDC
	middlewares := []Middleware{authMiddleware}
	if userSyncMiddleware != nil {
		middlewares = append(middlewares, userSyncMiddleware)
	}

	router.Group("/api/v1/users", func(r Router) {
		// Current user profile
		r.GET("/me", h.GetMe)
		r.PUT("/me", h.UpdateMe)
		r.PUT("/me/preferences", h.UpdatePreferences)

		// Current user's tenants/teams
		r.GET("/me/tenants", h.GetMyTenants)

		// Local auth session management
		if provider.SupportsLocal() && localAuthHandler != nil {
			r.POST("/me/change-password", localAuthHandler.ChangePassword)
			r.GET("/me/sessions", localAuthHandler.ListSessions)
			r.DELETE("/me/sessions", localAuthHandler.RevokeAllSessions)
			r.DELETE("/me/sessions/{sessionId}", localAuthHandler.RevokeSession)
		}
	}, middlewares...)
}
