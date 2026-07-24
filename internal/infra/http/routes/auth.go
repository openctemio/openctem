package routes

import (
	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/logger"
)

// registerAuthRoutes registers authentication endpoints based on provider.
func registerAuthRoutes(router Router, h Handlers, cfg *config.Config, authCfg AuthConfig, authMiddleware Middleware, log *logger.Logger) {
	// Create auth-specific rate limiter for brute-force protection
	// SECURITY: These endpoints are critical attack vectors and need stricter limits
	authRateLimiter := middleware.NewAuthRateLimiter(middleware.DefaultAuthRateLimitConfig(), nil)
	loginRL := authRateLimiter.LoginMiddleware()
	registerRL := authRateLimiter.RegisterMiddleware()
	passwordRL := authRateLimiter.PasswordMiddleware()
	tokenExchangeRL := authRateLimiter.TokenExchangeMiddleware()

	// Public login-capability snapshot: tells the UI which social buttons (and
	// the Entra SSO env fallback) are actually configured, so it can hide dead
	// affordances. Always available (unlike /oauth/providers, which only exists
	// when the OAuth handler is wired), tenant-agnostic, and booleans only —
	// no secrets. Rate-limited like the other public auth reads.
	authProvidersHandler := handler.NewAuthProvidersHandler(cfg.OAuth, cfg.Auth.EntraSSO, log)

	// Public auth routes
	router.Group("/api/v1/auth", func(r Router) {
		// Login-provider capability snapshot (public, no auth)
		providersHandler := ChainFunc(authProvidersHandler.GetProviders, loginRL)
		r.GET("/providers", providersHandler.ServeHTTP)

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

			// Token operations - separate rate limit (20/min)
			// Token exchange requires valid refresh token, not brute-forceable
			// Used for tenant switching which may happen frequently
			tokenHandler := ChainFunc(h.LocalAuth.ExchangeToken, tokenExchangeRL)
			r.POST("/token", tokenHandler.ServeHTTP)

			refreshHandler := ChainFunc(h.LocalAuth.RefreshToken, tokenExchangeRL)
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

		// Per-tenant SSO endpoints (public, rate limited)
		if h.SSO != nil {
			// SECURITY: Rate limit all public SSO endpoints to prevent enumeration
			ssoProvidersHandler := ChainFunc(h.SSO.ListTenantProviders, loginRL)
			r.GET("/sso/providers", ssoProvidersHandler.ServeHTTP)
			ssoAuthorizeHandler := ChainFunc(h.SSO.Authorize, loginRL)
			r.GET("/sso/{provider}/authorize", ssoAuthorizeHandler.ServeHTTP)
			ssoCallbackHandler := ChainFunc(h.SSO.Callback, loginRL)
			r.POST("/sso/{provider}/callback", ssoCallbackHandler.ServeHTTP)
		}

		// SAML 2.0 SP endpoints (public). Metadata is registered with the IdP;
		// login starts SP-initiated auth; ACS receives the IdP's signed response.
		if h.SAML != nil {
			samlMetadata := ChainFunc(h.SAML.Metadata, loginRL)
			r.GET("/saml/{org}/metadata", samlMetadata.ServeHTTP)
			samlLogin := ChainFunc(h.SAML.Login, loginRL)
			r.GET("/saml/{org}/login", samlLogin.ServeHTTP)
			// ACS is a cross-site top-level POST from the IdP — it carries the
			// signed SAML assertion (validated server-side), not a CSRF-token
			// form, so it must not sit behind the CSRF middleware.
			samlACS := ChainFunc(h.SAML.ACS, loginRL)
			r.POST("/saml/{org}/acs", samlACS.ServeHTTP)
		}
	})
}

// registerSAMLAdminRoutes registers admin endpoints for a tenant's SAML config.
func registerSAMLAdminRoutes(
	router Router,
	h *handler.SAMLHandler,
	authMiddleware, userSyncMiddleware Middleware,
) {
	if h == nil {
		return
	}
	middlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
	router.Group("/api/v1/settings/saml", func(r Router) {
		r.GET("/", h.GetConfig, middleware.RequireAdmin())
		r.PUT("/", h.SetConfig, middleware.RequireAdmin())
		r.DELETE("/", h.DeleteConfig, middleware.RequireAdmin())
	}, middlewares...)
}

// registerSSOAdminRoutes registers admin endpoints for managing tenant SSO identity providers.
func registerSSOAdminRoutes(
	router Router,
	h *handler.SSOHandler,
	authMiddleware, userSyncMiddleware Middleware,
) {
	middlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	router.Group("/api/v1/settings/identity-providers", func(r Router) {
		// All SSO admin operations require admin+ (configs contain sensitive client IDs).
		// These routes use the JWT-tenant chain (buildTokenTenantMiddlewares), which
		// populates the JWT-derived role/IsAdmin context — NOT the URL-path "team_role"
		// that RequireTeamAdmin reads. Using RequireTeamAdmin here 403'd every caller
		// (incl. owners/admins); RequireAdmin reads the JWT IsAdmin flag.
		r.GET("/", h.ListProviders, middleware.RequireAdmin())
		r.POST("/", h.CreateProvider, middleware.RequireAdmin())
		r.GET("/{id}", h.GetProvider, middleware.RequireAdmin())
		r.PUT("/{id}", h.UpdateProvider, middleware.RequireAdmin())
		r.DELETE("/{id}", h.DeleteProvider, middleware.RequireAdmin())
	}, middlewares...)
}

// registerVerifiedDomainRoutes registers admin endpoints for managing a
// tenant's DNS-verified domains (SSO P1). These gate SSO JIT auto-provisioning,
// so all operations require admin+. Uses the JWT-tenant chain — RequireAdmin
// reads the JWT IsAdmin flag (see registerSSOAdminRoutes for why not
// RequireTeamAdmin).
func registerVerifiedDomainRoutes(
	router Router,
	h *handler.VerifiedDomainHandler,
	authMiddleware, userSyncMiddleware Middleware,
) {
	if h == nil {
		return
	}
	middlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
	router.Group("/api/v1/settings/verified-domains", func(r Router) {
		r.GET("/", h.List, middleware.RequireAdmin())
		r.POST("/", h.AddDomain, middleware.RequireAdmin())
		r.POST("/{id}/verify", h.Verify, middleware.RequireAdmin())
		r.DELETE("/{id}", h.Delete, middleware.RequireAdmin())
	}, middlewares...)
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
		r.GET("/me/preferences", h.GetPreferences)
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
