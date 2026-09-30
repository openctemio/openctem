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
	// the Entra SSO env fallback) are actually usable, so it can hide dead
	// affordances. Always available (unlike /oauth/providers, which only exists
	// when the OAuth handler is wired), tenant-agnostic, and booleans only —
	// no secrets. Rate-limited like the other public auth reads.
	//
	// oauthRoutesLive is `h.OAuth != nil` — the exact condition that gates the
	// /oauth/* routes below. Passing it here keeps the advertised login surface
	// and the registered login surface identical: configuring OAUTH_* creds
	// without wiring the handler used to make the UI render Google/GitHub
	// buttons whose authorize call 404s.
	oauthRoutesLive := h.OAuth != nil
	authProvidersHandler := handler.NewAuthProvidersHandler(cfg.OAuth, cfg.Auth.EntraSSO, oauthRoutesLive, log).
		WithTenantCreationMode(cfg.Auth.TenantCreationMode)

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

		// OAuth endpoints (social login) - login rate limit.
		// Gated on the same condition reported by /auth/providers above.
		if oauthRoutesLive {
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

			// OIDC Back-Channel Logout 1.0 (public — authenticated by the signed
			// logout_token, NOT a user session; no CSRF, rate-limited). The IdP
			// (e.g. Azure Entra) POSTs form-encoded logout_token here when a user
			// signs out or is disabled, and we revoke the matching session(s).
			ssoBackchannelHandler := ChainFunc(h.SSO.BackChannelLogout, loginRL)
			r.POST("/backchannel-logout", ssoBackchannelHandler.ServeHTTP)
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

// registerSAMLAdminRoutes registers endpoints for a tenant's SAML config.
//
// SSO setup is an APPLICATION-administrator operation, not a tenant one
// (modeled on Tenable Security Center, where SAML lives under system-level
// Configuration). Guarded by RequirePlatformAdmin — the platform-admin flag is
// stamped from PLATFORM_ADMIN_EMAILS (see middleware.IsPlatformAdmin), so a
// tenant owner/admin can no longer configure SSO for their own tenant. Still on
// the JWT-tenant chain so the config resolves against the caller's tenant.
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
		r.GET("/", h.GetConfig, middleware.RequirePlatformAdmin())
		r.PUT("/", h.SetConfig, middleware.RequirePlatformAdmin())
		r.DELETE("/", h.DeleteConfig, middleware.RequirePlatformAdmin())
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
		// SSO identity-provider setup is an application-administrator operation
		// (see registerSAMLAdminRoutes): configs hold sensitive client IDs/secrets
		// and control the tenant's whole login trust. Guarded by
		// RequirePlatformAdmin — the platform-admin flag comes from
		// PLATFORM_ADMIN_EMAILS, not the tenant-level JWT IsAdmin flag, so tenant
		// owners/admins can no longer self-serve SSO. Stays on the JWT-tenant chain
		// so the provider resolves against the caller's tenant.
		r.GET("/", h.ListProviders, middleware.RequirePlatformAdmin())
		r.POST("/", h.CreateProvider, middleware.RequirePlatformAdmin())
		r.GET("/{id}", h.GetProvider, middleware.RequirePlatformAdmin())
		r.PUT("/{id}", h.UpdateProvider, middleware.RequirePlatformAdmin())
		r.DELETE("/{id}", h.DeleteProvider, middleware.RequirePlatformAdmin())
	}, middlewares...)
}

// registerVerifiedDomainRoutes registers endpoints for managing a tenant's
// DNS-verified domains (SSO P1). These gate SSO JIT auto-provisioning and are
// therefore part of SSO setup, so — like the SAML and identity-provider routes
// — they are an application-administrator operation guarded by
// RequirePlatformAdmin (flag from PLATFORM_ADMIN_EMAILS), not tenant admin.
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
		r.GET("/", h.List, middleware.RequirePlatformAdmin())
		r.POST("/", h.AddDomain, middleware.RequirePlatformAdmin())
		r.POST("/{id}/verify", h.Verify, middleware.RequirePlatformAdmin())
		r.DELETE("/{id}", h.Delete, middleware.RequirePlatformAdmin())
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
