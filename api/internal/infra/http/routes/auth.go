package routes

import (
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// registerAuthRoutes registers authentication endpoints based on provider.
func registerAuthRoutes(router Router, h Handlers, cfg *config.Config, authCfg AuthConfig, authMiddleware, userSyncMiddleware Middleware, log *logger.Logger) {
	// Create auth-specific rate limiter for brute-force protection
	// SECURITY: These endpoints are critical attack vectors and need stricter limits
	authRateLimiter := newAuthRateLimiter("auth")
	loginRL := authRateLimiter.LoginMiddleware()
	registerRL := authRateLimiter.RegisterMiddleware()
	passwordRL := authRateLimiter.PasswordMiddleware()
	tokenExchangeRL := authRateLimiter.TokenExchangeMiddleware()
	mfaRL := authRateLimiter.MFAMiddleware()

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
		WithTenantCreationMode(cfg.Auth.TenantCreationMode).
		WithRegistrationEnabled(cfg.Auth.SelfServiceTenantCreation())
	if h.SignupPolicy != nil {
		authProvidersHandler.WithSignupPolicy(h.SignupPolicy)
	}
	authProvidersHandler.WithCaptchaSiteKey(cfg.Auth.CaptchaTurnstileSiteKey)

	// Public auth routes
	router.Group("/api/v1/auth", func(r Router) {
		// Login-provider capability snapshot (public, no auth). A cheap,
		// cacheable config read the UI makes on many screens: it gets the
		// general API limiter, NOT loginRL (5/min per IP), which it used to
		// share — reading it spent the caller's login budget, so a user who
		// opened a few pages got 429 on the login itself.
		providersHandler := ChainFunc(authProvidersHandler.GetProviders, middleware.RateLimit(&cfg.RateLimit, log))
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
			// Request access (sign-up closed, requests allowed): the
			// registration budget; the service adds per-address and
			// per-domain limits and the optional CAPTCHA.
			if h.AccessRequest != nil {
				r.POST("/access-requests", ChainFunc(h.AccessRequest.Submit, registerRL).ServeHTTP)
				r.POST("/access-requests/confirm", ChainFunc(h.AccessRequest.Confirm, passwordRL).ServeHTTP)
			}

			// Registration - strict rate limit (3/min)
			registerHandler := ChainFunc(h.LocalAuth.Register, registerRL)
			r.POST("/register", registerHandler.ServeHTTP)

			// Login - strict rate limit (5/min)
			loginHandler := ChainFunc(h.LocalAuth.Login, loginRL)
			r.POST("/login", loginHandler.ServeHTTP)

			// Second login step (2FA). Authorized only by the short-lived
			// challenge token a password login returns. Its own buckets (per
			// challenge, and per IP), not the login one: the sign-ins that led
			// here must not use up the code attempts. Guessing is bounded by
			// the challenge's attempt cap and the per-user lockout.
			mfaVerifyHandler := ChainFunc(h.LocalAuth.VerifyMFA, mfaRL)
			r.POST("/mfa/verify", mfaVerifyHandler.ServeHTTP)
			mfaEnrollStartHandler := ChainFunc(h.LocalAuth.StartMFAEnrollment, mfaRL)
			r.POST("/mfa/enroll/start", mfaEnrollStartHandler.ServeHTTP)
			mfaEnrollConfirmHandler := ChainFunc(h.LocalAuth.ConfirmMFAEnrollment, mfaRL)
			r.POST("/mfa/enroll/confirm", mfaEnrollConfirmHandler.ServeHTTP)

			// Token operations - separate rate limit (20/min)
			// Token exchange requires valid refresh token, not brute-forceable
			// Used for tenant switching which may happen frequently.
			// This is the only handler of POST /auth/token, in local and
			// hybrid mode alike: an OIDC access token is verified by the auth
			// middleware on each request and is never exchanged here.
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

			// Step-up re-authentication (docs/architecture/step-up-reauth.md):
			// the signed-in user proves their identity again (TOTP when
			// enrolled, else the password) to open a 10-minute window on this
			// session for sensitive routes (requireStepUp). Its own rate-limit
			// bucket per IP; wrong proofs also count towards the account
			// lockout. CSRF is enforced by authMiddleware for cookie sessions.
			stepUpRL := newAuthRateLimiter("step-up").LoginMiddleware()
			r.GET("/step-up", ChainFunc(h.LocalAuth.GetStepUp, authMiddleware).ServeHTTP)
			r.POST("/step-up", ChainFunc(h.LocalAuth.StepUp, stepUpRL, authMiddleware).ServeHTTP)

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
			// Email-first sign-in: where does this email sign in? Its own
			// budget (20/min per address): it runs on every sign-in, before
			// the password is typed, and must not spend the login budget.
			discoverRL := newAuthRateLimiter("discover").TokenExchangeMiddleware()
			r.POST("/discover", ChainFunc(h.SSO.Discover, discoverRL).ServeHTTP)
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
			// Change-password checks the current password, so it gets the
			// password rate limiter (settings audit A-M2); wrong passwords
			// also count against the account lockout in the service.
			passwordRL := newAuthRateLimiter("account-password")
			r.POST("/me/change-password", localAuthHandler.ChangePassword, passwordRL.PasswordMiddleware())
			r.GET("/me/sessions", localAuthHandler.ListSessions)
			r.DELETE("/me/sessions", localAuthHandler.RevokeAllSessions)
			r.DELETE("/me/sessions/{sessionId}", localAuthHandler.RevokeSession)

			// Two-factor authentication for the signed-in user. Code-checking
			// calls are rate limited like the login and password endpoints;
			// mutating calls also carry the CSRF check.
			mfaRL := newAuthRateLimiter("account-2fa")
			codeRL := mfaRL.LoginMiddleware()
			sensitiveRL := mfaRL.PasswordMiddleware()
			withCSRF := func(rl Middleware) []Middleware {
				if csrfProtectionMiddleware != nil {
					return []Middleware{csrfProtectionMiddleware, rl}
				}
				return []Middleware{rl}
			}
			r.GET("/me/2fa", localAuthHandler.GetMFAStatus)
			r.POST("/me/2fa/setup", localAuthHandler.SetupMFA, withCSRF(codeRL)...)
			r.POST("/me/2fa/enable", localAuthHandler.EnableMFA, withCSRF(codeRL)...)
			r.POST("/me/2fa/disable", localAuthHandler.DisableMFA, withCSRF(sensitiveRL)...)
			r.POST("/me/2fa/recovery-codes", localAuthHandler.RegenerateRecoveryCodes, withCSRF(sensitiveRL)...)
		}
	}, middlewares...)
}
