package middleware

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	// CSRFTokenCookieName is the name of the cookie storing the CSRF token.
	// This cookie is NOT httpOnly so JavaScript can read it.
	CSRFTokenCookieName = "csrf_token"

	// CSRFHeaderName is the header name where the CSRF token should be sent.
	CSRFHeaderName = "X-CSRF-Token"

	// CSRFTokenLength is the length of the CSRF token in bytes.
	CSRFTokenLength = 32
)

// CSRFConfig holds CSRF middleware configuration.
type CSRFConfig struct {
	// Secure sets the Secure flag on the CSRF cookie.
	Secure bool
	// Domain sets the Domain for the CSRF cookie.
	Domain string
	// SameSite sets the SameSite policy.
	SameSite http.SameSite
	// Path sets the cookie path.
	Path string
	// TTL is the token validity period.
	TTL time.Duration
	// Logger for CSRF operations.
	Logger *logger.Logger
}

// NewCSRFConfig creates a CSRFConfig from AuthConfig.
func NewCSRFConfig(cfg config.AuthConfig, log *logger.Logger) CSRFConfig {
	sameSite := http.SameSiteLaxMode
	switch strings.ToLower(cfg.CookieSameSite) {
	case "strict":
		sameSite = http.SameSiteStrictMode
	case "none":
		sameSite = http.SameSiteNoneMode
	case "lax":
		sameSite = http.SameSiteLaxMode
	}

	return CSRFConfig{
		Secure:   cfg.CookieSecure,
		Domain:   cfg.CookieDomain,
		SameSite: sameSite,
		Path:     "/",
		TTL:      cfg.RefreshTokenDuration, // CSRF token lives as long as refresh token
		Logger:   log.With("middleware", "csrf"),
	}
}

// GenerateCSRFToken generates a cryptographically secure CSRF token.
func GenerateCSRFToken() (string, error) {
	b := make([]byte, CSRFTokenLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// SetCSRFTokenCookie sets the CSRF token in a JavaScript-readable cookie.
//
// The cookie is deliberately NOT HttpOnly: this is the double-submit pattern,
// where the frontend reads the cookie and echoes it in the X-CSRF-Token
// header. The token is a random nonce, not a credential — on its own it
// authenticates nothing. Secure follows AUTH_COOKIE_SECURE (true by default
// outside APP_ENV=development, required in production) and SameSite follows
// AUTH_COOKIE_SAMESITE (lax by default).
func SetCSRFTokenCookie(w http.ResponseWriter, token string, cfg CSRFConfig) {
	cookie := &http.Cookie{
		Name:     CSRFTokenCookieName,
		Value:    token,
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		MaxAge:   int(cfg.TTL.Seconds()),
		Secure:   cfg.Secure,
		HttpOnly: false, // Must be readable by JavaScript
		SameSite: cfg.SameSite,
	}
	http.SetCookie(w, cookie)
}

// ClearCSRFTokenCookie removes the CSRF token cookie.
func ClearCSRFTokenCookie(w http.ResponseWriter, cfg CSRFConfig) {
	cookie := &http.Cookie{
		Name:     CSRFTokenCookieName,
		Value:    "",
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		MaxAge:   -1,
		Secure:   cfg.Secure,
		HttpOnly: false,
		SameSite: cfg.SameSite,
	}
	http.SetCookie(w, cookie)
}

// CSRF returns a middleware that validates CSRF tokens using Double Submit Cookie pattern.
// It compares the token in the cookie with the token sent in the X-CSRF-Token header.
// Safe methods (GET, HEAD, OPTIONS) are exempt from CSRF validation.
func CSRF(cfg CSRFConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Safe methods are exempt from CSRF validation
			if isSafeMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}

			// Get CSRF token from cookie
			cookieToken, err := r.Cookie(CSRFTokenCookieName)
			if err != nil || cookieToken.Value == "" {
				cfg.Logger.Debug("CSRF token missing from cookie", "path", RedactPath(r.URL.Path))
				metrics.CSRFRejectionsTotal.WithLabelValues("missing_cookie", r.Method).Inc()
				apierror.Forbidden("CSRF token missing").WriteJSON(w)
				return
			}

			// Get CSRF token from header
			headerToken := r.Header.Get(CSRFHeaderName)
			if headerToken == "" {
				cfg.Logger.Debug("CSRF token missing from header", "path", RedactPath(r.URL.Path))
				metrics.CSRFRejectionsTotal.WithLabelValues("missing_header", r.Method).Inc()
				apierror.Forbidden("CSRF token missing from header").WriteJSON(w)
				return
			}

			// Compare tokens using constant-time comparison to prevent timing attacks
			if subtle.ConstantTimeCompare([]byte(cookieToken.Value), []byte(headerToken)) != 1 {
				cfg.Logger.Warn("CSRF token mismatch",
					"path", RedactPath(r.URL.Path),
					"ip", r.RemoteAddr,
				)
				metrics.CSRFRejectionsTotal.WithLabelValues("token_mismatch", r.Method).Inc()
				apierror.Forbidden("Invalid CSRF token").WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isSafeMethod returns true if the HTTP method is safe (doesn't modify state).
func isSafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

// CSRFOptional is like CSRF but, for a request that was NOT authenticated by
// the auth_token cookie, only validates when a csrf_token cookie is present.
// That keeps header-authenticated clients (Bearer JWT, API keys) working
// without a CSRF token: a cross-site page cannot attach an Authorization
// header, so those requests are not forgeable.
//
// A request authenticated by the auth_token cookie (see UnifiedAuth) is an
// ambient-credential request, and for it this middleware fails closed exactly
// like CSRF: a missing csrf_token cookie is a rejection, not a pass.
func CSRFOptional(cfg CSRFConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Safe methods are exempt
			if isSafeMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}

			cookieAuth := IsCookieAuthenticated(r.Context())

			// Check if CSRF cookie is present
			cookieToken, err := r.Cookie(CSRFTokenCookieName)
			if (err != nil || cookieToken.Value == "") && !cookieAuth {
				// Header-authenticated request without a CSRF cookie: not an
				// ambient-credential request, nothing to validate.
				next.ServeHTTP(w, r)
				return
			}

			if reason := csrfDoubleSubmitFailure(r); reason != "" {
				rejectCSRF(w, r, cfg.Logger, reason)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// cookieAuthKey marks a request whose access token came from the auth_token
// cookie rather than the Authorization header.
const cookieAuthKey logger.ContextKey = "auth_via_cookie"

// withCookieAuth records on the context that the request was authenticated by
// the auth_token cookie.
func withCookieAuth(ctx context.Context) context.Context {
	return context.WithValue(ctx, cookieAuthKey, true)
}

// IsCookieAuthenticated reports whether the request was authenticated by the
// auth_token cookie (an ambient credential) rather than by a header.
func IsCookieAuthenticated(ctx context.Context) bool {
	v, _ := ctx.Value(cookieAuthKey).(bool)
	return v
}

// Reasons a double-submit check fails; also the csrf_rejections_total label.
const (
	csrfReasonMissingCookie = "missing_cookie"
	csrfReasonMissingHeader = "missing_header"
	csrfReasonMismatch      = "token_mismatch"
)

// csrfDoubleSubmitFailure checks the double-submit pair on r and returns the
// metric reason of the failure, or "" when the csrf_token cookie and the
// X-CSRF-Token header are both present and equal.
func csrfDoubleSubmitFailure(r *http.Request) string {
	cookieToken, err := r.Cookie(CSRFTokenCookieName)
	if err != nil || cookieToken.Value == "" {
		return csrfReasonMissingCookie
	}
	headerToken := r.Header.Get(CSRFHeaderName)
	if headerToken == "" {
		return csrfReasonMissingHeader
	}
	if subtle.ConstantTimeCompare([]byte(cookieToken.Value), []byte(headerToken)) != 1 {
		return csrfReasonMismatch
	}
	return ""
}

// CheckDoubleSubmit validates the double-submit pair on r for a handler that
// authenticates the request itself from an ambient cookie (e.g. the
// refresh_token cookie on the auth routes). It writes the 403 and returns
// false when the pair is missing or does not match.
func CheckDoubleSubmit(w http.ResponseWriter, r *http.Request, log *logger.Logger) bool {
	if reason := csrfDoubleSubmitFailure(r); reason != "" {
		rejectCSRF(w, r, log, reason)
		return false
	}
	return true
}

// rejectCSRF writes the 403 for a failed double-submit check and counts it.
func rejectCSRF(w http.ResponseWriter, r *http.Request, log *logger.Logger, reason string) {
	metrics.CSRFRejectionsTotal.WithLabelValues(reason, r.Method).Inc()
	msg := "CSRF token missing"
	switch reason {
	case csrfReasonMissingHeader:
		msg = "CSRF token required in header"
	case csrfReasonMismatch:
		msg = "Invalid CSRF token"
		if log != nil {
			log.Warn("CSRF token mismatch", "path", logSafe(RedactPath(r.URL.Path)), "ip", logSafe(r.RemoteAddr))
		}
	}
	if reason != csrfReasonMismatch && log != nil {
		log.Debug("CSRF check failed", "reason", reason, "path", logSafe(RedactPath(r.URL.Path)))
	}
	apierror.Forbidden(msg).WriteJSON(w)
}
