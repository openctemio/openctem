package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/logger"
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
// This is NOT httpOnly so that frontend JavaScript can read and send it in headers.
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
				cfg.Logger.Debug("CSRF token missing from cookie", "path", r.URL.Path)
				apierror.Forbidden("CSRF token missing").WriteJSON(w)
				return
			}

			// Get CSRF token from header
			headerToken := r.Header.Get(CSRFHeaderName)
			if headerToken == "" {
				cfg.Logger.Debug("CSRF token missing from header", "path", r.URL.Path)
				apierror.Forbidden("CSRF token missing from header").WriteJSON(w)
				return
			}

			// Compare tokens using constant-time comparison to prevent timing attacks
			if subtle.ConstantTimeCompare([]byte(cookieToken.Value), []byte(headerToken)) != 1 {
				cfg.Logger.Warn("CSRF token mismatch",
					"path", r.URL.Path,
					"ip", r.RemoteAddr,
				)
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

// CSRFOptional is like CSRF but only validates if a CSRF cookie is present.
// Useful for endpoints that can be called both with and without cookies.
func CSRFOptional(cfg CSRFConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Safe methods are exempt
			if isSafeMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}

			// Check if CSRF cookie is present
			cookieToken, err := r.Cookie(CSRFTokenCookieName)
			if err != nil || cookieToken.Value == "" {
				// No cookie - skip CSRF validation (likely using token in body)
				next.ServeHTTP(w, r)
				return
			}

			// Cookie present - require header token
			headerToken := r.Header.Get(CSRFHeaderName)
			if headerToken == "" {
				cfg.Logger.Debug("CSRF token missing from header (cookie present)", "path", r.URL.Path)
				apierror.Forbidden("CSRF token required in header").WriteJSON(w)
				return
			}

			// Compare tokens
			if subtle.ConstantTimeCompare([]byte(cookieToken.Value), []byte(headerToken)) != 1 {
				cfg.Logger.Warn("CSRF token mismatch",
					"path", r.URL.Path,
					"ip", r.RemoteAddr,
				)
				apierror.Forbidden("Invalid CSRF token").WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
