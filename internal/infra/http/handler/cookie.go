package handler

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/api/internal/config"
)

// TenantCookieData represents the tenant info stored in cookie.
// This is read by frontend to know which tenant user is currently in.
type TenantCookieData struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Role string `json:"role"`
}

const (
	// DefaultTenantCookieName is the default name of the cookie storing the current tenant ID.
	// This is NOT httpOnly because frontend needs to read it.
	DefaultTenantCookieName = "app_tenant"
)

// CookieConfig holds cookie configuration for authentication.
type CookieConfig struct {
	Secure                 bool
	Domain                 string
	SameSite               http.SameSite
	Path                   string
	AccessTokenCookieName  string // Configurable access token cookie name
	RefreshTokenCookieName string // Configurable refresh token cookie name
	TenantCookieName       string // Configurable tenant cookie name
}

// NewCookieConfig creates a CookieConfig from AuthConfig.
func NewCookieConfig(cfg config.AuthConfig) CookieConfig {
	sameSite := http.SameSiteLaxMode
	switch strings.ToLower(cfg.CookieSameSite) {
	case "strict":
		sameSite = http.SameSiteStrictMode
	case "none":
		sameSite = http.SameSiteNoneMode
	case "lax":
		sameSite = http.SameSiteLaxMode
	}

	// Use configured cookie name, default to "auth_token" for access token
	accessTokenCookieName := cfg.AccessTokenCookieName
	if accessTokenCookieName == "" {
		accessTokenCookieName = "auth_token"
	}

	// Use configured cookie name, default to "refresh_token" for backward compatibility
	refreshTokenCookieName := cfg.RefreshTokenCookieName
	if refreshTokenCookieName == "" {
		refreshTokenCookieName = "refresh_token"
	}

	// Use configured tenant cookie name, default to "app_tenant"
	tenantCookieName := cfg.TenantCookieName
	if tenantCookieName == "" {
		tenantCookieName = DefaultTenantCookieName
	}

	return CookieConfig{
		Secure:                 cfg.CookieSecure,
		Domain:                 cfg.CookieDomain,
		SameSite:               sameSite,
		Path:                   "/", // Set to root so frontend can clear cookies
		AccessTokenCookieName:  accessTokenCookieName,
		RefreshTokenCookieName: refreshTokenCookieName,
		TenantCookieName:       tenantCookieName,
	}
}

// SetRefreshTokenCookie sets the refresh token in an httpOnly cookie.
// This is more secure than storing in localStorage as it prevents XSS attacks.
func SetRefreshTokenCookie(w http.ResponseWriter, token string, expiresAt time.Time, cfg CookieConfig) {
	cookie := &http.Cookie{
		Name:     cfg.RefreshTokenCookieName,
		Value:    token,
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
		Secure:   cfg.Secure,
		HttpOnly: true, // Prevents JavaScript access - XSS protection
		SameSite: cfg.SameSite,
	}
	http.SetCookie(w, cookie)
}

// ClearRefreshTokenCookie removes the refresh token cookie.
func ClearRefreshTokenCookie(w http.ResponseWriter, cfg CookieConfig) {
	cookie := &http.Cookie{
		Name:     cfg.RefreshTokenCookieName,
		Value:    "",
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   cfg.Secure,
		HttpOnly: true,
		SameSite: cfg.SameSite,
	}
	http.SetCookie(w, cookie)
}

// GetRefreshTokenFromCookie extracts the refresh token from the httpOnly cookie.
// Falls back to request body if cookie is not present (for backward compatibility).
func GetRefreshTokenFromCookie(r *http.Request, cfg CookieConfig) string {
	cookie, err := r.Cookie(cfg.RefreshTokenCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// SetTenantCookie sets the current tenant info as JSON in a cookie.
// This cookie is NOT httpOnly because frontend needs to read it.
// The JSON format matches what frontend TenantProvider expects: {id, slug, role}
func SetTenantCookie(w http.ResponseWriter, tenantID, tenantSlug, role string, cfg CookieConfig) {
	// Create JSON data
	data := TenantCookieData{
		ID:   tenantID,
		Slug: tenantSlug,
		Role: role,
	}
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		// Fallback to just tenant ID if JSON encoding fails
		jsonBytes = []byte(tenantID)
	}

	// URL encode the JSON to ensure it's safe for cookie storage
	encodedValue := url.QueryEscape(string(jsonBytes))

	// 30 days expiration
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	cookie := &http.Cookie{
		Name:     cfg.TenantCookieName,
		Value:    encodedValue,
		Path:     "/", // Available to all paths
		Domain:   cfg.Domain,
		Expires:  expiresAt,
		MaxAge:   int(30 * 24 * time.Hour.Seconds()),
		Secure:   cfg.Secure,
		HttpOnly: false, // Frontend needs to read this
		SameSite: cfg.SameSite,
	}
	http.SetCookie(w, cookie)
}

// ClearTenantCookie removes the tenant cookie.
func ClearTenantCookie(w http.ResponseWriter, cfg CookieConfig) {
	cookie := &http.Cookie{
		Name:     cfg.TenantCookieName,
		Value:    "",
		Path:     "/",
		Domain:   cfg.Domain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   cfg.Secure,
		HttpOnly: false,
		SameSite: cfg.SameSite,
	}
	http.SetCookie(w, cookie)
}

// SetAccessTokenCookie sets the access token in an httpOnly cookie.
// This is used by endpoints that issue access tokens directly (e.g., accept invitation with refresh token).
func SetAccessTokenCookie(w http.ResponseWriter, token string, expiresAt time.Time, cfg CookieConfig) {
	cookie := &http.Cookie{
		Name:     cfg.AccessTokenCookieName,
		Value:    token,
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
		Secure:   cfg.Secure,
		HttpOnly: true, // Prevents JavaScript access - XSS protection
		SameSite: cfg.SameSite,
	}
	http.SetCookie(w, cookie)
}
