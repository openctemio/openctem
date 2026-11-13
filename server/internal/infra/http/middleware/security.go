package middleware

import (
	"fmt"
	"net/http"
)

// SecurityHeadersConfig configures security headers.
type SecurityHeadersConfig struct {
	// HSTSEnabled enables HTTP Strict Transport Security.
	// Should be true in production with HTTPS.
	HSTSEnabled bool
	// HSTSMaxAge is the max-age for HSTS in seconds (default: 1 year).
	HSTSMaxAge int
	// HSTSIncludeSubdomains includes subdomains in HSTS.
	HSTSIncludeSubdomains bool
}

// SecurityHeaders adds security-related HTTP headers.
func SecurityHeaders() func(http.Handler) http.Handler {
	return SecurityHeadersWithConfig(SecurityHeadersConfig{})
}

// SecurityHeadersWithConfig adds security headers with custom configuration.
func SecurityHeadersWithConfig(cfg SecurityHeadersConfig) func(http.Handler) http.Handler {
	// Set defaults
	if cfg.HSTSMaxAge == 0 {
		cfg.HSTSMaxAge = 31536000 // 1 year
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Prevent MIME type sniffing
			w.Header().Set("X-Content-Type-Options", "nosniff")

			// Prevent clickjacking
			w.Header().Set("X-Frame-Options", "DENY")

			// Enable XSS filter
			w.Header().Set("X-XSS-Protection", "1; mode=block")

			// Referrer policy
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

			// Content Security Policy (API-friendly)
			w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

			// Permissions Policy
			w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

			// HTTP Strict Transport Security (HSTS)
			// Only send if enabled (should be enabled in production with HTTPS)
			if cfg.HSTSEnabled {
				hstsValue := fmt.Sprintf("max-age=%d", cfg.HSTSMaxAge)
				if cfg.HSTSIncludeSubdomains {
					hstsValue += "; includeSubDomains"
				}
				w.Header().Set("Strict-Transport-Security", hstsValue)
			}

			// Cache control for API responses
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")

			next.ServeHTTP(w, r)
		})
	}
}
