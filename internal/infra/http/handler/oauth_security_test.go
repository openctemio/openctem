package handler

import (
	"testing"

	"github.com/openctemio/api/internal/config"
)

func TestOAuthRedirectValidation(t *testing.T) {
	// Handler with FrontendCallbackURL configured
	h := &OAuthHandler{
		oauthConfig: config.OAuthConfig{
			FrontendCallbackURL: "https://app.example.com/auth/callback",
		},
	}

	tests := []struct {
		name    string
		url     string
		allowed bool
	}{
		// Valid redirects (same origin as FrontendCallbackURL)
		{
			name:    "matching origin with path",
			url:     "https://app.example.com/callback",
			allowed: true,
		},
		{
			name:    "matching origin different path",
			url:     "https://app.example.com/dashboard",
			allowed: true,
		},
		{
			name:    "empty string is allowed",
			url:     "",
			allowed: true,
		},

		// Invalid redirects
		{
			name:    "different host",
			url:     "https://evil.com/steal",
			allowed: false,
		},
		{
			name:    "javascript scheme",
			url:     "javascript:alert(1)",
			allowed: false,
		},
		{
			name:    "ftp scheme",
			url:     "ftp://example.com/file",
			allowed: false,
		},
		{
			name:    "data URI",
			url:     "data:text/html,<script>alert(1)</script>",
			allowed: false,
		},
		{
			name:    "different subdomain",
			url:     "https://evil.example.com/callback",
			allowed: false,
		},
		{
			name:    "http when frontend is https",
			url:     "http://app.example.com/callback",
			allowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := h.isRedirectAllowed(tt.url)
			if got != tt.allowed {
				t.Errorf("isRedirectAllowed(%q) = %v, want %v", tt.url, got, tt.allowed)
			}
		})
	}
}

func TestOAuthRedirectValidation_AllowedRedirectURLs(t *testing.T) {
	// Handler with explicit AllowedRedirectURLs list
	h := &OAuthHandler{
		oauthConfig: config.OAuthConfig{
			FrontendCallbackURL: "https://app.example.com/auth/callback",
			AllowedRedirectURLs: []string{
				"https://app.example.com",
				"https://staging.example.com",
			},
		},
	}

	tests := []struct {
		name    string
		url     string
		allowed bool
	}{
		{
			name:    "URL matching first allowed origin",
			url:     "https://app.example.com/callback",
			allowed: true,
		},
		{
			name:    "URL matching second allowed origin",
			url:     "https://staging.example.com/callback",
			allowed: true,
		},
		{
			name:    "URL not in allowed list",
			url:     "https://evil.com/steal",
			allowed: false,
		},
		{
			name:    "empty string is allowed",
			url:     "",
			allowed: true,
		},
		{
			name:    "javascript scheme rejected",
			url:     "javascript:alert(1)",
			allowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := h.isRedirectAllowed(tt.url)
			if got != tt.allowed {
				t.Errorf("isRedirectAllowed(%q) = %v, want %v", tt.url, got, tt.allowed)
			}
		})
	}
}

func TestOAuthRedirectValidation_NoFrontendURL(t *testing.T) {
	// Handler with no FrontendCallbackURL and no AllowedRedirectURLs
	h := &OAuthHandler{
		oauthConfig: config.OAuthConfig{},
	}

	tests := []struct {
		name    string
		url     string
		allowed bool
	}{
		{
			name:    "empty string is allowed",
			url:     "",
			allowed: true,
		},
		{
			name:    "any URL rejected when no frontend configured",
			url:     "https://example.com/callback",
			allowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := h.isRedirectAllowed(tt.url)
			if got != tt.allowed {
				t.Errorf("isRedirectAllowed(%q) = %v, want %v", tt.url, got, tt.allowed)
			}
		})
	}
}
