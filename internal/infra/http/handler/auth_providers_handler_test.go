package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/logger"
)

func configuredProvider(id string) config.OAuthProviderConfig {
	return config.OAuthProviderConfig{
		Enabled:      true,
		ClientID:     id + "-client-id",
		ClientSecret: id + "-super-secret-value",
	}
}

func TestAuthProvidersHandler_GetProviders(t *testing.T) {
	tests := []struct {
		name      string
		oauth     config.OAuthConfig
		entra     config.EntraSSOConfig
		wantMS    bool
		wantGoog  bool
		wantGH    bool
		wantEntra bool
	}{
		{
			name:  "all unset -> all false",
			oauth: config.OAuthConfig{},
			entra: config.EntraSSOConfig{},
		},
		{
			name: "each provider configured -> true",
			oauth: config.OAuthConfig{
				Microsoft: configuredProvider("microsoft"),
				Google:    configuredProvider("google"),
				GitHub:    configuredProvider("github"),
			},
			entra: config.EntraSSOConfig{
				Enabled:      true,
				ClientID:     "entra-client-id",
				ClientSecret: "entra-secret",
			},
			wantMS:    true,
			wantGoog:  true,
			wantGH:    true,
			wantEntra: true,
		},
		{
			name: "only google configured",
			oauth: config.OAuthConfig{
				Google: configuredProvider("google"),
			},
			wantGoog: true,
		},
		{
			name: "client_id set but disabled -> false",
			oauth: config.OAuthConfig{
				Microsoft: config.OAuthProviderConfig{
					Enabled:      false,
					ClientID:     "ms-client",
					ClientSecret: "ms-secret",
				},
			},
		},
		{
			name: "enabled but secret missing -> false",
			oauth: config.OAuthConfig{
				GitHub: config.OAuthProviderConfig{
					Enabled:  true,
					ClientID: "gh-client",
				},
			},
			entra: config.EntraSSOConfig{Enabled: true, ClientID: "id"}, // no secret
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := NewAuthProvidersHandler(tc.oauth, tc.entra, logger.NewNop())

			req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/providers", nil)
			rec := httptest.NewRecorder()
			h.GetProviders(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}

			var resp AuthProvidersResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v", err)
			}

			if resp.Social.Microsoft != tc.wantMS {
				t.Errorf("social.microsoft = %v, want %v", resp.Social.Microsoft, tc.wantMS)
			}
			if resp.Social.Google != tc.wantGoog {
				t.Errorf("social.google = %v, want %v", resp.Social.Google, tc.wantGoog)
			}
			if resp.Social.GitHub != tc.wantGH {
				t.Errorf("social.github = %v, want %v", resp.Social.GitHub, tc.wantGH)
			}
			if resp.SSOEnvEntraEnabled != tc.wantEntra {
				t.Errorf("sso_env_entra_enabled = %v, want %v", resp.SSOEnvEntraEnabled, tc.wantEntra)
			}
		})
	}
}

// TestAuthProvidersHandler_NoSecretLeak ensures the response body never
// contains client IDs or secrets — only booleans.
func TestAuthProvidersHandler_NoSecretLeak(t *testing.T) {
	oauth := config.OAuthConfig{
		Microsoft: config.OAuthProviderConfig{
			Enabled:      true,
			ClientID:     "MS_CLIENT_ID_SENTINEL",
			ClientSecret: "MS_SECRET_SENTINEL",
		},
		Google: config.OAuthProviderConfig{
			Enabled:      true,
			ClientID:     "GOOGLE_CLIENT_ID_SENTINEL",
			ClientSecret: "GOOGLE_SECRET_SENTINEL",
		},
		GitHub: config.OAuthProviderConfig{
			Enabled:      true,
			ClientID:     "GITHUB_CLIENT_ID_SENTINEL",
			ClientSecret: "GITHUB_SECRET_SENTINEL",
		},
	}
	entra := config.EntraSSOConfig{
		Enabled:      true,
		ClientID:     "ENTRA_CLIENT_ID_SENTINEL",
		ClientSecret: "ENTRA_SECRET_SENTINEL",
	}

	h := NewAuthProvidersHandler(oauth, entra, logger.NewNop())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/providers", nil)
	rec := httptest.NewRecorder()
	h.GetProviders(rec, req)

	body := rec.Body.String()
	sentinels := []string{
		"MS_CLIENT_ID_SENTINEL", "MS_SECRET_SENTINEL",
		"GOOGLE_CLIENT_ID_SENTINEL", "GOOGLE_SECRET_SENTINEL",
		"GITHUB_CLIENT_ID_SENTINEL", "GITHUB_SECRET_SENTINEL",
		"ENTRA_CLIENT_ID_SENTINEL", "ENTRA_SECRET_SENTINEL",
	}
	for _, s := range sentinels {
		if strings.Contains(body, s) {
			t.Errorf("response leaked credential material %q: %s", s, body)
		}
	}
}
