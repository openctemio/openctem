package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/password"
)

// The web states the password rules and the reset-link lifetime from this
// response only, so it must report exactly what the server enforces.
func TestAuthProvidersHandler_PasswordPolicy(t *testing.T) {
	cfg := config.AuthConfig{
		PasswordMinLength:      14,
		PasswordRequireUpper:   true,
		PasswordRequireLower:   true,
		PasswordRequireNumber:  false,
		PasswordRequireSpecial: true,
		PasswordResetDuration:  90 * time.Minute,
	}
	h := NewAuthProvidersHandler(config.OAuthConfig{}, config.EntraSSOConfig{}, false, logger.NewNop()).
		WithPasswordPolicy(cfg)

	rec := httptest.NewRecorder()
	h.GetProviders(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/providers", nil))

	var resp AuthProvidersResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	want := PasswordPolicyInfo{
		MinLength:             14,
		RequireUppercase:      true,
		RequireLowercase:      true,
		RequireNumber:         false,
		RequireSpecial:        true,
		ResetLinkValidMinutes: 90,
	}
	if resp.PasswordPolicy != want {
		t.Fatalf("password_policy = %+v, want %+v", resp.PasswordPolicy, want)
	}
}

func TestPasswordPolicyFromConfig_DefaultMinimum(t *testing.T) {
	got := PasswordPolicyFromConfig(config.AuthConfig{PasswordResetDuration: time.Hour})
	if got.MinLength != password.MinLengthDefault {
		t.Fatalf("min_length = %d, want the enforced default %d", got.MinLength, password.MinLengthDefault)
	}
	if got.ResetLinkValidMinutes != 60 {
		t.Fatalf("reset_link_valid_minutes = %d, want 60", got.ResetLinkValidMinutes)
	}
}
