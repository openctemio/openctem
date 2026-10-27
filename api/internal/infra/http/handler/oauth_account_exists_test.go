package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A social sign-in whose verified email names an account that signs in
// another way answered 500 INTERNAL_ERROR (prod v0.15.3). It is a conflict the
// person can act on: 409 with its own code, never a server error.
func TestOAuthCallback_AccountExistsIs409(t *testing.T) {
	h := &OAuthHandler{logger: logger.NewNop()}
	for name, err := range map[string]error{
		"as returned by the callback": fmt.Errorf("failed to find or create user: %w", auth.ErrOAuthAccountExists),
		"bare":                        auth.ErrOAuthAccountExists,
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.handleOAuthError(rec, err)
			if rec.Code != http.StatusConflict {
				t.Fatalf("status %d, want 409", rec.Code)
			}
			var body struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}
			if jerr := json.Unmarshal(rec.Body.Bytes(), &body); jerr != nil {
				t.Fatalf("body %q: %v", rec.Body.String(), jerr)
			}
			if body.Code != "OAUTH_ACCOUNT_EXISTS" {
				t.Fatalf("code %q, want OAUTH_ACCOUNT_EXISTS", body.Code)
			}
			if body.Message == "" {
				t.Fatal("no English fallback text for API clients")
			}
		})
	}
}

// A provider that sent no email is a 400 with a code, not a 500.
func TestOAuthCallback_NoEmailIs400(t *testing.T) {
	h := &OAuthHandler{logger: logger.NewNop()}
	rec := httptest.NewRecorder()
	h.handleOAuthError(rec, auth.ErrOAuthNoEmail)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	var body struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Code != "OAUTH_NO_EMAIL" {
		t.Fatalf("code %q, want OAUTH_NO_EMAIL", body.Code)
	}
}
