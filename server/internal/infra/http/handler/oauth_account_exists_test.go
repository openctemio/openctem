package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/config"
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

// The linking refusals of Account > Security are coded 4xx answers.
func TestIdentityLinkErrorsAreCoded(t *testing.T) {
	h := &OAuthHandler{logger: logger.NewNop()}
	for err, want := range map[error]struct {
		status int
		code   string
	}{
		auth.ErrIdentityLinkedElsewhere: {http.StatusConflict, "IDENTITY_LINKED_ELSEWHERE"},
		auth.ErrProviderAlreadyLinked:   {http.StatusConflict, "PROVIDER_ALREADY_LINKED"},
		auth.ErrLastSignInMethod:        {http.StatusConflict, "LAST_SIGN_IN_METHOD"},
		auth.ErrIdentityNotUnlinkable:   {http.StatusConflict, "IDENTITY_MANAGED_BY_ORGANIZATION"},
		auth.ErrIdentityNotFound:        {http.StatusNotFound, "IDENTITY_NOT_FOUND"},
		auth.ErrInvalidState:            {http.StatusBadRequest, "OAUTH_INVALID_STATE"},
	} {
		rec := httptest.NewRecorder()
		h.handleOAuthError(rec, fmt.Errorf("wrapped: %w", err))
		var body struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != want.status || body.Code != want.code {
			t.Errorf("%v: got %d %q, want %d %q", err, rec.Code, body.Code, want.status, want.code)
		}
	}
}

// A refused sign-in that left a pending link answers the same 409. The
// secret goes only into an HttpOnly cookie; the body says only that a link is
// pending.
func TestOAuthCallback_AccountExistsCarriesPendingLink(t *testing.T) {
	for _, secure := range []bool{true, false} {
		h := &OAuthHandler{logger: logger.NewNop(), authConfig: config.AuthConfig{CookieSecure: secure}}
		rec := httptest.NewRecorder()
		h.handleOAuthError(rec, fmt.Errorf("failed to find or create user: %w",
			&auth.PendingLinkError{Token: "secret-1", Provider: auth.OAuthProviderGoogle}))
		if rec.Code != http.StatusConflict {
			t.Fatalf("status %d, want 409", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "secret-1") {
			t.Fatalf("the secret reached the body: %s", rec.Body.String())
		}
		var body struct {
			Code    string             `json:"code"`
			Details PendingLinkDetails `json:"details"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Code != "OAUTH_ACCOUNT_EXISTS" || !body.Details.LinkPending || body.Details.Provider != "google" {
			t.Fatalf("got %s", rec.Body.String())
		}
		cookies := rec.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("want one cookie, got %v", cookies)
		}
		c := cookies[0]
		wantName := "oauth_pending_link"
		if secure {
			wantName = "__Host-oauth_pending_link"
		}
		if c.Name != wantName || c.Value != "secret-1" || !c.HttpOnly || c.Secure != secure ||
			c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.MaxAge != 600 || c.Domain != "" {
			t.Fatalf("cookie %+v", c)
		}
	}
}

// The pending-link routes read the secret from the cookie only: a body or
// query token is ignored.
func TestPendingLink_SecretFromCookieOnly(t *testing.T) {
	h := &OAuthHandler{logger: logger.NewNop(), authConfig: config.AuthConfig{CookieSecure: true}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/pending-sign-in-link/describe?token=secret-1",
		strings.NewReader(`{"token":"secret-1"}`))
	rec := httptest.NewRecorder()
	if _, ok := h.pendingLinkToken(rec, req); ok || rec.Code != http.StatusBadRequest {
		t.Fatalf("token taken from outside the cookie: %d", rec.Code)
	}
	req.AddCookie(&http.Cookie{Name: "oauth_pending_link", Value: "plain"}) // not the __Host- name
	rec = httptest.NewRecorder()
	if _, ok := h.pendingLinkToken(rec, req); ok {
		t.Fatal("accepted the cookie without the __Host- prefix on a Secure deployment")
	}
	req.AddCookie(&http.Cookie{Name: "__Host-oauth_pending_link", Value: "secret-1"})
	if tok, ok := h.pendingLinkToken(httptest.NewRecorder(), req); !ok || tok != "secret-1" {
		t.Fatalf("got %q %v", tok, ok)
	}
}

// The pending-link refusals have their own codes, never a 500.
func TestPendingLinkErrorCodes(t *testing.T) {
	h := &OAuthHandler{logger: logger.NewNop()}
	for err, want := range map[error]struct {
		status int
		code   string
	}{
		auth.ErrPendingLinkInvalid:     {http.StatusNotFound, "PENDING_LINK_INVALID"},
		auth.ErrPendingLinkNeedsSignIn: {http.StatusForbidden, "PENDING_LINK_SIGN_IN_REQUIRED"},
	} {
		rec := httptest.NewRecorder()
		h.handleOAuthError(rec, err)
		var body struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != want.status || body.Code != want.code {
			t.Fatalf("%v: %d %s", err, rec.Code, body.Code)
		}
	}
}

// A social sign-in on an identity the organization's single sign-on manages
// is a 409 with its own code, so the page can point at the organization sign-in.
func TestOAuthCallback_UseOrgSSOIs409(t *testing.T) {
	h := &OAuthHandler{logger: logger.NewNop()}
	rec := httptest.NewRecorder()
	h.handleOAuthError(rec, fmt.Errorf("failed to find or create user: %w", auth.ErrOAuthUseOrgSSO))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409", rec.Code)
	}
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Code != "OAUTH_USE_ORG_SSO" || body.Message != "This account signs in through your organization. Use your organization's sign-in." {
		t.Fatalf("got %+v", body)
	}
}
