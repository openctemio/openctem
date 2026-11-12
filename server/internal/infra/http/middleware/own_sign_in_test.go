package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type stubOwnSignIn struct {
	required bool
	err      error
}

func (s stubOwnSignIn) OwnSignInRequired(context.Context, string, string) (bool, error) {
	return s.required, s.err
}

// An action on the whole account from a session an organization's identity
// provider issued is refused when the account has its own sign-in: that IdP
// would otherwise delete the account or sign it out of every organization.
func TestRequireOwnSignIn(t *testing.T) {
	withSession := func(r *http.Request) *http.Request {
		ctx := context.WithValue(r.Context(), UserIDKey, "u1")
		return r.WithContext(context.WithValue(ctx, SessionIDKey, "s1"))
	}
	cases := []struct {
		name     string
		checker  OwnSignInChecker
		session  bool
		wantCode int
		wantErr  string
	}{
		{"own sign-in passes", stubOwnSignIn{}, true, http.StatusNoContent, ""},
		{"organization IdP session refused", stubOwnSignIn{required: true}, true, http.StatusForbidden, string(CodeOwnSignInRequired)},
		{"failure to decide refused", stubOwnSignIn{err: errors.New("db down")}, true, http.StatusInternalServerError, ""},
		{"no user session refused", stubOwnSignIn{}, false, http.StatusForbidden, string(CodeStepUpUnavailable)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := RequireOwnSignIn(c.checker)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			r := httptest.NewRequest(http.MethodDelete, "/api/v1/me/account/", nil)
			if c.session {
				r = withSession(r)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != c.wantCode {
				t.Fatalf("status = %d, want %d", w.Code, c.wantCode)
			}
			if c.wantErr != "" {
				var body struct {
					Code string `json:"code"`
				}
				_ = json.Unmarshal(w.Body.Bytes(), &body)
				if body.Code != c.wantErr {
					t.Fatalf("code = %q, want %q", body.Code, c.wantErr)
				}
			}
		})
	}
}
