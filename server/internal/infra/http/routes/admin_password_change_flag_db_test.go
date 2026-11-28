package routes

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/infra/http/handler"
	"github.com/openctemio/openctem/server/pkg/domain/admin"
	"github.com/openctemio/openctem/server/pkg/totp"
)

// The TOTP step's answer tells the console the truth about the temporary
// password: the console sends an administrator who must change it to the
// change-password step, while every other console route refuses the session
// with PASSWORD_CHANGE_REQUIRED. It used to answer false always, so the
// console opened its pages and each one failed.
func TestAdminVerifyMFA_ReportsPasswordChangeRequired_DB(t *testing.T) {
	h := newChainHarness(t)
	for _, required := range []bool{true, false} {
		c := h.newAdmin(admin.AdminRoleSuperAdmin)
		h.exec(`UPDATE admin_users SET password_change_required = $2 WHERE id = $1`, c.a.ID().String(), required)

		code, err := totp.Code(c.secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		st, body := c.do(http.MethodPost, "/api/v1/admin/auth/mfa", map[string]string{"code": code}, true)
		if st != http.StatusOK {
			t.Fatalf("mfa: %d %s", st, body)
		}
		var signedIn handler.ValidateResponse
		if err := json.Unmarshal([]byte(body), &signedIn); err != nil {
			t.Fatal(err)
		}
		if signedIn.PasswordChangeRequired != required {
			t.Fatalf("mfa password_change_required = %v, want %v", signedIn.PasswordChangeRequired, required)
		}
		if signedIn.AuthMethod != admin.AuthMethodPassword {
			t.Fatalf("mfa auth_method = %q, want password", signedIn.AuthMethod)
		}

		// Validate and the gate agree with the sign-in answer.
		st, body = c.do(http.MethodGet, "/api/v1/admin/auth/validate", nil, true)
		var who handler.ValidateResponse
		if err := json.Unmarshal([]byte(body), &who); st != http.StatusOK || err != nil {
			t.Fatalf("validate: %d %s", st, body)
		}
		if who.PasswordChangeRequired != required {
			t.Fatalf("validate password_change_required = %v, want %v", who.PasswordChangeRequired, required)
		}
		st, body = c.do(http.MethodGet, "/api/v1/admin/version", nil, true)
		if gated := st == http.StatusForbidden && strings.Contains(body, "PASSWORD_CHANGE_REQUIRED"); gated != required {
			t.Fatalf("console route: %d %s; gated %v, want %v", st, body, gated, required)
		}
	}
}
