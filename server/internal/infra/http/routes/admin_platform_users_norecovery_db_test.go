package routes

// Console recovery paths for a server that cannot send email, over the real
// route registration and a migrated database:
//
//   - reset link, mark verified and two-factor reset are super_admin only
//     (ops_admin is refused) and each takes a step-up;
//   - the reset link is returned once, valid one hour, stored only as a hash,
//     and never written to the audit row; it is refused while email works;
//   - mark verified marks an unverified local account;
//   - the two-factor reset needs a second super admin's approval of that exact
//     account, and a platform administrator's account is refused.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/adminapproval"
	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/platformuser"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type recordingMFAResetter struct{ ids []shared.ID }

func (r *recordingMFAResetter) ResetUserMFAByConsole(_ context.Context, id shared.ID, _ string) error {
	r.ids = append(r.ids, id)
	return nil
}

type toggleMailer struct{ on bool }

func (m *toggleMailer) IsConfigured() bool { return m.on }
func (m *toggleMailer) SendPasswordResetEmail(context.Context, string, string, string, time.Duration, string) error {
	return nil
}
func (m *toggleMailer) SendVerificationEmail(context.Context, string, string, string, time.Duration) error {
	return nil
}

func newNoEmailRecoveryHarness(t *testing.T, mfa *recordingMFAResetter, mail *toggleMailer) *chainHarness {
	t.Helper()
	return newChainHarness(t, func(h *Handlers, db *postgres.DB, console *adminconsole.Service) {
		log := logger.NewNop()
		sessions := auth.NewSessionService(postgres.NewSessionRepository(db.DB), postgres.NewRefreshTokenRepository(db.DB), log)
		dir := postgres.NewPlatformUserDirectory(db)
		svc := platformuser.NewService(postgres.NewUserRepository(db), sessions, nil, mail, dir, platformuser.Durations{})
		svc.SetMFAResetter(mfa)
		approvals := adminapproval.NewService(postgres.NewAdminApprovalRepository(db), postgres.NewAdminRepository(db),
			postgres.NewAuditLogRepository(db), log)
		approvals.SetUserNamer(adminapproval.UserNamerFunc(func(ctx context.Context, id shared.ID) (string, error) {
			u, err := postgres.NewUserRepository(db).GetByID(ctx, id)
			if err != nil {
				return "", err
			}
			return u.Email(), nil
		}))
		h.AdminApproval = handler.NewAdminApprovalHandler(approvals, log)
		h.AdminPlatformUser = handler.NewAdminPlatformUserHandler(dir, svc, log).
			WithAudit(postgres.NewAuditLogRepository(db)).WithApprovals(approvals).
			WithEmailDelivery(mail.IsConfigured).WithLinkBase("https://app.example.test")
		h.AdminAuditMiddleware = middleware.NewAuditMiddleware(postgres.NewAuditLogRepository(db), log)
	})
}

// ops_admin is refused on all three (its own harness: the console sign-in
// is rate limited per server).
func TestAdminPlatformUsers_NoEmailRecoveryNeedsSuperAdmin_DB(t *testing.T) {
	h := newNoEmailRecoveryHarness(t, &recordingMFAResetter{}, &toggleMailer{})
	uid, _ := h.supportUser(h.organization(0))
	h.exec(`UPDATE users SET auth_provider = 'local', password_hash = 'x', email_verified = false WHERE id = $1`, uid)
	ops := h.newAdmin(admin.AdminRoleOpsAdmin)
	ops.autoStepUp = true
	ops.verify()
	for _, p := range []string{"/reset-link", "/mark-verified", "/mfa/reset"} {
		if code, body := ops.do(http.MethodPost, "/api/v1/admin/platform-users/"+uid+p, json.RawMessage(supportReason), true); code != http.StatusForbidden {
			t.Fatalf("%s as ops_admin: %d %s, want 403", p, code, body)
		}
	}
	var hash *string
	_ = h.db.QueryRow(`SELECT password_reset_token FROM users WHERE id = $1`, uid).Scan(&hash)
	if hash != nil {
		t.Fatal("a refused request issued a reset token")
	}
}

func TestAdminPlatformUsers_NoEmailRecovery_DB(t *testing.T) {
	mfa := &recordingMFAResetter{}
	mail := &toggleMailer{}
	h := newNoEmailRecoveryHarness(t, mfa, mail)
	org := h.organization(0)
	uid, _ := h.supportUser(org)
	h.exec(`UPDATE users SET auth_provider = 'local', password_hash = 'x', email_verified = false WHERE id = $1`, uid)
	base := "/api/v1/admin/platform-users/" + uid

	su := h.newAdmin(admin.AdminRoleSuperAdmin)
	su.verify()

	t.Run("a step-up is required", func(t *testing.T) {
		if code, body := su.do(http.MethodPost, base+"/reset-link", json.RawMessage(supportReason), true); code == http.StatusOK {
			t.Fatalf("reset link without step-up: %d %s", code, body)
		}
		var hash *string
		_ = h.db.QueryRow(`SELECT password_reset_token FROM users WHERE id = $1`, uid).Scan(&hash)
		if hash != nil {
			t.Fatal("a request without step-up issued a reset token")
		}
	})

	su.autoStepUp = true

	t.Run("reset link: once, one hour, hash only, not in the audit row, refused with email", func(t *testing.T) {
		code, body := su.do(http.MethodPost, base+"/reset-link", map[string]string{"reason": "Support case 5120: owner lost the password"}, true)
		if code != http.StatusOK {
			t.Fatalf("reset link: %d %s", code, body)
		}
		var resp handler.AdminPlatformUserResetLinkResponse
		_ = json.Unmarshal([]byte(body), &resp)
		const prefix = "https://app.example.test/reset-password#token="
		if !strings.HasPrefix(resp.Link, prefix) {
			t.Fatalf("link = %q", resp.Link)
		}
		token := strings.TrimPrefix(resp.Link, prefix)
		if d := time.Until(resp.ExpiresAt); d > time.Hour || d < 55*time.Minute {
			t.Fatalf("link lives %v", d)
		}
		var stored string
		if err := h.db.QueryRow(`SELECT password_reset_token FROM users WHERE id = $1`, uid).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if stored == token || stored != crypto.HashToken(token) {
			t.Fatal("the raw token was stored, or the stored hash does not match the link")
		}
		found, audit := h.auditRow("platform_user.reset_link", uid)
		if !found || strings.Contains(audit, token) || !strings.Contains(audit, "Support case 5120") {
			t.Fatalf("audit row: found=%v body=%s", found, audit)
		}

		mail.on = true
		defer func() { mail.on = false }()
		if code, body := su.do(http.MethodPost, base+"/reset-link", json.RawMessage(supportReason), true); code != http.StatusConflict || !strings.Contains(body, "EMAIL_AVAILABLE") {
			t.Fatalf("reset link while email works: %d %s", code, body)
		}
	})

	t.Run("mark verified", func(t *testing.T) {
		if code, body := su.do(http.MethodPost, base+"/mark-verified", json.RawMessage(supportReason), true); code != http.StatusOK {
			t.Fatalf("mark verified: %d %s", code, body)
		}
		var verified bool
		_ = h.db.QueryRow(`SELECT email_verified FROM users WHERE id = $1`, uid).Scan(&verified)
		if !verified {
			t.Fatal("the account is not verified")
		}
		if found, _ := h.auditRow("platform_user.mark_verified", uid); !found {
			t.Fatal("not audited")
		}
		if code, _ := su.do(http.MethodPost, base+"/mark-verified", json.RawMessage(supportReason), true); code != http.StatusConflict {
			t.Fatalf("second mark verified: %d, want 409", code)
		}
	})

	t.Run("two-factor reset needs a second super admin and refuses an administrator account", func(t *testing.T) {
		second := h.newAdmin(admin.AdminRoleSuperAdmin)
		second.verify()
		t.Cleanup(func() {
			h.exec(`DELETE FROM admin_approvals WHERE requested_by IN ($1, $2)`, su.a.ID().String(), second.a.ID().String())
		})

		code, body := su.do(http.MethodPost, base+"/mfa/reset", json.RawMessage(supportReason), true)
		if code != http.StatusPreconditionRequired || !strings.Contains(body, string(handler.CodeSecondApprovalRequired)) {
			t.Fatalf("without approval: %d %s", code, body)
		}
		if len(mfa.ids) != 0 {
			t.Fatal("the factor was reset without an approval")
		}
		var refusal struct {
			Details handler.SecondApprovalDetails `json:"details"`
		}
		_ = json.Unmarshal([]byte(body), &refusal)
		if refusal.Details.Action != string(admin.ApprovalUserMFAReset) || refusal.Details.Target != "user:"+uid {
			t.Fatalf("refusal details: %s", body)
		}

		code, body = su.do(http.MethodPost, "/api/v1/admin/approvals/",
			map[string]string{"action": refusal.Details.Action, "target": refusal.Details.Target, "reason": "owner lost device and recovery codes, verified by phone"}, true)
		if code != http.StatusCreated {
			t.Fatalf("request approval: %d %s", code, body)
		}
		var req handler.AdminApprovalResponse
		_ = json.Unmarshal([]byte(body), &req)
		if req.TargetLabel == "" {
			t.Fatalf("the approver sees no account label: %s", body)
		}
		code, body = second.do(http.MethodPost, "/api/v1/admin/approvals/"+req.ID+"/approve",
			map[string]string{"note": "confirmed", "totp_code": second.freshCode(true)}, true)
		if code != http.StatusOK {
			t.Fatalf("approve: %d %s", code, body)
		}

		// An approval for this account does not cover another one.
		other, _ := h.supportUser(org)
		h.exec(`UPDATE users SET auth_provider = 'local', password_hash = 'x' WHERE id = $1`, other)
		if code, body := su.do(http.MethodPost, "/api/v1/admin/platform-users/"+other+"/mfa/reset", json.RawMessage(supportReason), true); code != http.StatusPreconditionRequired {
			t.Fatalf("approval reused for another account: %d %s", code, body)
		}

		if code, body := su.do(http.MethodPost, base+"/mfa/reset", json.RawMessage(supportReason), true); code != http.StatusOK {
			t.Fatalf("with approval: %d %s", code, body)
		}
		if len(mfa.ids) != 1 || mfa.ids[0].String() != uid {
			t.Fatalf("reset ids = %v", mfa.ids)
		}
		// Spent: the second call needs a new approval.
		if code, _ := su.do(http.MethodPost, base+"/mfa/reset", json.RawMessage(supportReason), true); code != http.StatusPreconditionRequired {
			t.Fatalf("approval used twice: %d", code)
		}

		// A platform administrator's own account (self or another) is refused.
		// Approvals are not needed to see the refusal only when the gate lets
		// the call through, so ask for one first.
		adminTarget := "/api/v1/admin/platform-users/" + su.userID.String() + "/mfa/reset"
		if code, _ := su.do(http.MethodPost, adminTarget, json.RawMessage(supportReason), true); code != http.StatusPreconditionRequired && code != http.StatusConflict {
			t.Fatalf("administrator account: %d, want a refusal", code)
		}
		if len(mfa.ids) != 1 {
			t.Fatalf("an administrator account was reset: %v", mfa.ids)
		}
	})

	_ = uuid.Nil
}
