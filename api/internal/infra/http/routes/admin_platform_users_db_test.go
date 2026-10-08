package routes

// Console > Users over the real route registration against a migrated
// database:
//
//   - every console role searches and views an account; a search shorter
//     than 3 characters is refused; viewing is audited;
//   - a read-only administrator cannot run a support action (403), and
//     nothing changes;
//   - an operations administrator revokes an account's sessions and unlocks
//     it, with a reason (400 without), and each action is audited with the
//     reason;
//   - a platform administrator's account is refused (409): administrators
//     are managed in Security, not here.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/platformuser"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func newPlatformUsersHarness(t *testing.T) *chainHarness {
	return newChainHarness(t, func(h *Handlers, db *postgres.DB, _ *adminconsole.Service) {
		log := logger.NewNop()
		sessions := auth.NewSessionService(postgres.NewSessionRepository(db.DB), postgres.NewRefreshTokenRepository(db.DB), log)
		dir := postgres.NewPlatformUserDirectory(db)
		svc := platformuser.NewService(postgres.NewUserRepository(db), sessions, nil, nil, dir, platformuser.Durations{})
		h.AdminPlatformUser = handler.NewAdminPlatformUserHandler(dir, svc, log)
		h.AdminAuditMiddleware = middleware.NewAuditMiddleware(postgres.NewAuditLogRepository(db), log)
	})
}

// supportUser is an account in one organization with an active session and a
// lockout from failed sign-ins.
func (h *chainHarness) supportUser(tenantID string) (id, email string) {
	h.t.Helper()
	id = uuid.NewString()
	email = "support-" + id[:8] + "@it.test"
	h.exec(`INSERT INTO users (id, email, name, failed_login_attempts, locked_until) VALUES ($1, $2, 'Support IT', 5, now() + interval '15 minutes')`, id, email)
	h.t.Cleanup(func() {
		ctx := context.Background()
		_, _ = h.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1`, id)
		_, _ = h.db.ExecContext(ctx, `DELETE FROM tenant_members WHERE user_id = $1`, id)
		_, _ = h.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id)
	})
	h.exec(`INSERT INTO tenant_members (id, user_id, tenant_id, role) VALUES ($1, $2, $3, 'member')`, uuid.NewString(), id, tenantID)
	h.exec(`INSERT INTO sessions (user_id, access_token_hash, expires_at) VALUES ($1, $2, now() + interval '1 hour')`,
		id, strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", "")[:64])
	return id, email
}

func (h *chainHarness) activeSessions(userID string) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM sessions WHERE user_id = $1 AND status = 'active'`, userID).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

// auditRow waits for the asynchronous admin audit row of action on resource.
func (h *chainHarness) auditRow(action, resourceID string) (found bool, body string) {
	h.t.Helper()
	for i := 0; i < 50; i++ {
		var b []byte
		err := h.db.QueryRowContext(context.Background(), `
			SELECT COALESCE(request_body::text, '') FROM admin_audit_logs
			WHERE action = $1 AND resource_id = $2 ORDER BY created_at DESC LIMIT 1`, action, resourceID).Scan(&b)
		if err == nil {
			return true, string(b)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false, ""
}

const supportReason = `{"reason":"Support case 4411: user locked out after a phone change"}`

func TestAdminPlatformUsers_SearchAndView(t *testing.T) {
	h := newPlatformUsersHarness(t)
	org := h.organization(0)
	uid, email := h.supportUser(org)

	c := h.newAdmin(admin.AdminRoleReadonly)
	c.verify()

	if code, body := c.do(http.MethodGet, "/api/v1/admin/platform-users?q=su", nil, false); code != http.StatusBadRequest {
		t.Fatalf("2-character search: %d %s, want 400", code, body)
	}

	code, body := c.do(http.MethodGet, "/api/v1/admin/platform-users?q="+url.QueryEscape(email[:16]), nil, false)
	if code != http.StatusOK {
		t.Fatalf("search: %d %s", code, body)
	}
	var list handler.AdminPlatformUserListResponse
	_ = json.Unmarshal([]byte(body), &list)
	if list.Total != 1 || list.Data[0].ID != uid || !list.Data[0].Locked || list.Data[0].Memberships != 1 {
		t.Fatalf("search result = %+v", list)
	}

	// By id.
	code, body = c.do(http.MethodGet, "/api/v1/admin/platform-users?q="+uid, nil, false)
	if code != http.StatusOK || !strings.Contains(body, uid) {
		t.Fatalf("search by id: %d %s", code, body)
	}

	code, body = c.do(http.MethodGet, "/api/v1/admin/platform-users/"+uid, nil, false)
	if code != http.StatusOK {
		t.Fatalf("view: %d %s", code, body)
	}
	var d handler.AdminPlatformUserDetailResponse
	_ = json.Unmarshal([]byte(body), &d)
	if len(d.MembershipList) != 1 || d.MembershipList[0].TenantID != org || len(d.Sessions) != 1 {
		t.Fatalf("detail = %+v", d)
	}
	if found, _ := h.auditRow("platform_user.view", uid); !found {
		t.Fatal("viewing an account was not audited")
	}

	if code, _ := c.do(http.MethodGet, "/api/v1/admin/platform-users/"+uuid.NewString(), nil, false); code != http.StatusNotFound {
		t.Fatalf("unknown account: %d, want 404", code)
	}
}

func TestAdminPlatformUsers_Actions(t *testing.T) {
	h := newPlatformUsersHarness(t)
	org := h.organization(0)
	uid, _ := h.supportUser(org)

	t.Run("read-only administrator is refused and nothing changes", func(t *testing.T) {
		c := newPlatformUsersHarness(t).newAdmin(admin.AdminRoleReadonly)
		c.verify()
		for _, action := range []string{"revoke-sessions", "unlock", "password-reset", "verification-emails"} {
			if code, body := c.do(http.MethodPost, "/api/v1/admin/platform-users/"+uid+"/"+action,
				json.RawMessage(supportReason), true); code != http.StatusForbidden {
				t.Fatalf("%s: %d %s, want 403", action, code, body)
			}
		}
		if h.activeSessions(uid) != 1 {
			t.Fatal("a refused action revoked a session")
		}
	})

	c := newPlatformUsersHarness(t).newAdmin(admin.AdminRoleOpsAdmin)
	c.verify()

	t.Run("a reason is required", func(t *testing.T) {
		if code, body := c.do(http.MethodPost, "/api/v1/admin/platform-users/"+uid+"/revoke-sessions",
			map[string]string{"reason": "short"}, true); code != http.StatusBadRequest {
			t.Fatalf("short reason: %d %s, want 400", code, body)
		}
		if h.activeSessions(uid) != 1 {
			t.Fatal("a refused action revoked a session")
		}
	})

	t.Run("revoke sessions", func(t *testing.T) {
		code, body := c.do(http.MethodPost, "/api/v1/admin/platform-users/"+uid+"/revoke-sessions", json.RawMessage(supportReason), true)
		if code != http.StatusOK {
			t.Fatalf("revoke: %d %s", code, body)
		}
		if n := h.activeSessions(uid); n != 0 {
			t.Fatalf("active sessions after revoke = %d", n)
		}
		found, audit := h.auditRow("platform_user.revoke_sessions", uid)
		if !found || !strings.Contains(audit, "Support case 4411") {
			t.Fatalf("revoke not audited with its reason: %v %s", found, audit)
		}
	})

	t.Run("unlock", func(t *testing.T) {
		code, body := c.do(http.MethodPost, "/api/v1/admin/platform-users/"+uid+"/unlock", json.RawMessage(supportReason), true)
		if code != http.StatusOK {
			t.Fatalf("unlock: %d %s", code, body)
		}
		var attempts int
		var locked bool
		_ = h.db.QueryRow(`SELECT failed_login_attempts, locked_until IS NOT NULL FROM users WHERE id = $1`, uid).Scan(&attempts, &locked)
		if attempts != 0 || locked {
			t.Fatalf("after unlock: attempts %d locked %v", attempts, locked)
		}
		// Unlocking again: nothing to do.
		if code, _ := c.do(http.MethodPost, "/api/v1/admin/platform-users/"+uid+"/unlock", json.RawMessage(supportReason), true); code != http.StatusConflict {
			t.Fatalf("second unlock: %d, want 409", code)
		}
	})

	t.Run("email actions without SMTP are refused", func(t *testing.T) {
		code, body := c.do(http.MethodPost, "/api/v1/admin/platform-users/"+uid+"/verification-emails", json.RawMessage(supportReason), true)
		if code != http.StatusConflict || !strings.Contains(body, "EMAIL_UNAVAILABLE") {
			t.Fatalf("resend verification: %d %s, want 409 EMAIL_UNAVAILABLE", code, body)
		}
	})

	t.Run("a platform administrator account is refused", func(t *testing.T) {
		other := h.newAdmin(admin.AdminRoleSuperAdmin)
		code, body := c.do(http.MethodPost, "/api/v1/admin/platform-users/"+other.userID.String()+"/revoke-sessions", json.RawMessage(supportReason), true)
		if code != http.StatusConflict {
			t.Fatalf("revoke an administrator: %d %s, want 409", code, body)
		}
	})
}
