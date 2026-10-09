package routes

// Security > Sessions over the real route registration:
//
//   - only a super admin lists console sessions or ends one (ops and
//     readonly administrators get 403);
//   - ending another administrator's session needs a reason and a fresh
//     authenticator code; that administrator's next request is refused at
//     once, and the action is audited at high severity;
//   - your own current session is not ended here (sign out instead).

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func newSessionsHarness(t *testing.T) *chainHarness {
	return newChainHarness(t, func(hs *Handlers, db *postgres.DB, console *adminconsole.Service) {
		log := logger.NewNop()
		hs.AdminAuditMiddleware = middleware.NewAuditMiddleware(postgres.NewAuditLogRepository(db), log)
		// The console service is the step-up verifier, as in the real wiring.
		hs.AdminSession = handler.NewAdminSessionHandler(postgres.NewAdminSessionDirectory(db), console, log)
	})
}

func sessionsOf(t *testing.T, c *consoleAdmin) handler.AdminSessionListResponse {
	t.Helper()
	code, body := c.do(http.MethodGet, "/api/v1/admin/console-sessions", nil, false)
	if code != http.StatusOK {
		t.Fatalf("list sessions: %d %s", code, body)
	}
	var out handler.AdminSessionListResponse
	_ = json.Unmarshal([]byte(body), &out)
	return out
}

func TestAdminSessions(t *testing.T) {
	h := newSessionsHarness(t)
	super := h.newAdmin(admin.AdminRoleSuperAdmin)
	super.verify()
	other := h.newAdmin(admin.AdminRoleOpsAdmin)
	other.verify()

	t.Run("ops and readonly administrators are refused", func(t *testing.T) {
		for _, c := range []*consoleAdmin{other, func() *consoleAdmin {
			ro := newSessionsHarness(t).newAdmin(admin.AdminRoleReadonly)
			ro.verify()
			return ro
		}()} {
			if code, _ := c.do(http.MethodGet, "/api/v1/admin/console-sessions", nil, false); code != http.StatusForbidden {
				t.Fatalf("list as %s: %d, want 403", c.a.Role(), code)
			}
		}
	})

	list := sessionsOf(t, super)
	var mine, theirs string
	for _, s := range list.Data {
		switch s.AdminID {
		case super.a.ID().String():
			if s.Current {
				mine = s.ID
			}
		case other.a.ID().String():
			theirs = s.ID
		}
	}
	if mine == "" || theirs == "" {
		t.Fatalf("sessions not listed (mine %q, theirs %q): %+v", mine, theirs, list.Data)
	}

	t.Run("your own current session is refused", func(t *testing.T) {
		if code, body := super.do(http.MethodDelete, "/api/v1/admin/console-sessions/"+mine,
			map[string]string{"reason": "Testing self termination", "totp_code": super.freshCode(true)}, true); code != http.StatusBadRequest {
			t.Fatalf("own session: %d %s, want 400", code, body)
		}
	})

	t.Run("a reason and a code are required", func(t *testing.T) {
		if code, _ := super.do(http.MethodDelete, "/api/v1/admin/console-sessions/"+theirs,
			map[string]string{"totp_code": "123456"}, true); code != http.StatusBadRequest {
			t.Fatalf("no reason: %d, want 400", code)
		}
		if code, _ := super.do(http.MethodDelete, "/api/v1/admin/console-sessions/"+theirs,
			map[string]string{"reason": "Laptop reported stolen, ticket 77"}, true); code != http.StatusUnauthorized {
			t.Fatalf("no code: %d, want 401", code)
		}
		if code, _ := other.do(http.MethodGet, "/api/v1/admin/overview", nil, false); code == http.StatusUnauthorized {
			t.Fatal("a refused request ended the session")
		}
	})

	t.Run("ending a session signs that administrator out at once", func(t *testing.T) {
		super.resetReplayGuard()
		code, body := super.do(http.MethodDelete, "/api/v1/admin/console-sessions/"+theirs,
			map[string]string{"reason": "Laptop reported stolen, ticket 77", "totp_code": super.freshCode(false)}, true)
		if code != http.StatusNoContent {
			t.Fatalf("end session: %d %s", code, body)
		}
		if code, _ := other.do(http.MethodGet, "/api/v1/admin/auth/validate", nil, false); code != http.StatusUnauthorized {
			t.Fatalf("ended session still works: %d", code)
		}
		var severity string
		for i := 0; i < 50 && severity == ""; i++ {
			_ = h.db.QueryRowContext(context.Background(), `
				SELECT severity FROM admin_audit_logs
				WHERE action = 'console.session_ended' AND admin_id = $1 AND resource_id = $2`,
				super.a.ID().String(), theirs).Scan(&severity)
			if severity == "" {
				time.Sleep(50 * time.Millisecond)
			}
		}
		if severity != "high" {
			t.Fatalf("audit severity %q, want high", severity)
		}
	})
}
