package routes

// The sign-up feed and its alert thresholds over the real route registration:
// an anonymous caller and an organization owner's token are refused; every
// console role reads the feed and the thresholds; only a super admin changes
// the thresholds, and only with a fresh authenticator code.

import (
	"context"
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	signupeventapp "github.com/openctemio/openctem/api/internal/app/signupevent"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func newSignupEventsHarness(t *testing.T) *chainHarness {
	t.Helper()
	return newChainHarness(t, func(hs *Handlers, db *postgres.DB, console *adminconsole.Service) {
		repo := postgres.NewSignupEventRepository(db)
		svc := signupeventapp.NewService(repo, repo, postgres.NewAuditLogRepository(db), logger.NewNop())
		hs.AdminSignupEvents = handler.NewAdminSignupEventHandler(svc, console, logger.NewNop())
	})
}

func TestAdminSignupEventRoutes(t *testing.T) {
	h := newSignupEventsHarness(t)
	org := h.organization(0)
	for name, hdr := range map[string]string{"anonymous": "", "tenant owner": "Bearer " + h.tenantToken(org, "owner")} {
		for _, path := range []string{"/api/v1/admin/signup-events", "/api/v1/admin/settings/signup-alerts"} {
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.srv.URL+path, nil)
			if hdr != "" {
				req.Header.Set("Authorization", hdr)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
				t.Fatalf("%s %s: %d, want 401/403", name, path, resp.StatusCode)
			}
		}
	}

	change := map[string]any{"per_ip_prefix": 5, "per_email_domain": 10, "window_minutes": 60, "version": 0, "reason": "test"}
	for _, role := range []admin.AdminRole{admin.AdminRoleReadonly, admin.AdminRoleOpsAdmin, admin.AdminRoleSuperAdmin} {
		// One harness per role: the console's verify step is rate limited.
		c := newSignupEventsHarness(t).newAdmin(role)
		c.verify()
		for _, path := range []string{"/api/v1/admin/signup-events", "/api/v1/admin/signup-events/daily", "/api/v1/admin/settings/signup-alerts"} {
			if code, body := c.do(http.MethodGet, path, nil, false); code != http.StatusOK {
				t.Fatalf("%s GET %s: %d %s", role, path, code, body)
			}
		}
		code, body := c.do(http.MethodPut, "/api/v1/admin/settings/signup-alerts", change, true)
		switch role {
		case admin.AdminRoleSuperAdmin:
			// No authenticator code: the step-up refuses it.
			if code != http.StatusUnauthorized && code != http.StatusForbidden {
				t.Fatalf("super admin without a code: %d %s", code, body)
			}
		default:
			if code != http.StatusForbidden {
				t.Fatalf("%s must not change the thresholds: %d %s", role, code, body)
			}
		}
	}
}
