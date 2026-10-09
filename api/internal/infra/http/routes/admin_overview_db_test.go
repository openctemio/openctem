package routes

// GET /api/v1/admin/overview over the real route registration against a
// migrated database:
//
//   - every console role (readonly included) reads it once the TOTP step is
//     done; a session that has not passed the step, and an organization
//     user's tenant token, are refused;
//   - an organization without an active owner is counted and named, and one
//     with an owner is not;
//   - the response carries counts and organization names only: no
//     administrator email and no member detail.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func newOverviewHarness(t *testing.T) *chainHarness {
	return newChainHarness(t, func(h *Handlers, db *postgres.DB, _ *adminconsole.Service) {
		h.AdminOverview = handler.NewAdminOverviewHandler(
			func(ctx context.Context, now time.Time) (postgres.AdminOverviewCounts, error) {
				return postgres.ReadAdminOverview(ctx, db.DB, now)
			},
			func(ctx context.Context) (postgres.OpsSnapshot, error) { return postgres.ReadOpsSnapshot(ctx, db.DB) },
			postgres.NewAdminRepository(db), 0, logger.NewNop())
	})
}

func TestAdminOverviewRoute(t *testing.T) {
	h := newOverviewHarness(t)

	// An organization with no owner, and one with an owner.
	orphan := h.organization(0)
	owned := h.organization(0)
	ownerToken := h.tenantToken(owned, "owner")

	t.Run("unverified console session is refused", func(t *testing.T) {
		c := newOverviewHarness(t).newAdmin(admin.AdminRoleSuperAdmin)
		if code, body := c.do(http.MethodGet, "/api/v1/admin/overview", nil, false); code != http.StatusUnauthorized {
			t.Fatalf("want 401 before the TOTP step, got %d %s", code, body)
		}
	})

	t.Run("tenant token is refused", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.srv.URL+"/api/v1/admin/overview", nil)
		req.Header.Set("Authorization", "Bearer "+ownerToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("want 401 for a tenant token, got %d", resp.StatusCode)
		}
	})

	for _, role := range []admin.AdminRole{admin.AdminRoleReadonly, admin.AdminRoleOpsAdmin, admin.AdminRoleSuperAdmin} {
		t.Run(string(role)+" reads the overview", func(t *testing.T) {
			// A harness per admin: each console sign-in spends the
			// per-client login budget (5/min).
			c := newOverviewHarness(t).newAdmin(role)
			c.verify()
			code, body := c.do(http.MethodGet, "/api/v1/admin/overview", nil, false)
			if code != http.StatusOK {
				t.Fatalf("want 200, got %d %s", code, body)
			}
			var got handler.AdminOverviewResponse
			if err := json.Unmarshal([]byte(body), &got); err != nil {
				t.Fatal(err)
			}
			if got.Organizations.Total < 2 || got.Organizations.WithoutOwner < 1 {
				t.Fatalf("organizations not counted: %+v", got.Organizations)
			}
			if !got.Platform.SchemaKnown || got.Platform.SchemaVersion == 0 {
				t.Fatalf("schema version not read: %+v", got.Platform)
			}
			// The sample is the newest few; ours were just created, so the
			// orphan is in it unless more than five newer orphans exist.
			names := map[string]bool{}
			for _, o := range got.Organizations.WithoutOwnerSample {
				names[o.ID] = true
			}
			if got.Organizations.WithoutOwner <= 5 && !names[orphan] {
				t.Fatalf("organization without owner %s not named: %+v", orphan, got.Organizations.WithoutOwnerSample)
			}
			if names[owned] {
				t.Fatalf("organization with an owner %s listed as without owner", owned)
			}
			if strings.Contains(body, "@it.test") {
				t.Fatalf("overview leaks an email: %s", body)
			}
		})
	}
}

// The break-glass and failed-action counts move with the admin audit rows
// they count.
func TestAdminOverviewSecurityCounts(t *testing.T) {
	h := newOverviewHarness(t)
	c := h.newAdmin(admin.AdminRoleReadonly)
	c.verify()

	read := func() handler.AdminOverviewResponse {
		t.Helper()
		code, body := c.do(http.MethodGet, "/api/v1/admin/overview", nil, false)
		if code != http.StatusOK {
			t.Fatalf("overview: %d %s", code, body)
		}
		var got handler.AdminOverviewResponse
		_ = json.Unmarshal([]byte(body), &got)
		return got
	}
	before := read()

	marker := uuid.NewString()
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM admin_audit_logs WHERE admin_email = $1`, marker+"@it.test")
	})
	ins := func(action string, success bool, age time.Duration) {
		h.exec(`INSERT INTO admin_audit_logs (admin_email, action, success, created_at) VALUES ($1, $2, $3, $4)`,
			marker+"@it.test", action, success, time.Now().Add(-age))
	}
	ins("console.break_glass_sign_in", true, time.Hour)
	ins("console.break_glass_sign_in", true, 8*24*time.Hour) // older than 7 days
	ins("console.mfa_failed", false, time.Hour)
	ins("console.mfa_failed", false, 25*time.Hour) // older than 24 hours

	after := read()
	if d := after.Security.BreakGlassSignIns7d - before.Security.BreakGlassSignIns7d; d != 1 {
		t.Fatalf("break-glass sign-ins moved by %d, want 1", d)
	}
	// The recent break-glass row is a success; only the recent failure counts.
	if d := after.Security.FailedAdminActions24h - before.Security.FailedAdminActions24h; d != 1 {
		t.Fatalf("failed actions moved by %d, want 1", d)
	}
}
