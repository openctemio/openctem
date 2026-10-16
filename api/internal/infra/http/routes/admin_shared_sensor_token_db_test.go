package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/app/sensorpairing"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorkey"
)

// Shared sensor enrollment tokens through the console route
// (docs/rfcs/RFC-100-shared-sensors.md §7): only a super admin issues one,
// with a reason and a fresh authenticator code; the token is shown once and
// stored hashed; the issue is in the console audit log; neither a read-only
// administrator (any role but super admin) nor an organization owner's token reaches the route.
func TestAdminSharedSensorToken_Routes_DB(t *testing.T) {
	h := newChainHarness(t, func(hs *Handlers, db *postgres.DB, console *adminconsole.Service) {
		log := logger.NewNop()
		svc, err := sensorpairing.NewService(postgres.NewSensorPairingRepository(db), postgres.NewSensorRepository(db),
			"0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0", "pepper-for-tests", log)
		if err != nil {
			t.Fatal(err)
		}
		svc.SetAdminAudit(postgres.NewAuditLogRepository(db))
		hs.AdminSharedSensor = handler.NewAdminSharedSensorHandler(svc, console, log)
	})
	const path = "/api/v1/admin/shared-sensors/enrollment-tokens"
	body := func(a *consoleAdmin) map[string]any {
		return map[string]any{"name": "central-01", "reason": "bundled scanner", "ttl_minutes": 30, "totp_code": a.freshCode(true)}
	}

	reader := h.newAdmin(admin.AdminRoleReadonly)
	reader.verify()
	if code, _ := reader.do(http.MethodPost, path, body(reader), true); code != http.StatusForbidden {
		t.Fatalf("a read-only administrator issued a token: %d", code)
	}
	root := h.newAdmin(admin.AdminRoleSuperAdmin)
	root.verify()
	if code, _ := root.do(http.MethodPost, path, map[string]any{"totp_code": root.freshCode(true)}, true); code != http.StatusBadRequest {
		t.Fatalf("no reason: %d", code)
	}
	root.resetReplayGuard()
	if code, _ := root.do(http.MethodPost, path, map[string]any{"reason": "r", "ttl_minutes": 120, "totp_code": root.freshCode(false)}, true); code != http.StatusBadRequest {
		t.Fatalf("two-hour token: %d", code)
	}
	root.closeStepUpWindow()
	if code, _ := root.do(http.MethodPost, path, map[string]any{"reason": "bundled scanner"}, true); code != http.StatusUnauthorized {
		t.Fatalf("no code: %d", code)
	}
	root.resetReplayGuard()
	code, raw := root.do(http.MethodPost, path, body(root), true)
	if code != http.StatusCreated {
		t.Fatalf("issue: %d %s", code, raw)
	}
	var out struct {
		ID, Token, Name string
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	if _, ok := sensorkey.Valid(out.Token); !ok || !strings.HasPrefix(out.Token, sensorkey.PrefixEnrollmentToken) || out.Name != "central-01" {
		t.Fatalf("answer: %s", raw)
	}
	t.Cleanup(func() { h.exec(`DELETE FROM instance_enrollment_tokens WHERE id = $1`, out.ID) })

	ctx := context.Background()
	var n int
	if err := h.db.QueryRowContext(ctx, `SELECT count(*) FROM instance_enrollment_tokens
		WHERE id = $1 AND created_by = $2 AND token_hash <> $3 AND expires_at <= created_at + interval '30 minutes'`,
		out.ID, root.a.ID().String(), out.Token).Scan(&n); err != nil || n != 1 {
		t.Fatalf("stored token: %d %v", n, err)
	}
	var auditBody string
	if err := h.db.QueryRowContext(ctx, `SELECT COALESCE(request_body::text, '') FROM admin_audit_logs WHERE admin_id = $1
		AND action = $2 AND severity = 'high' AND resource_id = $3`,
		root.a.ID().String(), admin.AuditActionInstanceTokenCreate, out.ID).Scan(&auditBody); err != nil {
		t.Fatalf("admin audit row: %v", err)
	}
	if strings.Contains(auditBody, out.Token) || !strings.Contains(auditBody, "bundled scanner") {
		t.Fatalf("audit body %s", auditBody)
	}

	// An organization owner's token is not a console session.
	tok := h.tenantToken(h.organization(0), "owner")
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, h.srv.URL+path, strings.NewReader(`{"reason":"x"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("an organization token reached the console route: %d", resp.StatusCode)
	}
	if err := h.db.QueryRowContext(ctx, `SELECT count(*) FROM instance_enrollment_tokens WHERE reason = 'x'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("an organization token issued a token: %d %v", n, err)
	}
}
