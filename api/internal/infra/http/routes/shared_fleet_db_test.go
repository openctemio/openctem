package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The console's shared sensor fleet (docs/rfcs/RFC-100-shared-sensors.md
// §12): any administrator lists the fleet, the queue and job metadata, and
// none of those carries a job's targets, payload, result or error text; a
// job's targets and logs come only through the audited view with a reason
// (super or ops admin), which writes its audit row first; pause, resume and
// retire need a super admin and a fresh code, touch only instance sensors,
// and are audited; a retired sensor cannot be resumed; no tenant token
// reaches the console routes.
func TestAdminSharedFleet_Routes_DB(t *testing.T) {
	wire := func(hs *Handlers, db *postgres.DB, _ *adminconsole.Service) {
		log := logger.NewNop()
		hs.AdminSharedFleet = handler.NewAdminSharedFleetHandler(sensorapp.NewSharedFleetService(
			postgres.NewSharedFleetRepository(db), postgres.NewCommandLogRepository(db), postgres.NewAuditLogRepository(db), log), log)
	}
	h := newChainHarness(t, wire)
	ctx := context.Background()
	orgA, orgB := h.organization(0), h.organization(0)

	sensor := func(name string, tenant any, scope string) string {
		id := uuid.NewString()
		h.exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, execution_mode, api_key_hash, api_key_prefix,
		            scope, region, version, last_seen_at, heartbeat_interval_seconds)
		        VALUES ($1, $2, $3, 'worker', 'active', 'online', 'daemon', $4, 'octs_flt', $5, 'eu', 'v1.2.3', now(), 60)`,
			id, tenant, name, "hash-"+id, scope)
		return id
	}
	shared := sensor("shared-eu-1", nil, "instance")
	own := sensor("org-a-own", orgA, "organization")

	job := func(tenant, status, target string) string {
		id := uuid.NewString()
		payload, _ := json.Marshal(map[string]any{"scanner": "nuclei", "targets": []string{target}})
		h.exec(`INSERT INTO commands (id, tenant_id, type, payload, status, is_platform_job, platform_sensor_id, error_message, result)
		        VALUES ($1, $2, 'scan', $3::jsonb, $4, TRUE, $5, 'dial secret-error.internal refused',
		                '{"findings":[{"title":"result-secret-finding"}]}'::jsonb)`, id, tenant, string(payload), status, shared)
		return id
	}
	jobA := job(orgA, "running", "a-target.example")
	job(orgB, "pending", "b-target.example")
	lines, _ := json.Marshal([]map[string]any{{"ts": time.Now().UTC().Format(time.RFC3339), "level": "info", "msg": "probing a-target.example"}})
	h.exec(`INSERT INTO command_logs (tenant_id, command_id, seq, lines, line_count, bytes, dropped)
	        VALUES ($1, $2, 0, $3::jsonb, 1, $4, 0)`, orgA, jobA, string(lines), len(lines))
	t.Cleanup(func() {
		for _, q := range []string{
			`DELETE FROM command_logs WHERE tenant_id IN ($1, $2)`,
			`DELETE FROM commands WHERE tenant_id IN ($1, $2)`,
		} {
			_, _ = h.db.ExecContext(ctx, q, orgA, orgB)
		}
		_, _ = h.db.ExecContext(ctx, `DELETE FROM sensors WHERE id IN ($1, $2)`, shared, own)
	})
	noTenantData := func(where, body string) {
		t.Helper()
		for _, leak := range []string{"a-target.example", "b-target.example", "secret-error", "result-secret-finding", "payload", "targets"} {
			if strings.Contains(body, leak) {
				t.Errorf("%s shows %q: %s", where, leak, body)
			}
		}
	}

	reader := h.newAdmin(admin.AdminRoleReadonly)
	reader.verify()
	code, body := reader.do(http.MethodGet, "/api/v1/admin/shared-sensors", nil, true)
	if code != http.StatusOK || !strings.Contains(body, shared) || !strings.Contains(body, "shared-eu-1") || strings.Contains(body, own) ||
		!strings.Contains(body, `"current_jobs":1`) {
		t.Fatalf("fleet: %d %s", code, body)
	}
	code, body = reader.do(http.MethodGet, "/api/v1/admin/shared-sensors/queue", nil, true)
	if code != http.StatusOK || !strings.Contains(body, `"tool":"nuclei","queued":1,"running":1`) || !strings.Contains(body, orgA) || !strings.Contains(body, orgB) {
		t.Fatalf("queue: %d %s", code, body)
	}
	noTenantData("queue", body)
	// A read-only administrator gets counts, not organization names.
	if strings.Contains(body, "Audit chain IT") || strings.Contains(body, "tenant_name") {
		t.Errorf("a read-only administrator sees organization names in the queue: %s", body)
	}
	code, body = reader.do(http.MethodGet, "/api/v1/admin/shared-sensors/jobs?tenant_id="+orgA, nil, true)
	if code != http.StatusOK || !strings.Contains(body, jobA) || !strings.Contains(body, `"total":1`) || !strings.Contains(body, "shared-eu-1") {
		t.Fatalf("jobs: %d %s", code, body)
	}
	noTenantData("job list", body)
	if strings.Contains(body, "Audit chain IT") || strings.Contains(body, "tenant_name") {
		t.Errorf("a read-only administrator sees organization names in the job list: %s", body)
	}
	if code, _ := reader.do(http.MethodGet, "/api/v1/admin/shared-sensors/jobs?status=bogus", nil, true); code != http.StatusBadRequest {
		t.Fatalf("bad status: %d", code)
	}
	// A read-only administrator may not view a job's details or act.
	viewPath := "/api/v1/admin/shared-sensors/jobs/" + jobA + "/view"
	if code, _ := reader.do(http.MethodPost, viewPath, map[string]any{"reason": "x"}, true); code != http.StatusForbidden {
		t.Fatalf("a read-only administrator viewed a job: %d", code)
	}
	for _, a := range []string{"pause", "resume", "retire"} {
		if code, _ := reader.do(http.MethodPost, "/api/v1/admin/shared-sensors/"+shared+"/"+a,
			map[string]any{"reason": "x", "totp_code": reader.freshCode(true)}, true); code != http.StatusForbidden {
			t.Fatalf("a read-only administrator could %s: %d", a, code)
		}
	}

	// The audited view: a reason is required; with one, the targets and
	// logs come back, never the result or the error text, and the audit
	// row names the organization and the reason.
	// A second server (same database): the sign-in rate limit is per server.
	ops := newChainHarness(t, wire).newAdmin(admin.AdminRoleOpsAdmin)
	ops.verify()
	// An operations administrator sees the organization names.
	for _, p := range []string{"/api/v1/admin/shared-sensors/queue", "/api/v1/admin/shared-sensors/jobs?tenant_id=" + orgA} {
		if code, body := ops.do(http.MethodGet, p, nil, true); code != http.StatusOK || !strings.Contains(body, `"tenant_name":"Audit chain IT"`) {
			t.Fatalf("ops %s: %d %s", p, code, body)
		}
	}
	if code, _ := ops.do(http.MethodPost, viewPath, map[string]any{"reason": "  "}, true); code != http.StatusBadRequest {
		t.Fatalf("view without a reason: %d", code)
	}
	code, body = ops.do(http.MethodPost, viewPath, map[string]any{"reason": "abuse report 42"}, true)
	if code != http.StatusOK || !strings.Contains(body, `"targets":["a-target.example"]`) || !strings.Contains(body, "probing a-target.example") {
		t.Fatalf("view: %d %s", code, body)
	}
	for _, leak := range []string{"secret-error", "result-secret-finding", "b-target.example"} {
		if strings.Contains(body, leak) {
			t.Errorf("the job view shows %q: %s", leak, body)
		}
	}
	var n int
	if err := h.db.QueryRowContext(ctx, `SELECT count(*) FROM admin_audit_logs WHERE admin_id = $1 AND action = $2
		AND severity = 'high' AND resource_id = $3 AND request_body->>'reason' = 'abuse report 42' AND request_body->>'tenant_id' = $4`,
		ops.a.ID().String(), sensorapp.ActionSharedSensorJobViewed, jobA, orgA).Scan(&n); err != nil || n != 1 {
		t.Fatalf("job view audit rows: %d %v, want 1", n, err)
	}
	// A tenant's own job that is not a shared job is not found here.
	ownJob := uuid.NewString()
	h.exec(`INSERT INTO commands (id, tenant_id, type, payload, status) VALUES ($1, $2, 'scan', '{"targets":["own.example"]}'::jsonb, 'pending')`, ownJob, orgA)
	if code, _ := ops.do(http.MethodPost, "/api/v1/admin/shared-sensors/jobs/"+ownJob+"/view", map[string]any{"reason": "x"}, true); code != http.StatusNotFound {
		t.Fatalf("an organization job through the shared view: %d", code)
	}
	// An operations administrator may not act.
	if code, _ := ops.do(http.MethodPost, "/api/v1/admin/shared-sensors/"+shared+"/pause",
		map[string]any{"reason": "x", "totp_code": ops.freshCode(true)}, true); code != http.StatusForbidden {
		t.Fatalf("an ops administrator paused a shared sensor: %d", code)
	}

	root := h.newAdmin(admin.AdminRoleSuperAdmin)
	root.verify()
	status := func(id string) string {
		var s string
		if err := h.db.QueryRowContext(ctx, `SELECT status FROM sensors WHERE id = $1`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	act := func(id, action string) int {
		root.resetReplayGuard()
		code, _ := root.do(http.MethodPost, "/api/v1/admin/shared-sensors/"+id+"/"+action,
			map[string]any{"reason": "maintenance", "totp_code": root.freshCode(false)}, true)
		return code
	}
	// The step-up is enforced on the route.
	if code, _ := root.do(http.MethodPost, "/api/v1/admin/shared-sensors/"+shared+"/pause",
		map[string]any{"reason": "x", "totp_code": "000000"}, true); code != http.StatusUnauthorized {
		t.Fatalf("pause with a bad code: %d", code)
	}
	if code := act(shared, "pause"); code != http.StatusNoContent || status(shared) != "disabled" {
		t.Fatalf("pause: %d %s", code, status(shared))
	}
	// An organization's sensor is not a shared sensor.
	if code := act(own, "pause"); code != http.StatusNotFound || status(own) != "active" {
		t.Fatalf("paused an organization sensor: %d %s", code, status(own))
	}
	if code := act(shared, "resume"); code != http.StatusNoContent || status(shared) != "active" {
		t.Fatalf("resume: %d %s", code, status(shared))
	}
	if code := act(shared, "retire"); code != http.StatusNoContent || status(shared) != "revoked" {
		t.Fatalf("retire: %d %s", code, status(shared))
	}
	if code := act(shared, "resume"); code != http.StatusConflict || status(shared) != "revoked" {
		t.Fatalf("resumed a retired sensor: %d %s", code, status(shared))
	}
	if err := h.db.QueryRowContext(ctx, `SELECT count(*) FROM admin_audit_logs WHERE admin_id = $1 AND severity = 'critical'
		AND action IN ('shared_sensor.paused', 'shared_sensor.resumed', 'shared_sensor.retired') AND resource_id = $2`,
		root.a.ID().String(), shared).Scan(&n); err != nil || n != 3 {
		t.Fatalf("action audit rows: %d %v, want 3", n, err)
	}

	// A tenant owner's token is not a console session.
	tok := h.tenantToken(orgA, "owner")
	for _, rt := range [][2]string{
		{http.MethodGet, "/api/v1/admin/shared-sensors"}, {http.MethodGet, "/api/v1/admin/shared-sensors/jobs"},
		{http.MethodPost, viewPath}, {http.MethodPost, "/api/v1/admin/shared-sensors/" + shared + "/resume"},
	} {
		code, _ := bearerDo(t, h.srv.URL+rt[1], tok, rt[0], `{"reason":"x"}`)
		if code != http.StatusUnauthorized && code != http.StatusForbidden {
			t.Fatalf("a tenant token reached %s %s: %d", rt[0], rt[1], code)
		}
	}
}
