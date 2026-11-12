package routes

// GET /api/v1/commands/{id}/logs (research/62): the logs of any command,
// read under the command's gate; a command about a finding (validate,
// retest) also needs findings:read and the finding in the caller's data
// scope; another tenant's command is not found.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	commandapp "github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/internal/app/commandlog"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/config"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

func newCommandLogsReadHarness(t *testing.T) *authzPolicyHarness {
	t.Helper()
	base := newAuthzPolicyHarness(t) // skips without a test database
	db := &postgres.DB{DB: base.db}
	log := logger.NewNop()
	h := handler.NewCommandHandler(commandapp.NewService(postgres.NewCommandRepository(db), log), validator.New(), log)
	h.SetCommandLogs(commandlog.NewService(postgres.NewCommandLogRepository(db)))
	h.SetFindingScope(datascope.New(postgres.NewDataScopeRepository(db), func(ctx context.Context) datascope.Caller {
		return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
	}, log))
	cfg := &config.Config{}
	cfg.Auth.Provider = config.AuthProviderLocal
	router := infrahttp.NewChiRouter()
	Register(router, Handlers{Command: h}, cfg, log, AuthConfig{Provider: config.AuthProviderLocal, LocalValidator: base.gen},
		postgres.NewTenantRepository(db), tenantapp.NewUserService(postgres.NewUserRepository(db), log), nil, nil, nil)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)
	base.srv = srv
	return base
}

// logsCommand inserts a command of tenantID with one stored log batch.
func (h *authzPolicyHarness) logsCommand(tenantID, cmdType, payload, msg string) string {
	h.t.Helper()
	id := uuid.NewString()
	h.exec(`INSERT INTO commands (id, tenant_id, type, payload, status) VALUES ($1, $2, $3, $4::jsonb, 'completed')`,
		id, tenantID, cmdType, payload)
	lines, _ := json.Marshal([]map[string]any{{"ts": "2026-10-07T10:00:00Z", "level": "info", "msg": msg, "source": "sensor"}})
	h.exec(`INSERT INTO command_logs (tenant_id, command_id, seq, lines, line_count, bytes, dropped)
	        VALUES ($1, $2, 0, $3::jsonb, 1, $4, 0)`, tenantID, id, string(lines), len(lines))
	return id
}

// scopedFinding inserts an asset and a finding on it, and returns the
// finding id and the asset id.
func (h *authzPolicyHarness) scopedFinding(tenantID string) (finding, asset string) {
	h.t.Helper()
	asset, finding = uuid.NewString(), uuid.NewString()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'domain')`, asset, tenantID, "a-"+asset[:8]+".example")
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint)
	        VALUES ($1, $2, $3, 'dast', 'nuclei', 'm', 'high', $4)`, finding, tenantID, asset, "fp-"+finding)
	return finding, asset
}

func TestCommandLogs_ReadByCommandID_DB(t *testing.T) {
	h := newCommandLogsReadHarness(t)
	tid, other := h.tenant(), h.tenant()
	admin, outsider := h.member(tid, "admin"), h.member(other, "admin")
	scoped := h.member(tid, "member")
	h.customRoleMember(scoped, tid, permission.CommandsRead, permission.FindingsRead)
	h.mintToken(&scoped, tid)
	noFindings := h.member(tid, "member")
	h.customRoleMember(noFindings, tid, permission.CommandsRead)
	h.mintToken(&noFindings, tid)

	scan := h.logsCommand(tid, "scan", `{"scanner":"httpx"}`, "Tool httpx finished: ok")
	finding, asset := h.scopedFinding(tid)
	validate := h.logsCommand(tid, "validate", `{"finding_id":"`+finding+`"}`, "Validation finished: detected")
	path := func(id string) string { return "/api/v1/commands/" + id + "/logs" }

	// Any command kind is readable under commands:read.
	if body := h.expect(admin, http.MethodGet, path(scan), "", http.StatusOK); !strings.Contains(body, "Tool httpx finished: ok") {
		t.Fatalf("scan logs: %s", body)
	}
	h.expect(scoped, http.MethodGet, path(scan), "", http.StatusOK)
	if body := h.expect(admin, http.MethodGet, path(validate), "", http.StatusOK); !strings.Contains(body, "Validation finished") {
		t.Fatalf("validate logs: %s", body)
	}

	// SECURITY: a command about a finding outside the caller's data scope,
	// or without findings:read, is not found.
	h.expect(scoped, http.MethodGet, path(validate), "", http.StatusNotFound)
	h.expect(noFindings, http.MethodGet, path(validate), "", http.StatusNotFound)
	// In scope: readable.
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`, scoped.id, tid, asset)
	h.expect(scoped, http.MethodGet, path(validate), "", http.StatusOK)

	// A retest's check command is about the retested finding.
	retest := h.logsCommand(tid, "scan", `{"scanner":"nuclei"}`, "Tool nuclei-validate finished: ok")
	h.exec(`INSERT INTO finding_retests (id, tenant_id, finding_id, trigger, prior_status, template_id, target, deadline_at, check_command_id)
	        VALUES ($1, $2, $3, 'manual', 'confirmed', 'tpl', 'https://a.example', now() + interval '1 hour', $4)`,
		uuid.NewString(), tid, finding, retest)
	h.expect(scoped, http.MethodGet, path(retest), "", http.StatusOK)
	h.expect(noFindings, http.MethodGet, path(retest), "", http.StatusNotFound)

	// SECURITY: another tenant's command is not found; so is an unknown id.
	h.expect(outsider, http.MethodGet, path(scan), "", http.StatusNotFound)
	h.expect(outsider, http.MethodGet, path(validate), "", http.StatusNotFound)
	h.expect(admin, http.MethodGet, path(uuid.NewString()), "", http.StatusNotFound)
	h.expect(admin, http.MethodGet, "/api/v1/commands/not-an-id/logs", "", http.StatusBadRequest)
}
