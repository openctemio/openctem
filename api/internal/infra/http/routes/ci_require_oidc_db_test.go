package routes

// "OIDC required for CI" (RFC-051) over the real v2 sensor routes: a CI
// (runner) sensor's key is refused while its organization requires OIDC,
// every other sensor is untouched, and the refusal is audited once.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/internal/app"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

func TestCIRequireOIDC_RunnerKeyRefused_DB(t *testing.T) {
	var policy *cirunapp.RunnerKeyPolicy
	h := newV2Harness(t, v2HarnessOpts{ciKeys: lazyPolicy{&policy}})
	db := &postgres.DB{DB: h.db}
	policy = cirunapp.NewRunnerKeyPolicy(postgres.NewCIRunRepository(db),
		auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop()), logger.NewNop())
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM audit_logs WHERE tenant_id = $1`, h.tenantID)
	})

	runner, err := h.sensors.CreateSensor(ctx, app.CreateSensorInput{TenantID: h.tenantID, Name: "ci-runner",
		Type: "runner", Capabilities: []string{"sast"}, Tools: []string{"semgrep"}, ExecutionMode: "standalone"})
	if err != nil {
		t.Fatalf("create runner sensor: %v", err)
	}
	daemonKey := h.key
	hello := func(key string) (int, protov2.Problem) {
		h.key = key
		resp, raw := h.do(http.MethodGet, protov2.PathPrefix+"/hello", nil)
		var p protov2.Problem
		_ = json.Unmarshal(raw, &p)
		return resp.StatusCode, p
	}

	// A tenant created now requires OIDC for CI by default.
	var require bool
	if err := h.db.QueryRowContext(ctx, `SELECT ci_require_oidc FROM tenants WHERE id = $1`, h.tenantID).Scan(&require); err != nil || !require {
		t.Fatalf("new tenant default: %v %v", require, err)
	}
	for range 2 {
		code, p := hello(runner.APIKey)
		if code != http.StatusForbidden || p.Type != protov2.ProblemTypeBaseSensor+string(protov2.ProblemCIOIDCRequired) {
			t.Fatalf("runner key while OIDC is required: %d %+v", code, p)
		}
	}
	// The daemon sensor of the same tenant is untouched.
	if code, _ := hello(daemonKey); code != http.StatusOK {
		t.Fatalf("daemon sensor: %d", code)
	}
	// Audited once for the two refusals, without the key.
	var n int
	_ = h.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'ci_run.runner_key_refused'
		AND resource_id = $2`, h.tenantID, runner.Sensor.ID.String()).Scan(&n)
	if n != 1 {
		t.Fatalf("refusal audit rows = %d, want 1", n)
	}
	var leaked int
	_ = h.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND (metadata::text LIKE '%' || $2 || '%' OR message LIKE '%' || $2 || '%')`,
		h.tenantID, runner.APIKey).Scan(&leaked)
	if leaked != 0 {
		t.Fatal("the audit log carries the sensor key")
	}

	// Opted out: the runner key works again (the existing-tenant default).
	if _, err := h.db.ExecContext(ctx, `UPDATE tenants SET ci_require_oidc = FALSE WHERE id = $1`, h.tenantID); err != nil {
		t.Fatal(err)
	}
	if code, _ := hello(runner.APIKey); code != http.StatusOK {
		t.Fatalf("runner key after opting out: %d", code)
	}
}

// lazyPolicy lets the harness take the policy before the database exists.
type lazyPolicy struct{ p **cirunapp.RunnerKeyPolicy }

func (l lazyPolicy) Refused(ctx context.Context, s *sensordom.Sensor, ip, ua string) bool {
	return (*l.p).Refused(ctx, s, ip, ua)
}
