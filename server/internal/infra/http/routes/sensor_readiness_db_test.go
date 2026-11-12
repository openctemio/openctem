package routes

// GET /api/v1/sensors/{id}/readiness through the routes: sensors:read reads
// it, another organization's sensor and a shared sensor answer 404, and the
// host confinement item stays unknown for a caller without sensors:write.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	sensorapp "github.com/openctemio/openctem/server/internal/app/sensor"
	"github.com/openctemio/openctem/server/internal/app/tenant"
	"github.com/openctemio/openctem/server/internal/config"
	infrahttp "github.com/openctemio/openctem/server/internal/infra/http"
	"github.com/openctemio/openctem/server/internal/infra/http/handler"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/validator"
)

func newReadinessRouteHarness(t *testing.T) *authzPolicyHarness {
	t.Helper()
	base := newAuthzPolicyHarness(t) // skips without a test database
	db := &postgres.DB{DB: base.db}
	log := logger.NewNop()
	sensorSvc := sensorapp.NewSensorService(postgres.NewSensorRepository(db), auditapp.NewAuditService(postgres.NewAuditRepository(db), log), log)
	h := handler.NewSensorHandler(sensorSvc, validator.New(), log)
	h.SetReadiness(sensorapp.NewReadinessService(sensorSvc, postgres.NewSensorGrantRepository(db), postgres.NewScanZoneRepository(db),
		sensorapp.ScopeByStatus{Repo: postgres.NewScopeTargetRepository(db)}))
	cfg := &config.Config{}
	cfg.Auth.Provider = config.AuthProviderLocal
	router := infrahttp.NewChiRouter()
	Register(router, Handlers{Sensor: h}, cfg, log, AuthConfig{Provider: config.AuthProviderLocal, LocalValidator: base.gen},
		postgres.NewTenantRepository(db), tenant.NewUserService(postgres.NewUserRepository(db), log), nil, nil, nil)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)
	base.srv = srv
	return base
}

func TestSensorReadiness_Route_DB(t *testing.T) {
	h := newReadinessRouteHarness(t)
	tid, other := h.tenant(), h.tenant()
	sid := h.sensor(tid)
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM scan_zones WHERE tenant_id = $1`, tid)
	})
	// The sensor is in a zone of 10.30.0.0/16, which is not in scope.
	zid := uuid.NewString()
	h.exec(`INSERT INTO scan_zones (id, tenant_id, name, ranges) VALUES ($1, $2, 'branch', ARRAY['10.30.0.0/16']::cidr[])`, zid, tid)
	h.exec(`INSERT INTO scan_zone_sensors (tenant_id, zone_id, sensor_id) VALUES ($1, $2, $3)`, tid, zid, sid)

	path := "/api/v1/sensors/" + sid + "/readiness"
	read := func(u policyUser) sensorapp.Readiness {
		t.Helper()
		var r sensorapp.Readiness
		mustJSON(t, h.expect(u, http.MethodGet, path, "", http.StatusOK), &r)
		return r
	}
	state := func(r sensorapp.Readiness, key string) sensorapp.ReadinessItem {
		t.Helper()
		for _, it := range r.Items {
			if it.Key == key {
				return it
			}
		}
		t.Fatalf("no %s item in %+v", key, r.Items)
		return sensorapp.ReadinessItem{}
	}

	viewer, admin := h.member(tid, "viewer"), h.member(tid, "admin")
	v := read(viewer)
	if v.SensorID != sid || v.Ready || len(v.Items) != 7 || v.Items[0].Key != sensorapp.ReadyOnline || v.Items[6].Key != sensorapp.ReadySandbox {
		t.Fatalf("viewer readiness %+v", v)
	}
	if it := state(v, sensorapp.ReadyNetworks); it.State != sensorapp.ReadyStateOK || it.Count != 1 {
		t.Fatalf("networks %+v", it)
	}
	sc := state(v, sensorapp.ReadyScope)
	if sc.State != sensorapp.ReadyStateBlocked || sc.Fix == nil || sc.Fix.Action != sensorapp.FixAddScope ||
		len(sc.Fix.Patterns) != 1 || sc.Fix.Patterns[0] != "10.30.0.0/16" || sc.Fix.Allowed {
		t.Fatalf("scope for a viewer (no scope:write): %+v %+v", sc, sc.Fix)
	}
	if it := state(v, sensorapp.ReadySandbox); it.State != sensorapp.ReadyStateUnknown {
		t.Fatalf("a viewer sees the host's confinement: %+v", it)
	}
	if a := state(read(admin), sensorapp.ReadyScope); a.Fix == nil || !a.Fix.Allowed {
		t.Fatalf("admin may add scope: %+v", a)
	}

	// Once the range is in scope the item clears.
	h.exec(`INSERT INTO scope_targets (id, tenant_id, target_type, pattern, status) VALUES ($1, $2, 'cidr', '10.0.0.0/8', 'active')`,
		uuid.NewString(), tid)
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM scope_targets WHERE tenant_id = $1`, tid)
	})
	if it := state(read(viewer), sensorapp.ReadyScope); it.State != sensorapp.ReadyStateOK {
		t.Fatalf("scope after the entry: %+v", it)
	}

	// BOLA: another organization's administrator, an unknown id, a shared
	// sensor.
	h.expect(h.member(other, "admin"), http.MethodGet, path, "", http.StatusNotFound)
	h.expect(admin, http.MethodGet, "/api/v1/sensors/"+uuid.NewString()+"/readiness", "", http.StatusNotFound)
	shared := uuid.NewString()
	h.exec(`INSERT INTO sensors (id, tenant_id, scope, name, type, status, health, execution_mode, api_key_hash, api_key_prefix)
	        VALUES ($1, NULL, 'instance', $2, 'worker', 'active', 'unknown', 'daemon', $3, 'rda_test')`, shared, "shared-"+shared[:8], "hash-"+shared)
	t.Cleanup(func() { _, _ = h.db.ExecContext(context.Background(), `DELETE FROM sensors WHERE id = $1`, shared) })
	h.expect(admin, http.MethodGet, "/api/v1/sensors/"+shared+"/readiness", "", http.StatusNotFound)
}
