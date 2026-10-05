package routes

// GET /api/v1/sensors/{id}/activity over the real route registration against
// a migrated database: who may read it, that audit-derived items reach only
// callers with audit:read (owners and administrators), that rows written
// before the agent -> sensor rename are visible, tenant isolation, the
// category filter and the cursor.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	sensorsvc "github.com/openctemio/openctem/api/internal/app/sensor"
	tenantsvc "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/config"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

func newActivityRouteHarness(t *testing.T) *authzPolicyHarness {
	t.Helper()
	base := newAuthzPolicyHarness(t) // skips without a test database

	db := &postgres.DB{DB: base.db}
	log := logger.NewNop()
	auditSvc := auditapp.NewAuditService(postgres.NewAuditRepository(db), log)
	sensorSvc := sensorsvc.NewSensorService(postgres.NewSensorRepository(db), auditSvc, log)
	events := postgres.NewSensorEventRepository(db)
	sensorSvc.SetEventRepository(events, sensor.DefaultEventLimits())
	sensorSvc.SetActivityReader(events)

	cfg := &config.Config{}
	cfg.Auth.Provider = config.AuthProviderLocal
	router := infrahttp.NewChiRouter()
	Register(router, Handlers{
		Sensor: handler.NewSensorHandler(sensorSvc, validator.New(), log),
	}, cfg, log, AuthConfig{Provider: config.AuthProviderLocal, LocalValidator: base.gen},
		postgres.NewTenantRepository(db), tenantsvc.NewUserService(postgres.NewUserRepository(db), log), nil, nil, nil)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)
	base.srv = srv
	return base
}

func TestSensorActivity_Routes_DB(t *testing.T) {
	h := newActivityRouteHarness(t)
	tid, other := h.tenant(), h.tenant()
	t.Cleanup(func() {
		for _, id := range []string{tid, other} {
			_, _ = h.db.ExecContext(context.Background(), `DELETE FROM commands WHERE tenant_id = $1`, id)
		}
	})
	owner, admin, member, viewer := h.member(tid, "owner"), h.member(tid, "admin"), h.member(tid, "member"), h.member(tid, "viewer")
	outsider := h.member(other, "admin")
	sid := h.sensor(tid)

	// The owner's screenshot: the only row is a connect written before the
	// rename, as resource type "agent". Plus an administrator action, a
	// server-written restart and a finished job.
	now := time.Now().Add(-time.Hour)
	h.exec(`INSERT INTO audit_logs (id, tenant_id, actor_email, action, resource_type, resource_id, result, severity, message, logged_at)
	        VALUES ($1, $2, 'system', 'agent.connected', 'agent', $3, 'success', 'low', 'Agent connected', $4)`,
		uuid.NewString(), tid, sid, now)
	h.exec(`INSERT INTO audit_logs (id, tenant_id, actor_email, action, resource_type, resource_id, result, severity, message, logged_at)
	        VALUES ($1, $2, $3, 'sensor.updated', 'sensor', $4, 'success', 'medium', 'Sensor updated', $5)`,
		uuid.NewString(), tid, "boss@it.test", sid, now.Add(time.Minute))
	h.exec(`INSERT INTO sensor_events (tenant_id, sensor_id, type, at, summary, details)
	        VALUES ($1, $2, 'restarted', $3, 'Sensor process restarted (down 40s)', '{"downtime_seconds":40}')`,
		tid, sid, now.Add(2*time.Minute))
	h.exec(`INSERT INTO commands (id, tenant_id, sensor_id, type, status, acknowledged_at, completed_at)
	        VALUES ($1, $2, $3, 'scan', 'completed', $4, $5)`,
		uuid.NewString(), tid, sid, now.Add(3*time.Minute), now.Add(4*time.Minute))

	path := "/api/v1/sensors/" + sid + "/activity"
	read := func(u policyUser, query string) handler.SensorActivityResponse {
		t.Helper()
		var r handler.SensorActivityResponse
		mustJSON(t, h.expect(u, http.MethodGet, path+query, "", http.StatusOK), &r)
		return r
	}
	types := func(r handler.SensorActivityResponse) []string {
		out := make([]string, 0, len(r.Items))
		for _, it := range r.Items {
			out = append(out, it.Category+"/"+it.Type)
		}
		return out
	}

	// Owners and administrators see everything, the historical row included.
	for _, u := range []policyUser{owner, admin} {
		r := read(u, "")
		got := types(r)
		want := []string{"jobs/job_completed", "jobs/job_claimed", "status/restarted", "people/audit", "status/online"}
		if !r.AuditIncluded || len(got) != len(want) {
			t.Fatalf("%s: audit_included=%v items %v", u.role, r.AuditIncluded, got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s: items %v, want %v", u.role, got, want)
			}
		}
		if hist := r.Items[4]; hist.Action != "sensor.connected" || hist.Actor != "system" || hist.Source != "audit" {
			t.Errorf("historical row %+v", hist)
		}
		if upd := r.Items[3]; upd.Action != "sensor.updated" || upd.Actor != "boss@it.test" {
			t.Errorf("admin action %+v", upd)
		}
	}

	// Members and viewers read the timeline, never an audit-derived item.
	for _, u := range []policyUser{member, viewer} {
		r := read(u, "")
		if r.AuditIncluded {
			t.Errorf("%s: audit_included", u.role)
		}
		for _, it := range r.Items {
			if it.Source == "audit" || it.Actor != "" {
				t.Errorf("%s saw an audit item %+v", u.role, it)
			}
		}
		if len(r.Items) != 3 {
			t.Errorf("%s: items %v", u.role, types(r))
		}
		if got := types(read(u, "?types=people")); len(got) != 0 {
			t.Errorf("%s: people filter returned %v", u.role, got)
		}
	}

	// Filter and paging.
	if got := types(read(admin, "?types=status,people")); len(got) != 3 {
		t.Errorf("status,people: %v", got)
	}
	p1 := read(admin, "?limit=2")
	if len(p1.Items) != 2 || p1.NextCursor == "" {
		t.Fatalf("page 1: %v cursor %q", types(p1), p1.NextCursor)
	}
	p2 := read(admin, "?limit=2&cursor="+p1.NextCursor)
	p3 := read(admin, "?limit=2&cursor="+p2.NextCursor)
	if len(p2.Items) != 2 || len(p3.Items) != 1 || p3.NextCursor != "" || p2.Items[0].ID == p1.Items[1].ID {
		t.Errorf("pages: %v | %v | %v (cursor %q)", types(p1), types(p2), types(p3), p3.NextCursor)
	}
	h.expect(admin, http.MethodGet, path+"?types=bogus", "", http.StatusBadRequest)
	h.expect(admin, http.MethodGet, path+"?cursor=not-a-cursor!", "", http.StatusBadRequest)

	// Another organization's administrator cannot read it, nor an unknown id.
	h.expect(outsider, http.MethodGet, path, "", http.StatusNotFound)
	h.expect(admin, http.MethodGet, "/api/v1/sensors/"+uuid.NewString()+"/activity", "", http.StatusNotFound)
}
