package routes

// A shared sensor (scope instance, docs/rfcs/RFC-100-shared-sensors.md) has
// no tenant. Its key authenticates it as a sensor, but never into a tenant:
// the authenticator sets no tenant context and the tenant-bound sensor
// routes answer 403 scope-denied. Requires DATABASE_URL.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/crypto"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorkey"
)

func TestSharedSensor_AuthenticatesWithoutTenant_DB(t *testing.T) {
	h := newV2Harness(t, v2HarnessOpts{})
	ctx := context.Background()

	key, err := sensorkey.New(sensorkey.PrefixSensorKey)
	if err != nil {
		t.Fatal(err)
	}
	s, err := sensordom.NewSensor(shared.NewID(), "shared-auth", sensordom.SensorTypeWorker, "", nil, sensordom.ExecutionModeDaemon)
	if err != nil {
		t.Fatal(err)
	}
	s.Scope, s.TenantID = sensordom.ScopeInstance, nil
	s.SetAPIKey(crypto.HashTokenPeppered(key, ""), sensorkey.DisplayPrefix(key))
	if err := postgres.NewSensorRepository(&postgres.DB{DB: h.db}).Create(ctx, s); err != nil {
		t.Fatalf("create shared sensor: %v", err)
	}
	t.Cleanup(func() { _, _ = h.db.ExecContext(context.Background(), `DELETE FROM sensors WHERE id = $1`, s.ID.String()) })

	// The row has no tenant, and neither has its default grant.
	var grantTenant *string
	if err := h.db.QueryRowContext(ctx, `SELECT tenant_id::text FROM sensor_grants WHERE sensor_id = $1`, s.ID.String()).
		Scan(&grantTenant); err != nil || grantTenant != nil {
		t.Fatalf("shared sensor grant tenant %v (%v), want NULL", grantTenant, err)
	}

	// The authenticator accepts the key but sets no tenant context.
	var reached bool
	var tenantInCtx any
	auth := handler.NewSensorResultsV2Handler(nil, h.sensors, logger.NewNop()).Authenticate(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			tenantInCtx = r.Context().Value(middleware.TenantIDKey)
			if got := handler.SensorFromContext(r.Context()); got == nil || !got.IsShared() || got.TenantID != nil {
				t.Errorf("sensor in context: %+v", got)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
	req := httptest.NewRequest(http.MethodGet, "/api/v2/sensor/results/"+newReportID(), nil)
	req.Header.Set("Authorization", "Bearer "+key)
	rec := httptest.NewRecorder()
	auth.ServeHTTP(rec, req)
	if !reached || tenantInCtx != nil {
		t.Fatalf("reached=%v tenant context=%v (status %d)", reached, tenantInCtx, rec.Code)
	}

	// On the real routes a shared sensor's key reaches no tenant data: the
	// results routes answer 403 scope-denied, for its own report id and for
	// an organization sensor's report alike.
	theirs := newReportID()
	resp, raw := h.do(http.MethodPut, "/api/v2/sensor/results/"+theirs, v2Segment("semgrep", "1.0", "a"))
	h.expect(resp, raw, 202, "")
	tenantKey := h.key
	h.key = key
	for _, path := range []string{"/api/v2/sensor/results/" + theirs, "/api/v2/sensor/results/" + newReportID()} {
		resp, raw = h.do(http.MethodPut, path, v2Segment("semgrep", "1.0", "zzz"))
		h.expect(resp, raw, http.StatusForbidden, "scope-denied")
		resp, raw = h.do(http.MethodGet, path, nil)
		h.expect(resp, raw, http.StatusForbidden, "scope-denied")
	}
	h.key = tenantKey
	_, raw = h.do(http.MethodGet, "/api/v2/sensor/results/"+theirs, nil)
	if st := h.status(raw); st.Segments.Received != 1 {
		t.Fatalf("the organization's report changed: %+v", st)
	}
}
