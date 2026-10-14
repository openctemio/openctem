package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/sensor/sensortest"

	"github.com/go-chi/chi/v5"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/app/sensorgrant"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

type stepUpGate struct{ err error }

func (g stepUpGate) RequireRecentAuth(context.Context, string) error { return g.err }

// TestSensorGrantSuggestion_Handler: the suggestion of a legacy-broad sensor
// is read and applied by its own tenant only; apply answers the step-up codes
// the console's re-authentication dialog handles and narrows the grant.
func TestSensorGrantSuggestion_Handler(t *testing.T) {
	h := newGrantHarness(t)
	pg := &postgres.DB{DB: h.db}
	grants := postgres.NewSensorGrantRepository(pg)
	newHandler := func(gate shared.RecentAuthGate) *SensorHandler {
		sh := NewSensorHandler(sensorapp.NewSensorService(postgres.NewSensorRepository(pg), nil, logger.NewNop()), validator.New(), logger.NewNop())
		svc := sensorgrant.NewService(grants, postgres.NewSensorRepository(pg), logger.NewNop())
		svc.SetUsage(grants, postgres.NewSensorRepository(pg))
		if gate != nil {
			svc.SetStepUpGate(gate)
		}
		sh.SetGrantService(svc)
		return sh
	}
	userID := shared.NewID().String()
	for _, q := range []string{
		`INSERT INTO users (id, email, name) VALUES ('` + userID + `', '` + userID + `@grant.test', 'grant admin')`,
		`UPDATE sensors SET trust_level = 'trusted' WHERE id = '` + h.sensorID + `'`,
		`UPDATE sensor_grants SET profile = 'legacy-broad', job_types = NULL, tier_ceiling = 2, allow_credentials = TRUE,
			allow_push_ingest = TRUE WHERE sensor_id = '` + h.sensorID + `'`,
		`INSERT INTO commands (tenant_id, sensor_id, type, payload, status) VALUES ('` + h.tenantID + `', '` + h.sensorID + `',
			'scan', '{"scanner":"httpx","targets":["https://example.com"]}', 'completed')`,
	} {
		if _, err := h.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	// The sensor is a released one: it reports httpx's contract.
	tid, _ := shared.IDFromString(h.tenantID)
	sid, _ := shared.IDFromString(h.sensorID)
	if err := sensortest.SaveReleased(context.Background(), postgres.NewSensorRepository(&postgres.DB{DB: h.db}), &tid, sid, []string{"httpx"}, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = h.db.Exec(`DELETE FROM commands WHERE tenant_id = $1`, h.tenantID)
		_, _ = h.db.Exec(`DELETE FROM users WHERE id = $1`, userID)
	})
	call := func(sh *SensorHandler, apply bool, tenant string, perms []string, body any) (int, map[string]any) {
		t.Helper()
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sensors/"+h.sensorID+"/grant/suggestion", &buf)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", h.sensorID)
		ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant)
		ctx = context.WithValue(ctx, middleware.UserIDKey, userID)
		ctx = context.WithValue(ctx, middleware.IsAdminKey, false)
		ctx = context.WithValue(ctx, middleware.FetchedPermissionsKey, perms)
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
		rec := httptest.NewRecorder()
		if apply {
			sh.ApplyGrantSuggestion(rec, req.WithContext(ctx))
		} else {
			sh.GetGrantSuggestion(rec, req.WithContext(ctx))
		}
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	narrow := []string{string(permission.SensorsGrantNarrow)}
	sh := newHandler(stepUpGate{})

	code, sug := call(sh, false, h.tenantID, narrow, nil)
	if code != http.StatusOK || sug["profile"] != "easm-external" || sug["available"] != true || sug["current_profile"] != "legacy-broad" {
		t.Fatalf("suggestion: %d %v", code, sug)
	}
	body := map[string]any{"version": sug["current_version"], "profile": sug["profile"]}
	if code, _ := call(sh, false, shared.NewID().String(), narrow, nil); code != http.StatusNotFound {
		t.Fatalf("cross-tenant suggestion: %d", code)
	}
	if code, _ := call(sh, true, shared.NewID().String(), narrow, body); code != http.StatusNotFound {
		t.Fatalf("cross-tenant apply: %d", code)
	}
	if code, _ := call(sh, true, h.tenantID, nil, body); code != http.StatusForbidden {
		t.Fatalf("apply without a grant permission: %d", code)
	}
	if code, _ := call(sh, true, h.tenantID, narrow, map[string]any{"version": 1}); code != http.StatusBadRequest {
		t.Fatalf("apply without a profile: %d", code)
	}
	if code, out := call(newHandler(stepUpGate{err: middleware.ErrStepUpRequired}), true, h.tenantID, narrow, body); code != http.StatusForbidden || out["code"] != string(middleware.CodeStepUpRequired) {
		t.Fatalf("apply without step-up: %d %v", code, out)
	}
	if code, out := call(newHandler(nil), true, h.tenantID, narrow, body); code != http.StatusForbidden || out["code"] != string(middleware.CodeStepUpUnavailable) {
		t.Fatalf("apply with step-up not wired: %d %v", code, out)
	}
	if code, _ := call(sh, true, h.tenantID, narrow, map[string]any{"version": sug["current_version"], "profile": "internal-network-scanner"}); code != http.StatusConflict {
		t.Fatalf("apply a stale suggestion: %d", code)
	}
	code, out := call(sh, true, h.tenantID, narrow, body)
	if code != http.StatusOK || out["profile"] != "easm-external" || out["target_network"] != "public" || out["legacy_broad"] != false {
		t.Fatalf("apply: %d %v", code, out)
	}
}
