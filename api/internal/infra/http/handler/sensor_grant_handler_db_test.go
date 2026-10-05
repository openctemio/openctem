package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/app/sensorgrant"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// TestSensorGrantHandler_Permissions (RFC-052 §5.3, threat 16): the grant
// route resolves which permission a change needs from the change itself; a
// holder of sensors:grant:narrow alone gets 403 for a promotion and 200 for a
// narrowing; another tenant gets 404.
func TestSensorGrantHandler_Permissions(t *testing.T) {
	h := newV1Harness(t)
	pg := &postgres.DB{DB: h.db}
	sh := NewSensorHandler(app.NewSensorService(postgres.NewSensorRepository(pg), nil, logger.NewNop()), validator.New(), logger.NewNop())
	grants := postgres.NewSensorGrantRepository(pg)
	sh.SetGrantService(sensorgrant.NewService(grants, postgres.NewSensorRepository(pg), logger.NewNop()))
	userID := shared.NewID().String()
	if _, err := h.db.Exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'grant admin')`, userID, userID+"@grant.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM users WHERE id = $1`, userID) })

	call := func(method, tenant string, perms []string, body any) (int, map[string]any) {
		t.Helper()
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, "/api/v1/sensors/"+h.sensorID+"/grant", &buf)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", h.sensorID)
		ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant)
		ctx = context.WithValue(ctx, middleware.UserIDKey, userID)
		ctx = context.WithValue(ctx, middleware.IsAdminKey, false)
		ctx = context.WithValue(ctx, middleware.FetchedPermissionsKey, perms)
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
		rec := httptest.NewRecorder()
		if method == http.MethodGet {
			sh.GetGrant(rec, req.WithContext(ctx))
		} else {
			sh.UpdateGrant(rec, req.WithContext(ctx))
		}
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	narrow := []string{string(permission.SensorsGrantNarrow)}
	widen := []string{string(permission.SensorsGrantNarrow), string(permission.SensorsGrantWiden)}

	// The list flags: the harness sensor is New with the default profile;
	// another tenant sees none of it.
	sumReq := func(tenant string) SensorGrantSummaries {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sensors/grant-summaries", nil)
		rec := httptest.NewRecorder()
		sh.ListGrantSummaries(rec, req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, tenant)))
		var out SensorGrantSummaries
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	if s := sumReq(h.tenantID); len(s.Data) != 1 || s.Data[0].SensorID != h.sensorID || s.Data[0].TrustLevel != "new" || s.Data[0].LegacyBroad {
		t.Fatalf("summaries: %+v", s)
	}
	if s := sumReq(shared.NewID().String()); len(s.Data) != 0 {
		t.Fatalf("cross-tenant summaries: %+v", s)
	}

	code, g := call(http.MethodGet, h.tenantID, nil, nil)
	if code != http.StatusOK || g["trust_level"] != "new" || g["legacy_broad"] != false {
		t.Fatalf("GET grant: %d %v", code, g)
	}
	if eff, _ := g["effective"].(map[string]any); eff["tier_ceiling"] != float64(0) || eff["allow_push_ingest"] != false {
		t.Fatalf("effective view: %v", g["effective"])
	}
	if code, _ := call(http.MethodGet, shared.NewID().String(), nil, nil); code != http.StatusNotFound {
		t.Fatalf("cross-tenant GET: %d", code)
	}

	promote := map[string]any{"version": g["version"], "trust_level": "trusted", "job_types": g["job_types"],
		"tier_ceiling": g["tier_ceiling"], "target_network": g["target_network"], "remote_actions": []string{}}
	if code, out := call(http.MethodPut, h.tenantID, narrow, promote); code != http.StatusForbidden {
		t.Fatalf("narrow-only promote: %d %v", code, out)
	}
	if code, _ := call(http.MethodPut, shared.NewID().String(), widen, promote); code != http.StatusNotFound {
		t.Fatalf("cross-tenant PUT: %d", code)
	}
	if code, _ := call(http.MethodPut, h.tenantID, widen, map[string]any{"version": 1, "tier_ceiling": 9}); code != http.StatusBadRequest {
		t.Fatalf("invalid grant: %d", code)
	}
	if code, _ := call(http.MethodPut, h.tenantID, widen, map[string]any{"version": 1, "owner": "x"}); code != http.StatusBadRequest {
		t.Fatalf("unknown field accepted: %d", code)
	}
	code, out := call(http.MethodPut, h.tenantID, widen, promote)
	if code != http.StatusOK || out["trust_level"] != "trusted" || out["version"] != float64(2) {
		t.Fatalf("promote: %d %v", code, out)
	}
	if code, _ := call(http.MethodPut, h.tenantID, widen, promote); code != http.StatusConflict {
		t.Fatalf("stale version: %d", code)
	}
	demote := promote
	demote["version"], demote["trust_level"] = 2, "new"
	if code, out := call(http.MethodPut, h.tenantID, narrow, demote); code != http.StatusOK || out["trust_level"] != "new" {
		t.Fatalf("narrow-only demote: %d %v", code, out)
	}
}
