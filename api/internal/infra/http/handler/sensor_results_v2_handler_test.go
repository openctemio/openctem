package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app/ingest"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/sensor"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	protov2 "github.com/openctemio/api/pkg/sensorproto/v2"
)

func v2ProblemOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var p protov2.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("body %q", rec.Body.String())
	}
	return p.Type
}

// A sensor without a tenant (a platform sensor) may not report on v2: 403
// scope-denied. Reached before any repository is used.
func TestSensorResultsV2_ScopeDenied(t *testing.T) {
	recv := ingest.NewV2Receiver(nil, nil, nil, nil, protov2.DefaultLimits(), 0, logger.NewNop())
	h := NewSensorResultsV2Handler(recv, nil, logger.NewNop())

	r := httptest.NewRequest(http.MethodPut, "/api/v2/sensor/results/0192a3b4-5c6d-7e8f-9a0b-1c2d3e4f5a6b", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("report_id", "0192a3b4-5c6d-7e8f-9a0b-1c2d3e4f5a6b")
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, sensorContextKey, &sensor.Sensor{ID: shared.NewID(), IsPlatformSensor: true})
	ctx = middleware.WithV2Body(ctx, &middleware.V2Body{Decoded: []byte(`{}`), Digest: "sha-256=:x:"})
	rec := httptest.NewRecorder()
	h.PutReport(rec, r.WithContext(ctx))
	if rec.Code != http.StatusForbidden || v2ProblemOf(t, rec) != protov2.ProblemScopeDenied.URI() {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
}

// A server fault is a retryable 500 internal problem that never echoes the
// error text.
func TestSensorResultsV2_InternalErrorIsGeneric(t *testing.T) {
	h := NewSensorResultsV2Handler(ingest.NewV2Receiver(nil, nil, nil, nil, protov2.DefaultLimits(), 0, nil), nil, logger.NewNop())
	rec := httptest.NewRecorder()
	h.fail(rec, "put_report", errors.New("pq: secret table detail\nforged log line"))
	if rec.Code != http.StatusInternalServerError || v2ProblemOf(t, rec) != protov2.ProblemInternal.URI() {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	var p protov2.Problem
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	if !p.Retryable || p.Detail != protov2.NewProblem(protov2.ProblemInternal).Detail {
		t.Fatalf("problem %+v", p)
	}
}
