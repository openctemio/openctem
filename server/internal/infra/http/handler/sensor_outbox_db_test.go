package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// TestHeartbeatOutbox_StoredAndShown: a heartbeat carrying the outbox block
// stores it, GET /sensors/{id} and GET /sensors show it with outbox_warning,
// and a heartbeat without it leaves the snapshot untouched.
func TestHeartbeatOutbox_StoredAndShown(t *testing.T) {
	h := newSensorHarness(t)
	sh := NewSensorHandler(
		sensor.NewSensorService(postgres.NewSensorRepository(&postgres.DB{DB: h.db}), nil, logger.NewNop()),
		validator.New(), logger.NewNop())

	getSensor := func() SensorResponse {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sensors/"+h.sensorID, nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", h.sensorID)
		ctx := context.WithValue(req.Context(), middleware.TenantIDKey, h.tenantID)
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
		rec := httptest.NewRecorder()
		sh.Get(rec, req.WithContext(ctx))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET sensor: %d %s", rec.Code, rec.Body.String())
		}
		var resp SensorResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode sensor: %v", err)
		}
		return resp
	}
	listSensor := func() SensorResponse {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sensors", nil)
		req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, h.tenantID))
		rec := httptest.NewRecorder()
		sh.List(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET sensors: %d %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Items []SensorResponse `json:"items"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		for _, s := range resp.Items {
			if s.ID == h.sensorID {
				return s
			}
		}
		t.Fatal("sensor missing from list")
		return SensorResponse{}
	}
	heartbeat := func(body map[string]any) {
		t.Helper()
		h.heartbeat(body)
	}

	// Never reported: outbox is null, no warning.
	if s := getSensor(); s.Outbox != nil || s.OutboxWarning {
		t.Fatalf("before any report: outbox=%+v warning=%v", s.Outbox, s.OutboxWarning)
	}
	// The field is present as null rather than missing.
	{
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", h.sensorID)
		ctx := context.WithValue(req.Context(), middleware.TenantIDKey, h.tenantID)
		rec := httptest.NewRecorder()
		sh.Get(rec, req.WithContext(context.WithValue(ctx, chi.RouteCtxKey, rctx)))
		var raw map[string]json.RawMessage
		_ = json.Unmarshal(rec.Body.Bytes(), &raw)
		if string(raw["outbox"]) != "null" || string(raw["outbox_warning"]) != "false" {
			t.Errorf("outbox=%s outbox_warning=%s, want null/false", raw["outbox"], raw["outbox_warning"])
		}
	}

	heartbeat(map[string]any{
		"status": "running", "version": "0.7.0",
		"outbox": map[string]any{
			"pending_count": 3, "pending_bytes": 123456, "oldest_age_seconds": 600,
			"dead_letter_count": 1, "evicted_count": 0,
		},
	})
	s := getSensor()
	if s.Outbox == nil {
		t.Fatal("outbox not shown after a heartbeat that carried it")
	}
	if s.Outbox.PendingCount != 3 || s.Outbox.PendingBytes != 123456 || s.Outbox.OldestAgeSeconds != 600 ||
		s.Outbox.DeadLetterCount != 1 || s.Outbox.EvictedCount != 0 || s.Outbox.ReportedAt == "" {
		t.Errorf("outbox = %+v", *s.Outbox)
	}
	if !s.OutboxWarning {
		t.Error("outbox_warning = false with dead_letter_count = 1")
	}
	if l := listSensor(); l.Outbox == nil || *l.Outbox != *s.Outbox || !l.OutboxWarning {
		t.Errorf("list outbox = %+v warning=%v, want %+v warning=true", l.Outbox, l.OutboxWarning, *s.Outbox)
	}
	reportedAt := s.Outbox.ReportedAt

	// A heartbeat from an SDK without an outbox leaves the snapshot as it was.
	heartbeat(map[string]any{"status": "running", "version": "0.6.0"})
	if s2 := getSensor(); s2.Outbox == nil || *s2.Outbox != *s.Outbox || s2.Outbox.ReportedAt != reportedAt {
		t.Errorf("heartbeat without outbox changed the snapshot: %+v, want %+v", s2.Outbox, *s.Outbox)
	}

	// A healthy outbox clears the warning; hostile values are clamped.
	heartbeat(map[string]any{
		"status": "running",
		"outbox": map[string]any{"pending_count": -5, "pending_bytes": 10, "oldest_age_seconds": 30},
	})
	s3 := getSensor()
	if s3.Outbox == nil || s3.Outbox.PendingCount != 0 || s3.Outbox.PendingBytes != 10 || s3.OutboxWarning {
		t.Errorf("after healthy report: outbox=%+v warning=%v", s3.Outbox, s3.OutboxWarning)
	}
}
