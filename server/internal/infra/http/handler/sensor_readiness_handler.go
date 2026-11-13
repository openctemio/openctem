package handler

// GET /api/v1/sensors/{id}/readiness: what still stops a sensor from
// scanning, in fix order (internal/app/sensor/readiness.go,
// docs/architecture/sensor-readiness.md).

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	sensorapp "github.com/openctemio/openctem/server/internal/app/sensor"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/domain/permission"
)

// SetReadiness wires the readiness checklist (nil: the route answers 503).
func (h *SensorHandler) SetReadiness(s *sensorapp.ReadinessService) { h.readiness = s }

// Readiness handles GET /api/v1/sensors/{id}/readiness.
//
// @Summary Why can this sensor not scan yet
// @Description The sensor's readiness checklist, in the order to fix it: online, trusted for active work, host allows private targets, host kill switch, networks (scan zones) assigned, those networks in scope (or waiting for an approval), tool confinement on the host. Each item has a state (ok, blocked, waiting, unknown, not_applicable) and, when it can be fixed, the one action, the permission it needs and whether the caller holds it. Reads only; changes nothing. The confinement item reads unknown for a caller without sensors:write (host details stay with owners and administrators). Another organization's sensor, and a shared sensor, is 404.
// @Tags Sensors
// @Produce json
// @Param id path string true "Sensor ID"
// @Success 200 {object} sensorapp.Readiness
// @Failure 404 {object} apierror.Error
// @Failure 503 {object} apierror.Error
// @Security BearerAuth
// @Router /sensors/{id}/readiness [get]
func (h *SensorHandler) Readiness(w http.ResponseWriter, r *http.Request) {
	if h.readiness == nil {
		apierror.ServiceUnavailable("The readiness check is not available").WriteJSON(w)
		return
	}
	ctx := r.Context()
	caller := sensorapp.ReadinessCaller{
		Has:          func(p string) bool { return middleware.HasPermission(ctx, p) },
		SeesHostInfo: middleware.HasPermission(ctx, string(permission.SensorsWrite)),
	}
	v, err := h.readiness.Readiness(ctx, middleware.GetTenantID(ctx), chi.URLParam(r, "id"), caller)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}
