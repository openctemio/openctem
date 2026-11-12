package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// OwnSensor guards every tenant route on one sensor (/sensors/{id}/...): the
// sensor must be one of the caller's organization's own sensors. A sensor of
// another organization and a shared platform sensor (whatever its row's
// tenant_id) both answer the same 404 before the route's handler runs, so no
// read or write on the tenant plane reaches a platform sensor, today's routes
// and any added later. Platform sensors are managed from the platform admin
// console only (RFC-022).
func (h *SensorHandler) OwnSensor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID := middleware.GetTenantID(r.Context())
		if _, err := shared.IDFromString(tenantID); err != nil {
			apierror.Unauthorized("").WriteJSON(w)
			return
		}
		sensorID := chi.URLParam(r, "id")
		if _, err := shared.IDFromString(sensorID); err != nil {
			apierror.BadRequest("Invalid sensor id").WriteJSON(w)
			return
		}
		// GetSensor finds only the tenant's own sensors (never a platform
		// sensor).
		if _, err := h.service.GetSensor(r.Context(), tenantID, sensorID); err != nil {
			if errors.Is(err, shared.ErrNotFound) {
				apierror.NotFound("Sensor").WriteJSON(w)
				return
			}
			h.logger.Error("sensor ownership check", "error", err)
			apierror.InternalServerError("").WriteJSON(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// platformText is s as a tenant may read it: for a platform job, the
// platform sensor's own addresses and paths are masked.
func platformText(platform bool, s string) string {
	if !platform {
		return s
	}
	return sensordom.RedactPlatformText(s)
}

// redactPlatformJSON masks a platform sensor's own addresses and paths in
// every string of a JSON document it wrote. A document that does not decode
// is dropped rather than shown unmasked.
func redactPlatformJSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	out, err := json.Marshal(sensordom.RedactPlatformValue(v))
	if err != nil {
		return nil
	}
	return out
}
