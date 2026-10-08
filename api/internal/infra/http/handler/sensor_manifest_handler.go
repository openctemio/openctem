package handler

// Management reads of sensor manifests (docs/rfcs/RFC-033-sensor-manifest.md).

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// SensorManifestResponse is one version of a sensor's manifest: the
// sanitized document, what was ignored, and when it was seen. source is
// "sensor" (the sensor registered it) or "heartbeat" (the platform derived
// it from a sensor that registers none).
type SensorManifestResponse struct {
	Digest       string                   `json:"digest"`
	Source       string                   `json:"source" enums:"sensor,heartbeat"`
	Current      bool                     `json:"current"`
	Manifest     sensor.Manifest          `json:"manifest"`
	Ignored      []sensor.ManifestIgnored `json:"ignored"`
	FirstSeenAt  string                   `json:"first_seen_at"`
	CurrentSince string                   `json:"current_since"`
	LastSeenAt   string                   `json:"last_seen_at"`
}

// SensorManifestListResponse is a sensor's manifest versions, most recently
// current first.
type SensorManifestListResponse struct {
	Items []SensorManifestResponse `json:"items"`
}

func toSensorManifestResponse(v sensor.ManifestVersion, current string) SensorManifestResponse {
	ignored := v.Ignored
	if ignored == nil {
		ignored = []sensor.ManifestIgnored{}
	}
	return SensorManifestResponse{
		Digest: v.Digest, Source: v.Source, Current: v.Digest == current,
		Manifest: v.Manifest, Ignored: ignored,
		FirstSeenAt:  v.FirstSeenAt.UTC().Format(time.RFC3339),
		CurrentSince: v.CurrentSince.UTC().Format(time.RFC3339),
		LastSeenAt:   v.LastSeenAt.UTC().Format(time.RFC3339),
	}
}

// Manifest handles GET /api/v1/sensors/{id}/manifest
// @Summary      Sensor manifest
// @Description  The sensor's current manifest (RFC-033): build, platform, resources, concurrency ceiling, and its tools with their kind, version, capabilities and content, as the platform kept them, plus what it ignored. 404 when the sensor has none yet.
// @Tags         Sensors
// @Produce      json
// @Param        id   path      string  true  "Sensor ID"
// @Success      200  {object}  SensorManifestResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id}/manifest [get]
func (h *SensorHandler) Manifest(w http.ResponseWriter, r *http.Request) {
	sensorID := chi.URLParam(r, "id")
	if sensorID == "" {
		apierror.BadRequest("Sensor ID is required").WriteJSON(w)
		return
	}
	v, err := h.service.CurrentManifest(r.Context(), middleware.GetTenantID(r.Context()), sensorID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toSensorManifestResponse(*v, v.Digest))
}

// Manifests handles GET /api/v1/sensors/{id}/manifests
// @Summary      Sensor manifest history
// @Description  The sensor's manifest versions, most recently current first (RFC-033). The newest 50 are kept, older ones for 90 days.
// @Tags         Sensors
// @Produce      json
// @Param        id     path      string  true   "Sensor ID"
// @Param        limit  query     int     false  "Versions (1-50)"  default(50)
// @Success      200  {object}  SensorManifestListResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id}/manifests [get]
func (h *SensorHandler) Manifests(w http.ResponseWriter, r *http.Request) {
	sensorID := chi.URLParam(r, "id")
	if sensorID == "" {
		apierror.BadRequest("Sensor ID is required").WriteJSON(w)
		return
	}
	tenantID := middleware.GetTenantID(r.Context())
	limit, ok := listLimit(w, r, sensor.ManifestVersionsKept, sensor.ManifestVersionsKept)
	if !ok {
		return
	}
	versions, err := h.service.ListManifests(r.Context(), tenantID, sensorID, limit)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	current := ""
	if a, err := h.service.GetSensor(r.Context(), tenantID, sensorID); err == nil {
		current = a.ManifestDigest
	}
	resp := SensorManifestListResponse{Items: make([]SensorManifestResponse, 0, len(versions))}
	for _, v := range versions {
		resp.Items = append(resp.Items, toSensorManifestResponse(v, current))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
