package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	auditapp "github.com/openctemio/api/internal/app/audit"
	scanzoneapp "github.com/openctemio/api/internal/app/scanzone"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/scanzone"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// ScanZoneHandler serves the scan zone management API (RFC-023 Phase 1):
// /api/v1/scan-zones. Tenant from the JWT; every query is tenant-scoped.
type ScanZoneHandler struct {
	service *scanzoneapp.Service
	logger  *logger.Logger
}

// NewScanZoneHandler creates a ScanZoneHandler.
func NewScanZoneHandler(svc *scanzoneapp.Service, log *logger.Logger) *ScanZoneHandler {
	return &ScanZoneHandler{service: svc, logger: log.With("handler", "scan_zone")}
}

// ScanZoneResponse is a scan zone.
type ScanZoneResponse struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsDefault   bool      `json:"is_default"`
	Ranges      []string  `json:"ranges"`
	SensorIDs   []string  `json:"sensor_ids"`
	CreatedBy   string    `json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ScanZoneListResponse is the list of a tenant's scan zones.
type ScanZoneListResponse struct {
	Data  []ScanZoneResponse `json:"data"`
	Total int                `json:"total"`
}

// CreateScanZoneRequest creates a scan zone. ranges accepts addresses,
// CIDRs and inclusive address ranges ("10.0.0.1-10.0.0.200").
type CreateScanZoneRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	IsDefault   bool     `json:"is_default"`
	Ranges      []string `json:"ranges"`
}

// UpdateScanZoneRequest changes a scan zone; omitted fields are unchanged.
type UpdateScanZoneRequest struct {
	Name        *string   `json:"name,omitempty"`
	Description *string   `json:"description,omitempty"`
	IsDefault   *bool     `json:"is_default,omitempty"`
	Ranges      *[]string `json:"ranges,omitempty"`
}

// ScanZoneCoverageZone is the coverage of one zone.
type ScanZoneCoverageZone struct {
	ZoneID          string `json:"zone_id"`
	Name            string `json:"name"`
	IsDefault       bool   `json:"is_default"`
	HasPrivateRange bool   `json:"has_private_range"`
	AssignedSensors int    `json:"assigned_sensors"`
	HealthySensors  int    `json:"healthy_sensors"`
	Addresses       int    `json:"addresses"`
}

// ScanZoneCoverageWarning is an actionable coverage problem.
type ScanZoneCoverageWarning struct {
	Code    string `json:"code"`
	ZoneID  string `json:"zone_id,omitempty"`
	Message string `json:"message"`
}

// ScanZoneCoverageResponse is how inventory addresses fall into zones.
type ScanZoneCoverageResponse struct {
	InventoryAddresses int                       `json:"inventory_addresses"`
	InZones            int                       `json:"in_zones"`
	OutsidePublic      int                       `json:"outside_public"`
	OutsidePrivate     int                       `json:"outside_private"`
	HasDefaultZone     bool                      `json:"has_default_zone"`
	Zones              []ScanZoneCoverageZone    `json:"zones"`
	Warnings           []ScanZoneCoverageWarning `json:"warnings"`
}

func toScanZoneResponse(z *scanzone.Zone) ScanZoneResponse {
	out := ScanZoneResponse{
		ID:          z.ID.String(),
		TenantID:    z.TenantID.String(),
		Name:        z.Name,
		Description: z.Description,
		IsDefault:   z.IsDefault,
		Ranges:      z.RangeStrings(),
		SensorIDs:   make([]string, 0, len(z.SensorIDs)),
		CreatedAt:   z.CreatedAt,
		UpdatedAt:   z.UpdatedAt,
	}
	for _, id := range z.SensorIDs {
		out.SensorIDs = append(out.SensorIDs, id.String())
	}
	if z.CreatedBy != nil {
		out.CreatedBy = z.CreatedBy.String()
	}
	return out
}

// List handles GET /api/v1/scan-zones
// @Summary      List scan zones
// @Description  Every scan zone of the tenant with its ranges and assigned sensors
// @Tags         Scan Zones
// @Produce      json
// @Success      200  {object}  ScanZoneListResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-zones [get]
func (h *ScanZoneHandler) List(w http.ResponseWriter, r *http.Request) {
	zones, err := h.service.ListZones(r.Context(), middleware.GetTenantID(r.Context()))
	if err != nil {
		h.handleError(w, err)
		return
	}
	resp := ScanZoneListResponse{Data: make([]ScanZoneResponse, 0, len(zones)), Total: len(zones)}
	for _, z := range zones {
		resp.Data = append(resp.Data, toScanZoneResponse(z))
	}
	writeScanZoneJSON(w, http.StatusOK, resp)
}

// Get handles GET /api/v1/scan-zones/{id}
// @Summary      Get scan zone
// @Tags         Scan Zones
// @Produce      json
// @Param        id   path      string  true  "Scan zone ID"
// @Success      200  {object}  ScanZoneResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-zones/{id} [get]
func (h *ScanZoneHandler) Get(w http.ResponseWriter, r *http.Request) {
	z, err := h.service.GetZone(r.Context(), middleware.GetTenantID(r.Context()), chi.URLParam(r, "id"))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toScanZoneResponse(z))
}

// Create handles POST /api/v1/scan-zones
// @Summary      Create scan zone
// @Description  Ranges are validated and normalized: no overlap with the built-in deny list (loopback, link-local/metadata, multicast, unspecified), IPv4 no wider than /8, IPv6 no wider than /32, at most 256 ranges. Only the default zone may have no ranges.
// @Tags         Scan Zones
// @Accept       json
// @Produce      json
// @Param        body  body      CreateScanZoneRequest  true  "Scan zone"
// @Success      201   {object}  ScanZoneResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error  "name taken, or a default zone already exists"
// @Security     BearerAuth
// @Router       /scan-zones [post]
func (h *ScanZoneHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateScanZoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	actx := buildScanZoneAuditContext(r)
	z, err := h.service.CreateZone(r.Context(), scanzoneapp.CreateInput{
		TenantID:    actx.TenantID,
		Name:        req.Name,
		Description: req.Description,
		IsDefault:   req.IsDefault,
		Ranges:      req.Ranges,
		CreatedBy:   actx.ActorID,
	}, actx)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusCreated, toScanZoneResponse(z))
}

// Update handles PATCH /api/v1/scan-zones/{id}
// @Summary      Update scan zone
// @Description  Omitted fields are unchanged. New ranges apply to the next scan trigger; jobs already routed keep their zone.
// @Tags         Scan Zones
// @Accept       json
// @Produce      json
// @Param        id    path      string                 true  "Scan zone ID"
// @Param        body  body      UpdateScanZoneRequest  true  "Changes"
// @Success      200   {object}  ScanZoneResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-zones/{id} [patch]
func (h *ScanZoneHandler) Update(w http.ResponseWriter, r *http.Request) {
	var req UpdateScanZoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	actx := buildScanZoneAuditContext(r)
	z, err := h.service.UpdateZone(r.Context(), scanzoneapp.UpdateInput{
		TenantID:    actx.TenantID,
		ZoneID:      chi.URLParam(r, "id"),
		Name:        req.Name,
		Description: req.Description,
		IsDefault:   req.IsDefault,
		Ranges:      req.Ranges,
	}, actx)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toScanZoneResponse(z))
}

// Delete handles DELETE /api/v1/scan-zones/{id}
// @Summary      Delete scan zone
// @Description  Refused with 409 while jobs routed to the zone are queued or running.
// @Tags         Scan Zones
// @Param        id   path  string  true  "Scan zone ID"
// @Success      204
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-zones/{id} [delete]
func (h *ScanZoneHandler) Delete(w http.ResponseWriter, r *http.Request) {
	actx := buildScanZoneAuditContext(r)
	if err := h.service.DeleteZone(r.Context(), actx.TenantID, chi.URLParam(r, "id"), actx); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// AssignSensor handles PUT /api/v1/scan-zones/{id}/sensors/{sensorId}
// @Summary      Assign a sensor to a scan zone
// @Description  Idempotent. The sensor must belong to the same tenant; platform sensors cannot be assigned.
// @Tags         Scan Zones
// @Produce      json
// @Param        id        path      string  true  "Scan zone ID"
// @Param        sensorId  path      string  true  "Sensor ID"
// @Success      200       {object}  ScanZoneResponse
// @Failure      401       {object}  apierror.Error
// @Failure      403       {object}  apierror.Error
// @Failure      404       {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-zones/{id}/sensors/{sensorId} [put]
func (h *ScanZoneHandler) AssignSensor(w http.ResponseWriter, r *http.Request) {
	actx := buildScanZoneAuditContext(r)
	z, err := h.service.AssignSensor(r.Context(), actx.TenantID, chi.URLParam(r, "id"), chi.URLParam(r, "sensorId"), actx)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toScanZoneResponse(z))
}

// UnassignSensor handles DELETE /api/v1/scan-zones/{id}/sensors/{sensorId}
// @Summary      Remove a sensor from a scan zone
// @Description  Jobs of the zone still queued for that sensor go back to the zone's pool.
// @Tags         Scan Zones
// @Param        id        path  string  true  "Scan zone ID"
// @Param        sensorId  path  string  true  "Sensor ID"
// @Success      204
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-zones/{id}/sensors/{sensorId} [delete]
func (h *ScanZoneHandler) UnassignSensor(w http.ResponseWriter, r *http.Request) {
	actx := buildScanZoneAuditContext(r)
	if err := h.service.UnassignSensor(r.Context(), actx.TenantID, chi.URLParam(r, "id"), chi.URLParam(r, "sensorId"), actx); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Coverage handles GET /api/v1/scan-zones/coverage
// @Summary      Scan zone coverage
// @Description  How inventory IP addresses fall into zones (outside_private are skipped by scans), per-zone sensor health, and warnings such as private ranges without a healthy sensor.
// @Tags         Scan Zones
// @Produce      json
// @Success      200  {object}  ScanZoneCoverageResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-zones/coverage [get]
func (h *ScanZoneHandler) Coverage(w http.ResponseWriter, r *http.Request) {
	cov, err := h.service.Coverage(r.Context(), middleware.GetTenantID(r.Context()))
	if err != nil {
		h.handleError(w, err)
		return
	}
	resp := ScanZoneCoverageResponse{
		InventoryAddresses: cov.InventoryAddresses,
		InZones:            cov.InZones,
		OutsidePublic:      cov.OutsidePublic,
		OutsidePrivate:     cov.OutsidePrivate,
		HasDefaultZone:     cov.HasDefaultZone,
		Zones:              make([]ScanZoneCoverageZone, 0, len(cov.Zones)),
		Warnings:           make([]ScanZoneCoverageWarning, 0, len(cov.Warnings)),
	}
	for _, z := range cov.Zones {
		resp.Zones = append(resp.Zones, ScanZoneCoverageZone{
			ZoneID:          z.ZoneID.String(),
			Name:            z.Name,
			IsDefault:       z.IsDefault,
			HasPrivateRange: z.HasPrivateRange,
			AssignedSensors: z.AssignedSensors,
			HealthySensors:  z.HealthySensors,
			Addresses:       z.Addresses,
		})
	}
	for _, wn := range cov.Warnings {
		resp.Warnings = append(resp.Warnings, ScanZoneCoverageWarning(wn))
	}
	writeScanZoneJSON(w, http.StatusOK, resp)
}

func (h *ScanZoneHandler) handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, scanzone.ErrSensorNotFound):
		apierror.NotFound("Sensor").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Scan zone").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists), errors.Is(err, shared.ErrConflict):
		apierror.Conflict(cleanErrorMessage(err, "Scan zone conflict")).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(cleanErrorMessage(err, "Invalid scan zone")).WriteJSON(w)
	default:
		h.logger.Error("scan zone service error", "error", sanitizeLogField(err.Error()))
		apierror.InternalError(err).WriteJSON(w)
	}
}

func writeScanZoneJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func buildScanZoneAuditContext(r *http.Request) auditapp.AuditContext {
	clientIP := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		clientIP = xff
	} else if xri := r.Header.Get("X-Real-IP"); xri != "" {
		clientIP = xri
	}
	return auditapp.AuditContext{
		TenantID:   middleware.GetTenantID(r.Context()),
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: middleware.GetUsername(r.Context()),
		ActorIP:    clientIP,
		UserAgent:  r.UserAgent(),
		RequestID:  r.Header.Get("X-Request-ID"),
	}
}
