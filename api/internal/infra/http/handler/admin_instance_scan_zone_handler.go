package handler

// Console routes of instance scan zones (docs/rfcs/RFC-100-shared-sensors.md
// §6.1). Any administrator reads; a super admin creates, changes, deletes,
// sets the shared sensors of and assigns a zone to organizations, with a
// reason and a fresh authenticator code (route-level step-up). The service
// records every change with the job signer first and writes a critical
// admin audit row.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/instancezone"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	zonedom "github.com/openctemio/openctem/api/pkg/domain/instancezone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const stepUpPurposeInstanceZone = "instance scan zone change"

// AdminInstanceScanZoneHandler serves the console routes.
type AdminInstanceScanZoneHandler struct {
	svc    *instancezone.Service
	stepUp StepUpVerifier
	logger *logger.Logger
}

// NewAdminInstanceScanZoneHandler creates the handler.
func NewAdminInstanceScanZoneHandler(svc *instancezone.Service, stepUp StepUpVerifier, log *logger.Logger) *AdminInstanceScanZoneHandler {
	return &AdminInstanceScanZoneHandler{svc: svc, stepUp: stepUp, logger: log.With("handler", "admin_instance_scan_zones")}
}

// InstanceScanZoneResponse is one instance scan zone.
type InstanceScanZoneResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Ranges are canonical private CIDRs.
	Ranges []string `json:"ranges"`
	// SensorIDs are the shared sensors that serve the zone.
	SensorIDs []string `json:"sensor_ids"`
	// OrganizationIDs are the organizations the zone is assigned to.
	OrganizationIDs []string `json:"organization_ids"`
}

// InstanceScanZoneListResponse lists the zones.
type InstanceScanZoneListResponse struct {
	Items []InstanceScanZoneResponse `json:"items"`
}

// InstanceScanZoneRequest creates or changes a zone.
type InstanceScanZoneRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Ranges      []string `json:"ranges"`
	Reason      string   `json:"reason"`
	TOTPCode    string   `json:"totp_code"`
}

// InstanceScanZoneMembersRequest replaces the sensors or organizations of a
// zone.
type InstanceScanZoneMembersRequest struct {
	IDs      []string `json:"ids"`
	Reason   string   `json:"reason"`
	TOTPCode string   `json:"totp_code"`
}

// DeleteInstanceScanZoneRequest deletes a zone.
type DeleteInstanceScanZoneRequest struct {
	Reason   string `json:"reason"`
	TOTPCode string `json:"totp_code"`
}

func zoneResponse(z *zonedom.Zone) InstanceScanZoneResponse {
	out := InstanceScanZoneResponse{ID: z.ID.String(), Name: z.Name, Description: z.Description, Ranges: z.Ranges,
		SensorIDs: make([]string, 0, len(z.SensorIDs)), OrganizationIDs: make([]string, 0, len(z.TenantIDs))}
	for _, id := range z.SensorIDs {
		out.SensorIDs = append(out.SensorIDs, id.String())
	}
	for _, id := range z.TenantIDs {
		out.OrganizationIDs = append(out.OrganizationIDs, id.String())
	}
	return out
}

// List returns every instance scan zone.
// @Summary      Instance scan zones
// @Description  Private ranges shared sensors may scan for the organizations each zone is assigned to. Any administrator.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  InstanceScanZoneListResponse
// @Router       /admin/instance-scan-zones [get]
func (h *AdminInstanceScanZoneHandler) List(w http.ResponseWriter, r *http.Request) {
	zones, err := h.svc.List(r.Context())
	if err != nil {
		h.writeErr(w, err)
		return
	}
	out := InstanceScanZoneListResponse{Items: make([]InstanceScanZoneResponse, 0, len(zones))}
	for _, z := range zones {
		out.Items = append(out.Items, zoneResponse(z))
	}
	writeJSON(w, http.StatusOK, out)
}

// Get returns one zone.
// @Summary      Instance scan zone
// @Description  One instance scan zone. Any administrator.
// @Tags         Admin System
// @Produce      json
// @Param        zone_id path      string  true  "Zone ID"
// @Success      200  {object}  InstanceScanZoneResponse
// @Failure      404  {object}  apierror.Error
// @Router       /admin/instance-scan-zones/{zone_id} [get]
func (h *AdminInstanceScanZoneHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := zoneIDParam(w, r)
	if !ok {
		return
	}
	z, err := h.svc.Get(r.Context(), id)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, zoneResponse(z))
}

// Create adds a zone.
// @Summary      Create an instance scan zone
// @Description  Super admin with a reason and a fresh authenticator code (route-level step-up). Ranges must lie wholly inside private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7). The zone has no sensors and no organizations until they are set. The job signer records the zone before it is saved. Audited (critical).
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      InstanceScanZoneRequest  true  "Zone"
// @Success      201  {object}  InstanceScanZoneResponse
// @Failure      409  {object}  apierror.Error
// @Router       /admin/instance-scan-zones [post]
func (h *AdminInstanceScanZoneHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req InstanceScanZoneRequest
	c, ok := h.decode(w, r, &req, func() (string, string) { return req.Reason, req.TOTPCode })
	if !ok {
		return
	}
	z, err := h.svc.Create(r.Context(), req.Name, req.Description, req.Ranges, c)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, zoneResponse(z))
}

// Update changes a zone's name, description and ranges.
// @Summary      Change an instance scan zone
// @Description  Super admin with a reason and a fresh authenticator code (route-level step-up). Audited (critical).
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        zone_id  path      string                   true  "Zone ID"
// @Param        request  body      InstanceScanZoneRequest  true  "Zone"
// @Success      200  {object}  InstanceScanZoneResponse
// @Failure      404  {object}  apierror.Error
// @Router       /admin/instance-scan-zones/{zone_id} [put]
func (h *AdminInstanceScanZoneHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, ok := zoneIDParam(w, r)
	if !ok {
		return
	}
	var req InstanceScanZoneRequest
	c, ok := h.decode(w, r, &req, func() (string, string) { return req.Reason, req.TOTPCode })
	if !ok {
		return
	}
	z, err := h.svc.Update(r.Context(), id, req.Name, req.Description, req.Ranges, c)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, zoneResponse(z))
}

// Delete removes a zone.
// @Summary      Delete an instance scan zone
// @Description  Super admin with a reason and a fresh authenticator code (route-level step-up). Queued shared jobs of the zone are never signed again. Audited (critical).
// @Tags         Admin System
// @Accept       json
// @Param        zone_id  path  string                         true  "Zone ID"
// @Param        request  body  DeleteInstanceScanZoneRequest  true  "Reason"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Router       /admin/instance-scan-zones/{zone_id} [delete]
func (h *AdminInstanceScanZoneHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, ok := zoneIDParam(w, r)
	if !ok {
		return
	}
	var req DeleteInstanceScanZoneRequest
	c, ok := h.decode(w, r, &req, func() (string, string) { return req.Reason, req.TOTPCode })
	if !ok {
		return
	}
	if err := h.svc.Delete(r.Context(), id, c); err != nil {
		h.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SetSensors replaces the shared sensors that serve a zone.
// @Summary      Set the shared sensors of an instance scan zone
// @Description  Super admin with a reason and a fresh authenticator code (route-level step-up). Only shared (instance) sensors. Audited (critical).
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        zone_id  path      string                          true  "Zone ID"
// @Param        request  body      InstanceScanZoneMembersRequest  true  "Sensor IDs"
// @Success      200  {object}  InstanceScanZoneResponse
// @Router       /admin/instance-scan-zones/{zone_id}/sensors [put]
func (h *AdminInstanceScanZoneHandler) SetSensors(w http.ResponseWriter, r *http.Request) {
	h.setMembers(w, r, h.svc.SetSensors)
}

// SetOrganizations replaces the organizations a zone is assigned to.
// @Summary      Assign an instance scan zone to organizations
// @Description  Super admin with a reason and a fresh authenticator code (route-level step-up). An organization's internal targets go to shared sensors only inside a zone assigned to it. Audited (critical).
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        zone_id  path      string                          true  "Zone ID"
// @Param        request  body      InstanceScanZoneMembersRequest  true  "Organization IDs"
// @Success      200  {object}  InstanceScanZoneResponse
// @Router       /admin/instance-scan-zones/{zone_id}/organizations [put]
func (h *AdminInstanceScanZoneHandler) SetOrganizations(w http.ResponseWriter, r *http.Request) {
	h.setMembers(w, r, h.svc.SetTenants)
}

type memberSetter func(ctx context.Context, id shared.ID, ids []shared.ID, c instancezone.Change) (*zonedom.Zone, error)

func (h *AdminInstanceScanZoneHandler) setMembers(w http.ResponseWriter, r *http.Request, set memberSetter) {
	id, ok := zoneIDParam(w, r)
	if !ok {
		return
	}
	var req InstanceScanZoneMembersRequest
	c, ok := h.decode(w, r, &req, func() (string, string) { return req.Reason, req.TOTPCode })
	if !ok {
		return
	}
	ids := make([]shared.ID, 0, len(req.IDs))
	for _, s := range req.IDs {
		mid, err := shared.IDFromString(s)
		if err != nil {
			apierror.BadRequest("ids must be uuids").WriteJSON(w)
			return
		}
		ids = append(ids, mid)
	}
	z, err := set(r.Context(), id, ids, c)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, zoneResponse(z))
}

func (h *AdminInstanceScanZoneHandler) decode(w http.ResponseWriter, r *http.Request, dst any, fields func() (string, string)) (instancezone.Change, bool) {
	actor := middleware.GetAdminUser(r.Context())
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
		return instancezone.Change{}, false
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(dst); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return instancezone.Change{}, false
	}
	reason, code := fields()
	if reason == "" || len(reason) > 1000 {
		apierror.BadRequest("a reason (at most 1000 characters) is required").WriteJSON(w)
		return instancezone.Change{}, false
	}
	if !confirmAdminStepUp(w, r, h.stepUp, code, stepUpPurposeInstanceZone, h.logger) {
		return instancezone.Change{}, false
	}
	return instancezone.Change{Actor: actor, Reason: reason, IP: middleware.ClientIP(r), UserAgent: r.UserAgent()}, true
}

func zoneIDParam(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(chi.URLParam(r, "zone_id"))
	if err != nil {
		apierror.NotFound("Instance scan zone").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

func (h *AdminInstanceScanZoneHandler) writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Instance scan zone").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, instancezone.ErrSignerRefused), errors.Is(err, shared.ErrConflict):
		apierror.Conflict(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("not allowed").WriteJSON(w)
	default:
		h.logger.Error("instance scan zone", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not complete the request").WriteJSON(w)
	}
}
