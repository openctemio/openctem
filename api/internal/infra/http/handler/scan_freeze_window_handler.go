package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	scanfreezeapp "github.com/openctemio/openctem/api/internal/app/scanfreeze"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/scanfreeze"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ScanFreezeWindowHandler serves /api/v1/scan-freeze-windows: times in
// which active scan work of the tenant, or of one scan zone, is not
// dispatched. Tenant from the JWT; every query is tenant-scoped, and a
// window or zone of another tenant is 404.
type ScanFreezeWindowHandler struct {
	service *scanfreezeapp.Service
	logger  *logger.Logger
}

// NewScanFreezeWindowHandler creates a ScanFreezeWindowHandler.
func NewScanFreezeWindowHandler(svc *scanfreezeapp.Service, log *logger.Logger) *ScanFreezeWindowHandler {
	return &ScanFreezeWindowHandler{service: svc, logger: log.With("handler", "scan_freeze_window")}
}

// ScanFreezeWindowResponse is a freeze window. active and active_until say
// whether it holds active scan work now and until when.
type ScanFreezeWindowResponse struct {
	ID          string     `json:"id"`
	ScanZoneID  *string    `json:"scan_zone_id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Timezone    string     `json:"timezone"`
	Recurrence  string     `json:"recurrence" enums:"once,weekly"`
	StartsAt    *time.Time `json:"starts_at,omitempty"`
	EndsAt      *time.Time `json:"ends_at,omitempty"`
	Days        []int      `json:"days,omitempty"`
	StartTime   string     `json:"start_time,omitempty"`
	EndTime     string     `json:"end_time,omitempty"`
	Enabled     bool       `json:"enabled"`
	Active      bool       `json:"active"`
	ActiveUntil *time.Time `json:"active_until,omitempty"`
	CreatedBy   string     `json:"created_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// ScanFreezeWindowListResponse lists freeze windows.
type ScanFreezeWindowListResponse struct {
	Data  []ScanFreezeWindowResponse `json:"data"`
	Total int                        `json:"total"`
}

// CreateScanFreezeWindowRequest creates a freeze window. A one-off window
// takes starts_at and ends_at (at most 31 days, ending in the future); a
// weekly window takes days (ISO, 1 Monday to 7 Sunday), start_time and
// end_time ("HH:MM" wall-clock in timezone; an end not after the start ends
// the next day). scan_zone_id empty freezes the whole organization.
type CreateScanFreezeWindowRequest struct {
	ScanZoneID  string     `json:"scan_zone_id,omitempty"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Timezone    string     `json:"timezone"`
	Recurrence  string     `json:"recurrence" enums:"once,weekly"`
	StartsAt    *time.Time `json:"starts_at,omitempty"`
	EndsAt      *time.Time `json:"ends_at,omitempty"`
	Days        []int      `json:"days,omitempty"`
	StartTime   string     `json:"start_time,omitempty"`
	EndTime     string     `json:"end_time,omitempty"`
	Enabled     *bool      `json:"enabled,omitempty"`
}

// UpdateScanFreezeWindowRequest changes a freeze window; omitted fields are
// unchanged. The zone cannot change.
type UpdateScanFreezeWindowRequest struct {
	Name        *string    `json:"name,omitempty"`
	Description *string    `json:"description,omitempty"`
	Timezone    *string    `json:"timezone,omitempty"`
	Recurrence  *string    `json:"recurrence,omitempty" enums:"once,weekly"`
	StartsAt    *time.Time `json:"starts_at,omitempty"`
	EndsAt      *time.Time `json:"ends_at,omitempty"`
	Days        *[]int     `json:"days,omitempty"`
	StartTime   *string    `json:"start_time,omitempty"`
	EndTime     *string    `json:"end_time,omitempty"`
	Enabled     *bool      `json:"enabled,omitempty"`
}

func toScanFreezeWindowResponse(w *scanfreeze.Window) ScanFreezeWindowResponse {
	out := ScanFreezeWindowResponse{
		ID:          w.ID.String(),
		Name:        w.Name,
		Description: w.Description,
		Timezone:    w.Timezone,
		Recurrence:  string(w.Recurrence),
		StartsAt:    w.StartsAt,
		EndsAt:      w.EndsAt,
		Enabled:     w.Enabled,
		Active:      w.ActiveUntil != nil,
		ActiveUntil: w.ActiveUntil,
		CreatedAt:   w.CreatedAt,
		UpdatedAt:   w.UpdatedAt,
	}
	if w.ScanZoneID != nil {
		z := w.ScanZoneID.String()
		out.ScanZoneID = &z
	}
	if w.Recurrence == scanfreeze.RecurrenceWeekly {
		out.Days = w.Days
		out.StartTime = scanfreeze.FormatMinute(w.StartMinute)
		out.EndTime = scanfreeze.FormatMinute(w.EndMinute)
	}
	if w.CreatedBy != nil {
		out.CreatedBy = w.CreatedBy.String()
	}
	return out
}

// List handles GET /api/v1/scan-freeze-windows
// @Summary      List scan freeze windows
// @Description  The organization's freeze windows, each with whether it is active now. scan_zone_id lists one zone's windows; scope=tenant lists only the windows that freeze the whole organization.
// @Tags         Scan Freeze Windows
// @Produce      json
// @Param        scan_zone_id  query     string  false  "Scan zone ID"
// @Param        scope         query     string  false  "tenant: only organization-wide windows"  Enums(tenant)
// @Success      200  {object}  ScanFreezeWindowListResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-freeze-windows [get]
func (h *ScanFreezeWindowHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ws, err := h.service.List(r.Context(), scanfreezeapp.ListInput{
		TenantID:   middleware.GetTenantID(r.Context()),
		ScanZoneID: q.Get("scan_zone_id"),
		TenantWide: q.Get("scope") == "tenant",
	})
	if err != nil {
		h.handleError(w, err)
		return
	}
	resp := ScanFreezeWindowListResponse{Data: make([]ScanFreezeWindowResponse, 0, len(ws)), Total: len(ws)}
	for _, fw := range ws {
		resp.Data = append(resp.Data, toScanFreezeWindowResponse(fw))
	}
	writeScanZoneJSON(w, http.StatusOK, resp)
}

// Get handles GET /api/v1/scan-freeze-windows/{id}
// @Summary      Get scan freeze window
// @Tags         Scan Freeze Windows
// @Produce      json
// @Param        id   path      string  true  "Freeze window ID"
// @Success      200  {object}  ScanFreezeWindowResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-freeze-windows/{id} [get]
func (h *ScanFreezeWindowHandler) Get(w http.ResponseWriter, r *http.Request) {
	fw, err := h.service.Get(r.Context(), middleware.GetTenantID(r.Context()), chi.URLParam(r, "id"))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toScanFreezeWindowResponse(fw))
}

// Create handles POST /api/v1/scan-freeze-windows
// @Summary      Create scan freeze window
// @Description  While the window is active, active (T1/T2) scan work of the organization, or of the zone, is not dispatched: scheduled runs are deferred to the window's end, other triggers are refused (409 SCAN_FREEZE_ACTIVE) unless the caller overrides with scans:freeze:override. Passive work and ingest continue. At most 50 windows per organization.
// @Tags         Scan Freeze Windows
// @Accept       json
// @Produce      json
// @Param        body  body      CreateScanFreezeWindowRequest  true  "Freeze window"
// @Success      201   {object}  ScanFreezeWindowResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error  "scan zone not in this organization"
// @Security     BearerAuth
// @Router       /scan-freeze-windows [post]
func (h *ScanFreezeWindowHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateScanFreezeWindowRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	actx := buildScanZoneAuditContext(r)
	fw, err := h.service.Create(r.Context(), scanfreezeapp.CreateInput{
		TenantID:   actx.TenantID,
		ScanZoneID: req.ScanZoneID,
		CreatedBy:  actx.ActorID,
		Spec: scanfreeze.Spec{
			Name: req.Name, Description: req.Description, Timezone: req.Timezone,
			Recurrence: scanfreeze.Recurrence(req.Recurrence),
			StartsAt:   req.StartsAt, EndsAt: req.EndsAt,
			Days: req.Days, StartTime: req.StartTime, EndTime: req.EndTime,
			Enabled: enabled,
		},
	}, actx)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusCreated, toScanFreezeWindowResponse(fw))
}

// Update handles PATCH /api/v1/scan-freeze-windows/{id}
// @Summary      Update scan freeze window
// @Description  Omitted fields are unchanged; the zone cannot change. Disabling a window releases the work it held.
// @Tags         Scan Freeze Windows
// @Accept       json
// @Produce      json
// @Param        id    path      string                         true  "Freeze window ID"
// @Param        body  body      UpdateScanFreezeWindowRequest  true  "Changes"
// @Success      200   {object}  ScanFreezeWindowResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-freeze-windows/{id} [patch]
func (h *ScanFreezeWindowHandler) Update(w http.ResponseWriter, r *http.Request) {
	var req UpdateScanFreezeWindowRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	actx := buildScanZoneAuditContext(r)
	in := scanfreezeapp.UpdateInput{
		TenantID: actx.TenantID, WindowID: chi.URLParam(r, "id"),
		Name: req.Name, Description: req.Description, Timezone: req.Timezone,
		StartsAt: req.StartsAt, EndsAt: req.EndsAt, Days: req.Days,
		StartTime: req.StartTime, EndTime: req.EndTime, Enabled: req.Enabled,
	}
	if req.Recurrence != nil {
		rec := scanfreeze.Recurrence(*req.Recurrence)
		in.Recurrence = &rec
	}
	fw, err := h.service.Update(r.Context(), in, actx)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toScanFreezeWindowResponse(fw))
}

// Delete handles DELETE /api/v1/scan-freeze-windows/{id}
// @Summary      Delete scan freeze window
// @Tags         Scan Freeze Windows
// @Param        id   path  string  true  "Freeze window ID"
// @Success      204
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-freeze-windows/{id} [delete]
func (h *ScanFreezeWindowHandler) Delete(w http.ResponseWriter, r *http.Request) {
	actx := buildScanZoneAuditContext(r)
	if err := h.service.Delete(r.Context(), actx.TenantID, chi.URLParam(r, "id"), actx); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ScanFreezeWindowHandler) handleError(w http.ResponseWriter, err error) {
	var de *shared.DomainError
	code := func(fallback apierror.Code) apierror.Code {
		if errors.As(err, &de) && de.Code != "" {
			return apierror.Code(de.Code)
		}
		return fallback
	}
	switch {
	case errors.Is(err, scanfreeze.ErrZoneNotFound):
		apierror.NotFound("Scan zone").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Freeze window").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.New(http.StatusBadRequest, code(apierror.CodeBadRequest), cleanErrorMessage(err, "Invalid freeze window")).WriteJSON(w)
	default:
		h.logger.Error("scan freeze window error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}
