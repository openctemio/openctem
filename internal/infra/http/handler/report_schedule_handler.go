package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/reportschedule"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// ReportScheduleHandler handles report schedule HTTP requests.
type ReportScheduleHandler struct {
	service *app.ReportScheduleService
	logger  *logger.Logger
}

// NewReportScheduleHandler creates a new ReportScheduleHandler.
func NewReportScheduleHandler(svc *app.ReportScheduleService, log *logger.Logger) *ReportScheduleHandler {
	return &ReportScheduleHandler{service: svc, logger: log}
}

type reportScheduleResponse struct {
	ID              string                       `json:"id"`
	Name            string                       `json:"name"`
	ReportType      string                       `json:"report_type"`
	Format          string                       `json:"format"`
	CronExpression  string                       `json:"cron_expression"`
	Timezone        string                       `json:"timezone"`
	Recipients      []reportschedule.Recipient   `json:"recipients"`
	DeliveryChannel string                       `json:"delivery_channel"`
	IsActive        bool                         `json:"is_active"`
	LastRunAt       *time.Time                   `json:"last_run_at,omitempty"`
	LastStatus      string                       `json:"last_status,omitempty"`
	NextRunAt       *time.Time                   `json:"next_run_at,omitempty"`
	RunCount        int                          `json:"run_count"`
	CreatedAt       time.Time                    `json:"created_at"`
}

func toReportScheduleResponse(s *reportschedule.ReportSchedule) reportScheduleResponse {
	return reportScheduleResponse{
		ID: s.ID().String(), Name: s.Name(),
		ReportType: s.ReportType(), Format: s.Format(),
		CronExpression: s.CronExpression(), Timezone: s.Timezone(),
		Recipients: s.Recipients(), DeliveryChannel: s.DeliveryChannel(),
		IsActive: s.IsActive(), LastRunAt: s.LastRunAt(),
		LastStatus: s.LastStatus(), NextRunAt: s.NextRunAt(),
		RunCount: s.RunCount(), CreatedAt: s.CreatedAt(),
	}
}

// List handles GET /api/v1/reports/schedules
func (h *ReportScheduleHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	perPage := parseQueryInt(r.URL.Query().Get("per_page"), 20)
	if perPage > 100 {
		perPage = 100
	}
	if perPage < 1 {
		perPage = 1
	}
	page := pagination.New(
		parseQueryInt(r.URL.Query().Get("page"), 1),
		perPage,
	)

	result, err := h.service.ListSchedules(r.Context(), tenantID, page)
	if err != nil {
		h.handleError(w, err)
		return
	}

	data := make([]reportScheduleResponse, 0, len(result.Data))
	for _, s := range result.Data {
		data = append(data, toReportScheduleResponse(s))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data":        data,
		"total":       result.Total,
		"page":        result.Page,
		"per_page":    result.PerPage,
		"total_pages": result.TotalPages,
	})
}

// Create handles POST /api/v1/reports/schedules
func (h *ReportScheduleHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	actorID := middleware.GetUserID(r.Context())

	var req struct {
		Name           string                       `json:"name"`
		ReportType     string                       `json:"report_type"`
		Format         string                       `json:"format"`
		CronExpression string                       `json:"cron_expression"`
		Timezone       string                       `json:"timezone"`
		Recipients     []reportschedule.Recipient   `json:"recipients"`
		Options        map[string]any               `json:"options"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	schedule, err := h.service.CreateSchedule(r.Context(), app.CreateReportScheduleInput{
		TenantID: tenantID, Name: req.Name,
		ReportType: req.ReportType, Format: req.Format,
		CronExpression: req.CronExpression, Timezone: req.Timezone,
		Recipients: req.Recipients, Options: req.Options,
		ActorID: actorID,
	})
	if err != nil {
		h.handleError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toReportScheduleResponse(schedule))
}

// Get handles GET /api/v1/reports/schedules/{id}
func (h *ReportScheduleHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := r.PathValue("id")

	schedule, err := h.service.GetSchedule(r.Context(), tenantID, id)
	if err != nil {
		h.handleError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toReportScheduleResponse(schedule))
}

// Delete handles DELETE /api/v1/reports/schedules/{id}
func (h *ReportScheduleHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := r.PathValue("id")

	if err := h.service.DeleteSchedule(r.Context(), tenantID, id); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Toggle handles PATCH /api/v1/reports/schedules/{id}/toggle
func (h *ReportScheduleHandler) Toggle(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := r.PathValue("id")

	var req struct {
		Active bool `json:"active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	if err := h.service.ToggleSchedule(r.Context(), tenantID, id, req.Active); err != nil {
		h.handleError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

func (h *ReportScheduleHandler) handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Schedule").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("report schedule error", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
	}
}
