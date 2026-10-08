package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/module"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/reportschedule"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ReportScheduleHandler handles report schedule HTTP requests.
type ReportScheduleHandler struct {
	service      *module.ReportScheduleService
	auditService *auditapp.AuditService
	logger       *logger.Logger
}

// SetAuditService records schedule creation, activation and deletion with
// the recipients (a schedule mails organization posture out).
func (h *ReportScheduleHandler) SetAuditService(a *auditapp.AuditService) { h.auditService = a }

func (h *ReportScheduleHandler) audit(r *http.Request, action auditdom.Action, scheduleID string, recipients []reportschedule.Recipient) {
	if h.auditService == nil {
		return
	}
	emails := make([]string, 0, len(recipients))
	for _, rc := range recipients {
		emails = append(emails, rc.Email)
	}
	event := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeReportSchedule, scheduleID).
		WithSeverity(auditdom.SeverityForAction(action))
	if recipients != nil {
		event = event.WithMetadata("recipients", emails)
	}
	actx := auditapp.AuditContext{
		TenantID:   middleware.GetTenantID(r.Context()),
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: auditActorEmail(r.Context()),
		ActorIP:    getClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  r.Header.Get("X-Request-ID"),
	}
	_ = h.auditService.LogEvent(r.Context(), actx, event)
}

// NewReportScheduleHandler creates a new ReportScheduleHandler.
func NewReportScheduleHandler(svc *module.ReportScheduleService, log *logger.Logger) *ReportScheduleHandler {
	return &ReportScheduleHandler{service: svc, logger: log}
}

type reportScheduleResponse struct {
	ID              string                     `json:"id"`
	Name            string                     `json:"name"`
	ReportType      string                     `json:"report_type"`
	Format          string                     `json:"format"`
	CronExpression  string                     `json:"cron_expression"`
	Timezone        string                     `json:"timezone"`
	Recipients      []reportschedule.Recipient `json:"recipients"`
	DeliveryChannel string                     `json:"delivery_channel"`
	IsActive        bool                       `json:"is_active"`
	LastRunAt       *time.Time                 `json:"last_run_at,omitempty"`
	LastStatus      string                     `json:"last_status,omitempty"`
	NextRunAt       *time.Time                 `json:"next_run_at,omitempty"`
	RunCount        int                        `json:"run_count"`
	CreatedAt       time.Time                  `json:"created_at"`
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
	page, ok := listPage(w, r, 20)
	if !ok {
		return
	}

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
		Name           string                     `json:"name"`
		ReportType     string                     `json:"report_type"`
		Format         string                     `json:"format"`
		CronExpression string                     `json:"cron_expression"`
		Timezone       string                     `json:"timezone"`
		Recipients     []reportschedule.Recipient `json:"recipients"`
		Options        map[string]any             `json:"options"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	schedule, err := h.service.CreateSchedule(r.Context(), module.CreateReportScheduleInput{
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
	h.audit(r, auditdom.ActionReportScheduleCreated, schedule.ID().String(), schedule.Recipients())

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
	h.audit(r, auditdom.ActionReportScheduleDeleted, id, nil)
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
	if req.Active {
		h.audit(r, auditdom.ActionReportScheduleActivated, id, nil)
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
