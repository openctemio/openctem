package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/module"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/reportschedule"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ReportScheduleHandler handles report schedule HTTP requests.
//
// Authorization: reports:read lists schedules and reports:write creates
// them; a schedule is paused, resumed or deleted only by its creator or a
// holder of reports:manage (owners and admins). Recipient addresses are
// personal data and are returned only to those same people.
type ReportScheduleHandler struct {
	service      *module.ReportScheduleService
	auditService *auditapp.AuditService
	creatorNames CreatorNameResolver
	logger       *logger.Logger
}

// CreatorNameResolver returns a user's display name, or "" when the user has
// no name other than an email address (an email is never shown here).
type CreatorNameResolver interface {
	GetUserNameByID(ctx context.Context, id shared.ID) (string, error)
}

// SetCreatorNames resolves the creator's name for the schedule list.
func (h *ReportScheduleHandler) SetCreatorNames(r CreatorNameResolver) { h.creatorNames = r }

// actor is the caller as a schedule actor.
func scheduleActor(r *http.Request) module.ReportScheduleActor {
	return module.ReportScheduleActor{
		UserID:       middleware.GetUserID(r.Context()),
		CanManageAll: middleware.HasPermission(r.Context(), permission.ReportsManage.String()),
	}
}

// SetAuditService records schedule creation, activation and deletion with
// the recipients (a schedule mails organization posture out).
func (h *ReportScheduleHandler) SetAuditService(a *auditapp.AuditService) { h.auditService = a }

func (h *ReportScheduleHandler) audit(r *http.Request, action auditdom.Action, scheduleID string, recipients []reportschedule.Recipient, createdBy *shared.ID) {
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
	if createdBy != nil {
		event = event.WithMetadata("created_by", createdBy.String())
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
	// CreatedBy is the creator's user ID ("" for a schedule without one);
	// CreatedByName their display name, never an email.
	CreatedBy     string `json:"created_by,omitempty"`
	CreatedByName string `json:"created_by_name,omitempty"`
	// CanManage tells the caller whether they may pause, resume or delete
	// the schedule. Recipients is empty when they may not; RecipientCount
	// is always the number of recipients.
	CanManage      bool `json:"can_manage"`
	RecipientCount int  `json:"recipient_count"`
}

func toReportScheduleResponse(s *reportschedule.ReportSchedule, actor module.ReportScheduleActor) reportScheduleResponse {
	canManage := s.ManageableBy(actor.UserID, actor.CanManageAll)
	recipients := []reportschedule.Recipient{}
	if canManage && s.Recipients() != nil {
		recipients = s.Recipients()
	}
	resp := reportScheduleResponse{
		ID: s.ID().String(), Name: s.Name(),
		ReportType: s.ReportType(), Format: s.Format(),
		CronExpression: s.CronExpression(), Timezone: s.Timezone(),
		Recipients: recipients, DeliveryChannel: s.DeliveryChannel(),
		IsActive: s.IsActive(), LastRunAt: s.LastRunAt(),
		LastStatus: s.LastStatus(), NextRunAt: s.NextRunAt(),
		RunCount: s.RunCount(), CreatedAt: s.CreatedAt(),
		CanManage: canManage, RecipientCount: len(s.Recipients()),
	}
	if cb := s.CreatedBy(); cb != nil {
		resp.CreatedBy = cb.String()
	}
	return resp
}

// withCreatorNames fills CreatedByName, one lookup per distinct creator.
func (h *ReportScheduleHandler) withCreatorNames(ctx context.Context, rows []reportScheduleResponse) {
	if h.creatorNames == nil {
		return
	}
	names := map[string]string{}
	for i := range rows {
		id := rows[i].CreatedBy
		if id == "" {
			continue
		}
		name, seen := names[id]
		if !seen {
			if uid, err := shared.IDFromString(id); err == nil {
				name, _ = h.creatorNames.GetUserNameByID(ctx, uid)
			}
			names[id] = name
		}
		rows[i].CreatedByName = name
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

	actor := scheduleActor(r)
	data := make([]reportScheduleResponse, 0, len(result.Data))
	for _, s := range result.Data {
		data = append(data, toReportScheduleResponse(s, actor))
	}
	h.withCreatorNames(r.Context(), data)

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
	h.audit(r, auditdom.ActionReportScheduleCreated, schedule.ID().String(), schedule.Recipients(), nil)

	resp := []reportScheduleResponse{toReportScheduleResponse(schedule, scheduleActor(r))}
	h.withCreatorNames(r.Context(), resp)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp[0])
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

	resp := []reportScheduleResponse{toReportScheduleResponse(schedule, scheduleActor(r))}
	h.withCreatorNames(r.Context(), resp)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp[0])
}

// Delete handles DELETE /api/v1/reports/schedules/{id}
func (h *ReportScheduleHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := r.PathValue("id")

	schedule, err := h.service.DeleteSchedule(r.Context(), tenantID, id, scheduleActor(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	h.audit(r, auditdom.ActionReportScheduleDeleted, id, schedule.Recipients(), schedule.CreatedBy())
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

	schedule, err := h.service.ToggleSchedule(r.Context(), tenantID, id, req.Active, scheduleActor(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	action := auditdom.ActionReportScheduleDeactivated
	if req.Active {
		action = auditdom.ActionReportScheduleActivated
	}
	h.audit(r, action, id, schedule.Recipients(), schedule.CreatedBy())

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

func (h *ReportScheduleHandler) handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Schedule").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("Only the schedule's creator or a member who manages reports can change it").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("report schedule error", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
	}
}
