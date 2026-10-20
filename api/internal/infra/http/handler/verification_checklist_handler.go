package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	findingapp "github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// VerificationChecklistHandler handles finding verification checklist endpoints.
// The rules (tenant and data scope, who completed it, audit) live in the
// finding service; this handler only decodes and encodes.
type VerificationChecklistHandler struct {
	configAuditor
	svc    *findingapp.VerificationChecklistService
	logger *logger.Logger
}

// NewVerificationChecklistHandler creates a new handler.
func NewVerificationChecklistHandler(svc *findingapp.VerificationChecklistService, log *logger.Logger) *VerificationChecklistHandler {
	return &VerificationChecklistHandler{svc: svc, logger: log}
}

type checklistResponse struct {
	ID                  string  `json:"id"`
	FindingID           string  `json:"finding_id"`
	ExposureCleared     bool    `json:"exposure_cleared"`
	EvidenceAttached    bool    `json:"evidence_attached"`
	RegisterUpdated     bool    `json:"register_updated"`
	MonitoringAdded     *bool   `json:"monitoring_added"`
	RegressionScheduled *bool   `json:"regression_scheduled"`
	Notes               string  `json:"notes"`
	IsComplete          bool    `json:"is_complete"`
	CompletedBy         *string `json:"completed_by,omitempty"`
	CompletedAt         *string `json:"completed_at,omitempty"`
}

func checklistResponseOf(v *findingapp.ChecklistView) checklistResponse {
	resp := checklistResponse{FindingID: v.FindingID.String()}
	c := v.Checklist
	if c == nil {
		return resp // no checklist yet: all items false, nothing recorded
	}
	resp.ID = c.ID().String()
	resp.ExposureCleared = c.ExposureCleared()
	resp.EvidenceAttached = c.EvidenceAttached()
	resp.RegisterUpdated = c.RegisterUpdated()
	resp.MonitoringAdded = c.MonitoringAdded()
	resp.RegressionScheduled = c.RegressionScheduled()
	resp.Notes = c.Notes()
	resp.IsComplete = c.IsComplete()
	if by := c.CompletedBy(); by != nil {
		s := by.String()
		resp.CompletedBy = &s
	}
	if at := c.CompletedAt(); at != nil {
		s := at.Format(time.RFC3339)
		resp.CompletedAt = &s
	}
	return resp
}

func (h *VerificationChecklistHandler) writeError(w http.ResponseWriter, err error, op string) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("finding not found").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error(op, "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
	}
}

func (h *VerificationChecklistHandler) ids(w http.ResponseWriter, r *http.Request) (tenantID, findingID shared.ID, ok bool) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.NotFound("finding not found").WriteJSON(w)
		return tenantID, findingID, false
	}
	findingID, err = shared.IDFromString(chi.URLParam(r, "findingId"))
	if err != nil {
		apierror.NotFound("finding not found").WriteJSON(w)
		return tenantID, findingID, false
	}
	return tenantID, findingID, true
}

// Get returns the verification checklist for a finding. It is read-only: a
// finding without a checklist reads as an empty, incomplete one.
func (h *VerificationChecklistHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID, findingID, ok := h.ids(w, r)
	if !ok {
		return
	}
	v, err := h.svc.Get(r.Context(), tenantID, findingID)
	if err != nil {
		h.writeError(w, err, "get verification checklist")
		return
	}
	writeJSON(w, http.StatusOK, checklistResponseOf(v))
}

// Update updates checklist items. The person making the edit that leaves every
// required item true is recorded as the one who completed it; an edit that
// unticks a required item clears that record.
func (h *VerificationChecklistHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID, findingID, ok := h.ids(w, r)
	if !ok {
		return
	}
	actor, err := shared.IDFromString(middleware.GetUserID(r.Context()))
	if err != nil {
		apierror.Forbidden("authenticated user required").WriteJSON(w)
		return
	}
	var req struct {
		ExposureCleared     *bool   `json:"exposure_cleared"`
		EvidenceAttached    *bool   `json:"evidence_attached"`
		RegisterUpdated     *bool   `json:"register_updated"`
		MonitoringAdded     *bool   `json:"monitoring_added"`
		RegressionScheduled *bool   `json:"regression_scheduled"`
		Notes               *string `json:"notes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	v, change, err := h.svc.Update(r.Context(), tenantID, findingID, actor, findingapp.ChecklistUpdate{
		ExposureCleared: req.ExposureCleared, EvidenceAttached: req.EvidenceAttached,
		RegisterUpdated: req.RegisterUpdated, MonitoringAdded: req.MonitoringAdded,
		RegressionScheduled: req.RegressionScheduled, Notes: req.Notes,
	})
	if err != nil {
		h.writeError(w, err, "update verification checklist")
		return
	}
	h.auditUpdate(r, findingID, actor, change)
	writeJSON(w, http.StatusOK, checklistResponseOf(v))
}

// auditUpdate records the edit (best effort: it already happened). The notes
// text is not recorded.
func (h *VerificationChecklistHandler) auditUpdate(r *http.Request, findingID, actor shared.ID, change *findingapp.ChecklistChange) {
	ev := auditapp.NewSuccessEvent(auditdom.ActionFindingVerificationChecklistUpdated, auditdom.ResourceTypeFinding, findingID.String()).
		WithMessage("Updated a finding's verification checklist").
		WithMetadata("finding_id", findingID.String()).
		WithMetadata("changed_items", change.ChangedItems).
		WithMetadata("complete", change.Complete).
		WithMetadata("completed", change.Completed).
		WithMetadata("completion_cleared", change.Cleared).
		WithSeverity(auditdom.SeverityMedium)
	if change.Completed {
		ev = ev.WithMetadata("completed_by", actor.String())
	}
	recordConfigAudit(r.Context(), h.audit, h.logger, configAuditContext(r), ev)
}
