package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	automationsvc "github.com/openctemio/openctem/api/internal/app/automation"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// WorkflowVersionResponse is one published definition of an automation.
type WorkflowVersionResponse struct {
	ID          string  `json:"id"`
	Version     int     `json:"version"`
	Digest      string  `json:"digest"`
	RiskClass   string  `json:"risk_class"`
	Status      string  `json:"status"`
	PublishedBy *string `json:"published_by,omitempty"`
	PublishedAt *string `json:"published_at,omitempty"`
	ApprovedBy  *string `json:"approved_by,omitempty"`
	ApprovedAt  *string `json:"approved_at,omitempty"`
	StepUpAt    *string `json:"step_up_at,omitempty"`
	CreatedAt   string  `json:"created_at"`
	// Definition is set only on GET /workflows/{id}/versions/{versionId}.
	Definition *automation.Definition `json:"definition,omitempty"`
}

func timePtrString(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.Format(time.RFC3339)
	return &s
}

func toWorkflowVersionResponse(v *automation.Version, withDefinition bool) *WorkflowVersionResponse {
	if v == nil {
		return nil
	}
	resp := &WorkflowVersionResponse{
		ID: v.ID.String(), Version: v.Version, Digest: v.Digest, RiskClass: string(v.RiskClass), Status: string(v.Status),
		PublishedBy: idPtrString(v.PublishedBy), PublishedAt: timePtrString(v.PublishedAt),
		ApprovedBy: idPtrString(v.ApprovedBy), ApprovedAt: timePtrString(v.ApprovedAt),
		StepUpAt: timePtrString(v.StepUpAt), CreatedAt: v.CreatedAt.Format(time.RFC3339),
	}
	if withDefinition {
		def := v.Definition
		resp.Definition = &def
	}
	return resp
}

// toWorkflowDetailResponse is the automation with its draft graph, mode,
// versions and the draft's risk class.
func toWorkflowDetailResponse(d *automationsvc.WorkflowDetail) *WorkflowResponse {
	resp := toWorkflowResponse(d.Workflow)
	resp.RiskClass = string(d.RiskClass)
	resp.DraftChanged = d.DraftChanged
	resp.PublishedVersion = toWorkflowVersionResponse(d.Published, false)
	resp.PendingVersion = toWorkflowVersionResponse(d.Pending, false)
	return resp
}

// workflowPathIDs reads the tenant and the {id} path parameter, writing a 400
// and returning false when either is not an id.
func workflowPathIDs(w http.ResponseWriter, r *http.Request) (tenantID, workflowID, userID shared.ID, ok bool) {
	tenantID, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return tenantID, workflowID, userID, false
	}
	workflowID, err = shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest("Invalid workflow ID").WriteJSON(w)
		return tenantID, workflowID, userID, false
	}
	userID, _ = shared.IDFromString(middleware.GetUserID(r.Context()))
	return tenantID, workflowID, userID, true
}

// ListVersions handles GET /api/v1/workflows/{id}/versions.
func (h *WorkflowHandler) ListVersions(w http.ResponseWriter, r *http.Request) {
	tenantID, workflowID, _, ok := workflowPathIDs(w, r)
	if !ok {
		return
	}
	versions, err := h.service.ListVersions(r.Context(), tenantID, workflowID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	items := make([]*WorkflowVersionResponse, 0, len(versions))
	for _, v := range versions {
		items = append(items, toWorkflowVersionResponse(v, false))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
}

// GetVersion handles GET /api/v1/workflows/{id}/versions/{versionId}.
func (h *WorkflowHandler) GetVersion(w http.ResponseWriter, r *http.Request) {
	tenantID, workflowID, _, ok := workflowPathIDs(w, r)
	if !ok {
		return
	}
	versionID, err := shared.IDFromString(chi.URLParam(r, "versionId"))
	if err != nil {
		apierror.BadRequest("Invalid version ID").WriteJSON(w)
		return
	}
	v, err := h.service.GetVersion(r.Context(), tenantID, workflowID, versionID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toWorkflowVersionResponse(v, true))
}

// Publish handles POST /api/v1/workflows/{id}/publish: the draft becomes a
// new version and goes live. The caller needs the permission of every step,
// as switching an automation on does.
func (h *WorkflowHandler) Publish(w http.ResponseWriter, r *http.Request) {
	tenantID, workflowID, userID, ok := workflowPathIDs(w, r)
	if !ok {
		return
	}
	if !h.requireWorkflowPermissions(w, r, tenantID, workflowID) {
		return
	}
	if _, err := h.service.Publish(r.Context(), automationsvc.PublishInput{TenantID: tenantID, UserID: userID, WorkflowID: workflowID}); err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.writeWorkflowDetail(w, r, tenantID, workflowID, http.StatusOK)
}

// Rollback handles POST /api/v1/workflows/{id}/versions/{versionId}/rollback:
// the older version's definition is published again as a new version.
func (h *WorkflowHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	tenantID, workflowID, userID, ok := workflowPathIDs(w, r)
	if !ok {
		return
	}
	versionID, err := shared.IDFromString(chi.URLParam(r, "versionId"))
	if err != nil {
		apierror.BadRequest("Invalid version ID").WriteJSON(w)
		return
	}
	old, err := h.service.GetVersion(r.Context(), tenantID, workflowID, versionID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	// The caller needs the permission of every step the old version has.
	cfgs := make([]*NodeConfigRequest, 0, len(old.Definition.Nodes))
	for _, n := range old.Definition.Nodes {
		cfgs = append(cfgs, &NodeConfigRequest{ActionType: string(n.Config.ActionType), NotificationType: string(n.Config.NotificationType)})
	}
	if !h.requireActionPermissions(w, r, cfgs...) {
		return
	}
	if _, err := h.service.Rollback(r.Context(), automationsvc.PublishInput{TenantID: tenantID, UserID: userID, WorkflowID: workflowID}, versionID); err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.writeWorkflowDetail(w, r, tenantID, workflowID, http.StatusOK)
}

// SetWorkflowModeRequest is the body of PUT /workflows/{id}/mode.
type SetWorkflowModeRequest struct {
	Mode string `json:"mode" validate:"required,oneof=simulate live"`
}

// SetMode handles PUT /api/v1/workflows/{id}/mode. Only simulate is
// accepted: an automation goes live by publishing.
func (h *WorkflowHandler) SetMode(w http.ResponseWriter, r *http.Request) {
	tenantID, workflowID, userID, ok := workflowPathIDs(w, r)
	if !ok {
		return
	}
	var req SetWorkflowModeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	if _, err := h.service.SetMode(r.Context(), tenantID, userID, workflowID, automation.Mode(req.Mode)); err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.writeWorkflowDetail(w, r, tenantID, workflowID, http.StatusOK)
}

func (h *WorkflowHandler) writeWorkflowDetail(w http.ResponseWriter, r *http.Request, tenantID, workflowID shared.ID, status int) {
	d, err := h.service.GetWorkflowDetail(r.Context(), tenantID, workflowID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(toWorkflowDetailResponse(d))
}
