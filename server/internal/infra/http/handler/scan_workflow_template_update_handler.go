package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TemplateUpdateResponse is the update a tenant's copy of a system template
// is offered. Available is false (and the rest empty) when there is none.
type TemplateUpdateResponse struct {
	Available          bool                          `json:"available"`
	SourceTemplateID   string                        `json:"source_template_id,omitempty"`
	SourceTemplateName string                        `json:"source_template_name,omitempty"`
	TemplateDigest     string                        `json:"template_digest,omitempty"`
	Changes            []scanworkflow.TemplateChange `json:"changes"`
}

// TemplateUpdateRequest names the update the caller reviewed.
type TemplateUpdateRequest struct {
	TemplateDigest string `json:"template_digest" validate:"required,max=128"`
}

// GetTemplateUpdate handles GET /api/v1/scan-workflows/{id}/template-update
// @Summary      Template update offered to a copy
// @Description  For a tenant's copy of a system scan workflow: the changes the system template made since the copy last took it that the copy can take (a step it added, a step it rewired). Nothing is changed.
// @Tags         Scan workflows
// @Produce      json
// @Param        id   path      string  true  "Scan workflow ID"
// @Success      200  {object}  TemplateUpdateResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-workflows/{id}/template-update [get]
func (h *ScanWorkflowHandler) GetTemplateUpdate(w http.ResponseWriter, r *http.Request) {
	v, err := h.service.GetTemplateUpdate(r.Context(), middleware.GetTenantID(r.Context()), chi.URLParam(r, "id"))
	if err != nil {
		h.handleTemplateUpdateError(w, err)
		return
	}
	out := TemplateUpdateResponse{Changes: []scanworkflow.TemplateChange{}}
	if v != nil {
		out = TemplateUpdateResponse{Available: true, SourceTemplateID: v.SourceTemplateID,
			SourceTemplateName: v.SourceTemplateName, TemplateDigest: v.TemplateDigest, Changes: v.Changes}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (h *ScanWorkflowHandler) decodeTemplateUpdate(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req TemplateUpdateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return "", false
	}
	if req.TemplateDigest == "" || len(req.TemplateDigest) > 128 {
		apierror.BadRequest("template_digest is required").WriteJSON(w)
		return "", false
	}
	return req.TemplateDigest, true
}

// ApplyTemplateUpdate handles POST /api/v1/scan-workflows/{id}/template-update/apply
// @Summary      Apply a template update to a copy
// @Description  Applies the offered changes to the tenant's copy: checked like a published draft, steps replaced in place, version moved on, audited. Refused while the copy has an unpublished draft, or when the template changed since template_digest was shown (409).
// @Tags         Scan workflows
// @Accept       json
// @Produce      json
// @Param        id    path      string                 true  "Scan workflow ID"
// @Param        body  body      TemplateUpdateRequest  true  "The reviewed update"
// @Success      200   {object}  TemplateResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Failure      422   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-workflows/{id}/template-update/apply [post]
func (h *ScanWorkflowHandler) ApplyTemplateUpdate(w http.ResponseWriter, r *http.Request) {
	digest, ok := h.decodeTemplateUpdate(w, r)
	if !ok {
		return
	}
	t, err := h.service.ApplyTemplateUpdate(scanWorkflowAuditCtx(r), middleware.GetTenantID(r.Context()), chi.URLParam(r, "id"), digest)
	if err != nil {
		h.handleTemplateUpdateError(w, err)
		return
	}
	if steps, err := h.service.GetSteps(r.Context(), t.ID.String()); err == nil {
		t.Steps = steps
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toTemplateResponse(t))
}

// DismissTemplateUpdate handles POST /api/v1/scan-workflows/{id}/template-update/reject
// @Summary      Dismiss a template update
// @Description  Keeps the copy as it is and stops offering the changes shown; audited. 409 when the template changed since template_digest was shown.
// @Tags         Scan workflows
// @Accept       json
// @Param        id    path  string                 true  "Scan workflow ID"
// @Param        body  body  TemplateUpdateRequest  true  "The reviewed update"
// @Success      204
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-workflows/{id}/template-update/reject [post]
func (h *ScanWorkflowHandler) DismissTemplateUpdate(w http.ResponseWriter, r *http.Request) {
	digest, ok := h.decodeTemplateUpdate(w, r)
	if !ok {
		return
	}
	if err := h.service.DismissTemplateUpdate(scanWorkflowAuditCtx(r), middleware.GetTenantID(r.Context()), chi.URLParam(r, "id"), digest); err != nil {
		h.handleTemplateUpdateError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ScanWorkflowHandler) handleTemplateUpdateError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Scan workflow").WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict(err.Error()).WriteJSON(w)
	default:
		h.handleStepError(w, err)
	}
}
