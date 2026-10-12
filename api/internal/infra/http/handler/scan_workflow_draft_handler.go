package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/scanrun"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// maxDraftSteps bounds a draft (the same bound as a saved workflow).
const maxDraftSteps = 50

// ScanWorkflowDraftRequest is the builder's draft: its steps as drawn, valid
// or not, and the Start/End node positions.
type ScanWorkflowDraftRequest struct {
	Steps           []CreateStepRequest `json:"steps"`
	UIStartPosition *UIPositionRequest  `json:"ui_start_position"`
	UIEndPosition   *UIPositionRequest  `json:"ui_end_position"`
}

// ScanWorkflowDraftResponse is a stored draft and what its last check found.
type ScanWorkflowDraftResponse struct {
	Steps           []CreateStepRequest                 `json:"steps"`
	UIStartPosition *UIPositionResponse                 `json:"ui_start_position,omitempty"`
	UIEndPosition   *UIPositionResponse                 `json:"ui_end_position,omitempty"`
	Issues          ScanWorkflowGraphValidationResponse `json:"issues"`
	UpdatedAt       string                              `json:"updated_at"`
}

// GetDraft handles GET /api/v1/scan-workflows/{id}/draft
// @Summary      Get a scan workflow's draft
// @Description  The editable draft the builder saved last, valid or not, with the issues its check found. 404 when the workflow has no draft.
// @Tags         Scan workflows
// @Produce      json
// @Param        id   path      string  true  "Scan workflow ID"
// @Success      200  {object}  ScanWorkflowDraftResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-workflows/{id}/draft [get]
func (h *ScanWorkflowHandler) GetDraft(w http.ResponseWriter, r *http.Request) {
	v, err := h.service.GetDraft(r.Context(), middleware.GetTenantID(r.Context()), chi.URLParam(r, "id"))
	if err != nil {
		h.handleDraftError(w, err)
		return
	}
	writeDraft(w, v)
}

// SaveDraft handles PUT /api/v1/scan-workflows/{id}/draft
// @Summary      Save a scan workflow's draft
// @Description  Saves the builder's draft whatever its state (layout and edits are never lost), checks it and returns every issue: errors block a publish, warnings do not. Runs keep using the published steps.
// @Tags         Scan workflows
// @Accept       json
// @Produce      json
// @Param        id    path      string                    true  "Scan workflow ID"
// @Param        body  body      ScanWorkflowDraftRequest  true  "Draft"
// @Success      200   {object}  ScanWorkflowDraftResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-workflows/{id}/draft [put]
func (h *ScanWorkflowHandler) SaveDraft(w http.ResponseWriter, r *http.Request) {
	var req ScanWorkflowDraftRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if len(req.Steps) > maxDraftSteps {
		apierror.BadRequest("A scan workflow has at most 50 steps").WriteJSON(w)
		return
	}
	tenantID := middleware.GetTenantID(r.Context())
	templateID := chi.URLParam(r, "id")
	spec := scanrun.DraftSpec{
		Steps:           make([]scanrun.AddStepInput, 0, len(req.Steps)),
		UIStartPosition: toUIPosition(req.UIStartPosition),
		UIEndPosition:   toUIPosition(req.UIEndPosition),
	}
	for _, st := range req.Steps {
		spec.Steps = append(spec.Steps, toAddStepInput(tenantID, templateID, st))
	}
	v, err := h.service.SaveDraft(scanWorkflowAuditCtx(r), scanrun.DraftInput{TenantID: tenantID, TemplateID: templateID, Spec: spec})
	if err != nil {
		h.handleDraftError(w, err)
		return
	}
	writeDraft(w, v)
}

// DiscardDraft handles DELETE /api/v1/scan-workflows/{id}/draft
// @Summary      Discard a scan workflow's draft
// @Tags         Scan workflows
// @Param        id   path  string  true  "Scan workflow ID"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-workflows/{id}/draft [delete]
func (h *ScanWorkflowHandler) DiscardDraft(w http.ResponseWriter, r *http.Request) {
	if err := h.service.DiscardDraft(scanWorkflowAuditCtx(r), middleware.GetTenantID(r.Context()), chi.URLParam(r, "id")); err != nil {
		h.handleDraftError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// PublishDraft handles POST /api/v1/scan-workflows/{id}/publish
// @Summary      Publish a scan workflow's draft
// @Description  Makes the draft the steps runs use. Checked again now: a blocking issue refuses it with 422 and every issue, and the draft stays. Steps keep their ids and run history; the version moves on and the draft is removed.
// @Tags         Scan workflows
// @Produce      json
// @Param        id   path      string  true  "Scan workflow ID"
// @Success      200  {object}  TemplateResponse
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      422  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-workflows/{id}/publish [post]
func (h *ScanWorkflowHandler) PublishDraft(w http.ResponseWriter, r *http.Request) {
	t, err := h.service.PublishDraft(scanWorkflowAuditCtx(r), middleware.GetTenantID(r.Context()), chi.URLParam(r, "id"))
	if err != nil {
		h.handleDraftError(w, err)
		return
	}
	if steps, err := h.service.GetSteps(r.Context(), t.ID.String()); err == nil {
		t.Steps = steps
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toTemplateResponse(t))
}

func (h *ScanWorkflowHandler) handleDraftError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, scanworkflow.ErrNoDraft):
		apierror.New(http.StatusConflict, apierror.Code(scanworkflow.ErrNoDraft.Code), scanworkflow.ErrNoDraft.Message).WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Scan workflow draft").WriteJSON(w)
	default:
		h.handleStepError(w, err)
	}
}

func writeDraft(w http.ResponseWriter, v *scanrun.DraftView) {
	out := ScanWorkflowDraftResponse{
		Steps:     make([]CreateStepRequest, 0, len(v.Spec.Steps)),
		Issues:    toGraphValidationResponse(v.Issues),
		UpdatedAt: v.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	for _, s := range v.Spec.Steps {
		out.Steps = append(out.Steps, fromAddStepInput(s))
	}
	if p := v.Spec.UIStartPosition; p != nil {
		out.UIStartPosition = &UIPositionResponse{X: p.X, Y: p.Y}
	}
	if p := v.Spec.UIEndPosition; p != nil {
		out.UIEndPosition = &UIPositionResponse{X: p.X, Y: p.Y}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func toGraphValidationResponse(rep stage.GraphReport) ScanWorkflowGraphValidationResponse {
	out := ScanWorkflowGraphValidationResponse{
		Valid:    rep.Valid(),
		Errors:   make([]ScanWorkflowGraphIssueResponse, 0, len(rep.Errors)),
		Warnings: make([]ScanWorkflowGraphIssueResponse, 0, len(rep.Warnings)),
	}
	for _, is := range rep.Errors {
		out.Errors = append(out.Errors, toGraphIssueResponse(is))
	}
	for _, is := range rep.Warnings {
		out.Warnings = append(out.Warnings, toGraphIssueResponse(is))
	}
	return out
}

// fromAddStepInput is the request shape of a stored draft step.
func fromAddStepInput(in scanrun.AddStepInput) CreateStepRequest {
	out := CreateStepRequest{
		ID:                in.ID,
		StepKey:           in.StepKey,
		Name:              in.Name,
		Description:       in.Description,
		Order:             in.Order,
		Tool:              in.Tool,
		Capabilities:      in.Capabilities,
		PreferTools:       in.PreferTools,
		Config:            in.Config,
		TimeoutSeconds:    in.TimeoutSeconds,
		DependsOn:         in.DependsOn,
		MaxRetries:        in.MaxRetries,
		RetryDelaySeconds: in.RetryDelaySeconds,
	}
	if in.UIPositionX != nil && in.UIPositionY != nil {
		out.UIPosition = &UIPositionRequest{X: *in.UIPositionX, Y: *in.UIPositionY}
	}
	if in.Condition != nil {
		out.Condition = &StepConditionRequest{Type: string(in.Condition.Type), Value: in.Condition.Value}
	}
	return out
}
