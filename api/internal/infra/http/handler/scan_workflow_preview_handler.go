package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"

	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
)

// WorkflowPreviewRequest is a workflow and the targets a scan would run it on.
type WorkflowPreviewRequest struct {
	ScanWorkflowID string   `json:"scan_workflow_id" validate:"required,uuid"`
	Targets        []string `json:"targets" validate:"max=1000,dive,max=500"`
	AssetGroupIDs  []string `json:"asset_group_ids" validate:"max=20,dive,uuid"`
	ScanZoneID     string   `json:"scan_zone_id" validate:"omitempty,uuid"`
}

// PreviewWorkflow handles POST /api/v1/scans/workflow-preview
// @Summary      Preview a workflow scan
// @Description  What a workflow scan would do, before it is saved or started: per step the capability, tier, the tool the planner picks and whether an online sensor may run it; the targets (zone routing, scope exclusions; at most 20 samples); an active freeze window. Computed with the trigger's code; creates nothing. `blocking` is true when a trigger with these settings would be refused.
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        body  body      WorkflowPreviewRequest  true  "Workflow and targets"
// @Success      200   {object}  scansvc.WorkflowPreview
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error  "workflow, scan zone or asset group not in this tenant"
// @Security     BearerAuth
// @Router       /scans/workflow-preview [post]
func (h *ScanHandler) PreviewWorkflow(w http.ResponseWriter, r *http.Request) {
	var req WorkflowPreviewRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		apierror.BadRequest("Invalid workflow preview request").WriteJSON(w)
		return
	}
	out, err := h.service.PreviewWorkflow(r.Context(), scansvc.WorkflowPreviewInput{
		TenantID:       middleware.GetTenantID(r.Context()),
		ScanWorkflowID: req.ScanWorkflowID,
		Targets:        req.Targets,
		AssetGroupIDs:  req.AssetGroupIDs,
		ScanZoneID:     req.ScanZoneID,
	})
	if err != nil {
		switch {
		case errors.Is(err, scanzone.ErrZoneNotFound):
			apierror.NotFound("Scan zone").WriteJSON(w)
		case errors.Is(err, shared.ErrNotFound):
			apierror.NotFound("Workflow or asset group").WriteJSON(w)
		default:
			h.handleServiceError(w, err)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
