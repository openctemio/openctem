package handler

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"

	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
)

// QuickScanPreviewRequest is the Quick Scan form as typed.
type QuickScanPreviewRequest struct {
	Targets     []string `json:"targets" validate:"required,min=1,max=1000,dive,max=500"`
	ScannerName string   `json:"scanner_name" validate:"omitempty,max=100"`
	WorkflowID  string   `json:"workflow_id" validate:"omitempty,uuid"`
}

// PreviewQuickScan handles POST /api/v1/scans/quick/preview
// @Summary      Preview a quick scan
// @Description  What a quick scan of the typed targets would do, before it starts: per target the number of known assets a wildcard or range covers, how many names the run would scan and how many it leaves out (exclusions, scope, deny list) with the reason, and a short sample of names. At most 20 targets are previewed, 5 sample names each. Uses the run's own expansion and scope checks as the caller; creates nothing. A wildcard that covers no known name carries a subdomain discovery offer.
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        body  body      QuickScanPreviewRequest  true  "Targets and scanner"
// @Success      200   {object}  scansvc.QuickScanPreview
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error  "workflow not in this tenant"
// @Security     BearerAuth
// @Router       /scans/quick/preview [post]
func (h *ScanHandler) PreviewQuickScan(w http.ResponseWriter, r *http.Request) {
	var req QuickScanPreviewRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		apierror.BadRequest("tenant_id is required").WriteJSON(w)
		return
	}
	out, err := h.service.PreviewQuickScan(r.Context(), scansvc.QuickScanPreviewInput{
		TenantID:    tenantID,
		UserID:      middleware.GetUserID(r.Context()),
		Targets:     req.Targets,
		ScannerName: req.ScannerName,
		WorkflowID:  req.WorkflowID,
	})
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
