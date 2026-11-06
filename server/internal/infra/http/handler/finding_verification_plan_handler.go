package handler

import (
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
)

// FindingVerificationPlanResponse is the body of GET /findings/{id}/verification.
type FindingVerificationPlanResponse = finding.VerificationPlan

// GetFindingVerificationPlan handles GET /api/v1/findings/{id}/verification.
// @Summary      How a finding can be verified
// @Description  The server's verification plan for one finding: its risk tier and what a person's resolve needs at that tier, each verification method (retest, covered scan, safe-check, rotation proof, evidence review) with whether it is available and a reason code when not, and the proof recorded so far (latest retest, checklist state, whether it is fresh). Advisory: the transition engine enforces the rule on every resolve. Records nothing.
// @Tags         Findings
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Finding ID"
// @Success      200  {object}  FindingVerificationPlanResponse
// @Failure      404  {object}  map[string]string
// @Router       /findings/{id}/verification [get]
func (h *VulnerabilityHandler) GetFindingVerificationPlan(w http.ResponseWriter, r *http.Request) {
	plan, err := h.service.GetVerificationPlan(r.Context(), middleware.GetTenantID(r.Context()), r.PathValue("id"), middleware.GetUserID(r.Context()))
	if err != nil {
		h.handleServiceError(w, err, "Finding")
		return
	}
	writeJSON(w, http.StatusOK, plan)
}
