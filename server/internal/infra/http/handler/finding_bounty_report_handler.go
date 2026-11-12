package handler

// Report fields of bug-bounty findings.
// https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-121-bug-bounty-reports.md

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// maxBountyReportBody bounds the report object request: every field is
// short (the report text lives in the finding description).
const maxBountyReportBody = 16 << 10

// UpdateFindingBountyReport handles PUT /api/v1/findings/{id}/bounty-report.
//
//	@Summary		Replace the bug-bounty report fields of a finding
//	@Description	Replaces the report object of a bug_bounty finding in the caller's data scope (404 otherwise). Intake and ref cannot change once set. Setting or changing reward or disclosure needs findings:triage (403 TRIAGE_PERMISSION_REQUIRED). The server never fetches the url. Audited with the old and new value of every changed field.
//	@Tags			Findings
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			id		path		string						true	"Finding ID"
//	@Param			request	body		vulnerability.BountyReport	true	"The report object"
//	@Success		200		{object}	FindingResponse
//	@Failure		400		{object}	apierror.Error
//	@Failure		403		{object}	apierror.Error
//	@Failure		404		{object}	apierror.Error
//	@Failure		409		{object}	apierror.Error
//	@Router			/findings/{id}/bounty-report [put]
func (h *VulnerabilityHandler) UpdateFindingBountyReport(w http.ResponseWriter, r *http.Request) {
	var req vulnerability.BountyReport
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBountyReportBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	ctx := r.Context()
	f, err := h.service.UpdateBountyReport(ctx, finding.UpdateBountyReportInput{
		TenantID:  middleware.MustGetTenantID(ctx),
		FindingID: r.PathValue("id"),
		Report:    req,
		CanTriage: middleware.HasPermission(ctx, permission.FindingsTriage.String()),
		ActorID:   middleware.GetUserID(ctx),
		Audit:     h.buildAuditContext(r),
	})
	if err != nil {
		h.handleServiceError(w, err, "Finding")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toFindingResponse(f))
}
