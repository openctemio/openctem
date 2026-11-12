package handler

// The organization's license policy. Design:
// api/docs/rfcs/RFC-070-software-components-inventory.md, "License policy".

import (
	"context"
	"encoding/json"
	"net/http"

	licapp "github.com/openctemio/openctem/api/internal/app/licensepolicy"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/licensepolicy"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// LicensePolicyEvaluator re-evaluates the organization's package links.
type LicensePolicyEvaluator interface {
	EvaluateTenant(ctx context.Context, tenantID shared.ID) (licapp.Result, error)
}

// SetLicensePolicyEvaluator wires the evaluation run after a policy change.
func (h *TenantHandler) SetLicensePolicyEvaluator(e LicensePolicyEvaluator) { h.licenseEvaluator = e }

// LicensePolicyResponse is the policy and, after a change, what its
// evaluation did.
type LicensePolicyResponse struct {
	Policy     licensepolicy.Policy `json:"policy"`
	Evaluation *licapp.Result       `json:"evaluation,omitempty"`
	// EvaluationError is set when the policy was saved but re-evaluating
	// the inventory did not finish; it runs again on the next package write.
	EvaluationError string `json:"evaluation_error,omitempty"`
}

// GetLicensePolicySettings handles GET /api/v1/organization/settings/license-policy.
// @Summary      Get the license policy
// @Description  The organization's license policy: allow, review or deny per SPDX license id (optionally WITH an exception) or category (category:copyleft), optionally limited to dependency scopes; the verdict of known licenses no rule matches (default) and of unknown or missing licenses (unknown); whether review verdicts open findings.
// @Tags         Tenants
// @Produce      json
// @Success      200     {object}  LicensePolicyResponse
// @Failure      400     {object}  apierror.Error
// @Failure      403     {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/settings/license-policy [get]
func (h *TenantHandler) GetLicensePolicySettings(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil || tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	p, err := h.service.GetLicensePolicySettings(r.Context(), tenantID.String())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.writeSectionETag(w, r, tenantID, tenant.SectionLicensePolicy)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(LicensePolicyResponse{Policy: *p})
}

// UpdateLicensePolicySettings handles PUT /api/v1/organization/settings/license-policy.
// @Summary      Replace the license policy
// @Description  Saves the policy (at most 200 rules) and re-evaluates every package link of the organization: a deny verdict opens a high license finding per asset, package and declared licenses, a review verdict a medium one when review_findings is set; findings the policy no longer flags are resolved. Audited.
// @Tags         Tenants
// @Accept       json
// @Produce      json
// @Param        body  body  licensepolicy.Policy  true  "License policy"
// @Success      200     {object}  LicensePolicyResponse
// @Failure      400     {object}  apierror.Error
// @Failure      403     {object}  apierror.Error
// @Failure      409     {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/settings/license-policy [put]
func (h *TenantHandler) UpdateLicensePolicySettings(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil || tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	decoder.DisallowUnknownFields()
	var req licensepolicy.Policy
	if err := decoder.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := req.Normalize(); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}
	p, err := h.service.UpdateLicensePolicySettings(settingsWriteCtx(r), tenantID.String(), req, h.buildAuditContext(r))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	resp := LicensePolicyResponse{Policy: *p}
	if h.licenseEvaluator != nil {
		res, evErr := h.licenseEvaluator.EvaluateTenant(r.Context(), tenantID)
		if evErr != nil {
			h.logger.Error("license policy evaluation failed", "tenant_id", tenantID.String(), "error", evErr)
			resp.EvaluationError = "the policy was saved; evaluating the inventory did not finish"
		} else {
			resp.Evaluation = &res
		}
	}
	h.writeSectionETag(w, r, tenantID, tenant.SectionLicensePolicy)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
