package handler

// Edits that lower an asset's risk inputs: impact preview, pending requests
// and their decisions (docs/architecture/asset-risk-governance.md).

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SetRiskGovernance wires the preview and the decisions of risk-lowering edits.
func (h *AssetHandler) SetRiskGovernance(g *finding.AssetRiskGovernance) { h.riskGov = g }

// RiskRequestResponse is an edit that lowers risk inputs and waits for approval.
type RiskRequestResponse struct {
	ID                 string          `json:"id"`
	LoweredFields      []string        `json:"lowered_fields"`
	Requested          RiskInputsBody  `json:"requested"`
	Previous           RiskInputsBody  `json:"previous"`
	Reason             string          `json:"reason"`
	RequestedBy        string          `json:"requested_by,omitempty"`
	Status             string          `json:"status"`
	Tier               string          `json:"tier"`
	RequiredApprovals  int             `json:"required_approvals"`
	ApprovalsCollected int             `json:"approvals_collected"`
	Impact             json.RawMessage `json:"impact,omitempty"`
	DecideBy           string          `json:"decide_by"`
	CreatedAt          string          `json:"created_at"`
}

// RiskInputsBody is the priority inputs of an asset.
type RiskInputsBody struct {
	Exposure    string `json:"exposure"`
	Criticality string `json:"criticality"`
	CrownJewel  bool   `json:"is_crown_jewel"`
}

func toRiskInputsBody(p asset.PriorityInputs) RiskInputsBody {
	return RiskInputsBody{Exposure: string(p.Exposure), Criticality: string(p.Criticality), CrownJewel: p.CrownJewel}
}

func toRiskRequestResponse(r *asset.RiskChangeRequest) *RiskRequestResponse {
	if r == nil {
		return nil
	}
	out := &RiskRequestResponse{
		ID: r.ID.String(), LoweredFields: r.Lowered, Requested: toRiskInputsBody(r.Requested), Previous: toRiskInputsBody(r.Previous),
		Reason: r.Reason, Status: string(r.Status), Tier: r.Tier, RequiredApprovals: r.RequiredApprovals,
		ApprovalsCollected: r.ApprovalsCollected, DecideBy: r.DecideBy.UTC().Format(time.RFC3339),
		CreatedAt: r.CreatedAt.UTC().Format(time.RFC3339),
	}
	if len(r.Impact) > 0 {
		out.Impact = json.RawMessage(r.Impact)
	}
	if r.RequestedBy != nil {
		out.RequestedBy = r.RequestedBy.String()
	}
	return out
}

// riskContext is who edits and what they said, for the governed service calls.
func (h *AssetHandler) riskContext(r *http.Request, reason string) assetapp.RiskContext {
	return assetapp.RiskContext{
		CanApprove: middleware.HasPermission(r.Context(), permission.FindingsApprove.String()),
		Reason:     reason,
		Audit:      h.buildAuditContext(r),
	}
}

// writeRiskError answers the errors of the risk governance: an approval
// policy refusal (403, or 409 when nobody can approve), a conflict (a request
// is already pending, the asset changed, the decision window passed) and a
// forbidden decision keep their message; everything else is the asset
// handler's usual mapping.
func (h *AssetHandler) writeRiskError(w http.ResponseWriter, err error) {
	if ref, ok := approvalpolicy.IsRefusal(err); ok {
		status := http.StatusForbidden
		if ref.Code == approvalpolicy.CodeNoEligibleApprover {
			status = http.StatusConflict
		}
		apierror.New(status, apierror.Code(ref.Code), ref.Error()).
			WithDetails(map[string]string{"reason": ref.Reason}).WriteJSON(w)
		return
	}
	switch {
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden) && !errors.Is(err, shared.ErrNotFound):
		apierror.Forbidden(err.Error()).WriteJSON(w)
	default:
		h.handleServiceError(w, err)
	}
}

// writeAssetHeld answers an edit whose lowered fields wait for approval: 202
// with the asset as it is (the rest of the edit applied) and the request.
func (h *AssetHandler) writeAssetHeld(w http.ResponseWriter, a *asset.Asset, held *asset.RiskChangeRequest) {
	resp := toAssetResponse(a)
	resp.PendingRiskRequest = toRiskRequestResponse(held)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(resp)
}

// addPendingRiskRequest adds the asset's pending request (the asset was read
// under the caller's data scope).
func (h *AssetHandler) addPendingRiskRequest(r *http.Request, tenantID string, resp *AssetResponse) {
	if h.riskGov == nil {
		return
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return
	}
	aid, err := shared.IDFromString(resp.ID)
	if err != nil {
		return
	}
	req, err := h.riskGov.PendingRequest(r.Context(), tid, aid)
	if err != nil {
		h.logger.Warn("read pending risk request", "asset_id", resp.ID, "error", err)
		return
	}
	resp.PendingRiskRequest = toRiskRequestResponse(req)
}

// RiskImpactRequest is a proposed change of an asset's priority inputs; an
// omitted field keeps the asset's value.
type RiskImpactRequest struct {
	Exposure     *string `json:"exposure" validate:"omitempty,exposure"`
	Criticality  *string `json:"criticality" validate:"omitempty,criticality"`
	IsCrownJewel *bool   `json:"is_crown_jewel"`
}

// PreviewRiskChange handles POST /api/v1/assets/{id}/risk-impact
// @Summary      Preview the impact of lowering an asset's risk inputs
// @Description  Counts the asset's open findings whose priority class would drop if exposure, criticality or the crown-jewel flag changed as given, and says how the change would be decided for the caller (alone, or by a second person under the organization's approval policy). Read-only; nothing is stored.
// @Tags         Assets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id       path      string             true  "Asset ID"
// @Param        request  body      RiskImpactRequest  true  "Proposed values"
// @Success      200  {object}  asset.RiskPreview
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /assets/{id}/risk-impact [post]
func (h *AssetHandler) PreviewRiskChange(w http.ResponseWriter, r *http.Request) {
	if h.riskGov == nil {
		apierror.NotFound("Asset risk governance is not available").WriteJSON(w)
		return
	}
	var req RiskImpactRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	tenantID := middleware.MustGetTenantID(r.Context())
	a, err := h.service.GetAsset(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeRiskError(w, err)
		return
	}
	proposed := asset.PriorityInputsOf(a)
	if req.Exposure != nil {
		e, perr := asset.ParseExposure(*req.Exposure)
		if perr != nil {
			apierror.BadRequest("invalid exposure").WriteJSON(w)
			return
		}
		proposed.Exposure = e
	}
	if req.Criticality != nil {
		c, perr := asset.ParseCriticality(*req.Criticality)
		if perr != nil {
			apierror.BadRequest("invalid criticality").WriteJSON(w)
			return
		}
		proposed.Criticality = c
	}
	if req.IsCrownJewel != nil {
		proposed.CrownJewel = *req.IsCrownJewel
	}
	caller, _ := shared.IDFromString(middleware.GetUserID(r.Context()))
	prev, err := h.riskGov.Preview(r.Context(), a.TenantID(), a.ID(), caller,
		middleware.HasPermission(r.Context(), permission.FindingsApprove.String()), proposed)
	if err != nil {
		h.writeRiskError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, prev)
}

// RejectRiskRequestRequest carries the reason of a rejection.
type RejectRiskRequestRequest struct {
	Reason string `json:"reason"`
}

func (h *AssetHandler) riskDecisionInput(r *http.Request, note string) finding.DecideRiskRequestInput {
	return finding.DecideRiskRequestInput{
		TenantID:  middleware.MustGetTenantID(r.Context()),
		AssetID:   r.PathValue("id"),
		RequestID: r.PathValue("request_id"),
		ActorID:   middleware.GetUserID(r.Context()),
		Note:      note,
		Audit:     h.buildAuditContext(r),
	}
}

func (h *AssetHandler) writeRiskDecision(w http.ResponseWriter, r *http.Request, res *finding.RiskDecisionResult) {
	a, err := h.service.GetAsset(r.Context(), middleware.MustGetTenantID(r.Context()), r.PathValue("id"))
	if err != nil {
		h.writeRiskError(w, err)
		return
	}
	resp := toAssetResponse(a)
	if res.Request != nil && res.Request.Status == asset.RiskRequestPending {
		resp.PendingRiskRequest = toRiskRequestResponse(res.Request)
	}
	writeJSON(w, http.StatusOK, resp)
}

// GetPendingRiskRequest handles GET /api/v1/assets/{id}/risk-requests/pending
// @Summary      The asset's pending risk change request
// @Description  The edit that lowers the asset's exposure, criticality or crown-jewel flag and waits for approval, or 404 when there is none.
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      200  {object}  RiskRequestResponse
// @Failure      404  {object}  map[string]string
// @Router       /assets/{id}/risk-requests/pending [get]
func (h *AssetHandler) GetPendingRiskRequest(w http.ResponseWriter, r *http.Request) {
	if h.riskGov == nil {
		apierror.NotFound("Asset risk governance is not available").WriteJSON(w)
		return
	}
	a, err := h.service.GetAsset(r.Context(), middleware.MustGetTenantID(r.Context()), r.PathValue("id"))
	if err != nil {
		h.writeRiskError(w, err)
		return
	}
	req, err := h.riskGov.PendingRequest(r.Context(), a.TenantID(), a.ID())
	if err != nil {
		h.writeRiskError(w, err)
		return
	}
	if req == nil {
		apierror.NotFound("No risk change request is waiting for this asset").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, toRiskRequestResponse(req))
}

// ApproveRiskRequest handles POST /api/v1/assets/{id}/risk-requests/{request_id}/approve
// @Summary      Approve a risk change request
// @Description  Records the caller's approval of a pending request to lower an asset's risk inputs under the approval policy evaluated now; the last approval needed applies it. The requester and the asset's owners cannot approve.
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id          path  string  true  "Asset ID"
// @Param        request_id  path  string  true  "Request ID"
// @Success      200  {object}  AssetResponse
// @Failure      403  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      409  {object}  map[string]string
// @Router       /assets/{id}/risk-requests/{request_id}/approve [post]
func (h *AssetHandler) ApproveRiskRequest(w http.ResponseWriter, r *http.Request) {
	if h.riskGov == nil {
		apierror.NotFound("Asset risk governance is not available").WriteJSON(w)
		return
	}
	res, err := h.riskGov.ApproveRequest(r.Context(), h.riskDecisionInput(r, ""))
	if err != nil {
		if middleware.WriteStepUpError(w, err, authapp.StepUpWindow) {
			return
		}
		h.writeRiskError(w, err)
		return
	}
	h.writeRiskDecision(w, r, res)
}

// RejectRiskRequest handles POST /api/v1/assets/{id}/risk-requests/{request_id}/reject
// @Summary      Reject a risk change request
// @Description  Rejects a pending request with a reason; the asset keeps its values.
// @Tags         Assets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id          path  string                    true  "Asset ID"
// @Param        request_id  path  string                    true  "Request ID"
// @Param        request     body  RejectRiskRequestRequest  true  "Reason"
// @Success      200  {object}  AssetResponse
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /assets/{id}/risk-requests/{request_id}/reject [post]
func (h *AssetHandler) RejectRiskRequest(w http.ResponseWriter, r *http.Request) {
	if h.riskGov == nil {
		apierror.NotFound("Asset risk governance is not available").WriteJSON(w)
		return
	}
	var req RejectRiskRequestRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	res, err := h.riskGov.RejectRequest(r.Context(), h.riskDecisionInput(r, req.Reason))
	if err != nil {
		h.writeRiskError(w, err)
		return
	}
	h.writeRiskDecision(w, r, res)
}

// CancelRiskRequest handles POST /api/v1/assets/{id}/risk-requests/{request_id}/cancel
// @Summary      Withdraw a risk change request
// @Description  The requester withdraws their own pending request.
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id          path  string  true  "Asset ID"
// @Param        request_id  path  string  true  "Request ID"
// @Success      200  {object}  AssetResponse
// @Failure      403  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /assets/{id}/risk-requests/{request_id}/cancel [post]
func (h *AssetHandler) CancelRiskRequest(w http.ResponseWriter, r *http.Request) {
	if h.riskGov == nil {
		apierror.NotFound("Asset risk governance is not available").WriteJSON(w)
		return
	}
	res, err := h.riskGov.CancelRequest(r.Context(), h.riskDecisionInput(r, ""))
	if err != nil {
		h.writeRiskError(w, err)
		return
	}
	h.writeRiskDecision(w, r, res)
}
