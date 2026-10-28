package handler

// POST /api/v1/scope/targets/bulk: add many scope entries in one request.
// Design: docs/rfcs/RFC-054-scope-model.md §14.

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// BulkCreateScopeTargetsRequest is a list of scope entries to add.
type BulkCreateScopeTargetsRequest struct {
	Items []BulkScopeTargetItem `json:"items" validate:"required,min=1,max=200,dive"`
	// Reason is recorded on every entry of the batch (optional).
	Reason string `json:"reason" validate:"max=1000"`
	// Origin: refusal_fix when the entries fix the targets a scan refused;
	// otherwise the entries are recorded as imported.
	Origin string `json:"origin" validate:"omitempty,oneof=refusal_fix"`
	// ExpiresInDays makes every entry of the batch expire (1..365, and the
	// organization's limit per item); omitted: permanent.
	ExpiresInDays *int `json:"expires_in_days" validate:"omitempty,min=1,max=365"`
	// MaxTier is the deepest probe every entry allows (t0, t1, t2);
	// omitted: the organization's default.
	MaxTier string `json:"max_tier" validate:"omitempty,oneof=t0 t1 t2"`
}

// BulkScopeTargetItem is one entry of a bulk add.
type BulkScopeTargetItem struct {
	TargetType string `json:"target_type" validate:"required,max=50"`
	Pattern    string `json:"pattern" validate:"required,max=500"`
}

// Results of one item of a bulk add.
const (
	BulkScopeResultCreated = "created" // the entry was added (status says whether it is in effect)
	BulkScopeResultExists  = "exists"  // the organization already has this entry (id, status)
	BulkScopeResultRefused = "refused" // not added (code, message)
)

// BulkScopeTargetResult is what happened to one item, in request order.
type BulkScopeTargetResult struct {
	TargetType string `json:"target_type"`
	Pattern    string `json:"pattern"`
	Result     string `json:"result"`
	ID         string `json:"id,omitempty"`
	Status     string `json:"status,omitempty"`
	Code       string `json:"code,omitempty"`
	Message    string `json:"message,omitempty"`
}

// BulkCreateScopeTargetsResponse lists every item's result and the counts.
type BulkCreateScopeTargetsResponse struct {
	Results  []BulkScopeTargetResult `json:"results"`
	Created  int                     `json:"created"`
	Existing int                     `json:"existing"`
	Refused  int                     `json:"refused"`
}

// BulkCreateTargets handles POST /api/v1/scope/targets/bulk
// @Summary      Add many scope entries
// @Description  Add up to 200 scope entries in one request (permanent, or all expiring after expires_in_days) (a pasted list, inventory assets, or the targets a scan refused). Each item is added as POST /scope/targets would add it: platform guardrails, duplicates, the Strict request and approval rules and the signer ledger apply per item, and each added entry is audited. A caller who adds entries directly needs a recent re-authentication once for the batch (403 STEP_UP_REQUIRED, nothing written); the administrators get one notice for the batch. Every item gets a result: created (with the entry's status), exists (the organization's existing entry) or refused (a code and a message).
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        body  body      BulkCreateScopeTargetsRequest  true  "The entries"
// @Success      200   {object}  BulkCreateScopeTargetsResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/targets/bulk [post]
func (h *ScopeHandler) BulkCreateTargets(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	var req BulkCreateScopeTargetsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	items := make([]scope.BulkTargetItem, 0, len(req.Items))
	for _, it := range req.Items {
		items = append(items, scope.BulkTargetItem{TargetType: it.TargetType, Pattern: it.Pattern})
	}
	outcomes, err := h.service.CreateTargets(r.Context(), scope.BulkTargetsInput{
		TenantID:  tenantID,
		Items:     items,
		Reason:    req.Reason,
		CreatedBy: middleware.GetUserID(r.Context()),
		Actor:     scopeActor(r),
		Origin:    scopedom.Origin(req.Origin),

		ExpiresInDays: req.ExpiresInDays,
		MaxTier:       req.MaxTier,
	})
	if err != nil {
		h.handleServiceError(w, "Scope target", err)
		return
	}

	out := BulkCreateScopeTargetsResponse{Results: make([]BulkScopeTargetResult, 0, len(outcomes))}
	var started, swept bool
	for _, o := range outcomes {
		res := BulkScopeTargetResult{TargetType: o.Item.TargetType, Pattern: o.Item.Pattern}
		switch {
		case o.Err == nil:
			res.Result, res.ID, res.Status = BulkScopeResultCreated, o.Target.ID().String(), o.Target.Status().String()
			res.TargetType, res.Pattern = o.Target.TargetType().String(), o.Target.Pattern()
			h.auditTarget(r, audit.ActionScopeTargetCreated, res.ID, nil, o.Target)
			// The scans waiting for scope and a discovery sweep run once per
			// tenant for the whole batch.
			if !started && o.Target.IsActive() {
				h.startWaits(tenantID, o.Target)
				started = true
			}
			if !swept && o.Target.IsActive() && o.Target.Discovery() {
				h.sweepSeed(tenantID, o.Target)
				swept = true
			}
			out.Created++
		default:
			var dup *scopedom.DuplicateError
			if errors.As(o.Err, &dup) {
				res.Result, res.ID, res.Status = BulkScopeResultExists, dup.Existing.ID.String(), dup.Existing.Status.String()
				out.Existing++
				break
			}
			res.Result = BulkScopeResultRefused
			res.Code, res.Message = bulkItemRefusal(o.Err)
			out.Refused++
		}
		out.Results = append(out.Results, res)
	}
	if out.Created > 0 {
		h.logger.Info("scope entries added in bulk", "created", out.Created, "existing", out.Existing, "refused", out.Refused)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// bulkItemRefusal is the code and message of an item that was not added: the
// domain error's own (the codes POST /scope/targets answers), a validation
// message, or a generic failure that names nothing internal.
func bulkItemRefusal(err error) (string, string) {
	var de *shared.DomainError
	if errors.As(err, &de) && de.Code != "" {
		return de.Code, de.Message
	}
	if errors.Is(err, shared.ErrValidation) {
		return "VALIDATION_ERROR", logger.SanitizeError(err)
	}
	return "INTERNAL_ERROR", "This entry could not be added; try again"
}
