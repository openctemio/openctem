package handler

// POST /api/v1/scope/exclusions/bulk and /bulk/preview: mark many inventory
// assets out of scope in one request (research/124, RFC-054 §15.8).

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
)

// BulkScopeExclusionItem is one exclusion of a bulk request.
type BulkScopeExclusionItem struct {
	// ExclusionType: domain, subdomain, ip_address, ip_range, cidr, url or
	// repository.
	ExclusionType string `json:"exclusion_type" validate:"required,max=50"`
	Pattern       string `json:"pattern" validate:"required,max=500"`
}

// BulkCreateScopeExclusionsRequest is a list of exclusions to add.
type BulkCreateScopeExclusionsRequest struct {
	Items []BulkScopeExclusionItem `json:"items" validate:"required,min=1,max=200,dive"`
	// Reason is recorded on every exclusion (default: marked out of scope
	// from the inventory).
	Reason string `json:"reason" validate:"max=1000"`
	// Kind: why they are out of scope (default do_not_scan). not_ours and
	// retired close the open findings of what they match unless ExpiresAt
	// is set (an end date only pauses scanning).
	Kind      string     `json:"kind,omitempty" validate:"omitempty,oneof=do_not_scan not_ours retired"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// BulkScopeExclusionResult is what happened to one item, in request order.
type BulkScopeExclusionResult struct {
	ExclusionType string `json:"exclusion_type"`
	Pattern       string `json:"pattern"`
	// Result: created, exists or refused (BulkScopeResult*).
	Result  string `json:"result"`
	ID      string `json:"id,omitempty"`
	Status  string `json:"status,omitempty"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// BulkCreateScopeExclusionsResponse lists every item's result and the counts.
type BulkCreateScopeExclusionsResponse struct {
	Results  []BulkScopeExclusionResult `json:"results"`
	Created  int                        `json:"created"`
	Existing int                        `json:"existing"`
	Refused  int                        `json:"refused"`
}

// BulkCreateExclusions handles POST /api/v1/scope/exclusions/bulk
// @Summary      Mark many assets out of scope
// @Description  Add up to 200 scope exclusions in one request (exact names, a parent-domain wildcard, an address range). Each item is added as POST /scope/exclusions would add it: pattern validation, duplicates, the Strict approval rule and the signer ledger apply per item, and each added exclusion is audited. An exclusion only narrows what may be scanned; undo with POST /scope/exclusions/bulk/delete (re-authentication required). Every item gets a result: created (with the exclusion's status), exists or refused (a code and a message).
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        body  body      BulkCreateScopeExclusionsRequest  true  "The exclusions"
// @Success      200   {object}  BulkCreateScopeExclusionsResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/exclusions/bulk [post]
func (h *ScopeHandler) BulkCreateExclusions(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	var req BulkCreateScopeExclusionsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	outcomes, err := h.service.CreateExclusions(r.Context(), scope.BulkExclusionsInput{
		TenantID: tenantID, Items: bulkExclusionItems(req.Items), Reason: req.Reason,
		CreatedBy: middleware.GetUserID(r.Context()), Kind: req.Kind, ExpiresAt: req.ExpiresAt,
	})
	if err != nil {
		h.handleServiceError(w, "Scope exclusion", err)
		return
	}
	out := BulkCreateScopeExclusionsResponse{Results: make([]BulkScopeExclusionResult, 0, len(outcomes))}
	for _, o := range outcomes {
		res := BulkScopeExclusionResult{ExclusionType: o.Item.ExclusionType, Pattern: o.Item.Pattern}
		switch {
		case o.Err == nil:
			res.Result, res.ID, res.Status = BulkScopeResultCreated, o.Exclusion.ID().String(), o.Exclusion.Status().String()
			res.ExclusionType, res.Pattern = o.Exclusion.ExclusionType().String(), o.Exclusion.Pattern()
			h.auditExclusion(r, audit.ActionScopeExclusionCreated, res.ID, nil, o.Exclusion)
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
		h.logger.Info("scope exclusions added in bulk", "created", out.Created, "existing", out.Existing, "refused", out.Refused)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// PreviewScopeExclusionsRequest is the exclusions to preview.
type PreviewScopeExclusionsRequest struct {
	Items []BulkScopeExclusionItem `json:"items" validate:"required,min=1,max=200,dive"`
}

// ScopeExclusionPreviewItem is what one exclusion would match.
type ScopeExclusionPreviewItem struct {
	ExclusionType string `json:"exclusion_type"`
	Pattern       string `json:"pattern"`
	// Matched is how many of the caller's visible inventory assets it would
	// match; Sample up to ten of their names.
	Matched int      `json:"matched"`
	Sample  []string `json:"sample"`
	// OpenFindings is how many open findings those assets have: what a
	// permanent not_ours or retired exclusion would close.
	OpenFindings int `json:"open_findings"`
	// ClosingNeedsFullAccess is true when the caller has limited data access
	// and this is not an exact hostname or IP: as a not_ours or retired rule
	// it needs full data access.
	ClosingNeedsFullAccess bool `json:"closing_needs_full_access,omitempty"`
	// Code and Message say why the item would be refused.
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// PreviewScopeExclusionsResponse is the preview, in request order.
type PreviewScopeExclusionsResponse struct {
	Items []ScopeExclusionPreviewItem `json:"items"`
}

// PreviewBulkExclusions handles POST /api/v1/scope/exclusions/bulk/preview
// @Summary      Preview marking assets out of scope
// @Description  For each candidate exclusion, how many of the caller's visible inventory assets it would match (data scope applies) and up to ten of their names, or why it would be refused. Nothing is written.
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        body  body      PreviewScopeExclusionsRequest  true  "The exclusions"
// @Success      200   {object}  PreviewScopeExclusionsResponse
// @Failure      400   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/exclusions/bulk/preview [post]
func (h *ScopeHandler) PreviewBulkExclusions(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	var req PreviewScopeExclusionsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	previews, err := h.service.PreviewExclusions(r.Context(), tenantID, bulkExclusionItems(req.Items))
	if err != nil {
		h.handleServiceError(w, "Scope exclusion", err)
		return
	}
	out := PreviewScopeExclusionsResponse{Items: make([]ScopeExclusionPreviewItem, 0, len(previews))}
	for _, p := range previews {
		item := ScopeExclusionPreviewItem{ExclusionType: p.Item.ExclusionType, Pattern: p.Item.Pattern,
			Matched: p.Match.Matched, Sample: p.Match.Sample, OpenFindings: p.Match.OpenFindings,
			ClosingNeedsFullAccess: p.ClosingNeedsFullAccess}
		if item.Sample == nil {
			item.Sample = []string{}
		}
		if p.Err != nil {
			item.Code, item.Message = bulkItemRefusal(p.Err)
		}
		out.Items = append(out.Items, item)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func bulkExclusionItems(in []BulkScopeExclusionItem) []scope.BulkExclusionItem {
	out := make([]scope.BulkExclusionItem, 0, len(in))
	for _, it := range in {
		out = append(out, scope.BulkExclusionItem{ExclusionType: it.ExclusionType, Pattern: it.Pattern})
	}
	return out
}
