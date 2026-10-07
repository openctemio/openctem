package handler

// Review by rule (RFC-054 §6.7): grouped suggestions, a preview and three
// actions on the review queue.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// EASMRuleService serves review by rule (*easm.RuleService).
type EASMRuleService interface {
	Suggest(ctx context.Context, tenantID shared.ID, states []attribution.State, limit int) (*easmapp.RuleSuggestions, error)
	Preview(ctx context.Context, tenantID shared.ID, in easmapp.RuleActionInput) (*easmapp.RulePreview, error)
	Apply(ctx context.Context, tenantID shared.ID, in easmapp.RuleActionInput) (*easmapp.RuleApplied, error)
}

// SetRules wires review by rule.
func (h *EASMHandler) SetRules(r EASMRuleService) *EASMHandler {
	h.rules = r
	return h
}

// HasRules reports whether review by rule is wired.
func (h *EASMHandler) HasRules() bool { return h.rules != nil }

// EASMRuleRequest is a review-by-rule action.
type EASMRuleRequest struct {
	// Action: accept_rule, accept_selected or reject_rule.
	Action string `json:"action"`
	// TargetType: domain, cidr, ip_range or ip_address (accept_rule, reject_rule).
	TargetType string `json:"target_type"`
	Pattern    string `json:"pattern"`
	// AssetIDs are the items to confirm (accept_selected), at most 200.
	AssetIDs []string `json:"asset_ids"`
	// Reason is required for accept_rule and reject_rule (audited).
	Reason string `json:"reason"`
}

// Suggestions handles GET /api/v1/easm/candidates/suggestions
// @Summary      Review by rule: suggestions
// @Description  The caller's pending review items grouped into candidate scope rules (RFC-054 §6.7): wildcards at each label level up to the registrable domain (never a public suffix), /24 (IPv4) or /48 (IPv6) ranges (never for shared, CDN or cloud-provider space: those are listed individually), each with the items it covers, the items an exclusion or rejection keeps out, ownership hints and a strength. Narrowed to the caller's data scope.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Param        states  query string false "Attribution states (comma-separated); default needs_review"
// @Param        limit   query int    false "Suggestions to return" default(50) maximum(50)
// @Success      200  {object}  easmapp.RuleSuggestions
// @Failure      400  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /easm/candidates/suggestions [get]
func (h *EASMHandler) Suggestions(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}
	raw := parseQueryArray(r.URL.Query().Get("states"))
	states := make([]attribution.State, 0, len(raw))
	for _, s := range raw {
		st := attribution.State(s)
		if !st.Valid() {
			apierror.BadRequest("unknown attribution state").WriteJSON(w)
			return
		}
		states = append(states, st)
	}
	limit := parseQueryIntBounded(r.URL.Query().Get("limit"), 50, 1, 50)
	out, err := h.rules.Suggest(r.Context(), tenantID, states, limit)
	if err != nil {
		h.logger.Error("review by rule: suggestions", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to build suggestions").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (h *EASMHandler) ruleInput(w http.ResponseWriter, r *http.Request) (shared.ID, easmapp.RuleActionInput, bool) {
	ctx := r.Context()
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(ctx))
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return shared.ID{}, easmapp.RuleActionInput{}, false
	}
	limitBody(w, r)
	var req EASMRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return shared.ID{}, easmapp.RuleActionInput{}, false
	}
	if len(req.Pattern) > 500 || len(req.Reason) > 1000 || len(req.AssetIDs) > easmapp.MaxDecisionBatch {
		apierror.BadRequest("pattern, reason or asset_ids too long").WriteJSON(w)
		return shared.ID{}, easmapp.RuleActionInput{}, false
	}
	return tenantID, easmapp.RuleActionInput{
		Action: req.Action, TargetType: req.TargetType, Pattern: req.Pattern, Reason: req.Reason, AssetIDs: req.AssetIDs,
		Actor: scope.Actor{UserID: middleware.GetUserID(ctx), CanApprove: middleware.HasPermission(ctx, permission.ScopeApprove.String())},
	}, true
}

// PreviewRule handles POST /api/v1/easm/candidates/rules/preview
// @Summary      Review by rule: preview
// @Description  Exactly what a review-by-rule action would change, changing nothing: the scope entry or exclusion it would create (with the status and approvals it would get), the items it would confirm or reject, the items that stay blocked, and whether it needs a recent re-authentication. A refusal (PUBLIC_SUFFIX, DENY_LIST, CIDR_TOO_LARGE, REQUEST_MUST_BE_ONE_OFF, ...) comes back in refusal.
// @Tags         Attack Surface
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body EASMRuleRequest true "Action"
// @Success      200  {object}  easmapp.RulePreview
// @Failure      400  {object}  apierror.Error
// @Router       /easm/candidates/rules/preview [post]
func (h *EASMHandler) PreviewRule(w http.ResponseWriter, r *http.Request) {
	tenantID, in, ok := h.ruleInput(w, r)
	if !ok {
		return
	}
	out, err := h.rules.Preview(r.Context(), tenantID, in)
	if err != nil {
		h.ruleError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// ApplyRule handles POST /api/v1/easm/candidates/rules
// @Summary      Review by rule: apply
// @Description  accept_rule creates a permanent scope entry exactly as POST /scope/targets does (attack_surface:scope:write; with scope:approve a recent re-authentication, then the organization's approvals; everyone notified) and, once it is in effect, confirms the pending items it covers. accept_selected confirms only asset_ids. reject_rule creates a scope exclusion (pending its approval) and rejects the pending items it covers. Every change is audited. The answer is the preview with what was applied.
// @Tags         Attack Surface
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body EASMRuleRequest true "Action"
// @Success      200  {object}  easmapp.RulePreview
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Router       /easm/candidates/rules [post]
func (h *EASMHandler) ApplyRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID, in, ok := h.ruleInput(w, r)
	if !ok {
		return
	}
	// The scope entry and exclusion actions need scope:write besides the
	// route's assets:write.
	if (in.Action == easmapp.RuleAcceptRule || in.Action == easmapp.RuleRejectRule) &&
		!middleware.HasPermission(ctx, permission.ScopeWrite.String()) {
		apierror.Forbidden("This action needs the scope write permission").WriteJSON(w)
		return
	}
	res, err := h.rules.Apply(ctx, tenantID, in)
	if err != nil {
		h.ruleError(w, err)
		return
	}
	h.auditRule(r, in, res)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res.Preview)
}

func (h *EASMHandler) ruleError(w http.ResponseWriter, err error) {
	if middleware.WriteStepUpError(w, err, authapp.StepUpWindow) {
		return
	}
	var de *shared.DomainError
	switch {
	case errors.As(err, &de) && de.Code != "":
		status := http.StatusBadRequest
		if errors.Is(err, shared.ErrForbidden) {
			status = http.StatusForbidden
		} else if errors.Is(err, shared.ErrConflict) {
			status = http.StatusConflict
		}
		apierror.New(status, apierror.Code(de.Code), de.Message).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(easmValidationMessage(err)).WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict(easmValidationMessage(err)).WriteJSON(w)
	default:
		h.logger.Error("review by rule failed", "error", logger.SanitizeError(err))
		apierror.InternalServerError("the action failed").WriteJSON(w)
	}
}

// auditRule records what a review-by-rule action created and decided.
func (h *EASMHandler) auditRule(r *http.Request, in easmapp.RuleActionInput, res *easmapp.RuleApplied) {
	if h.audit == nil || res == nil {
		return
	}
	ctx := r.Context()
	actx := auditapp.AuditContext{
		TenantID: middleware.MustGetTenantID(ctx), ActorID: middleware.GetUserID(ctx), ActorEmail: auditActorEmail(ctx),
		ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID"),
	}
	reason := logger.SanitizeValue(in.Reason)
	if t := res.Target; t != nil {
		_ = h.audit.LogEvent(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionScopeTargetCreated, auditdom.ResourceTypeScopeTarget, t.ID().String()).
			WithResourceName(t.Pattern()).WithMessage("Scope entry created from the review queue").
			WithMetadata("via", "review_rule").WithMetadata("status", t.Status().String()).WithMetadata("reason", reason))
	}
	if e := res.Exclusion; e != nil {
		_ = h.audit.LogEvent(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionScopeExclusionCreated, auditdom.ResourceTypeScopeExclusion, e.ID().String()).
			WithResourceName(e.Pattern()).WithMessage("Scope exclusion requested from the review queue").
			WithMetadata("via", "review_rule").WithMetadata("reason", reason))
	}
	if res.Decisions != nil {
		for _, d := range res.Decisions.Decided {
			_ = h.audit.LogEvent(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionAssetAttributionDecided, auditdom.ResourceTypeAsset, d.AssetID).
				WithMessage("Attribution set to "+d.To).WithMetadata("from", d.From).WithMetadata("to", d.To).
				WithMetadata("via", "review_rule").WithMetadata("rule", logger.SanitizeValue(in.Pattern)).
				WithSeverity(auditdom.SeverityMedium))
		}
	}
}
