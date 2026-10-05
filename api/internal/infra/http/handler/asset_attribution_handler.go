package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/apierror"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AttributionReader reads an asset's attribution and evidence and records
// a person's decision.
type AttributionReader interface {
	Get(ctx context.Context, tenantID shared.ID, assetID string) (*postgres.AttributionView, bool, error)
	SaveDecision(ctx context.Context, tenantID shared.ID, assetID string, state attribution.State, decidedBy string) (bool, error)
}

// AttributionAuditor records attribution decisions in the audit log.
type AttributionAuditor interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// ScopedAssetGetter loads an asset the caller may see (tenant + data scope).
type ScopedAssetGetter interface {
	GetAssetWithScope(ctx context.Context, tenantID, assetID, actingUserID string, isAdmin bool) (*assetdom.Asset, error)
}

// AssetAttributionHandler serves why an asset is believed to be the tenant's
// (RFC-036 §6.4).
type AssetAttributionHandler struct {
	attribution AttributionReader
	assets      ScopedAssetGetter
	audit       AttributionAuditor
	activeGate  ActiveScanGate
	logger      *logger.Logger
}

// ActiveScanGate is the active-scan ownership gate (*easm.ActiveGate).
type ActiveScanGate interface {
	ActiveCheckBlocked(ctx context.Context, tenantID shared.ID, assetIDs []string) (map[string]attribution.State, error)
}

// SetActiveGate makes active_checks_allowed answer with the gate scans use.
func (h *AssetAttributionHandler) SetActiveGate(g ActiveScanGate) { h.activeGate = g }

// SetAuditService records decisions in the audit log.
func (h *AssetAttributionHandler) SetAuditService(a AttributionAuditor) { h.audit = a }

// NewAssetAttributionHandler creates the handler.
func NewAssetAttributionHandler(attr AttributionReader, assets ScopedAssetGetter, log *logger.Logger) *AssetAttributionHandler {
	return &AssetAttributionHandler{attribution: attr, assets: assets, logger: log}
}

// AssetAttributionResponse is an asset's attribution.
type AssetAttributionResponse struct {
	// State: confirmed, needs_review, candidate, dependency, monitor_only,
	// rejected. An asset with no record is a legacy asset and reports
	// confirmed with recorded=false.
	State      string `json:"state"`
	Confidence int    `json:"confidence"`
	Reason     string `json:"reason,omitempty"`
	Recorded   bool   `json:"recorded"`
	// HumanDecided: a person set the state; automation will not change it.
	HumanDecided bool `json:"human_decided"`
	// ActiveChecksAllowed: whether a scan may touch the asset.
	ActiveChecksAllowed bool `json:"active_checks_allowed"`
	// ActiveChecksBlockedBy says why a scan may not touch the asset when
	// active_checks_allowed is false: its state (needs_review, candidate,
	// dependency, monitor_only, rejected; rejected also for a name under a
	// rejected name), or unattributed: no record, and neither inside a scope
	// target nor under a root-domain seed or verified domain.
	ActiveChecksBlockedBy string                     `json:"active_checks_blocked_by,omitempty"`
	DecidedAt             *time.Time                 `json:"decided_at,omitempty"`
	Evidence              []AssetAttributionEvidence `json:"evidence"`
}

// AssetAttributionEvidence is one reason.
type AssetAttributionEvidence struct {
	Rule            string         `json:"rule"`
	Technique       string         `json:"technique"`
	Source          string         `json:"source"`
	Weight          float64        `json:"weight"`
	Observed        map[string]any `json:"observed,omitempty"`
	FirstObservedAt time.Time      `json:"first_observed_at"`
	LastObservedAt  time.Time      `json:"last_observed_at"`
}

// Get handles GET /api/v1/assets/{id}/attribution
// @Summary      Asset attribution
// @Description  Whether the asset is believed to be the organization's, how confident the platform is, and the evidence (rule, technique, source, observed datum). Assets discovered passively under a domain the organization did not verify wait for review and are skipped by scans until confirmed.
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Asset ID"
// @Success      200  {object}  AssetAttributionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /assets/{id}/attribution [get]
func (h *AssetAttributionHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenant := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenant)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}
	assetID := r.PathValue("id")
	if _, err := shared.IDFromString(assetID); err != nil {
		apierror.BadRequest("Invalid asset ID").WriteJSON(w)
		return
	}
	// Tenant isolation and data scope, as for the asset itself.
	if _, err := h.assets.GetAssetWithScope(ctx, tenant, assetID, middleware.GetUserID(ctx), middleware.IsAdmin(ctx)); err != nil {
		if errors.Is(err, shared.ErrNotFound) || errors.Is(err, shared.ErrForbidden) {
			apierror.NotFound("Asset").WriteJSON(w)
			return
		}
		h.logger.Error("failed to load asset for attribution", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to load asset").WriteJSON(w)
		return
	}

	view, found, err := h.attribution.Get(ctx, tenantID, assetID)
	if err != nil {
		h.logger.Error("failed to load attribution", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to load attribution").WriteJSON(w)
		return
	}
	resp := toAssetAttributionResponse(view, found)
	h.applyActiveGate(ctx, tenantID, assetID, &resp)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// applyActiveGate answers active_checks_allowed with the gate scans use, so
// the page says what a scan will do. A failed lookup reports not allowed.
func (h *AssetAttributionHandler) applyActiveGate(ctx context.Context, tenantID shared.ID, assetID string, resp *AssetAttributionResponse) {
	if h.activeGate == nil {
		return
	}
	blocked, err := h.activeGate.ActiveCheckBlocked(ctx, tenantID, []string{assetID})
	if err != nil {
		h.logger.Warn("active-scan gate lookup failed", "error", logger.SanitizeError(err))
		resp.ActiveChecksAllowed = false
		return
	}
	state, no := blocked[assetID]
	resp.ActiveChecksAllowed = !no
	if no {
		resp.ActiveChecksBlockedBy = string(state)
	}
}

// AssetAttributionDecisionRequest is a person's decision.
type AssetAttributionDecisionRequest struct {
	// State: confirmed, rejected, dependency, monitor_only or needs_review.
	State string `json:"state"`
}

// Decide handles PUT /api/v1/assets/{id}/attribution
// @Summary      Decide asset attribution
// @Description  Record whether the asset is the organization's. confirmed lets scans reach it; rejected, dependency (the organization's name on someone else's infrastructure) and monitor_only keep it passive. Automation never changes a decided state. Audited.
// @Tags         Assets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id   path string true "Asset ID"
// @Param        body body AssetAttributionDecisionRequest true "Decision"
// @Success      200  {object}  AssetAttributionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /assets/{id}/attribution [put]
func (h *AssetAttributionHandler) Decide(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenant := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenant)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}
	assetID := r.PathValue("id")
	if _, err := shared.IDFromString(assetID); err != nil {
		apierror.BadRequest("Invalid asset ID").WriteJSON(w)
		return
	}
	limitBody(w, r)
	var req AssetAttributionDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	state := attribution.State(req.State)
	switch state {
	case attribution.StateConfirmed, attribution.StateRejected, attribution.StateDependency,
		attribution.StateMonitorOnly, attribution.StateNeedsReview:
	default:
		apierror.BadRequest("state must be confirmed, rejected, dependency, monitor_only or needs_review").WriteJSON(w)
		return
	}
	userID := middleware.GetUserID(ctx)
	if _, err := h.assets.GetAssetWithScope(ctx, tenant, assetID, userID, middleware.IsAdmin(ctx)); err != nil {
		if errors.Is(err, shared.ErrNotFound) || errors.Is(err, shared.ErrForbidden) {
			apierror.NotFound("Asset").WriteJSON(w)
			return
		}
		h.logger.Error("failed to load asset for attribution decision", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to load asset").WriteJSON(w)
		return
	}
	before, _, err := h.attribution.Get(ctx, tenantID, assetID)
	if err != nil {
		h.logger.Error("failed to load attribution", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to load attribution").WriteJSON(w)
		return
	}
	from := string(attribution.StateConfirmed) // no record: a legacy, confirmed asset
	if before != nil && before.Record.State != "" {
		from = string(before.Record.State)
	}
	ok, err := h.attribution.SaveDecision(ctx, tenantID, assetID, state, userID)
	if err != nil {
		h.logger.Error("failed to save attribution decision", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to save decision").WriteJSON(w)
		return
	}
	if !ok {
		apierror.NotFound("Asset").WriteJSON(w)
		return
	}
	if h.audit != nil {
		event := auditapp.NewSuccessEvent(auditdom.ActionAssetAttributionDecided, auditdom.ResourceTypeAsset, assetID).
			WithMessage("Attribution set to "+string(state)).
			WithMetadata("from", from).
			WithMetadata("to", string(state)).
			WithSeverity(auditdom.SeverityMedium)
		_ = h.audit.LogEvent(ctx, auditapp.AuditContext{
			TenantID: tenant, ActorID: userID, ActorEmail: auditActorEmail(ctx),
			ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID"),
		}, event)
	}
	view, found, err := h.attribution.Get(ctx, tenantID, assetID)
	if err != nil {
		apierror.InternalServerError("failed to load attribution").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	resp := toAssetAttributionResponse(view, found)
	h.applyActiveGate(ctx, tenantID, assetID, &resp)
	_ = json.NewEncoder(w).Encode(resp)
}

func toAssetAttributionResponse(view *postgres.AttributionView, found bool) AssetAttributionResponse {
	resp := AssetAttributionResponse{
		State:      string(attribution.StateConfirmed),
		Confidence: 100,
		Evidence:   []AssetAttributionEvidence{},
	}
	if found {
		resp.State = string(view.Record.State)
		resp.Confidence = view.Record.Confidence
		resp.Reason = string(view.Record.Reason)
		resp.Recorded = true
		resp.HumanDecided = view.Record.HumanDecided
		resp.DecidedAt = view.DecidedAt
	}
	resp.ActiveChecksAllowed = attribution.State(resp.State).AllowsActiveChecks()
	if view != nil {
		for _, e := range view.Evidence {
			resp.Evidence = append(resp.Evidence, AssetAttributionEvidence{
				Rule: string(e.Rule), Technique: e.Technique, Source: e.Source, Weight: e.Weight,
				Observed: e.Observed, FirstObservedAt: e.FirstObservedAt, LastObservedAt: e.LastObservedAt,
			})
		}
	}
	return resp
}
