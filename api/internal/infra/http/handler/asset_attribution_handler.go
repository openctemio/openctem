package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/scopeauth"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
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
	attribution  AttributionReader
	assets       ScopedAssetGetter
	audit        AttributionAuditor
	activeGate   ActiveScanGate
	scope        AssetScopeReader
	certificates CertificateStandingReader
	effects      *easmapp.DecisionEffects
	confirm      *easmapp.ConfirmScope
	logger       *logger.Logger
}

// SetConfirmScope makes a person's confirmation add the asset's exact scope
// entry (research/117). Nil: a confirmation records ownership only.
func (h *AssetAttributionHandler) SetConfirmScope(c *easmapp.ConfirmScope) { h.confirm = c }

// SetDecisionEffects runs reclassification and rejection hygiene after a
// decision (research/22 P0-9).
func (h *AssetAttributionHandler) SetDecisionEffects(e *easmapp.DecisionEffects) { h.effects = e }

// ActiveScanGate is the active-scan ownership gate (*easm.ActiveGate).
type ActiveScanGate interface {
	ActiveCheckBlocked(ctx context.Context, tenantID shared.ID, assetIDs []string) (map[string]attribution.State, error)
}

// SetActiveGate makes active_checks_allowed answer with the gate scans use.
func (h *AssetAttributionHandler) SetActiveGate(g ActiveScanGate) { h.activeGate = g }

// AssetScopeReader answers whether the organization's scope covers an asset
// (*easm.ActiveGate).
type AssetScopeReader interface {
	ScopeOfAsset(ctx context.Context, tenantID shared.ID, assetID string) (string, *scopeauth.Via, error)
}

// SetScopeReader fills scope_status and covered_by (RFC-054 §6.6).
func (h *AssetAttributionHandler) SetScopeReader(s AssetScopeReader) { h.scope = s }

// CertificateStandingReader answers the standing of certificate assets
// (*easm.ActiveGate).
type CertificateStandingReader interface {
	CertificateStandings(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[string]easmapp.CertStanding, error)
}

// SetCertificateReader fills certificate on a certificate asset's
// attribution (RFC-054 §19).
func (h *AssetAttributionHandler) SetCertificateReader(c CertificateStandingReader) {
	h.certificates = c
}

// SetAuditService records decisions in the audit log.
func (h *AssetAttributionHandler) SetAuditService(a AttributionAuditor) { h.audit = a }

// NewAssetAttributionHandler creates the handler.
func NewAssetAttributionHandler(attr AttributionReader, assets ScopedAssetGetter, log *logger.Logger) *AssetAttributionHandler {
	return &AssetAttributionHandler{attribution: attr, assets: assets, logger: log}
}

// AssetAttributionResponse is an asset's attribution.
type AssetAttributionResponse struct {
	// State: confirmed, discovered, needs_review, candidate, dependency, monitor_only,
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
	// active_checks_allowed is false: its state (discovered: in the
	// inventory, no scope entry covers it, passive only; needs_review,
	// candidate,
	// dependency, monitor_only, rejected; rejected also for a name under a
	// rejected name), unattributed: no record, and neither inside a scope
	// entry, or
	// out_of_scope: confirmed, but no scope entry
	// covers it (confirmation alone does not authorize active checks).
	ActiveChecksBlockedBy string `json:"active_checks_blocked_by,omitempty"`
	// BlockedCode is the structured refusal code (RFC-054 §6.5) for
	// active_checks_blocked_by.
	BlockedCode string `json:"blocked_code,omitempty"`
	// ScopeStatus: in_scope, out_of_scope, internal (zone-gated) or
	// not_applicable. CoveredBy is the organization's scope target, seed or
	// verified domain that covers it (RFC-054 §6.6). Removing the scope entry
	// keeps the asset and its findings; active checks stop (out_of_scope).
	ScopeStatus string         `json:"scope_status,omitempty"`
	CoveredBy   *scopeauth.Via `json:"covered_by,omitempty"`
	DecidedAt   *time.Time     `json:"decided_at,omitempty"`
	// Certificate: on a certificate asset, why it is or is not in scope
	// (the endpoints that served it) and whether it is the organization's
	// (a name in it under a domain root). Endpoints outside the caller's
	// data scope are not named.
	Certificate *easmapp.CertStanding      `json:"certificate,omitempty"`
	Evidence    []AssetAttributionEvidence `json:"evidence"`
	// Scope: on a confirmation, the exact scope entry it added (or why
	// not); absent otherwise (research/117).
	Scope *easmapp.ConfirmScopeResult `json:"scope,omitempty"`
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
		resp.BlockedCode = scansvc.RefusalCodeForState(state)
	}
	h.applyCertificate(ctx, tenantID, assetID, resp)
	if h.scope != nil {
		status, via, err := h.scope.ScopeOfAsset(ctx, tenantID, assetID)
		if err != nil {
			h.logger.Warn("asset scope lookup failed", "error", logger.SanitizeError(err))
			return
		}
		resp.ScopeStatus, resp.CoveredBy = status, via
	}
}

// applyCertificate fills the certificate standing of a certificate asset.
// The endpoints it names are the caller's to see: one outside the caller's
// data scope is left unnamed (the counts stay).
func (h *AssetAttributionHandler) applyCertificate(ctx context.Context, tenantID shared.ID, assetID string, resp *AssetAttributionResponse) {
	if h.certificates == nil {
		return
	}
	id, err := shared.IDFromString(assetID)
	if err != nil {
		return
	}
	got, err := h.certificates.CertificateStandings(ctx, tenantID, []shared.ID{id})
	if err != nil {
		h.logger.Warn("certificate standing lookup failed", "error", logger.SanitizeError(err))
		return
	}
	st, ok := got[assetID]
	if !ok {
		return
	}
	userID, admin := middleware.GetUserID(ctx), middleware.IsAdmin(ctx)
	seen := map[string]bool{}
	visible := func(endpointID string) bool {
		if v, ok := seen[endpointID]; ok {
			return v
		}
		_, err := h.assets.GetAssetWithScope(ctx, tenantID.String(), endpointID, userID, admin)
		seen[endpointID] = err == nil
		return err == nil
	}
	eps := make([]easmapp.CertEndpoint, 0, len(st.Endpoints))
	for _, e := range st.Endpoints {
		if visible(e.AssetID) {
			eps = append(eps, e)
		}
	}
	st.Endpoints = eps
	if st.ServedBy != nil && !visible(st.ServedBy.Endpoint) {
		v := *st.ServedBy
		v.Endpoint, v.Name = "", ""
		st.ServedBy = &v
	}
	if st.HeldBy != nil && !visible(st.HeldBy.AssetID) {
		st.HeldBy = &easmapp.CertEndpoint{State: st.HeldBy.State, Guardrail: st.HeldBy.Guardrail}
	}
	resp.Certificate = &st
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
	// A confirmation adds the asset's exact scope entry first: a missing
	// re-authentication (403 STEP_UP_REQUIRED) saves nothing.
	var added *easmapp.ConfirmScopeResult
	if state == attribution.StateConfirmed && h.confirm != nil {
		added, err = h.confirm.Add(ctx, tenantID, []string{assetID}, confirmActor(ctx), easmapp.ConfirmReason)
		if err != nil {
			if middleware.WriteStepUpError(w, err, authapp.StepUpWindow) {
				return
			}
			h.logger.Error("failed to add the confirmed asset's scope entry", "error", logger.SanitizeError(err))
			apierror.InternalServerError("failed to add the scope entry").WriteJSON(w)
			return
		}
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
	h.effects.AfterDecision(ctx, tenantID, []string{assetID}, state)
	if h.audit != nil {
		event := auditapp.NewSuccessEvent(auditdom.ActionAssetAttributionDecided, auditdom.ResourceTypeAsset, assetID).
			WithMessage("Attribution set to "+string(state)).
			WithMetadata("from", from).
			WithMetadata("to", string(state)).
			WithSeverity(auditdom.SeverityMedium)
		actx := auditapp.AuditContext{
			TenantID: tenant, ActorID: userID, ActorEmail: auditActorEmail(ctx),
			ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: middleware.GetRequestID(r.Context()),
		}
		_ = h.audit.LogEvent(ctx, actx, event)
		auditConfirmEntries(ctx, h.audit, actx, added, "ownership_tab")
	}
	view, found, err := h.attribution.Get(ctx, tenantID, assetID)
	if err != nil {
		apierror.InternalServerError("failed to load attribution").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	resp := toAssetAttributionResponse(view, found)
	resp.Scope = added
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
