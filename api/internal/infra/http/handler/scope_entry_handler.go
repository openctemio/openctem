package handler

// Approving scope entries and the organization's scope settings (RFC-054
// §6.1, §6.3).

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ScopeSettingsStore reads and writes the organization's scope settings
// (*tenant.TenantService).
type ScopeSettingsStore interface {
	GetScopeSettings(ctx context.Context, tenantID string) (*tenant.ScopeSettings, error)
	UpdateScopeSettings(ctx context.Context, tenantID string, ss tenant.ScopeSettings, actx auditapp.AuditContext) (*tenant.ScopeSettings, error)
	UpdateIntrusiveScopeSettings(ctx context.Context, tenantID string, in tenant.IntrusiveScopeSettings, reason string, actx auditapp.AuditContext) (*tenant.ScopeSettings, error)
}

// SetSettingsStore wires GET/PUT /scope/settings.
func (h *ScopeHandler) SetSettingsStore(s ScopeSettingsStore) { h.settings = s }

// SetActiveProof shows the operator's SCOPE_ACTIVE_PROOF in the settings
// (read-only; RFC-054 §8.1).
func (h *ScopeHandler) SetActiveProof(mode string) { h.activeProof = mode }

// ApproveTarget handles POST /api/v1/scope/targets/{id}/approve
// @Summary      Approve scope entry
// @Description  Record your approval of a pending scope entry (RFC-054). Needs attack_surface:scope:approve and a recent re-authentication (403 STEP_UP_REQUIRED). The requester cannot approve, and nobody approves twice; once the entry has its required approvals it is active. Audited; the administrators are notified when it takes effect.
// @Tags         Scope
// @Produce      json
// @Param        id   path      string  true  "Target ID"
// @Success      200  {object}  ScopeTargetResponse
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/targets/{id}/approve [post]
func (h *ScopeHandler) ApproveTarget(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())
	before, ok := h.targetBefore(w, r, tenantID, targetID)
	if !ok {
		return
	}
	target, effective, err := h.service.ApproveTarget(r.Context(), targetID, tenantID, scopeActor(r))
	if err != nil {
		h.handleServiceError(w, "Scope target", err)
		return
	}
	h.auditTarget(r, audit.ActionScopeTargetApproved, targetID, before, target)
	out := h.targetOut(r, target)
	if effective {
		h.discover(tenantID, target)
		out = h.joinedOut(r, target)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// RejectTarget handles POST /api/v1/scope/targets/{id}/reject
// @Summary      Reject scope entry
// @Description  Decline a pending scope entry; it never takes effect. Needs attack_surface:scope:approve. Audited.
// @Tags         Scope
// @Produce      json
// @Param        id   path      string  true  "Target ID"
// @Success      200  {object}  ScopeTargetResponse
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/targets/{id}/reject [post]
func (h *ScopeHandler) RejectTarget(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())
	before, ok := h.targetBefore(w, r, tenantID, targetID)
	if !ok {
		return
	}
	target, err := h.service.RejectTarget(r.Context(), targetID, tenantID, scopeActor(r))
	if err != nil {
		h.handleServiceError(w, "Scope target", err)
		return
	}
	h.auditTarget(r, audit.ActionScopeTargetRejected, targetID, before, target)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.targetOut(r, target))
}

// ScopeSettingsResponse is the organization's scope settings (RFC-054 §6.3).
type ScopeSettingsResponse struct {
	AutoJoinDiscovered bool `json:"auto_join_discovered"`
	// OneOffTargets: admins, admins_and_requests or disabled.
	OneOffTargets string `json:"one_off_targets"`
	OneOffMaxDays int    `json:"one_off_max_days"`
	// WideningApprovals: null is the default min(1, admins-1).
	WideningApprovals *int   `json:"widening_approvals"`
	DefaultMaxTier    string `json:"default_max_tier"`
	// Read-only: the approvals a widening needs now, and the administrators
	// that count.
	EffectiveWideningApprovals int `json:"effective_widening_approvals"`
	AdminCount                 int `json:"admin_count"`
	// ActiveProof is the operator's setting: off, platform_sensors or all.
	// Read-only; no tenant setting changes it.
	ActiveProof string `json:"active_proof"`
	// T2MaxDuration is the longest an intrusive (t2) entry may last: 7d,
	// 30d, 90d, 365d or permanent. Owner-only (PUT /scope/settings/intrusive).
	T2MaxDuration string `json:"t2_max_duration" enums:"7d,30d,90d,365d,permanent"`
	// T2MaxDays is the most expires_in_days a t2 entry may ask for.
	T2MaxDays int `json:"t2_max_days"`
	// T2PermanentAllowed: a t2 entry may be permanent.
	T2PermanentAllowed bool `json:"t2_permanent_allowed"`
}

// ScopeSettingsRequest replaces the settings. There is no field that turns
// scope off.
type ScopeSettingsRequest struct {
	AutoJoinDiscovered *bool  `json:"auto_join_discovered"`
	OneOffTargets      string `json:"one_off_targets" validate:"omitempty,oneof=admins admins_and_requests disabled"`
	OneOffMaxDays      int    `json:"one_off_max_days" validate:"omitempty,min=1,max=30"`
	WideningApprovals  *int   `json:"widening_approvals" validate:"omitempty,min=0,max=2"`
	DefaultMaxTier     string `json:"default_max_tier" validate:"omitempty,oneof=t0 t1"`
}

func (h *ScopeHandler) settingsResponse(ctx context.Context, tenantID string, ss tenant.ScopeSettings) (ScopeSettingsResponse, error) {
	approvals, admins, err := h.service.EffectiveApprovals(ctx, tenantID)
	if err != nil {
		return ScopeSettingsResponse{}, err
	}
	t2Days, t2Permanent := ss.T2Max()
	return ScopeSettingsResponse{
		AutoJoinDiscovered: !ss.AutoJoinDisabled, OneOffTargets: ss.OneOffPolicy(), OneOffMaxDays: ss.MaxDays(),
		WideningApprovals: ss.WideningApprovals, DefaultMaxTier: ss.Tier(),
		EffectiveWideningApprovals: approvals, AdminCount: admins,
		ActiveProof:   activeProofOrOff(h.activeProof),
		T2MaxDuration: ss.T2Duration(), T2MaxDays: t2Days, T2PermanentAllowed: t2Permanent,
	}, nil
}

func activeProofOrOff(m string) string {
	if m == "" {
		return "off"
	}
	return m
}

// GetSettings handles GET /api/v1/scope/settings
// @Summary      Scope settings
// @Description  The organization's scope knobs (RFC-054): auto-join of discovered names, who adds one-off entries, their maximum days, the widening approval count and the default tier, with the approval count in effect now.
// @Tags         Scope
// @Produce      json
// @Success      200  {object}  ScopeSettingsResponse
// @Failure      401  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/settings [get]
func (h *ScopeHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	if h.settings == nil {
		apierror.InternalServerError("scope settings are not available").WriteJSON(w)
		return
	}
	ss, err := h.settings.GetScopeSettings(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("scope settings: read", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to read the settings").WriteJSON(w)
		return
	}
	resp, err := h.settingsResponse(r.Context(), tenantID, *ss)
	if err != nil {
		h.logger.Error("scope settings: approvals", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to read the settings").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// UpdateSettings handles PUT /api/v1/scope/settings
// @Summary      Change scope settings
// @Description  Replace the organization's scope knobs. Needs attack_surface:scope:approve and a recent re-authentication (403 STEP_UP_REQUIRED). An organization with two or more administrators cannot go below one approval, and intrusive entries always need one. Audited; every administrator is notified.
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        body body ScopeSettingsRequest true "Settings"
// @Success      200  {object}  ScopeSettingsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/settings [put]
func (h *ScopeHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := middleware.MustGetTenantID(ctx)
	if h.settings == nil {
		apierror.InternalServerError("scope settings are not available").WriteJSON(w)
		return
	}
	var req ScopeSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	ss := tenant.ScopeSettings{
		AutoJoinDisabled: req.AutoJoinDiscovered != nil && !*req.AutoJoinDiscovered,
		OneOffTargets:    req.OneOffTargets, OneOffMaxDays: req.OneOffMaxDays,
		WideningApprovals: req.WideningApprovals, DefaultMaxTier: req.DefaultMaxTier,
	}
	actx := auditapp.AuditContext{
		TenantID: tenantID, ActorID: middleware.GetUserID(ctx), ActorEmail: auditActorEmail(ctx),
		ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID"),
	}
	out, err := h.settings.UpdateScopeSettings(ctx, tenantID, ss, actx)
	if err != nil {
		h.handleServiceError(w, "Scope settings", err)
		return
	}
	if id, err := shared.IDFromString(tenantID); err == nil {
		h.service.NotifyAdmins(ctx, id, "Scope settings changed", "The organization's scope settings were changed; review them in Scoping.")
	}
	resp, err := h.settingsResponse(ctx, tenantID, *out)
	if err != nil {
		h.logger.Error("scope settings: approvals", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to read the settings").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// ScopeIntrusiveSettingsRequest changes the owner-only scope settings.
type ScopeIntrusiveSettingsRequest struct {
	// T2MaxDuration: 7d, 30d, 90d, 365d or permanent.
	T2MaxDuration string `json:"t2_max_duration" validate:"required,oneof=7d 30d 90d 365d permanent"`
	// Reason is kept in the audit log.
	Reason string `json:"reason" validate:"required,max=1000"`
}

// UpdateIntrusiveSettings handles PUT /api/v1/scope/settings/intrusive
// @Summary      Change the intrusive (t2) scope settings
// @Description  The longest an intrusive (t2) scope entry may last: 7d, 30d (default), 90d, 365d or permanent (RFC-054 §12.4). Owner only, with a recent re-authentication (403 STEP_UP_REQUIRED) and a reason. A t2 entry still needs a verified domain and an approval. Audited at high severity; every administrator is notified. PUT /scope/settings never changes it.
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        body body ScopeIntrusiveSettingsRequest true "Settings"
// @Success      200  {object}  ScopeSettingsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/settings/intrusive [put]
func (h *ScopeHandler) UpdateIntrusiveSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := middleware.MustGetTenantID(ctx)
	if h.settings == nil {
		apierror.InternalServerError("scope settings are not available").WriteJSON(w)
		return
	}
	var req ScopeIntrusiveSettingsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	actx := auditapp.AuditContext{
		TenantID: tenantID, ActorID: middleware.GetUserID(ctx), ActorEmail: auditActorEmail(ctx),
		ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID"),
	}
	out, err := h.settings.UpdateIntrusiveScopeSettings(ctx, tenantID, tenant.IntrusiveScopeSettings{T2MaxDuration: req.T2MaxDuration}, req.Reason, actx)
	if err != nil {
		h.handleServiceError(w, "Scope settings", err)
		return
	}
	if id, err := shared.IDFromString(tenantID); err == nil {
		h.service.NotifyAdmins(ctx, id, "Intrusive scope settings changed",
			"An owner changed how long intrusive (t2) scope entries may last to "+out.T2Duration()+". Reason: "+strings.TrimSpace(req.Reason))
	}
	resp, err := h.settingsResponse(ctx, tenantID, *out)
	if err != nil {
		h.logger.Error("scope settings: approvals", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to read the settings").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
