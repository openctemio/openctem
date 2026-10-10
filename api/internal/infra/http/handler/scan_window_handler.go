package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	swapp "github.com/openctemio/openctem/api/internal/app/scanwindow"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	swdom "github.com/openctemio/openctem/api/pkg/domain/scanwindow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ScanWindowHandler serves scan window policies, their evaluation and
// overrides (docs/architecture/scan-windows.md). Tenant from the JWT; every
// query is tenant-scoped; a policy, override or asset of another
// organization is 404.
type ScanWindowHandler struct {
	service *swapp.Service
	logger  *logger.Logger
}

// NewScanWindowHandler creates a ScanWindowHandler.
func NewScanWindowHandler(svc *swapp.Service, log *logger.Logger) *ScanWindowHandler {
	return &ScanWindowHandler{service: svc, logger: log.With("handler", "scan_window")}
}

// ScanWindowSelector says which targets a policy governs: every given
// dimension must match, any value of a dimension matches it. Empty: every
// target of the organization.
type ScanWindowSelector struct {
	Tags            []string `json:"tags,omitempty"`
	AssetGroupIDs   []string `json:"asset_group_ids,omitempty"`
	AssetTypes      []string `json:"asset_types,omitempty"`
	Criticalities   []string `json:"criticalities,omitempty"`
	BusinessUnitIDs []string `json:"business_unit_ids,omitempty"`
	ScopeTargetIDs  []string `json:"scope_target_ids,omitempty"`
	ScanZoneIDs     []string `json:"scan_zone_ids,omitempty"`
	ProgramIDs      []string `json:"program_ids,omitempty"`
}

// ScanWindowSlot is a weekly window: ISO days (1 Monday ... 7 Sunday),
// start and end "HH:MM" in the policy's time zone (an end not after the start
// runs past midnight; equal times are 24 hours).
type ScanWindowSlot struct {
	Days  []int  `json:"days"`
	Start string `json:"start"`
	End   string `json:"end"`
}

// ScanWindowOneOff is a dated window (at most 31 days).
type ScanWindowOneOff struct {
	StartsAt time.Time `json:"starts_at"`
	EndsAt   time.Time `json:"ends_at"`
}

// ScanWindowPolicyRequest creates or changes a policy; on PATCH omitted
// fields are unchanged.
type ScanWindowPolicyRequest struct {
	Name          *string             `json:"name,omitempty"`
	Description   *string             `json:"description,omitempty"`
	Enabled       *bool               `json:"enabled,omitempty"`
	Kind          *string             `json:"kind,omitempty" enums:"allow,blackout"`
	MinTier       *int                `json:"min_tier,omitempty" enums:"0,1,2"`
	Selector      *ScanWindowSelector `json:"selector,omitempty"`
	Timezone      *string             `json:"timezone,omitempty"`
	Slots         *[]ScanWindowSlot   `json:"slots,omitempty"`
	OneOffs       *[]ScanWindowOneOff `json:"one_offs,omitempty"`
	GraceMinutes  *int                `json:"grace_minutes,omitempty"`
	RateLimitRPS  *int                `json:"rate_limit_rps,omitempty"`
	MaxConcurrent *int                `json:"max_concurrent,omitempty"`
}

// ScanWindowPolicyResponse is a policy. open_now and next_change_at are its
// own windows now: an allow policy's window is open, a blackout is not
// active.
type ScanWindowPolicyResponse struct {
	ID            string             `json:"id"`
	Name          string             `json:"name"`
	Description   string             `json:"description"`
	Enabled       bool               `json:"enabled"`
	Kind          string             `json:"kind" enums:"allow,blackout"`
	MinTier       int                `json:"min_tier"`
	Selector      ScanWindowSelector `json:"selector"`
	Timezone      string             `json:"timezone"`
	Slots         []ScanWindowSlot   `json:"slots"`
	OneOffs       []ScanWindowOneOff `json:"one_offs"`
	GraceMinutes  int                `json:"grace_minutes"`
	RateLimitRPS  int                `json:"rate_limit_rps"`
	MaxConcurrent int                `json:"max_concurrent"`
	OpenNow       bool               `json:"open_now"`
	NextChangeAt  *time.Time         `json:"next_change_at,omitempty"`
	CreatedBy     string             `json:"created_by,omitempty"`
	CreatedAt     time.Time          `json:"created_at"`
	UpdatedAt     time.Time          `json:"updated_at"`
}

// ScanWindowPolicyListResponse lists policies.
type ScanWindowPolicyListResponse struct {
	Data  []ScanWindowPolicyResponse `json:"data"`
	Total int                        `json:"total"`
}

// ScanWindowEvaluateRequest asks what the windows mean now for targets and
// assets (at most 200 together).
type ScanWindowEvaluateRequest struct {
	Targets    []string `json:"targets,omitempty"`
	AssetIDs   []string `json:"asset_ids,omitempty"`
	Tier       *int     `json:"tier,omitempty" enums:"0,1,2"`
	ScanZoneID string   `json:"scan_zone_id,omitempty"`
}

// ScanWindowEvaluateResponse is the decision for each target and asset.
type ScanWindowEvaluateResponse struct {
	Data []swapp.TargetDecision `json:"data"`
}

// ScanWindowOverrideRequest suspends one policy (policy_id) or every policy
// of the organization, for 15 to 1440 minutes, with a reason and a current
// authenticator code. Program windows are never suspended.
type ScanWindowOverrideRequest struct {
	PolicyID        string `json:"policy_id,omitempty"`
	Reason          string `json:"reason"`
	DurationMinutes int    `json:"duration_minutes"`
	TOTPCode        string `json:"totp_code"`
}

// ScanWindowOverrideResponse is an override.
type ScanWindowOverrideResponse struct {
	ID         string     `json:"id"`
	PolicyID   string     `json:"policy_id,omitempty"`
	PolicyName string     `json:"policy_name,omitempty"`
	Reason     string     `json:"reason"`
	StartsAt   time.Time  `json:"starts_at"`
	EndsAt     time.Time  `json:"ends_at"`
	Active     bool       `json:"active"`
	CreatedBy  string     `json:"created_by,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	RevokedBy  string     `json:"revoked_by,omitempty"`
}

// ScanWindowOverrideListResponse lists recent overrides.
type ScanWindowOverrideListResponse struct {
	Data []ScanWindowOverrideResponse `json:"data"`
}

func toScanWindowPolicyResponse(v swapp.PolicyView) ScanWindowPolicyResponse {
	p := v.Policy
	out := ScanWindowPolicyResponse{
		ID: p.ID.String(), Name: p.Name, Description: p.Description, Enabled: p.Enabled, Kind: string(p.Kind),
		MinTier: p.MinTier, Timezone: p.Timezone, GraceMinutes: p.GraceMinutes, RateLimitRPS: p.RateLimitRPS,
		MaxConcurrent: p.MaxConcurrent, OpenNow: v.OpenNow, NextChangeAt: v.NextChange,
		CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
		Selector: ScanWindowSelector(p.Selector),
		Slots:    make([]ScanWindowSlot, 0, len(p.Slots)), OneOffs: make([]ScanWindowOneOff, 0, len(p.OneOffs)),
	}
	for _, s := range p.Slots {
		out.Slots = append(out.Slots, ScanWindowSlot(s))
	}
	for _, o := range p.OneOffs {
		out.OneOffs = append(out.OneOffs, ScanWindowOneOff(o))
	}
	if p.CreatedBy != nil {
		out.CreatedBy = p.CreatedBy.String()
	}
	return out
}

func toScanWindowOverrideResponse(o *swdom.Override, now time.Time) ScanWindowOverrideResponse {
	out := ScanWindowOverrideResponse{ID: o.ID.String(), PolicyName: o.PolicyName, Reason: o.Reason,
		StartsAt: o.StartsAt, EndsAt: o.EndsAt, Active: o.ActiveAt(now), RevokedAt: o.RevokedAt}
	if o.PolicyID != nil {
		out.PolicyID = o.PolicyID.String()
	}
	if o.CreatedBy != nil {
		out.CreatedBy = o.CreatedBy.String()
	}
	if o.RevokedBy != nil {
		out.RevokedBy = o.RevokedBy.String()
	}
	return out
}

// applyPolicyRequest writes the request's fields into spec.
func applyPolicyRequest(spec *swdom.Spec, req ScanWindowPolicyRequest) {
	if req.Name != nil {
		spec.Name = *req.Name
	}
	if req.Description != nil {
		spec.Description = *req.Description
	}
	if req.Enabled != nil {
		spec.Enabled = *req.Enabled
	}
	if req.Kind != nil {
		spec.Kind = swdom.Kind(*req.Kind)
	}
	if req.MinTier != nil {
		spec.MinTier = *req.MinTier
	}
	if req.Selector != nil {
		spec.Selector = swdom.Selector(*req.Selector)
	}
	if req.Timezone != nil {
		spec.Timezone = *req.Timezone
	}
	if req.Slots != nil {
		spec.Slots = make([]swdom.Slot, 0, len(*req.Slots))
		for _, s := range *req.Slots {
			spec.Slots = append(spec.Slots, swdom.Slot(s))
		}
	}
	if req.OneOffs != nil {
		spec.OneOffs = make([]swdom.OneOff, 0, len(*req.OneOffs))
		for _, o := range *req.OneOffs {
			spec.OneOffs = append(spec.OneOffs, swdom.OneOff(o))
		}
	}
	if req.GraceMinutes != nil {
		spec.GraceMinutes = *req.GraceMinutes
	}
	if req.RateLimitRPS != nil {
		spec.RateLimitRPS = *req.RateLimitRPS
	}
	if req.MaxConcurrent != nil {
		spec.MaxConcurrent = *req.MaxConcurrent
	}
}

// newPolicySpec is the spec of a new policy: defaults, then the request.
func newPolicySpec(req ScanWindowPolicyRequest) swdom.Spec {
	spec := swdom.Spec{Enabled: true, MinTier: swdom.TierActive, GraceMinutes: swdom.DefaultGraceMinutes}
	applyPolicyRequest(&spec, req)
	return spec
}

func (h *ScanWindowHandler) tenant(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	tid, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("").WriteJSON(w)
		return shared.ID{}, false
	}
	return tid, true
}

func decodeScanWindowBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(v); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return false
	}
	return true
}

// ListPolicies handles GET /api/v1/scan-window-policies
// @Summary      List scan window policies
// @Description  The organization's scan window policies, each with whether its own window is open (allow) or active (blackout) now and when that changes.
// @Tags         Scan Windows
// @Produce      json
// @Success      200  {object}  ScanWindowPolicyListResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-window-policies [get]
func (h *ScanWindowHandler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	ps, err := h.service.List(r.Context(), tid)
	if err != nil {
		h.handleError(w, err)
		return
	}
	resp := ScanWindowPolicyListResponse{Data: make([]ScanWindowPolicyResponse, 0, len(ps)), Total: len(ps)}
	for _, p := range ps {
		resp.Data = append(resp.Data, toScanWindowPolicyResponse(p))
	}
	writeScanZoneJSON(w, http.StatusOK, resp)
}

// GetPolicy handles GET /api/v1/scan-window-policies/{id}
// @Summary      Get scan window policy
// @Tags         Scan Windows
// @Produce      json
// @Param        id   path      string  true  "Policy ID"
// @Success      200  {object}  ScanWindowPolicyResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-window-policies/{id} [get]
func (h *ScanWindowHandler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	p, err := h.service.Get(r.Context(), tid, chi.URLParam(r, "id"))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toScanWindowPolicyResponse(p))
}

// CreatePolicy handles POST /api/v1/scan-window-policies
// @Summary      Create scan window policy
// @Description  allow: the selected targets are scanned only inside the windows; blackout: never inside them. min_tier 0 governs every tool, 1 (default) active and intrusive tools, 2 intrusive only. Every selector id must be one of the organization's own objects (422 otherwise). At most 50 policies per organization.
// @Tags         Scan Windows
// @Accept       json
// @Produce      json
// @Param        body  body      ScanWindowPolicyRequest  true  "Policy"
// @Success      201   {object}  ScanWindowPolicyResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      422   {object}  apierror.Error  "a selector id is not the organization's"
// @Security     BearerAuth
// @Router       /scan-window-policies [post]
func (h *ScanWindowHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	var req ScanWindowPolicyRequest
	if !decodeScanWindowBody(w, r, &req) {
		return
	}
	p, err := h.service.Create(r.Context(), tid, newPolicySpec(req), buildScanZoneAuditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusCreated, toScanWindowPolicyResponse(p))
}

// UpdatePolicy handles PATCH /api/v1/scan-window-policies/{id}
// @Summary      Update scan window policy
// @Description  Omitted fields are unchanged. Jobs waiting for a window are evaluated again at the next claim.
// @Tags         Scan Windows
// @Accept       json
// @Produce      json
// @Param        id    path      string                   true  "Policy ID"
// @Param        body  body      ScanWindowPolicyRequest  true  "Changes"
// @Success      200   {object}  ScanWindowPolicyResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      422   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-window-policies/{id} [patch]
func (h *ScanWindowHandler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	var req ScanWindowPolicyRequest
	if !decodeScanWindowBody(w, r, &req) {
		return
	}
	p, err := h.service.Update(r.Context(), tid, chi.URLParam(r, "id"),
		func(spec *swdom.Spec) { applyPolicyRequest(spec, req) }, buildScanZoneAuditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toScanWindowPolicyResponse(p))
}

// DeletePolicy handles DELETE /api/v1/scan-window-policies/{id}
// @Summary      Delete scan window policy
// @Tags         Scan Windows
// @Param        id   path  string  true  "Policy ID"
// @Success      204
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-window-policies/{id} [delete]
func (h *ScanWindowHandler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	if err := h.service.Delete(r.Context(), tid, chi.URLParam(r, "id"), buildScanZoneAuditContext(r)); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// PreviewPolicy handles POST /api/v1/scan-window-policies/preview
// @Summary      Preview a scan window policy
// @Description  A draft policy, not stored: the assets its asset dimensions select (those the caller may see; at most 50 listed) and its next five openings.
// @Tags         Scan Windows
// @Accept       json
// @Produce      json
// @Param        body  body      ScanWindowPolicyRequest  true  "Draft policy"
// @Success      200   {object}  swapp.Preview
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      422   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-window-policies/preview [post]
func (h *ScanWindowHandler) PreviewPolicy(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	var req ScanWindowPolicyRequest
	if !decodeScanWindowBody(w, r, &req) {
		return
	}
	out, err := h.service.PreviewPolicy(r.Context(), tid, newPolicySpec(req))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, out)
}

// Evaluate handles POST /api/v1/scan-windows/preview
// @Summary      Evaluate scan windows
// @Description  For each target and asset: whether work of the tier (default 1, active) may run now, the windows that block it and until when, the next opening, or that it never opens. Zone policies apply only with scan_zone_id. An asset the caller may not see is 404.
// @Tags         Scan Windows
// @Accept       json
// @Produce      json
// @Param        body  body      ScanWindowEvaluateRequest  true  "Targets and assets"
// @Success      200   {object}  ScanWindowEvaluateResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-windows/preview [post]
func (h *ScanWindowHandler) Evaluate(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	var req ScanWindowEvaluateRequest
	if !decodeScanWindowBody(w, r, &req) {
		return
	}
	in := swapp.EvaluateInput{TenantID: tid, Targets: req.Targets, AssetIDs: req.AssetIDs, Tier: req.Tier}
	if req.ScanZoneID != "" {
		zid, err := shared.IDFromString(req.ScanZoneID)
		if err != nil {
			apierror.BadRequest("invalid scan_zone_id").WriteJSON(w)
			return
		}
		in.ScanZoneID = &zid
	}
	out, err := h.service.Evaluate(r.Context(), in)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, ScanWindowEvaluateResponse{Data: out})
}

// ListOverrides handles GET /api/v1/scan-window-overrides
// @Summary      List scan window overrides
// @Description  The organization's 50 most recent overrides, active or not.
// @Tags         Scan Windows
// @Produce      json
// @Success      200  {object}  ScanWindowOverrideListResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-window-overrides [get]
func (h *ScanWindowHandler) ListOverrides(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	os, err := h.service.ListOverrides(r.Context(), tid)
	if err != nil {
		h.handleError(w, err)
		return
	}
	now := time.Now()
	resp := ScanWindowOverrideListResponse{Data: make([]ScanWindowOverrideResponse, 0, len(os))}
	for _, o := range os {
		resp.Data = append(resp.Data, toScanWindowOverrideResponse(o, now))
	}
	writeScanZoneJSON(w, http.StatusOK, resp)
}

// CreateOverride handles POST /api/v1/scan-window-overrides
// @Summary      Override scan windows
// @Description  Emergency override: suspends one policy, or every policy of the organization, for 15 to 1440 minutes. Needs a reason and a current code from the caller's authenticator app (403 WINDOW_OVERRIDE_NEEDS_TOTP without one, 403 WINDOW_OVERRIDE_INVALID_CODE for a wrong code). Bug-bounty program windows are never suspended. Audited (high) and notified to every owner and administrator.
// @Tags         Scan Windows
// @Accept       json
// @Produce      json
// @Param        body  body      ScanWindowOverrideRequest  true  "Override"
// @Success      201   {object}  ScanWindowOverrideResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-window-overrides [post]
func (h *ScanWindowHandler) CreateOverride(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	var req ScanWindowOverrideRequest
	if !decodeScanWindowBody(w, r, &req) {
		return
	}
	actx := buildScanZoneAuditContext(r)
	o, err := h.service.CreateOverride(r.Context(), swapp.OverrideInput{
		TenantID: tid, UserID: actx.ActorID, PolicyID: req.PolicyID, Reason: req.Reason,
		DurationMinutes: req.DurationMinutes, TOTPCode: req.TOTPCode,
	}, actx)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusCreated, toScanWindowOverrideResponse(o, time.Now()))
}

// RevokeOverride handles DELETE /api/v1/scan-window-overrides/{id}
// @Summary      End a scan window override early
// @Tags         Scan Windows
// @Param        id   path  string  true  "Override ID"
// @Success      204
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-window-overrides/{id} [delete]
func (h *ScanWindowHandler) RevokeOverride(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	actx := buildScanZoneAuditContext(r)
	if err := h.service.RevokeOverride(r.Context(), tid, chi.URLParam(r, "id"), actx.ActorID, actx); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ScanWindowHandler) handleError(w http.ResponseWriter, err error) {
	var de *shared.DomainError
	code := func(fallback apierror.Code) apierror.Code {
		if errors.As(err, &de) && de.Code != "" {
			return apierror.Code(de.Code)
		}
		return fallback
	}
	switch {
	case errors.Is(err, swdom.ErrUnknownReference):
		apierror.New(http.StatusUnprocessableEntity, code(apierror.CodeBadRequest), cleanErrorMessage(err, "Unknown reference")).WriteJSON(w)
	case errors.Is(err, swdom.ErrOverrideNotFound):
		apierror.NotFound("Scan window override").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Scan window policy").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.New(http.StatusForbidden, code(apierror.CodeForbidden), cleanErrorMessage(err, "Forbidden")).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.New(http.StatusBadRequest, code(apierror.CodeBadRequest), cleanErrorMessage(err, "Invalid scan window")).WriteJSON(w)
	default:
		h.logger.Error("scan window error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}
