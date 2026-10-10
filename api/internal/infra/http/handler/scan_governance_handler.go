package handler

// The organization's scan approval settings (RFC-073,
// docs/rfcs/RFC-073-scan-approval-governance.md §4): the mode (owner, step-up,
// reason) and the approval rules (owner or administrator, step-up, reason),
// under the token singleton /api/v1/organization. Reads: anyone who reads
// scans, so the New Scan page can say what will need approval.

import (
	"encoding/json"
	"errors"
	"net/http"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	scangovapp "github.com/openctemio/openctem/api/internal/app/scangov"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ScanGovernanceHandler serves the scan approval settings.
type ScanGovernanceHandler struct {
	svc    *scangovapp.Service
	logger *logger.Logger
}

// NewScanGovernanceHandler creates the handler.
func NewScanGovernanceHandler(svc *scangovapp.Service, log *logger.Logger) *ScanGovernanceHandler {
	return &ScanGovernanceHandler{svc: svc, logger: log.With("handler", "scan_governance")}
}

// ScanGovernanceResponse is the organization's scan approval settings.
type ScanGovernanceResponse struct {
	// Mode in force: off, on or strict.
	Mode string `json:"mode" enums:"off,on,strict"`
	// Source: organization (the owner's choice) or platform (forced).
	Source string `json:"source" enums:"organization,platform"`
	// OrganizationMode is the owner's own choice (what the platform may
	// override).
	OrganizationMode string `json:"organization_mode" enums:"off,on,strict"`
	// PlatformPolicy: tenant_controlled, off, on or strict.
	PlatformPolicy string `json:"platform_policy" enums:"tenant_controlled,off,on,strict"`
	// SelectableModes are the modes the owner may choose under the policy.
	SelectableModes []string `json:"selectable_modes"`
	// ScopeEntriesNeedApproval: in Strict, widening a scope entry needs
	// approval (RFC-054 §7); in Off and On it does not.
	ScopeEntriesNeedApproval bool           `json:"scope_entries_need_approval"`
	Rules                    []scangov.Rule `json:"rules"`
	PendingExpiryDays        int            `json:"pending_expiry_days"`
	// Presets are the ready-made rule sets (light, standard, strict).
	Presets map[string][]scangov.Rule `json:"presets"`
}

// UpdateScanGovernanceModeRequest changes the owner's choice.
type UpdateScanGovernanceModeRequest struct {
	Mode   string `json:"mode"`
	Reason string `json:"reason"`
}

// UpdateScanGovernanceRulesRequest replaces the approval rules.
type UpdateScanGovernanceRulesRequest struct {
	Rules             []scangov.Rule `json:"rules"`
	PendingExpiryDays int            `json:"pending_expiry_days"`
	Reason            string         `json:"reason"`
}

func (h *ScanGovernanceHandler) tenantID(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	tid, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil || tid.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return shared.ID{}, false
	}
	return tid, true
}

// Get handles GET /api/v1/organization/settings/scan-governance.
// @Summary      Scan approval settings
// @Description  The organization's scan approval (RFC-073): the mode in force (off by default, on, strict) and who set it, the owner's own choice, the platform policy, the approval rules and the presets. Needs scans:read.
// @Tags         Scans
// @Produce      json
// @Success      200  {object}  ScanGovernanceResponse
// @Failure      400  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/settings/scan-governance [get]
func (h *ScanGovernanceHandler) Get(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	v, err := h.svc.Settings(r.Context(), tid)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, governanceResponse(v))
}

// UpdateMode handles PUT /api/v1/organization/settings/scan-governance/mode.
// @Summary      Turn scan approval off, on or strict
// @Description  Owner only, with step-up re-authentication and a reason. Turning it on with no rule seeds the Light preset (intrusive scans need one approval). Refused with 403 SCAN_APPROVAL_FORCED when the platform administrator sets the mode for the organization. Audited (high).
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        body  body      UpdateScanGovernanceModeRequest  true  "Mode and reason"
// @Success      200   {object}  ScanGovernanceResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/settings/scan-governance/mode [put]
func (h *ScanGovernanceHandler) UpdateMode(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	var req UpdateScanGovernanceModeRequest
	if !decodeGovernanceBody(w, r, &req) {
		return
	}
	m, err := scangov.ParseMode(req.Mode)
	if err != nil {
		apierror.BadRequest("mode must be off, on or strict").WriteJSON(w)
		return
	}
	v, err := h.svc.SetMode(settingsWriteCtx(r), tid, m, req.Reason, governanceAuditContext(r))
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, governanceResponse(v))
}

// UpdateRules handles PUT /api/v1/organization/settings/scan-governance/rules.
// @Summary      Replace the scan approval rules
// @Description  Owner or administrator, with step-up re-authentication and a reason. Rules are evaluated in order: every matching rule is shown, the one asking the most approvals decides the approvers (at most 50 rules). Audited (high).
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        body  body      UpdateScanGovernanceRulesRequest  true  "Rules and reason"
// @Success      200   {object}  ScanGovernanceResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/settings/scan-governance/rules [put]
func (h *ScanGovernanceHandler) UpdateRules(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	var req UpdateScanGovernanceRulesRequest
	if !decodeGovernanceBody(w, r, &req) {
		return
	}
	v, err := h.svc.SetRules(settingsWriteCtx(r), tid, scangovapp.RulesInput{
		Rules: req.Rules, PendingExpiryDays: req.PendingExpiryDays, Reason: req.Reason,
	}, governanceAuditContext(r))
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, governanceResponse(v))
}

// TestScanGovernanceRulesRequest is a rule set to try.
type TestScanGovernanceRulesRequest struct {
	Rules []scangov.Rule `json:"rules"`
}

// TestRules handles POST /api/v1/organization/settings/scan-governance/test.
// @Summary      Try scan approval rules on existing scans
// @Description  Owner or administrator. Evaluates a proposed rule set (validated as a save would be, nothing is written) against the organization's saved scans (at most 200, newest first), each as a run its creator starts from the console at its next scheduled time: which scans it would hold for approval, which only monitor rules catch, and how many scans each rule catches. Off is evaluated as On.
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        body  body      TestScanGovernanceRulesRequest  true  "Rules to try"
// @Success      200   {object}  scangovapp.RuleTest
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/settings/scan-governance/test [post]
func (h *ScanGovernanceHandler) TestRules(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	var req TestScanGovernanceRulesRequest
	if !decodeGovernanceBody(w, r, &req) {
		return
	}
	out, err := h.svc.TestRules(r.Context(), tid, req.Rules)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func decodeGovernanceBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return false
	}
	return true
}

func governanceAuditContext(r *http.Request) auditsvc.AuditContext {
	actx := auditsvc.AuditContext{ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID")}
	if u := middleware.GetLocalUser(r.Context()); u != nil {
		actx.ActorID, actx.ActorEmail = u.ID().String(), u.Email()
	}
	return actx
}

func governanceResponse(v *scangovapp.View) ScanGovernanceResponse {
	st := v.Settings
	rules := st.Rules
	if rules == nil {
		rules = []scangov.Rule{}
	}
	selectable := []string{}
	for _, m := range []scangov.Mode{scangov.ModeOff, scangov.ModeOn, scangov.ModeStrict} {
		if scangov.TenantMayChoose(m, v.Policy) {
			selectable = append(selectable, string(m))
		}
	}
	return ScanGovernanceResponse{
		Mode: string(v.Mode), Source: v.Source, OrganizationMode: string(st.EffectiveMode()),
		PlatformPolicy: string(v.Policy), SelectableModes: selectable,
		ScopeEntriesNeedApproval: scangov.ScopeEntriesNeedApproval(v.Mode),
		Rules:                    rules, PendingExpiryDays: st.PendingDays(),
		Presets: map[string][]scangov.Rule{
			scangov.PresetLight:    scangov.Preset(scangov.PresetLight),
			scangov.PresetStandard: scangov.Preset(scangov.PresetStandard),
			scangov.PresetStrict:   scangov.Preset(scangov.PresetStrict),
		},
	}
}

func (h *ScanGovernanceHandler) writeErr(w http.ResponseWriter, err error) {
	if writeStepUpError(w, err) {
		return
	}
	var conflict *tenant.SettingsConflictError
	if errors.As(err, &conflict) {
		writeSettingsConflict(w, conflict)
		return
	}
	var de *shared.DomainError
	switch {
	case errors.As(err, &de) && de.Code != "":
		status := http.StatusBadRequest
		if errors.Is(err, shared.ErrForbidden) {
			status = http.StatusForbidden
		}
		apierror.New(status, apierror.Code(de.Code), de.Message).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Organization").WriteJSON(w)
	default:
		h.logger.Error("scan governance settings", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not handle the scan approval settings").WriteJSON(w)
	}
}
