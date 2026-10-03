package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/audit/chainclassify"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Platform admin "Rebaseline audit chain" (admin console, Organizations).
//
// A tenant's audit hash-chain can carry breaks left by a known hashing defect
// (see internal/app/audit/chainclassify). Clearing them means re-signing the
// chain, which is irreversible and erases tamper evidence as readily as noise,
// so the console first shows the classification and only re-signs when every
// break is explained, the chain is exactly the one the administrator reviewed,
// and the administrator has re-entered a code from the console authenticator.

// Admin audit actions for the audit chain.
const (
	AdminActionAuditChainRebaseline = "organization.audit_chain_rebaseline"
)

// Error codes the console acts on.
const (
	codeChainUnexplained    apierror.Code = "AUDIT_CHAIN_UNEXPLAINED"
	codeChainChanged        apierror.Code = "AUDIT_CHAIN_CHANGED"
	codeChainSourceMissing  apierror.Code = "AUDIT_CHAIN_SOURCE_MISSING"
	codeStepUpRequired      apierror.Code = "STEP_UP_REQUIRED"
	codeStepUpUnavailable   apierror.Code = "STEP_UP_UNAVAILABLE"
	stepUpPurposeRebaseline               = "audit chain rebaseline"
)

// AuditChainService is the audit service surface the handler needs.
type AuditChainService interface {
	ClassifyChain(ctx context.Context, tenantID shared.ID) (*chainclassify.Report, error)
	RebaselineChainIfExplained(ctx context.Context, tenantID shared.ID, expectedFingerprint string,
		actx auditapp.AuditContext, archiveActorID string) (*auditapp.RebaselineResult, *chainclassify.Report, error)
	VerifyChain(ctx context.Context, tenantID shared.ID, limit int) (*auditapp.ChainVerifyResult, error)
}

// StepUpVerifier re-confirms an administrator with a fresh authenticator code.
type StepUpVerifier interface {
	StepUp(ctx context.Context, a *admin.AdminUser, code, purpose string, client adminconsole.ClientInfo) error
}

// AdminAuditChainHandler serves the admin console's audit-chain panel.
type AdminAuditChainHandler struct {
	audit      AuditChainService
	stepUp     StepUpVerifier
	adminAudit admin.AuditLogRepository
	orgs       admin.OrganizationReader
	logger     *logger.Logger
}

// NewAdminAuditChainHandler creates the handler.
func NewAdminAuditChainHandler(audit AuditChainService, stepUp StepUpVerifier, adminAudit admin.AuditLogRepository,
	orgs admin.OrganizationReader, log *logger.Logger,
) *AdminAuditChainHandler {
	return &AdminAuditChainHandler{
		audit: audit, stepUp: stepUp, adminAudit: adminAudit, orgs: orgs,
		logger: log.With("handler", "admin_audit_chain"),
	}
}

// AdminAuditChainStatusResponse is the classification of an organization's
// audit hash-chain.
type AdminAuditChainStatusResponse struct {
	TenantID     string                 `json:"tenant_id"`
	ClassifiedAt time.Time              `json:"classified_at"`
	Total        int                    `json:"total"`
	Counts       chainclassify.Counts   `json:"counts"`
	Breaks       int                    `json:"breaks"`
	Blocking     int                    `json:"blocking"`
	LastPosition int64                  `json:"last_position"`
	Fingerprint  string                 `json:"fingerprint"`
	Samples      []chainclassify.Sample `json:"samples"`
	// RebaselineAllowed is true when every break is explained by a known
	// hashing defect. A chain with no breaks needs no rebaseline.
	RebaselineAllowed bool `json:"rebaseline_allowed"`
}

func toAuditChainStatus(tenantID shared.ID, rep *chainclassify.Report) AdminAuditChainStatusResponse {
	return AdminAuditChainStatusResponse{
		TenantID: tenantID.String(), ClassifiedAt: time.Now().UTC(),
		Total: rep.Total, Counts: rep.Counts, Breaks: rep.Breaks, Blocking: rep.Blocking,
		LastPosition: rep.LastPosition, Fingerprint: rep.Fingerprint, Samples: rep.Samples,
		RebaselineAllowed: rep.RebaselineAllowed(),
	}
}

// AdminAuditChainRebaselineRequest confirms a rebaseline.
type AdminAuditChainRebaselineRequest struct {
	// Fingerprint of the classification the administrator reviewed.
	Fingerprint string `json:"fingerprint"`
	// TOTPCode is a fresh code from the console authenticator.
	TOTPCode string `json:"totp_code"`
}

// AdminAuditChainVerifyResult is the chain verification run right after a
// rebaseline.
type AdminAuditChainVerifyResult struct {
	Total    int  `json:"total"`
	Verified int  `json:"verified"`
	Breaks   int  `json:"breaks"`
	OK       bool `json:"ok"`
}

// AdminAuditChainRebaselineResponse is the outcome of a rebaseline.
type AdminAuditChainRebaselineResponse struct {
	OK               bool                         `json:"ok"`
	RebaselineID     string                       `json:"rebaseline_id"`
	EntriesTotal     int                          `json:"entries_total"`
	EntriesRewritten int                          `json:"entries_rewritten"`
	Verify           *AdminAuditChainVerifyResult `json:"verify,omitempty"`
}

// Classify handles GET /api/v1/admin/tenants/{tenantId}/audit-chain.
// @Summary Classify an organization's audit chain (platform admin)
// @Description Classifies every row of the organization's audit hash-chain: verifies, explained by a known hashing defect (legacy truncate, pre-#79 nanosecond), or blocking (unexplained, missing source, broken link). The fingerprint names the exact chain classified and must be sent with a rebaseline.
// @Tags Admin Organizations
// @Produce json
// @Param tenantId path string true "Organization ID"
// @Success 200 {object} AdminAuditChainStatusResponse
// @Failure 401 {object} apierror.Error "Unauthorized"
// @Failure 404 {object} apierror.Error "Not Found"
// @Security BearerAuth
// @Router /admin/tenants/{tenantId}/audit-chain [get]
func (h *AdminAuditChainHandler) Classify(w http.ResponseWriter, r *http.Request) {
	id, ok := orgIDParam(r)
	if !ok {
		apierror.BadRequest("invalid organization id").WriteJSON(w)
		return
	}
	rep, err := h.audit.ClassifyChain(r.Context(), id)
	if err != nil {
		h.logger.Error("classify audit chain", "tenant_id", id.String(), "error", sanitizeLogField(err.Error()))
		apierror.InternalServerError("could not classify the audit chain").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, toAuditChainStatus(id, rep))
}

// Rebaseline handles POST /api/v1/admin/tenants/{tenantId}/audit-chain/rebaseline.
// @Summary Rebaseline an organization's audit chain (platform admin)
// @Description Re-signs the organization's audit hash-chain from current data. Irreversible: the old hashes are archived, and the action is written to the organization's audit log and the platform admin audit log. Refused (409, nothing changed) when any break is unexplained or the chain changed since the classification whose fingerprint is sent. Requires a fresh code from the console authenticator.
// @Tags Admin Organizations
// @Accept json
// @Produce json
// @Param tenantId path string true "Organization ID"
// @Param body body AdminAuditChainRebaselineRequest true "Reviewed fingerprint and authenticator code"
// @Success 200 {object} AdminAuditChainRebaselineResponse
// @Failure 400 {object} apierror.Error "Bad Request"
// @Failure 401 {object} apierror.Error "Unauthorized or wrong code"
// @Failure 403 {object} apierror.Error "Forbidden"
// @Failure 409 {object} apierror.Error "Unexplained breaks, or the chain changed"
// @Security BearerAuth
// @Router /admin/tenants/{tenantId}/audit-chain/rebaseline [post]
func (h *AdminAuditChainHandler) Rebaseline(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	id, ok := orgIDParam(r)
	if actor == nil || !ok {
		apierror.BadRequest("invalid organization id").WriteJSON(w)
		return
	}
	var req AdminAuditChainRebaselineRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	req.TOTPCode = strings.TrimSpace(req.TOTPCode)
	req.Fingerprint = strings.TrimSpace(req.Fingerprint)
	if req.Fingerprint == "" {
		apierror.BadRequest("fingerprint is required: classify the chain first").WriteJSON(w)
		return
	}
	if req.TOTPCode == "" {
		apierror.New(http.StatusUnauthorized, codeStepUpRequired,
			"Enter a code from your authenticator to confirm the rebaseline").WriteJSON(w)
		return
	}

	orgName := ""
	if o, err := h.orgs.GetOrganization(r.Context(), id); err == nil {
		orgName = o.Name
	}
	entry := admin.NewAuditLogBuilder(actor, AdminActionAuditChainRebaseline).
		Resource("tenant", &id, orgName).
		Context(middleware.ClientIP(r), r.UserAgent()).
		High()
	record := func(status int, body map[string]any, failure string) {
		entry.Request(r.Method, r.URL.Path, body).Response(status)
		if failure != "" {
			entry.Error(failure)
		}
		// Detached from the request: the record must survive a client that
		// disconnects once the response is written.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		defer cancel()
		if err := h.adminAudit.Create(ctx, entry.Build()); err != nil {
			h.logger.Error("write admin audit for audit chain rebaseline", "tenant_id", id.String(), "error", err)
		}
	}

	// Step-up before anything touches the tenant: a wrong code must not leave
	// a refused-rebaseline event on the organization's chain.
	if err := h.stepUp.StepUp(r.Context(), actor, req.TOTPCode, stepUpPurposeRebaseline, clientInfo(r)); err != nil {
		// StepUp writes its own console.step_up_failed record.
		switch {
		case errors.Is(err, admin.ErrStepUpUnavailable):
			apierror.New(http.StatusForbidden, codeStepUpUnavailable,
				"Enroll the console authenticator (sign in with your password and TOTP) to confirm this action").WriteJSON(w)
		case errors.Is(err, admin.ErrInvalidMFACode):
			apierror.Unauthorized("Invalid or already used code; wait for your authenticator to show a new one").WriteJSON(w)
		default:
			h.logger.Error("audit chain rebaseline step-up", "error", err)
			apierror.InternalServerError("could not verify the code").WriteJSON(w)
		}
		return
	}

	actx := adminAuditContext(r, id.String())
	archiveActor := ""
	if uid := actor.UserID(); uid != nil {
		archiveActor = uid.String()
	}
	res, rep, err := h.audit.RebaselineChainIfExplained(r.Context(), id, req.Fingerprint, actx, archiveActor)
	if err != nil {
		var details any
		if rep != nil {
			details = toAuditChainStatus(id, rep)
		}
		switch {
		case errors.Is(err, auditapp.ErrChainUnexplained):
			record(http.StatusConflict, map[string]any{"fingerprint": req.Fingerprint}, "refused: unexplained breaks")
			apierror.New(http.StatusConflict, codeChainUnexplained,
				"The chain has breaks no known defect explains; nothing was changed. Investigate them before any rebaseline.").
				WithDetails(details).WriteJSON(w)
		case errors.Is(err, auditapp.ErrChainFingerprintMismatch), errors.Is(err, auditdom.ErrChainRebaselineConflict):
			record(http.StatusConflict, map[string]any{"fingerprint": req.Fingerprint}, "refused: chain changed since review")
			apierror.New(http.StatusConflict, codeChainChanged,
				"The chain changed since you reviewed it; nothing was changed. Review the new classification and confirm again.").
				WithDetails(details).WriteJSON(w)
		case errors.Is(err, shared.ErrConflict):
			// A chain row whose audit log is missing.
			record(http.StatusConflict, map[string]any{"fingerprint": req.Fingerprint}, sanitizeLogField(err.Error()))
			apierror.New(http.StatusConflict, codeChainSourceMissing,
				"The chain cannot be rebaselined as it stands; nothing was changed. Review it again.").WriteJSON(w)
		case errors.Is(err, shared.ErrValidation):
			apierror.BadRequest("fingerprint is required: classify the chain first").WriteJSON(w)
		default:
			h.logger.Error("audit chain rebaseline", "tenant_id", id.String(), "error", sanitizeLogField(err.Error()))
			record(http.StatusInternalServerError, map[string]any{"fingerprint": req.Fingerprint}, "rebaseline failed")
			apierror.InternalServerError("rebaseline failed").WriteJSON(w)
		}
		return
	}

	resp := AdminAuditChainRebaselineResponse{
		OK: true, RebaselineID: res.RebaselineID, EntriesTotal: res.EntriesTotal, EntriesRewritten: res.EntriesRewritten,
	}
	if v, err := h.audit.VerifyChain(r.Context(), id, 0); err == nil {
		resp.Verify = &AdminAuditChainVerifyResult{Total: v.Total, Verified: v.Verified, Breaks: len(v.Breaks), OK: v.OK}
	} else {
		h.logger.Warn("verify audit chain after rebaseline", "tenant_id", id.String(), "error", err)
	}
	body := map[string]any{
		"fingerprint": req.Fingerprint, "rebaseline_id": res.RebaselineID,
		"entries_total": res.EntriesTotal, "entries_rewritten": res.EntriesRewritten,
	}
	if rep != nil {
		body["legacy_truncate"] = rep.Counts.LegacyTruncate
		body["pre_79_nanosecond"] = rep.Counts.PreHashReduction
	}
	record(http.StatusOK, body, "")
	writeJSON(w, http.StatusOK, resp)
}
