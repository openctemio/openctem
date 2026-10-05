package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/app"
	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	identityproviderdom "github.com/openctemio/openctem/api/pkg/domain/identityprovider"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ssochange"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SSO changes a platform administrator submits from the admin console wait
// for an owner of the organization (RFC-022, owner decision 2026-10-02). See
// internal/app/auth/sso_change.go for the rule and the bootstrap exception.

// SSOChangeHandler serves the pending-change list to the admin console and
// the list/approve/reject endpoints to the organization's owners.
type SSOChangeHandler struct {
	svc    *app.SSOChangeService
	audit  *auditsvc.AuditService
	logger *logger.Logger
}

// NewSSOChangeHandler creates the handler.
func NewSSOChangeHandler(svc *app.SSOChangeService, auditSvc *auditsvc.AuditService, log *logger.Logger) *SSOChangeHandler {
	return &SSOChangeHandler{svc: svc, audit: auditSvc, logger: log.With("handler", "sso_change")}
}

// SSOChangeResponse is a pending (or decided) SSO change. It never carries a
// secret: an OIDC client secret shows only as client_secret_set /
// client_secret_changed in payload.
type SSOChangeResponse struct {
	ID       string `json:"id"`
	Kind     string `json:"kind" enums:"saml_config,idp_create,idp_update"`
	TargetID string `json:"target_id,omitempty"`
	Status   string `json:"status" enums:"pending,approved,rejected,expired,superseded"`
	// Summary is a one-line description of the change.
	Summary string `json:"summary"`
	// Payload is the proposed configuration.
	Payload json.RawMessage `json:"payload" swaggertype:"object"`
	// CertificateSHA256 identifies the IdP signing certificate a SAML change
	// installs; compare it with the certificate your IdP shows.
	CertificateSHA256 string  `json:"certificate_sha256,omitempty"`
	RequestedBy       string  `json:"requested_by"`
	CreatedAt         string  `json:"created_at"`
	ExpiresAt         string  `json:"expires_at"`
	DecidedAt         *string `json:"decided_at,omitempty"`
	DecidedBy         string  `json:"decided_by,omitempty"`
}

// SSOChangeListResponse lists SSO changes, newest first.
type SSOChangeListResponse struct {
	Changes []SSOChangeResponse `json:"changes"`
}

func toSSOChangeResponse(c *ssochange.Change) SSOChangeResponse {
	resp := SSOChangeResponse{
		ID:          c.ID.String(),
		Kind:        string(c.Kind),
		TargetID:    c.TargetID,
		Status:      string(c.EffectiveStatus(time.Now())),
		Summary:     app.DescribeSSOChange(c),
		Payload:     c.Payload,
		RequestedBy: c.RequestedByEmail,
		CreatedAt:   c.CreatedAt.UTC().Format(time.RFC3339),
		ExpiresAt:   c.ExpiresAt.UTC().Format(time.RFC3339),
	}
	if len(resp.Payload) == 0 {
		resp.Payload = json.RawMessage("{}")
	}
	if c.Kind == ssochange.KindSAMLConfig {
		var p struct {
			Cert string `json:"idp_certificate"`
		}
		if json.Unmarshal(c.Payload, &p) == nil {
			resp.CertificateSHA256 = app.CertificateFingerprint(p.Cert)
		}
	}
	if c.DecidedAt != nil {
		s := c.DecidedAt.UTC().Format(time.RFC3339)
		resp.DecidedAt = &s
	}
	if c.DecidedBy != nil {
		resp.DecidedBy = c.DecidedBy.String()
	}
	return resp
}

func (h *SSOChangeHandler) writeList(w http.ResponseWriter, r *http.Request, tenantID shared.ID) {
	pendingOnly := r.URL.Query().Get("status") != "all"
	changes, err := h.svc.List(r.Context(), tenantID, pendingOnly)
	if err != nil {
		h.logger.Error("list sso changes failed", "error", err)
		apierror.InternalServerError("failed to list SSO changes").WriteJSON(w)
		return
	}
	out := SSOChangeListResponse{Changes: make([]SSOChangeResponse, 0, len(changes))}
	for _, c := range changes {
		out.Changes = append(out.Changes, toSSOChangeResponse(c))
	}
	writeJSON(w, http.StatusOK, out)
}

// AdminList handles GET /api/v1/admin/tenants/{tenantId}/sso/changes.
// @Summary List an organization's SSO changes awaiting owner approval
// @Description Platform admin console (RFC-022). SAML and identity-provider changes submitted here wait for an owner of the organization. Pending, unexpired changes by default; status=all includes decided ones.
// @Tags Admin Organization SSO
// @Produce json
// @Param tenantId path string true "Organization ID"
// @Param status query string false "pending (default) or all"
// @Success 200 {object} SSOChangeListResponse
// @Security BearerAuth
// @Router /admin/tenants/{tenantId}/sso/changes [get]
func (h *SSOChangeHandler) AdminList(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.BadRequest("invalid organization id").WriteJSON(w)
		return
	}
	h.writeList(w, r, tenantID)
}

// OwnerList handles GET /api/v1/tenants/{tenant}/settings/sso/changes.
// @Summary List SSO changes awaiting your approval
// @Description Owner only. SAML and identity-provider changes a platform administrator proposed for this organization; none takes effect until an owner approves it. Pending, unexpired changes by default; status=all includes decided ones.
// @Tags Tenants
// @Produce json
// @Param tenant path string true "Tenant ID or slug"
// @Param status query string false "pending (default) or all"
// @Success 200 {object} SSOChangeListResponse
// @Failure 403 {object} apierror.Error
// @Security BearerAuth
// @Router /tenants/{tenant}/settings/sso/changes [get]
func (h *SSOChangeHandler) OwnerList(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	h.writeList(w, r, tenantID)
}

// Approve handles POST /api/v1/tenants/{tenant}/settings/sso/changes/{changeId}/approve.
// @Summary Approve an SSO change
// @Description Owner only. Applies the proposed SAML or identity-provider change to this organization's live configuration.
// @Tags Tenants
// @Produce json
// @Param tenant path string true "Tenant ID or slug"
// @Param changeId path string true "SSO change ID"
// @Success 200 {object} SSOChangeResponse
// @Failure 403 {object} apierror.Error
// @Failure 404 {object} apierror.Error
// @Failure 409 {object} apierror.Error
// @Failure 410 {object} apierror.Error
// @Security BearerAuth
// @Router /tenants/{tenant}/settings/sso/changes/{changeId}/approve [post]
func (h *SSOChangeHandler) Approve(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, true)
}

// Reject handles POST /api/v1/tenants/{tenant}/settings/sso/changes/{changeId}/reject.
// @Summary Reject an SSO change
// @Description Owner only. Discards the proposed change; the live configuration is unchanged.
// @Tags Tenants
// @Produce json
// @Param tenant path string true "Tenant ID or slug"
// @Param changeId path string true "SSO change ID"
// @Success 200 {object} SSOChangeResponse
// @Failure 403 {object} apierror.Error
// @Failure 404 {object} apierror.Error
// @Failure 409 {object} apierror.Error
// @Failure 410 {object} apierror.Error
// @Security BearerAuth
// @Router /tenants/{tenant}/settings/sso/changes/{changeId}/reject [post]
func (h *SSOChangeHandler) Reject(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, false)
}

func (h *SSOChangeHandler) decide(w http.ResponseWriter, r *http.Request, approve bool) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	changeID, err := shared.IDFromString(r.PathValue("changeId"))
	if err != nil {
		apierror.NotFound("SSO change").WriteJSON(w)
		return
	}
	userID := middleware.GetLocalUserID(r.Context())

	var c *ssochange.Change
	if approve {
		c, err = h.svc.Approve(r.Context(), tenantID, changeID, userID)
	} else {
		c, err = h.svc.Reject(r.Context(), tenantID, changeID, userID)
	}
	if err != nil {
		h.writeDecideError(w, err)
		return
	}

	action, message := audit.ActionSSOChangeRejected, "SSO change rejected: "
	if approve {
		action, message = audit.ActionSSOChangeApproved, "SSO change approved and applied: "
	}
	event := auditsvc.NewSuccessEvent(action, audit.ResourceTypeSSOChange, c.ID.String()).
		WithMessage(message+app.DescribeSSOChange(c)).
		WithMetadata("kind", string(c.Kind)).
		WithMetadata("requested_by", c.RequestedByEmail)
	if c.TargetID != "" {
		event = event.WithMetadata("target_id", c.TargetID)
	}
	if h.audit != nil {
		actx := auditsvc.AuditContext{
			TenantID:  tenantID.String(),
			ActorIP:   middleware.ClientIP(r),
			UserAgent: r.UserAgent(),
			RequestID: r.Header.Get("X-Request-ID"),
		}
		if u := middleware.GetLocalUser(r.Context()); u != nil {
			actx.ActorID = u.ID().String()
			actx.ActorEmail = u.Email()
		}
		if aerr := h.audit.LogEvent(r.Context(), actx, event); aerr != nil {
			h.logger.Error("failed to write sso change audit event", "error", aerr)
		}
	}
	writeJSON(w, http.StatusOK, toSSOChangeResponse(c))
}

func (h *SSOChangeHandler) writeDecideError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ssochange.ErrNotOwner):
		apierror.Forbidden("Only an owner of the organization can approve or reject an SSO change").WriteJSON(w)
	case errors.Is(err, ssochange.ErrNotFound):
		apierror.NotFound("SSO change").WriteJSON(w)
	case errors.Is(err, ssochange.ErrExpired):
		apierror.New(http.StatusGone, "SSO_CHANGE_EXPIRED", "This SSO change has expired; ask the administrator to submit it again").WriteJSON(w)
	case errors.Is(err, ssochange.ErrNotPending):
		apierror.Conflict("This SSO change was already decided or replaced by a newer one").WriteJSON(w)
	case errors.Is(err, identityproviderdom.ErrAlreadyExists):
		apierror.Conflict("An identity provider of this type already exists for this organization").WriteJSON(w)
	case errors.Is(err, identityproviderdom.ErrNotFound):
		apierror.Conflict("The identity provider this change updates no longer exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation), errors.Is(err, identityproviderdom.ErrInvalidConfig):
		apierror.BadRequest("The proposed SSO configuration is no longer valid").WriteJSON(w)
	default:
		h.logger.Error("decide sso change failed", "error", err)
		apierror.InternalServerError("failed to decide SSO change").WriteJSON(w)
	}
}

// --- admin console submission (used by the SAML and SSO handlers) ---

// ssoChangeRequester is the platform administrator behind an admin-console
// request, or nil for any other caller.
func ssoChangeRequester(r *http.Request) *app.SSOChangeRequester {
	a := middleware.GetAdminUser(r.Context())
	if a == nil {
		return nil
	}
	return &app.SSOChangeRequester{AdminID: a.ID(), Email: a.Email()}
}

// writeSSOChangePending answers a submission stored for an owner's approval
// (202) and records it in the organization's audit log.
func writeSSOChangePending(w http.ResponseWriter, r *http.Request, auditSvc *auditsvc.AuditService, log *logger.Logger, c *ssochange.Change) {
	event := auditsvc.NewSuccessEvent(audit.ActionSSOChangeRequested, audit.ResourceTypeSSOChange, c.ID.String()).
		WithMessage("SSO change proposed, waiting for an owner's approval: "+app.DescribeSSOChange(c)).
		WithMetadata("kind", string(c.Kind)).
		WithMetadata("expires_at", c.ExpiresAt.UTC().Format(time.RFC3339))
	if c.TargetID != "" {
		event = event.WithMetadata("target_id", c.TargetID)
	}
	logOrgSSOEvent(r.Context(), auditSvc, log, r, event)
	writeJSON(w, http.StatusAccepted, toSSOChangeResponse(c))
}

// writeSSOChangeApprovalUnavailable answers an admin-console SSO write when
// the approval service is not wired: fail closed rather than apply the change
// directly.
func writeSSOChangeApprovalUnavailable(w http.ResponseWriter) {
	apierror.ServiceUnavailable("SSO change approval is not configured").WriteJSON(w)
}
