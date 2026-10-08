package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/audit"
	orgtrustapp "github.com/openctemio/openctem/api/internal/app/orgtrust"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/orgtrust"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// OrgTrustHandler serves trusted organizations (RFC-058) under the token
// singleton /api/v1/organization/trusts: the organization comes from the
// credential, never from the path.
type OrgTrustHandler struct {
	service *orgtrustapp.Service
	logger  *logger.Logger
}

// NewOrgTrustHandler creates the handler.
func NewOrgTrustHandler(svc *orgtrustapp.Service, log *logger.Logger) *OrgTrustHandler {
	return &OrgTrustHandler{service: svc, logger: log.With("handler", "org_trust")}
}

// OrgTrustSettingsRequest is what the host decides for members from the home.
type OrgTrustSettingsRequest struct {
	// MaxRole: viewer or member (default member).
	MaxRole string `json:"max_role"`
	// AcceptHomeSSO: accept a sign-in at the home's identity provider as SSO
	// here (default true).
	AcceptHomeSSO *bool `json:"accept_home_sso"`
	// RequireMFAEvidence: accept the home sign-in only when the provider
	// proved a second factor.
	RequireMFAEvidence bool `json:"require_mfa_evidence"`
	// AllowAPIKeys: members from the home may create API keys here.
	AllowAPIKeys bool `json:"allow_api_keys"`
	// DefaultExpiryDays: end of access proposed for new members (1-365).
	DefaultExpiryDays *int `json:"default_expiry_days"`
}

// CreateOrgTrustRequest asks to trust the organization holding a domain.
type CreateOrgTrustRequest struct {
	// HomeDomain is an email domain the other organization verified for SSO.
	HomeDomain string `json:"home_domain"`
	OrgTrustSettingsRequest
}

// AcceptOrgTrustRequest accepts a trust.
type AcceptOrgTrustRequest struct {
	// AttestIdPMFA: the home owner states that its identity provider enforces
	// MFA for everyone.
	AttestIdPMFA bool `json:"attest_idp_mfa"`
}

// OrgTrustResponse is a trust seen from the caller's organization.
type OrgTrustResponse struct {
	ID                 string     `json:"id"`
	Direction          string     `json:"direction"`
	Organization       string     `json:"organization"`
	Status             string     `json:"status"`
	MaxRole            string     `json:"max_role"`
	AcceptHomeSSO      bool       `json:"accept_home_sso"`
	RequireMFAEvidence bool       `json:"require_mfa_evidence"`
	HomeAttestsMFA     bool       `json:"home_attests_mfa"`
	AllowAPIKeys       bool       `json:"allow_api_keys"`
	DefaultExpiryDays  *int       `json:"default_expiry_days,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	AcceptedAt         *time.Time `json:"accepted_at,omitempty"`
}

// OrgTrustListResponse lists trusts.
type OrgTrustListResponse struct {
	Data []OrgTrustResponse `json:"data"`
}

func toOrgTrustResponse(v orgtrustapp.View) OrgTrustResponse {
	t := v.Trust
	return OrgTrustResponse{
		ID: t.ID.String(), Direction: v.Direction, Organization: v.OtherName, Status: string(t.Status),
		MaxRole: string(t.Settings.MaxRole), AcceptHomeSSO: t.Settings.AcceptHomeSSO,
		RequireMFAEvidence: t.Settings.RequireMFAEvidence, HomeAttestsMFA: t.HomeAttestsMFA,
		AllowAPIKeys: t.Settings.AllowAPIKeys, DefaultExpiryDays: t.Settings.DefaultExpiryDays,
		CreatedAt: t.CreatedAt, AcceptedAt: t.AcceptedAt,
	}
}

func (r OrgTrustSettingsRequest) settings() orgtrust.Settings {
	s := orgtrust.DefaultSettings()
	if r.MaxRole != "" {
		s.MaxRole = orgtrust.MaxRole(strings.ToLower(strings.TrimSpace(r.MaxRole)))
	}
	if r.AcceptHomeSSO != nil {
		s.AcceptHomeSSO = *r.AcceptHomeSSO
	}
	s.RequireMFAEvidence = r.RequireMFAEvidence
	s.AllowAPIKeys = r.AllowAPIKeys
	s.DefaultExpiryDays = r.DefaultExpiryDays
	return s
}

// caller returns the token's organization and user, writing 401 when absent.
func (h *OrgTrustHandler) caller(w http.ResponseWriter, r *http.Request) (tenantID, userID shared.ID, actx audit.AuditContext, ok bool) {
	tid, terr := shared.IDFromString(middleware.GetTenantID(r.Context()))
	uid, uerr := shared.IDFromString(middleware.GetUserID(r.Context()))
	if terr != nil || uerr != nil {
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return shared.ID{}, shared.ID{}, audit.AuditContext{}, false
	}
	actx = audit.AuditContext{
		TenantID: tid.String(), ActorID: uid.String(), ActorEmail: auditActorEmail(r.Context()),
		ActorIP: middleware.ClientIP(r), UserAgent: r.UserAgent(), RequestID: middleware.GetRequestID(r.Context()),
	}
	return tid, uid, actx, true
}

func (h *OrgTrustHandler) writeError(w http.ResponseWriter, err error) {
	switch {
	case orgtrustapp.IsNotFound(err):
		apierror.NotFound("Trust").WriteJSON(w)
	case errors.Is(err, orgtrust.ErrExists):
		apierror.Conflict("This organization is already trusted or asked").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("trust request failed", "error", err)
		apierror.InternalServerError("The trust could not be changed").WriteJSON(w)
	}
}

func decodeOrgTrust(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.ContentLength == 0 {
		return true
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(v); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return false
	}
	return true
}

func writeOrgTrust(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// List handles GET /api/v1/organization/trusts
// @Summary      List trusted organizations
// @Description  Trusts this organization asked for (outgoing) and was asked for (incoming), with the other organization's name only (RFC-058).
// @Tags         Organization
// @Produce      json
// @Success      200  {object}  OrgTrustListResponse
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/trusts [get]
func (h *OrgTrustHandler) List(w http.ResponseWriter, r *http.Request) {
	tid, _, _, ok := h.caller(w, r)
	if !ok {
		return
	}
	views, err := h.service.List(r.Context(), tid)
	if err != nil {
		h.writeError(w, err)
		return
	}
	out := OrgTrustListResponse{Data: make([]OrgTrustResponse, 0, len(views))}
	for _, v := range views {
		out.Data = append(out.Data, toOrgTrustResponse(v))
	}
	writeOrgTrust(w, http.StatusOK, out)
}

// Create handles POST /api/v1/organization/trusts
// @Summary      Trust an organization
// @Description  Owner only, with recent re-authentication. Names the other organization by a domain it verified for SSO; the trust grants nothing until that organization's owner accepts.
// @Tags         Organization
// @Accept       json
// @Produce      json
// @Param        body  body      CreateOrgTrustRequest  true  "The organization to trust and the settings"
// @Success      201   {object}  OrgTrustResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/trusts [post]
func (h *OrgTrustHandler) Create(w http.ResponseWriter, r *http.Request) {
	tid, uid, actx, ok := h.caller(w, r)
	if !ok {
		return
	}
	var req CreateOrgTrustRequest
	if !decodeOrgTrust(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.HomeDomain) == "" || len(req.HomeDomain) > 253 {
		apierror.BadRequest("home_domain is required").WriteJSON(w)
		return
	}
	v, err := h.service.Request(r.Context(), tid, uid, req.HomeDomain, req.settings(), actx)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeOrgTrust(w, http.StatusCreated, toOrgTrustResponse(*v))
}

// Update handles PATCH /api/v1/organization/trusts/{trust_id}
// @Summary      Change a trust's settings
// @Description  Owner of the trusting (host) organization only, with recent re-authentication.
// @Tags         Organization
// @Accept       json
// @Produce      json
// @Param        trust_id  path      string                   true  "Trust ID"
// @Param        body      body      OrgTrustSettingsRequest  true  "Settings"
// @Success      200       {object}  OrgTrustResponse
// @Failure      400       {object}  apierror.Error
// @Failure      404       {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/trusts/{trust_id} [patch]
func (h *OrgTrustHandler) Update(w http.ResponseWriter, r *http.Request) {
	tid, _, actx, ok := h.caller(w, r)
	if !ok {
		return
	}
	id, err := shared.IDFromString(chi.URLParam(r, "trust_id"))
	if err != nil {
		apierror.NotFound("Trust").WriteJSON(w)
		return
	}
	var req OrgTrustSettingsRequest
	if !decodeOrgTrust(w, r, &req) {
		return
	}
	v, err := h.service.Update(r.Context(), tid, id, req.settings(), actx)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeOrgTrust(w, http.StatusOK, toOrgTrustResponse(*v))
}

// Accept handles POST /api/v1/organization/trusts/{trust_id}/approve
// @Summary      Accept a trust
// @Description  Owner of the trusted (home) organization only, with recent re-authentication. Its people may then sign in to the other organization with this organization's single sign-on.
// @Tags         Organization
// @Accept       json
// @Produce      json
// @Param        trust_id  path      string                 true   "Trust ID"
// @Param        body      body      AcceptOrgTrustRequest  false  "Attestation"
// @Success      200       {object}  OrgTrustResponse
// @Failure      403       {object}  apierror.Error
// @Failure      404       {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/trusts/{trust_id}/approve [post]
func (h *OrgTrustHandler) Accept(w http.ResponseWriter, r *http.Request) {
	tid, uid, actx, ok := h.caller(w, r)
	if !ok {
		return
	}
	id, err := shared.IDFromString(chi.URLParam(r, "trust_id"))
	if err != nil {
		apierror.NotFound("Trust").WriteJSON(w)
		return
	}
	var req AcceptOrgTrustRequest
	if !decodeOrgTrust(w, r, &req) {
		return
	}
	v, err := h.service.Accept(r.Context(), tid, id, uid, req.AttestIdPMFA, actx)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeOrgTrust(w, http.StatusOK, toOrgTrustResponse(*v))
}

// Delete handles DELETE /api/v1/organization/trusts/{trust_id}
// @Summary      End a trust
// @Description  Owner of either organization, with recent re-authentication: withdraws, declines or ends the trust. Members of the trusting organization who come from the other organization are suspended there.
// @Tags         Organization
// @Param        trust_id  path  string  true  "Trust ID"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/trusts/{trust_id} [delete]
func (h *OrgTrustHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tid, _, actx, ok := h.caller(w, r)
	if !ok {
		return
	}
	id, err := shared.IDFromString(chi.URLParam(r, "trust_id"))
	if err != nil {
		apierror.NotFound("Trust").WriteJSON(w)
		return
	}
	if err := h.service.Revoke(r.Context(), tid, id, actx); err != nil {
		h.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
