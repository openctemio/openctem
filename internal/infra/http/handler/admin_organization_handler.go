package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/admin"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/user"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// AdminOrganizationHandler serves the platform admin's Organizations API
// (RFC-022 Phase 2): list, view and create organizations, and set SSO
// enforcement per organization. SAML, identity-provider and verified-domain
// setup reuse the tenant SSO handlers under AdminTenantScope.
type AdminOrganizationHandler struct {
	orgs      admin.OrganizationReader
	tenants   *app.TenantService
	users     user.Repository
	validator *validator.Validator
	logger    *logger.Logger
}

// NewAdminOrganizationHandler creates the handler.
func NewAdminOrganizationHandler(orgs admin.OrganizationReader, tenants *app.TenantService, users user.Repository, v *validator.Validator, log *logger.Logger) *AdminOrganizationHandler {
	return &AdminOrganizationHandler{orgs: orgs, tenants: tenants, users: users, validator: v, logger: log.With("handler", "admin_organization")}
}

// TenantExists reports whether an organization exists; used by AdminTenantScope.
func (h *AdminOrganizationHandler) TenantExists(ctx context.Context, id shared.ID) error {
	_, err := h.orgs.GetOrganization(ctx, id)
	return err
}

// AdminOrganizationResponse is one organization in the admin console.
type AdminOrganizationResponse struct {
	ID                      string    `json:"id"`
	Name                    string    `json:"name"`
	Slug                    string    `json:"slug"`
	Description             string    `json:"description,omitempty"`
	CreatedAt               time.Time `json:"created_at"`
	ActiveMembers           int       `json:"active_members"`
	OwnerEmails             []string  `json:"owner_emails"`
	SAMLEnabled             bool      `json:"saml_enabled"`
	ActiveIdentityProviders int       `json:"active_identity_providers"`
	VerifiedDomains         int       `json:"verified_domains"`
	SSOEnforced             bool      `json:"sso_enforced"`
}

// AdminOrganizationListResponse is a page of organizations.
type AdminOrganizationListResponse struct {
	Data       []AdminOrganizationResponse `json:"data"`
	Total      int                         `json:"total"`
	Page       int                         `json:"page"`
	PerPage    int                         `json:"per_page"`
	TotalPages int                         `json:"total_pages"`
}

// AdminCreateOrganizationRequest creates an organization owned by an existing user.
type AdminCreateOrganizationRequest struct {
	Name        string `json:"name" validate:"required,min=2,max=100"`
	Slug        string `json:"slug" validate:"required,min=3,max=100,slug"`
	Description string `json:"description" validate:"max=500"`
	OwnerEmail  string `json:"owner_email" validate:"required,email"`
}

// AdminSSOEnforcementRequest turns SSO enforcement on or off for an organization.
type AdminSSOEnforcementRequest struct {
	Enforced *bool `json:"enforced" validate:"required"`
}

// AdminSSOEnforcementResponse reports an organization's SSO enforcement.
type AdminSSOEnforcementResponse struct {
	Enforced bool `json:"enforced"`
}

func toAdminOrganizationResponse(o *admin.Organization) AdminOrganizationResponse {
	owners := o.OwnerEmails
	if owners == nil {
		owners = []string{}
	}
	return AdminOrganizationResponse{
		ID: o.ID.String(), Name: o.Name, Slug: o.Slug, Description: o.Description,
		CreatedAt: o.CreatedAt, ActiveMembers: o.ActiveMembers, OwnerEmails: owners,
		SAMLEnabled: o.SAMLEnabled, ActiveIdentityProviders: o.ActiveIdentityProviders,
		VerifiedDomains: o.VerifiedDomains, SSOEnforced: o.SSOEnforced,
	}
}

// adminAuditContext attributes a tenant-audit event to the platform admin. The
// admin is not a users row, so actor_id stays empty (it references users) and
// the email is prefixed so the organization's own audit log shows who did it.
func adminAuditContext(r *http.Request, tenantID string) app.AuditContext {
	actx := app.AuditContext{
		TenantID:  tenantID,
		ActorIP:   r.RemoteAddr,
		UserAgent: r.UserAgent(),
		RequestID: r.Header.Get("X-Request-ID"),
	}
	if a := middleware.GetAdminUser(r.Context()); a != nil {
		actx.ActorEmail = "platform-admin:" + a.Email()
	}
	return actx
}

func orgIDParam(r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(r.PathValue(middleware.AdminTenantParam))
	return id, err == nil
}

// List handles GET /api/v1/admin/tenants.
// @Summary List organizations (platform admin)
// @Description Cross-tenant list of organizations with size and SSO posture. Newest first.
// @Tags Admin Organizations
// @Produce json
// @Param search query string false "Match name or slug"
// @Param page query int false "Page (default 1)"
// @Param per_page query int false "Page size (default 50, max 200)"
// @Success 200 {object} AdminOrganizationListResponse
// @Failure 401 {object} apierror.Error "Unauthorized"
// @Security BearerAuth
// @Router /admin/tenants [get]
func (h *AdminOrganizationHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	page = max(page, 1)
	perPage, _ := strconv.Atoi(q.Get("per_page"))
	if perPage <= 0 || perPage > 200 {
		perPage = 50
	}
	orgs, total, err := h.orgs.ListOrganizations(r.Context(), admin.OrganizationFilter{
		Search: q.Get("search"), Limit: perPage, Offset: (page - 1) * perPage,
	})
	if err != nil {
		h.logger.Error("list organizations", "error", sanitizeLogField(err.Error()))
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	resp := AdminOrganizationListResponse{
		Data: make([]AdminOrganizationResponse, 0, len(orgs)), Total: total, Page: page, PerPage: perPage,
		TotalPages: (total + perPage - 1) / perPage,
	}
	for _, o := range orgs {
		resp.Data = append(resp.Data, toAdminOrganizationResponse(o))
	}
	writeJSON(w, http.StatusOK, resp)
}

// Get handles GET /api/v1/admin/tenants/{tenantId}.
// @Summary Get an organization (platform admin)
// @Tags Admin Organizations
// @Produce json
// @Param tenantId path string true "Organization ID"
// @Success 200 {object} AdminOrganizationResponse
// @Failure 404 {object} apierror.Error "Not Found"
// @Security BearerAuth
// @Router /admin/tenants/{tenantId} [get]
func (h *AdminOrganizationHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := orgIDParam(r)
	if !ok {
		apierror.BadRequest("invalid organization id").WriteJSON(w)
		return
	}
	o, err := h.orgs.GetOrganization(r.Context(), id)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			apierror.NotFound("organization").WriteJSON(w)
			return
		}
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, toAdminOrganizationResponse(o))
}

// Create handles POST /api/v1/admin/tenants. The owner must be an existing
// user; the organization is created in either TENANT_CREATION_MODE.
// @Summary Create an organization (platform admin)
// @Description Creates an organization with an existing user as its owner. Works in both TENANT_CREATION_MODE values.
// @Tags Admin Organizations
// @Accept json
// @Produce json
// @Param request body AdminCreateOrganizationRequest true "Organization"
// @Success 201 {object} AdminOrganizationResponse
// @Failure 400 {object} apierror.Error "Bad Request"
// @Security BearerAuth
// @Router /admin/tenants [post]
func (h *AdminOrganizationHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req AdminCreateOrganizationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	req.Slug = strings.ToLower(strings.TrimSpace(req.Slug))
	req.OwnerEmail = strings.ToLower(strings.TrimSpace(req.OwnerEmail))
	if err := h.validator.Validate(req); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}
	owner, err := h.users.GetByEmail(r.Context(), req.OwnerEmail)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			apierror.BadRequest("owner_email must belong to an existing user").WriteJSON(w)
			return
		}
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	t, err := h.tenants.CreateTenant(r.Context(), app.CreateTenantInput{
		Name: req.Name, Slug: req.Slug, Description: req.Description,
	}, owner.ID(), adminAuditContext(r, ""))
	if err != nil {
		if shared.IsValidation(err) {
			apierror.BadRequest(err.Error()).WriteJSON(w)
			return
		}
		h.logger.Error("create organization", "error", sanitizeLogField(err.Error()))
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	o, err := h.orgs.GetOrganization(r.Context(), t.ID())
	if err != nil {
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusCreated, toAdminOrganizationResponse(o))
}

// GetSSOEnforcement handles GET /api/v1/admin/tenants/{tenantId}/sso/enforcement.
// @Summary Get an organization's SSO enforcement
// @Tags Admin Organizations
// @Produce json
// @Param tenantId path string true "Organization ID"
// @Success 200 {object} AdminSSOEnforcementResponse
// @Security BearerAuth
// @Router /admin/tenants/{tenantId}/sso/enforcement [get]
func (h *AdminOrganizationHandler) GetSSOEnforcement(w http.ResponseWriter, r *http.Request) {
	id, ok := orgIDParam(r)
	if !ok {
		apierror.BadRequest("invalid organization id").WriteJSON(w)
		return
	}
	o, err := h.orgs.GetOrganization(r.Context(), id)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			apierror.NotFound("organization").WriteJSON(w)
			return
		}
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, AdminSSOEnforcementResponse{Enforced: o.SSOEnforced})
}

// SetSSOEnforcement handles PUT /api/v1/admin/tenants/{tenantId}/sso/enforcement.
// Turning it on requires a usable SSO path (active identity provider or the
// env fallback), the same guard the tenant settings used to apply; the owner
// break-glass at login still applies.
// @Summary Set an organization's SSO enforcement
// @Description Requires members to sign in via SSO (the owner is exempt as break-glass). Refused with 400 when the organization has no usable SSO path.
// @Tags Admin Organizations
// @Accept json
// @Produce json
// @Param tenantId path string true "Organization ID"
// @Param request body AdminSSOEnforcementRequest true "Enforcement"
// @Success 200 {object} AdminSSOEnforcementResponse
// @Failure 400 {object} apierror.Error "Bad Request"
// @Security BearerAuth
// @Router /admin/tenants/{tenantId}/sso/enforcement [put]
func (h *AdminOrganizationHandler) SetSSOEnforcement(w http.ResponseWriter, r *http.Request) {
	id, ok := orgIDParam(r)
	if !ok {
		apierror.BadRequest("invalid organization id").WriteJSON(w)
		return
	}
	var req AdminSSOEnforcementRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil || req.Enforced == nil {
		apierror.BadRequest("enforced is required").WriteJSON(w)
		return
	}
	settings, err := h.tenants.UpdateSecuritySettings(r.Context(), id.String(),
		app.UpdateSecuritySettingsInput{SSOEnforced: req.Enforced}, adminAuditContext(r, id.String()))
	if err != nil {
		switch {
		case errors.Is(err, shared.ErrNotFound):
			apierror.NotFound("organization").WriteJSON(w)
		case shared.IsValidation(err):
			apierror.BadRequest(err.Error()).WriteJSON(w)
		default:
			h.logger.Error("set sso enforcement", "error", sanitizeLogField(err.Error()))
			apierror.InternalError(err).WriteJSON(w)
		}
		return
	}
	writeJSON(w, http.StatusOK, AdminSSOEnforcementResponse{Enforced: settings.Security.SSOEnforced})
}
