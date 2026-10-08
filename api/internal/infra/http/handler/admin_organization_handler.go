package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/audit"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// AdminOrganizationHandler serves the platform admin's Organizations API
// (RFC-022 Phase 2): list, view and create organizations, and set SSO
// enforcement per organization. SAML, identity-provider and verified-domain
// setup reuse the tenant SSO handlers under AdminTenantScope.
type AdminOrganizationHandler struct {
	orgs      admin.OrganizationReader
	tenants   *tenantapp.TenantService
	users     user.Repository
	validator *validator.Validator
	logger    *logger.Logger
	// provisioning creates accounts (organization users, and the owner of a
	// new organization) — the same service organization admins use.
	provisioning *tenantapp.UserProvisioningService
	// stepUp checks a fresh console authenticator code for owner recovery.
	stepUp StepUpVerifier
}

// WithStepUp wires the console step-up check (owner recovery needs it).
func (h *AdminOrganizationHandler) WithStepUp(v StepUpVerifier) *AdminOrganizationHandler {
	h.stepUp = v
	return h
}

// confirmRecoveryStepUp demands a fresh authenticator code. Without a
// verifier the recovery is refused rather than run unconfirmed.
func (h *AdminOrganizationHandler) confirmRecoveryStepUp(w http.ResponseWriter, r *http.Request, code string) bool {
	actor := middleware.GetAdminUser(r.Context())
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
		return false
	}
	if h.stepUp == nil {
		apierror.ServiceUnavailable("Owner recovery is not available").WriteJSON(w)
		return false
	}
	code = strings.TrimSpace(code)
	if code == "" {
		apierror.New(http.StatusUnauthorized, codeStepUpRequired, "Enter a code from your authenticator to confirm the owner recovery").WriteJSON(w)
		return false
	}
	if err := h.stepUp.StepUp(r.Context(), actor, code, stepUpPurposeOwnerRecovery, clientInfo(r)); err != nil {
		switch {
		case errors.Is(err, admin.ErrStepUpUnavailable):
			apierror.New(http.StatusForbidden, codeStepUpUnavailable,
				"Enroll the console authenticator (sign in with your password and TOTP) to confirm this action").WriteJSON(w)
		case errors.Is(err, admin.ErrInvalidMFACode):
			apierror.Unauthorized("Invalid or already used code; wait for your authenticator to show a new one").WriteJSON(w)
		default:
			h.logger.Error("owner recovery step-up", "error", err)
			apierror.InternalServerError("could not verify the code").WriteJSON(w)
		}
		return false
	}
	return true
}

// WithUserProvisioning wires administrator-created accounts.
func (h *AdminOrganizationHandler) WithUserProvisioning(svc *tenantapp.UserProvisioningService) *AdminOrganizationHandler {
	h.provisioning = svc
	return h
}

// NewAdminOrganizationHandler creates the handler.
func NewAdminOrganizationHandler(orgs admin.OrganizationReader, tenants *tenantapp.TenantService, users user.Repository, v *validator.Validator, log *logger.Logger) *AdminOrganizationHandler {
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
	// Plan is free, pro or enterprise.
	Plan string `json:"plan"`
}

// AdminOrganizationListResponse is a page of organizations.
type AdminOrganizationListResponse struct {
	Data       []AdminOrganizationResponse `json:"data"`
	Total      int                         `json:"total"`
	Page       int                         `json:"page"`
	PerPage    int                         `json:"per_page"`
	TotalPages int                         `json:"total_pages"`
}

// AdminCreateOrganizationRequest creates an organization. When owner_email has
// no account yet, one is created for the owner with a one-time
// set-password link.
type AdminCreateOrganizationRequest struct {
	Name        string `json:"name" validate:"required,min=2,max=100"`
	Slug        string `json:"slug" validate:"required,min=3,max=100,slug"`
	Description string `json:"description" validate:"max=500"`
	OwnerEmail  string `json:"owner_email" validate:"required,email"`
	OwnerName   string `json:"owner_name" validate:"max=255"`
}

// AdminOwnerSetupResponse describes the owner account created with an
// organization. SetupToken is present only when the organization cannot send
// email at all; when it can, the link is only ever emailed (EmailFailed
// reports a failed send, recovered with forgot-password).
type AdminOwnerSetupResponse struct {
	EmailSent      bool       `json:"email_sent"`
	EmailFailed    bool       `json:"email_failed,omitempty"`
	SetupToken     string     `json:"setup_token,omitempty"`
	SetupExpiresAt *time.Time `json:"setup_expires_at,omitempty"`
}

// AdminCreateOrganizationResponse is the created organization plus, when its
// owner account was created too, how the owner sets their password.
type AdminCreateOrganizationResponse struct {
	AdminOrganizationResponse
	OwnerSetup *AdminOwnerSetupResponse `json:"owner_setup,omitempty"`
}

// AdminCreateOrgUserRequest creates the first owner of an organization that
// has none. That is the only user the platform administrator may create in an
// organization; Role may be omitted, and anything other than "owner" is
// refused.
type AdminCreateOrgUserRequest struct {
	Email string `json:"email" validate:"required,email,max=254"`
	Name  string `json:"name" validate:"max=255"`
	Role  string `json:"role" validate:"omitempty,oneof=owner"`
	// Recovery creates a new owner for an organization whose owners are all
	// suspended. Super admin only; the set-password link is emailed and
	// never returned; refused while any owner is active.
	Recovery bool `json:"recovery,omitempty"`
	// Reason (recovery only, required) is why the administrator takes this
	// step; it is kept in the admin audit row.
	Reason string `json:"reason,omitempty" validate:"max=500"`
	// TOTPCode (recovery only, required) is a fresh code from the console
	// authenticator (step-up).
	TOTPCode string `json:"totp_code,omitempty" validate:"max=16"`
}

// Owner recovery reason length bounds.
const (
	ownerRecoveryReasonMin = 10
	ownerRecoveryReasonMax = 500
)

const stepUpPurposeOwnerRecovery = "owner recovery"

// AdminOrgUserResponse is one member of an organization in the console.
type AdminOrgUserResponse struct {
	UserID       string    `json:"user_id"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	Role         string    `json:"role"`
	Status       string    `json:"status"`
	PendingSetup bool      `json:"pending_setup"`
	JoinedAt     time.Time `json:"joined_at"`
}

// AdminOrgUserListResponse lists an organization's members.
type AdminOrgUserListResponse struct {
	Data  []AdminOrgUserResponse `json:"data"`
	Total int                    `json:"total"`
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
		VerifiedDomains: o.VerifiedDomains, SSOEnforced: o.SSOEnforced, Plan: o.Plan,
	}
}

// adminAuditContext attributes a tenant-audit event to the platform admin. The
// admin is not a users row, so actor_id stays empty (it references users) and
// the email is prefixed so the organization's own audit log shows who did it.
func adminAuditContext(r *http.Request, tenantID string) audit.AuditContext {
	actx := audit.AuditContext{
		TenantID: tenantID,
		// The resolved client IP (forwarding headers only from a trusted
		// proxy), not the proxy's socket address.
		ActorIP:   middleware.ClientIP(r),
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
// @Param owner query string false "none: no active owner; present: has one" Enums(none, present)
// @Param plan query string false "Plan" Enums(free, pro, enterprise)
// @Param include_system query bool false "Also list the internal platform system organization (left out by default)"
// @Param page query int false "Page (default 1)"
// @Param per_page query int false "Page size (default 50, max 100)"
// @Success 200 {object} AdminOrganizationListResponse
// @Failure 401 {object} apierror.Error "Unauthorized"
// @Security BearerAuth
// @Router /admin/tenants [get]
func (h *AdminOrganizationHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	paging, ok := listPage(w, r, 50)
	if !ok {
		return
	}
	page, perPage := paging.Page, paging.PerPage
	f := admin.OrganizationFilter{
		Search: q.Get("search"), Limit: perPage, Offset: (page - 1) * perPage,
	}
	switch owner := q.Get("owner"); owner {
	case "", admin.OrganizationOwnerNone, admin.OrganizationOwnerPresent:
		f.Owner = owner
	default:
		apierror.BadRequest("owner must be none or present").WriteJSON(w)
		return
	}
	switch q.Get("include_system") {
	case "", queryParamFalse:
	case queryParamTrue:
		f.IncludeSystem = true
	default:
		apierror.BadRequest("include_system must be true or false").WriteJSON(w)
		return
	}
	if p := q.Get("plan"); p != "" {
		if !plan.Plan(p).IsValid() {
			apierror.BadRequest("plan must be free, pro or enterprise").WriteJSON(w)
			return
		}
		f.Plan = p
	}
	orgs, total, err := h.orgs.ListOrganizations(r.Context(), f)
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
	created, err := tenantapp.NewOrganizationCreator(h.tenants, h.provisioning, h.users, h.logger).
		Create(r.Context(), tenantapp.CreateOrganizationInput{
			Name: req.Name, Slug: req.Slug, Description: req.Description,
			OwnerEmail: req.OwnerEmail, OwnerName: req.OwnerName,
		}, adminAuditContext(r, ""))
	if err != nil {
		switch {
		case errors.Is(err, tenant.ErrPlatformAdminMembership):
			apierror.Conflict("Platform administrators cannot belong to an organization. Use another owner email.").WriteJSON(w)
		case errors.Is(err, tenantapp.ErrAccountExists):
			apierror.Conflict("An account with this email was just created. Try again.").WriteJSON(w)
		case shared.IsValidation(err):
			apierror.BadRequest(err.Error()).WriteJSON(w)
		default:
			h.logger.Error("create organization", "error", sanitizeLogField(err.Error()))
			apierror.InternalError(err).WriteJSON(w)
		}
		return
	}
	t := created.Tenant
	middleware.SetAuditResource(r.Context(), t.ID(), t.Name())
	resp := AdminCreateOrganizationResponse{}
	if setup := created.OwnerSetup; setup != nil {
		resp.OwnerSetup = &AdminOwnerSetupResponse{EmailSent: setup.EmailSent, EmailFailed: setup.EmailFailed, SetupToken: setup.SetupToken}
		if setup.SetupToken != "" {
			exp := setup.SetupExpiresAt
			resp.OwnerSetup.SetupExpiresAt = &exp
		}
	}
	o, err := h.orgs.GetOrganization(r.Context(), t.ID())
	if err != nil {
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	resp.AdminOrganizationResponse = toAdminOrganizationResponse(o)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, resp)
}

// ListUsers handles GET /api/v1/admin/tenants/{tenantId}/users.
// @Summary List an organization's users (platform admin)
// @Tags Admin Organizations
// @Produce json
// @Param tenantId path string true "Organization ID"
// @Success 200 {object} AdminOrgUserListResponse
// @Failure 404 {object} apierror.Error "Not Found"
// @Security BearerAuth
// @Router /admin/tenants/{tenantId}/users [get]
func (h *AdminOrganizationHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	id, ok := orgIDParam(r)
	if !ok {
		apierror.BadRequest("invalid organization id").WriteJSON(w)
		return
	}
	members, err := h.tenants.ListMembersWithUserInfo(r.Context(), id.String())
	if err != nil {
		h.logger.Error("list organization users", "error", sanitizeLogField(err.Error()))
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	resp := AdminOrgUserListResponse{Data: make([]AdminOrgUserResponse, 0, len(members))}
	for _, m := range members {
		resp.Data = append(resp.Data, AdminOrgUserResponse{
			UserID: m.UserID.String(), Email: m.Email, Name: m.Name, Role: m.Role.String(),
			Status: m.Status, PendingSetup: m.PendingSetup, JoinedAt: m.JoinedAt,
		})
	}
	resp.Total = len(resp.Data)
	writeJSON(w, http.StatusOK, resp)
}

// CreateUser handles POST /api/v1/admin/tenants/{tenantId}/users.
// @Summary Create the first owner of an organization (platform admin)
// @Description Bootstrap only: creates the owner of an organization that has no owner, and nothing else (409 when it has one, active or suspended: its owner and administrators add users themselves). The one-time set-password link is emailed when the organization can send email and is then never returned; only when email cannot be sent is setup_token returned, once. Written to the organization's audit log. With "recovery": true (super admin only, 403 otherwise) it creates a new owner of an organization whose owners are all suspended (409 while any owner is active); the link is then emailed only and never returned (400 when the organization cannot send email), and the action is audited as organization.owner_recovery in the admin audit log and at critical severity in the organization's audit log.
// @Tags Admin Organizations
// @Accept json
// @Produce json
// @Param tenantId path string true "Organization ID"
// @Param request body AdminCreateOrgUserRequest true "First owner"
// @Success 201 {object} ProvisionedUserResponse
// @Failure 400 {object} apierror.Error "Bad Request"
// @Failure 403 {object} apierror.Error "Owner recovery by an administrator who is not a super admin"
// @Failure 409 {object} apierror.Error "Organization already has an owner, or the account exists"
// @Security BearerAuth
// @Router /admin/tenants/{tenantId}/users [post]
func (h *AdminOrganizationHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	if h.provisioning == nil {
		apierror.ServiceUnavailable("User creation is not available").WriteJSON(w)
		return
	}
	id, ok := orgIDParam(r)
	if !ok {
		apierror.BadRequest("invalid organization id").WriteJSON(w)
		return
	}
	var req AdminCreateOrgUserRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}
	create := h.provisioning.CreateFirstOwner
	if req.Recovery {
		// Owner recovery overrides a suspended owner's hold on the
		// organization: super admin only, and audited under its own action.
		middleware.SetAuditAction(r.Context(), "organization.owner_recovery", true)
		if middleware.GetAdminRole(r.Context()) != string(admin.AdminRoleSuperAdmin) {
			apierror.Forbidden("Owner recovery requires the super admin role.").WriteJSON(w)
			return
		}
		if n := len([]rune(strings.TrimSpace(req.Reason))); n < ownerRecoveryReasonMin || n > ownerRecoveryReasonMax {
			apierror.BadRequest("Give a reason for the owner recovery (10 to 500 characters); it is kept in the audit log.").WriteJSON(w)
			return
		}
		if !h.confirmRecoveryStepUp(w, r, req.TOTPCode) {
			return
		}
		create = h.provisioning.RecoverOwner
	}
	result, err := create(r.Context(), id.String(), req.Email, req.Name, adminAuditContext(r, id.String()))
	if err != nil {
		switch {
		case errors.Is(err, tenant.ErrOrganizationHasOwner) && req.Recovery:
			apierror.Conflict("This organization has an active owner. Owner recovery is only for an organization whose owners are all suspended.").WriteJSON(w)
		case errors.Is(err, tenant.ErrOrganizationHasOwner):
			apierror.Conflict("This organization already has an owner (active or suspended). Its owner and administrators invite or create users themselves; if every owner is suspended, a super admin can use owner recovery.").WriteJSON(w)
		case errors.Is(err, tenant.ErrPlatformAdminMembership):
			apierror.Conflict("Platform administrators cannot belong to an organization.").WriteJSON(w)
		case errors.Is(err, tenantapp.ErrAccountExists):
			apierror.Conflict("An account with this email already exists. The first owner must be a new account.").WriteJSON(w)
		case errors.Is(err, shared.ErrNotFound):
			apierror.NotFound("organization").WriteJSON(w)
		case shared.IsValidation(err):
			msg := err.Error()
			if idx := strings.Index(msg, ": "); idx != -1 {
				msg = msg[idx+2:]
			}
			apierror.BadRequest(msg).WriteJSON(w)
		default:
			h.logger.Error("create organization user", "error", sanitizeLogField(err.Error()))
			apierror.InternalError(err).WriteJSON(w)
		}
		return
	}
	writeProvisionedUser(w, http.StatusCreated, result)
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
		tenantapp.UpdateSecuritySettingsInput{SSOEnforced: req.Enforced}, adminAuditContext(r, id.String()))
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
