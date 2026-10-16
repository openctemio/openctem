package handler

// Support access, organization side (docs/rfcs/RFC-063-support-access.md):
// an owner grants a named platform administrator time-boxed, read-only
// access; owners and admins see and revoke grants; every member sees the
// active ones (the banner).

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	supportapp "github.com/openctemio/openctem/api/internal/app/supportaccess"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/supportaccess"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SupportAccessHandler serves the organization's support access settings.
type SupportAccessHandler struct {
	svc *supportapp.Service
	log *logger.Logger
}

// NewSupportAccessHandler creates the handler.
func NewSupportAccessHandler(svc *supportapp.Service, log *logger.Logger) *SupportAccessHandler {
	return &SupportAccessHandler{svc: svc, log: log.With("handler", "support_access")}
}

// SupportGrantRequest is an owner's grant.
type SupportGrantRequest struct {
	// AdminEmail is the platform support administrator to name.
	AdminEmail string `json:"admin_email"`
	// Scopes: findings, assets (default both). Always read-only.
	Scopes []string `json:"scopes"`
	// DurationHours: 1 to 72 (default 4).
	DurationHours int    `json:"duration_hours"`
	Reason        string `json:"reason"`
	CaseRef       string `json:"case_ref"`
}

// SupportGrantResponse is one grant as the organization sees it.
type SupportGrantResponse struct {
	ID           string     `json:"id"`
	AdminEmail   string     `json:"admin_email"`
	AdminName    string     `json:"admin_name"`
	Level        string     `json:"level"`
	Scopes       []string   `json:"scopes"`
	Reason       string     `json:"reason"`
	CaseRef      string     `json:"case_ref,omitempty"`
	StartsAt     time.Time  `json:"starts_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	Active       bool       `json:"active"`
	SessionCount int        `json:"session_count"`
	OpenSession  bool       `json:"open_session"`
	LastAccessAt *time.Time `json:"last_access_at,omitempty"`
}

// SupportGrantListResponse wraps a list of grants.
type SupportGrantListResponse struct {
	Data []SupportGrantResponse `json:"data"`
}

// SupportActiveResponse is what every member sees while support may look in.
type SupportActiveResponse struct {
	Data []SupportActiveGrant `json:"data"`
}

// SupportActiveGrant is one active grant, minimal: who, until when, what.
type SupportActiveGrant struct {
	AdminName   string    `json:"admin_name"`
	Scopes      []string  `json:"scopes"`
	ExpiresAt   time.Time `json:"expires_at"`
	OpenSession bool      `json:"open_session"`
	CaseRef     string    `json:"case_ref,omitempty"`
}

func toSupportGrantResponse(g *supportaccess.Grant, now time.Time) SupportGrantResponse {
	return SupportGrantResponse{
		ID: g.ID.String(), AdminEmail: g.AdminEmail, AdminName: g.AdminName, Level: g.Level, Scopes: g.Scopes,
		Reason: g.Reason, CaseRef: g.CaseRef, StartsAt: g.StartsAt, ExpiresAt: g.ExpiresAt, RevokedAt: g.RevokedAt,
		CreatedAt: g.CreatedAt, Active: g.ActiveAt(now), SessionCount: g.SessionCount, OpenSession: g.OpenSession && g.ActiveAt(now),
		LastAccessAt: g.LastAccessAt,
	}
}

func supportClient(r *http.Request) supportapp.Client {
	return supportapp.Client{IP: middleware.ClientIP(r), UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID")}
}

func (h *SupportAccessHandler) writeError(w http.ResponseWriter, err error, op string) {
	switch {
	case errors.Is(err, supportaccess.ErrGrantNotFound):
		apierror.NotFound("support grant").WriteJSON(w)
	case errors.Is(err, supportaccess.ErrNotOwner):
		apierror.Forbidden("Only an owner of the organization grants support access").WriteJSON(w)
	case errors.Is(err, supportaccess.ErrNotSupportAdmin):
		apierror.BadRequest("No platform support administrator has this email").WriteJSON(w)
	case errors.Is(err, supportaccess.ErrTooManyActiveGrant):
		apierror.Conflict("This administrator already holds active access here; revoke it first").WriteJSON(w)
	case shared.IsValidation(err):
		apierror.BadRequest(sanitizeLogField(err.Error())).WriteJSON(w)
	default:
		h.log.Error("support access", "op", op, "error", err)
		apierror.InternalServerError("could not complete the request").WriteJSON(w)
	}
}

// List handles GET /api/v1/organization/support-access/grants.
// @Summary List support access grants
// @Description Owners and admins. The organization's support access grants, newest first, with their sessions.
// @Tags Organization
// @Produce json
// @Success 200 {object} SupportGrantListResponse
// @Failure 403 {object} apierror.Error
// @Security BearerAuth
// @Router /organization/support-access/grants [get]
func (h *SupportAccessHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, _ := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	grants, err := h.svc.ListGrants(r.Context(), tenantID)
	if err != nil {
		h.writeError(w, err, "list")
		return
	}
	now := time.Now()
	out := SupportGrantListResponse{Data: make([]SupportGrantResponse, 0, len(grants))}
	for _, g := range grants {
		out.Data = append(out.Data, toSupportGrantResponse(g, now))
	}
	writeJSON(w, http.StatusOK, out)
}

// Create handles POST /api/v1/organization/support-access/grants.
// @Summary Grant support access
// @Description Owner only, with a recent step-up. Grants one named platform support administrator read-only access to the chosen data for 1 to 72 hours (default 4), with a reason. Owners are emailed; the grant is in the audit log.
// @Tags Organization
// @Accept json
// @Produce json
// @Param request body SupportGrantRequest true "Grant"
// @Success 201 {object} SupportGrantResponse
// @Failure 400 {object} apierror.Error
// @Failure 403 {object} apierror.Error
// @Failure 409 {object} apierror.Error
// @Security BearerAuth
// @Router /organization/support-access/grants [post]
func (h *SupportAccessHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID, _ := shared.IDFromString(middleware.GetTenantID(r.Context()))
	u := middleware.GetLocalUser(r.Context())
	if tenantID.IsZero() || u == nil {
		apierror.Forbidden("owner session required").WriteJSON(w)
		return
	}
	var req SupportGrantRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	g, err := h.svc.CreateGrant(r.Context(), supportapp.CreateGrantInput{
		TenantID: tenantID, GrantedBy: u.ID(), GrantedByEmail: u.Email(), AdminEmail: req.AdminEmail,
		Scopes: req.Scopes, DurationHours: req.DurationHours, Reason: req.Reason, CaseRef: req.CaseRef,
	}, supportClient(r))
	if err != nil {
		h.writeError(w, err, "create")
		return
	}
	writeJSON(w, http.StatusCreated, toSupportGrantResponse(g, time.Now()))
}

// Revoke handles DELETE /api/v1/organization/support-access/grants/{grant_id}.
// @Summary Revoke support access
// @Description Owners and admins. Ends the grant and any open support session at once; the next support request is refused. Owners are emailed.
// @Tags Organization
// @Produce json
// @Param grant_id path string true "Grant ID"
// @Success 200 {object} SupportGrantResponse
// @Failure 404 {object} apierror.Error "Not this organization's, or no longer active"
// @Security BearerAuth
// @Router /organization/support-access/grants/{grant_id} [delete]
func (h *SupportAccessHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	tenantID, _ := shared.IDFromString(middleware.GetTenantID(r.Context()))
	u := middleware.GetLocalUser(r.Context())
	if tenantID.IsZero() || u == nil {
		apierror.Forbidden("administrator session required").WriteJSON(w)
		return
	}
	id, err := shared.IDFromString(r.PathValue("grant_id"))
	if err != nil {
		apierror.NotFound("support grant").WriteJSON(w)
		return
	}
	g, err := h.svc.RevokeGrant(r.Context(), tenantID, id, u.ID(), u.Email(), supportClient(r))
	if err != nil {
		h.writeError(w, err, "revoke")
		return
	}
	writeJSON(w, http.StatusOK, toSupportGrantResponse(g, time.Now()))
}

// Active handles GET /api/v1/organization/support-access/active.
// @Summary Active support access
// @Description Any member. The grants usable now (who, until when, which data), for the banner.
// @Tags Organization
// @Produce json
// @Success 200 {object} SupportActiveResponse
// @Security BearerAuth
// @Router /organization/support-access/active [get]
func (h *SupportAccessHandler) Active(w http.ResponseWriter, r *http.Request) {
	tenantID, _ := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	grants, err := h.svc.ActiveGrants(r.Context(), tenantID)
	if err != nil {
		h.writeError(w, err, "active")
		return
	}
	out := SupportActiveResponse{Data: make([]SupportActiveGrant, 0, len(grants))}
	for _, g := range grants {
		name := g.AdminName
		if name == "" {
			name = "Platform support"
		}
		out.Data = append(out.Data, SupportActiveGrant{AdminName: name, Scopes: g.Scopes, ExpiresAt: g.ExpiresAt, OpenSession: g.OpenSession, CaseRef: g.CaseRef})
	}
	writeJSON(w, http.StatusOK, out)
}
