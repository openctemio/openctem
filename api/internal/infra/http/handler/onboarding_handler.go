package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/onboarding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/joinrequest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// Onboarding (docs/rfcs/RFC-104): an account without an organization sees
// its invitations, the organizations its verified domain may join, and
// whether it may create one. Authenticated by the refresh token, like
// create-first-team (an account with no organization has no access token).

// SetOnboarding wires the onboarding service.
func (h *LocalAuthHandler) SetOnboarding(svc *onboarding.Service) { h.onboarding = svc }

// OnboardingRequest authenticates an onboarding call; refresh_token may be
// omitted when the cookie and the CSRF pair are sent.
type OnboardingRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// OnboardingAcceptRequest takes one offer by its reference.
type OnboardingAcceptRequest struct {
	RefreshToken string `json:"refresh_token"`
	Ref          string `json:"ref"`
}

func (h *LocalAuthHandler) onboardingAccount(w http.ResponseWriter, r *http.Request, bodyToken string) (*auth.RefreshSessionIdentity, bool) {
	if h.onboarding == nil {
		apierror.ServiceUnavailable("Onboarding is not available").WriteJSON(w)
		return nil, false
	}
	token, ok := h.refreshTokenFrom(w, r, bodyToken)
	if !ok {
		return nil, false
	}
	if token == "" {
		apierror.Unauthorized("refresh_token is required (in body or cookie)").WriteJSON(w)
		return nil, false
	}
	id, err := h.authService.IdentifyRefreshSession(r.Context(), token)
	if err != nil {
		apierror.Unauthorized("Session expired; sign in again").WriteJSON(w)
		return nil, false
	}
	return id, true
}

// OnboardingOptions returns the onboarding fork for the signed-in account.
// @Summary      Onboarding options
// @Description  Pending invitations for the verified address, organizations its verified domain may join (only discoverable ones), and whether it may create an organization. Offers carry opaque per-account references.
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        request  body  OnboardingRequest  false  "Refresh token (or cookie + CSRF)"
// @Success      200  {object}  onboarding.Options
// @Router       /auth/onboarding/options [post]
func (h *LocalAuthHandler) OnboardingOptions(w http.ResponseWriter, r *http.Request) {
	var req OnboardingRequest
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req)
	acc, ok := h.onboardingAccount(w, r, req.RefreshToken)
	if !ok {
		return
	}
	opts, err := h.onboarding.Options(r.Context(), acc.User)
	if err != nil {
		h.logger.Error("onboarding options", "error", err)
		apierror.InternalServerError("could not load the options").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(opts)
}

// OnboardingAccept takes one offer: accept an invitation, join an
// organization of the verified domain, or ask to join it.
// @Summary      Take an onboarding offer
// @Description  The reference comes from /auth/onboarding/options and is bound to the account. Every condition is checked again; a stale or foreign reference is refused with one answer.
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        request  body  OnboardingAcceptRequest  true  "Offer"
// @Success      200  {object}  onboarding.AcceptResult
// @Router       /auth/onboarding/accept [post]
func (h *LocalAuthHandler) OnboardingAccept(w http.ResponseWriter, r *http.Request) {
	var req OnboardingAcceptRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil || strings.TrimSpace(req.Ref) == "" {
		apierror.BadRequest("ref is required").WriteJSON(w)
		return
	}
	acc, ok := h.onboardingAccount(w, r, req.RefreshToken)
	if !ok {
		return
	}
	u := acc.User
	actx := auditapp.AuditContext{ActorID: u.ID().String(), ActorEmail: u.Email(), ActorIP: getClientIP(r),
		UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID")}
	res, err := h.onboarding.Accept(r.Context(), u, strings.TrimSpace(req.Ref), actx)
	switch {
	case err == nil:
	case errors.Is(err, onboarding.ErrInvalidRef), errors.Is(err, shared.ErrNotFound):
		apierror.New(http.StatusConflict, "OFFER_UNAVAILABLE", "This offer is no longer available").WriteJSON(w)
		return
	case errors.Is(err, onboarding.ErrEmailNotVerified):
		apierror.Forbidden("Verify your email address first").WriteJSON(w)
		return
	case errors.Is(err, joinrequest.ErrAlreadyPending):
		apierror.Conflict("Your request to join is already waiting").WriteJSON(w)
		return
	case errors.Is(err, joinrequest.ErrTooMany):
		apierror.TooManyRequests("Too many requests to join; try again tomorrow").WriteJSON(w)
		return
	case errors.Is(err, shared.ErrValidation), errors.Is(err, shared.ErrForbidden):
		apierror.New(http.StatusConflict, "OFFER_UNAVAILABLE", "This offer is no longer available").WriteJSON(w)
		return
	default:
		h.logger.Error("onboarding accept", "error", err)
		apierror.InternalServerError("could not take the offer").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// --- the organization's inbox (Members > Requests) ---

// SetJoinRequests wires the join-request inbox.
func (h *TenantHandler) SetJoinRequests(svc *onboarding.Service) { h.joinRequests = svc }

// JoinRequestResponse is a waiting request, shown to the organization's
// administrators only.
type JoinRequestResponse struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name,omitempty"`
	EmailVerified bool   `json:"email_verified"`
	RequestedRole string `json:"requested_role"`
	RequestedAt   string `json:"requested_at"`
	ExpiresAt     string `json:"expires_at"`
}

// DecideJoinRequestRequest approves a request with a role.
type DecideJoinRequestRequest struct {
	// Role: viewer or member. Nobody becomes an administrator by request.
	Role string `json:"role"`
}

// ListJoinRequests lists the organization's waiting join requests.
// @Summary      List requests to join
// @Description  Owner or admin. Waiting requests from verified holders of the organization's domains.
// @Tags         Tenants
// @Produce      json
// @Param        tenant  path  string  true  "Tenant ID or slug"
// @Success      200  {array}  JoinRequestResponse
// @Router       /tenants/{tenant}/join-requests [get]
func (h *TenantHandler) ListJoinRequests(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.joinRequestTenant(w, r)
	if !ok {
		return
	}
	rows, err := h.joinRequests.ListRequests(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("list join requests", "error", err)
		apierror.InternalServerError("could not list requests").WriteJSON(w)
		return
	}
	out := make([]JoinRequestResponse, 0, len(rows))
	for _, jr := range rows {
		out = append(out, JoinRequestResponse{ID: jr.ID.String(), Email: jr.Email, Name: jr.Name, EmailVerified: jr.EmailVerified,
			RequestedRole: jr.RequestedRole, RequestedAt: jr.CreatedAt.UTC().Format(time.RFC3339),
			ExpiresAt: jr.ExpiresAt.UTC().Format(time.RFC3339)})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// ApproveJoinRequest approves a waiting request and creates the membership.
// @Summary      Approve a request to join
// @Description  Owner or admin with members:write. Role viewer or member. A request of another organization is not found.
// @Tags         Tenants
// @Accept       json
// @Param        tenant     path  string                    true  "Tenant ID or slug"
// @Param        requestId  path  string                    true  "Request ID"
// @Param        request    body  DecideJoinRequestRequest  true  "Role"
// @Success      204
// @Router       /tenants/{tenant}/join-requests/{requestId}/approve [post]
func (h *TenantHandler) ApproveJoinRequest(w http.ResponseWriter, r *http.Request) {
	h.decideJoinRequest(w, r, true)
}

// RejectJoinRequest rejects a waiting request.
// @Summary      Reject a request to join
// @Description  Owner or admin with members:write. The requester is not told who decided.
// @Tags         Tenants
// @Param        tenant     path  string  true  "Tenant ID or slug"
// @Param        requestId  path  string  true  "Request ID"
// @Success      204
// @Router       /tenants/{tenant}/join-requests/{requestId}/reject [post]
func (h *TenantHandler) RejectJoinRequest(w http.ResponseWriter, r *http.Request) {
	h.decideJoinRequest(w, r, false)
}

func (h *TenantHandler) decideJoinRequest(w http.ResponseWriter, r *http.Request, approve bool) {
	tenantID, ok := h.joinRequestTenant(w, r)
	if !ok {
		return
	}
	id, err := shared.IDFromString(chi.URLParam(r, "requestId"))
	if err != nil {
		apierror.NotFound("Request not found").WriteJSON(w)
		return
	}
	by := middleware.GetLocalUserID(r.Context())
	actx := auditapp.AuditContext{TenantID: tenantID.String(), ActorID: by.String(), ActorEmail: auditActorEmail(r.Context()),
		ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID")}
	if approve {
		var req DecideJoinRequestRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
			apierror.BadRequest("Invalid request body").WriteJSON(w)
			return
		}
		err = h.joinRequests.Approve(r.Context(), tenantID, id, by, strings.TrimSpace(req.Role), actx)
	} else {
		err = h.joinRequests.Reject(r.Context(), tenantID, id, by, actx)
	}
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, joinrequest.ErrNotFound):
		apierror.NotFound("Request not found").WriteJSON(w)
	case errors.Is(err, joinrequest.ErrNotPending):
		apierror.Conflict("The request is no longer waiting").WriteJSON(w)
	case errors.Is(err, joinrequest.ErrInvalidRole):
		apierror.BadRequest("role must be viewer or member").WriteJSON(w)
	case errors.Is(err, tenantdom.ErrPlatformAdminMembership), errors.Is(err, shared.ErrValidation):
		apierror.Conflict("The person cannot be added to this organization").WriteJSON(w)
	default:
		h.logger.Error("decide join request", "error", err)
		apierror.InternalServerError("could not decide the request").WriteJSON(w)
	}
}

func (h *TenantHandler) joinRequestTenant(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return shared.ID{}, false
	}
	if h.joinRequests == nil {
		apierror.ServiceUnavailable("Join requests are not available").WriteJSON(w)
		return shared.ID{}, false
	}
	return tenantID, true
}
