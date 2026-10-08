package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/platformuser"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Platform user search needs at least this many characters (an id or part of
// an email or name), so the directory is looked up, not browsed.
const platformUserSearchMin = 3

// Support action reason length bounds (kept in the admin audit row).
const (
	platformUserReasonMin = 10
	platformUserReasonMax = 500
)

// PlatformUserDirectoryReader reads the cross-organization user directory.
type PlatformUserDirectoryReader interface {
	Search(ctx context.Context, q string, limit, offset int) ([]postgres.PlatformUserSummary, int, error)
	Get(ctx context.Context, id shared.ID) (*postgres.PlatformUserDetail, error)
}

// AdminPlatformUserHandler serves Console > Users (RFC-022): find
// an account across organizations and run a support action on it.
type AdminPlatformUserHandler struct {
	dir     PlatformUserDirectoryReader
	actions *platformuser.Service
	logger  *logger.Logger
}

// NewAdminPlatformUserHandler creates the handler.
func NewAdminPlatformUserHandler(dir PlatformUserDirectoryReader, actions *platformuser.Service, log *logger.Logger) *AdminPlatformUserHandler {
	return &AdminPlatformUserHandler{dir: dir, actions: actions, logger: log.With("handler", "admin_platform_user")}
}

// AdminPlatformUserResponse is one account in the console.
type AdminPlatformUserResponse struct {
	ID              string     `json:"id"`
	Email           string     `json:"email"`
	Name            string     `json:"name"`
	Status          string     `json:"status"`
	AuthProvider    string     `json:"auth_provider"`
	EmailVerified   bool       `json:"email_verified"`
	Locked          bool       `json:"locked"`
	LockedUntil     *time.Time `json:"locked_until,omitempty"`
	FailedLogins    int        `json:"failed_logins"`
	LastLoginAt     *time.Time `json:"last_login_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	Memberships     int        `json:"memberships"`
	MFAEnabled      bool       `json:"mfa_enabled"`
	IsPlatformAdmin bool       `json:"is_platform_admin"`
	Erased          bool       `json:"erased"`
}

// AdminPlatformUserListResponse is a page of accounts.
type AdminPlatformUserListResponse struct {
	Data       []AdminPlatformUserResponse `json:"data"`
	Total      int                         `json:"total"`
	Page       int                         `json:"page"`
	PerPage    int                         `json:"per_page"`
	TotalPages int                         `json:"total_pages"`
}

// AdminPlatformUserMembership is one organization the account belongs to.
type AdminPlatformUserMembership struct {
	TenantID   string    `json:"tenant_id"`
	TenantName string    `json:"tenant_name"`
	TenantSlug string    `json:"tenant_slug"`
	Role       string    `json:"role"`
	Status     string    `json:"status"`
	JoinedAt   time.Time `json:"joined_at"`
}

// AdminPlatformUserIdentity is one federated identity of the account.
type AdminPlatformUserIdentity struct {
	Issuer     string     `json:"issuer"`
	Subject    string     `json:"subject"`
	TenantID   string     `json:"tenant_id,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// AdminPlatformUserSession is one active session of the account.
type AdminPlatformUserSession struct {
	ID           string    `json:"id"`
	IPAddress    string    `json:"ip_address,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
	AuthMethod   string    `json:"auth_method"`
	CreatedAt    time.Time `json:"created_at"`
	LastActivity time.Time `json:"last_activity_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// AdminPlatformUserDetailResponse is one account with memberships,
// identities and active sessions.
type AdminPlatformUserDetailResponse struct {
	AdminPlatformUserResponse
	MembershipList []AdminPlatformUserMembership `json:"membership_list"`
	Identities     []AdminPlatformUserIdentity   `json:"identities"`
	Sessions       []AdminPlatformUserSession    `json:"sessions"`
}

// AdminPlatformUserActionRequest is the body of a support action.
type AdminPlatformUserActionRequest struct {
	// Reason is why the administrator acts (10 to 500 characters); it is
	// kept in the admin audit row.
	Reason string `json:"reason"`
}

func toPlatformUserResponse(s postgres.PlatformUserSummary, now time.Time) AdminPlatformUserResponse {
	return AdminPlatformUserResponse{
		ID: s.ID, Email: s.Email, Name: s.Name, Status: s.Status, AuthProvider: s.AuthProvider,
		EmailVerified: s.EmailVerified, Locked: s.LockedUntil != nil && s.LockedUntil.After(now),
		LockedUntil: s.LockedUntil, FailedLogins: s.FailedLogins, LastLoginAt: s.LastLoginAt,
		CreatedAt: s.CreatedAt, Memberships: s.Memberships, MFAEnabled: s.MFAEnabled,
		IsPlatformAdmin: s.IsPlatformAdmin, Erased: s.Erased,
	}
}

// Search handles GET /api/v1/admin/platform-users.
//
// @Summary      Find accounts across organizations (platform admin)
// @Description  Accounts whose email or name contains q (at least 3 characters), or whose id is q. Any admin role. Account-level facts only.
// @Tags         Admin
// @Produce      json
// @Param        q         query  string  true   "Email, name or id (3+ characters)"
// @Param        page      query  int     false  "Page"
// @Param        per_page  query  int     false  "Page size (max 100)"
// @Success      200  {object}  AdminPlatformUserListResponse
// @Failure      400  {object}  apierror.Error
// @Router       /admin/platform-users [get]
func (h *AdminPlatformUserHandler) Search(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len([]rune(q)) < platformUserSearchMin || len(q) > 254 {
		apierror.BadRequest("Search with at least 3 characters of an email, a name or an id").WriteJSON(w)
		return
	}
	paging, ok := listPage(w, r, 25)
	if !ok {
		return
	}
	rows, total, err := h.dir.Search(r.Context(), q, paging.PerPage, (paging.Page-1)*paging.PerPage)
	if err != nil {
		h.logger.Error("search platform users", "error", err)
		apierror.InternalServerError("could not search accounts").WriteJSON(w)
		return
	}
	now := time.Now()
	resp := AdminPlatformUserListResponse{
		Data: make([]AdminPlatformUserResponse, 0, len(rows)), Total: total,
		Page: paging.Page, PerPage: paging.PerPage, TotalPages: (total + paging.PerPage - 1) / paging.PerPage,
	}
	for _, s := range rows {
		resp.Data = append(resp.Data, toPlatformUserResponse(s, now))
	}
	writeJSON(w, http.StatusOK, resp)
}

func platformUserID(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(chi.URLParam(r, "userId"))
	if err != nil {
		apierror.BadRequest("invalid user id").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

// Get handles GET /api/v1/admin/platform-users/{userId}.
//
// @Summary      One account across organizations (platform admin)
// @Description  The account, the organizations it belongs to, its federated identities and its active sessions. Any admin role; audited.
// @Tags         Admin
// @Produce      json
// @Param        userId  path  string  true  "User ID"
// @Success      200  {object}  AdminPlatformUserDetailResponse
// @Failure      404  {object}  apierror.Error
// @Router       /admin/platform-users/{userId} [get]
func (h *AdminPlatformUserHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := platformUserID(w, r)
	if !ok {
		return
	}
	d, err := h.dir.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			apierror.NotFound("user").WriteJSON(w)
			return
		}
		h.logger.Error("get platform user", "error", err)
		apierror.InternalServerError("could not read the account").WriteJSON(w)
		return
	}
	resp := AdminPlatformUserDetailResponse{
		AdminPlatformUserResponse: toPlatformUserResponse(d.PlatformUserSummary, time.Now()),
		MembershipList:            make([]AdminPlatformUserMembership, 0, len(d.Memberships)),
		Identities:                make([]AdminPlatformUserIdentity, 0, len(d.Identities)),
		Sessions:                  make([]AdminPlatformUserSession, 0, len(d.Sessions)),
	}
	for _, m := range d.Memberships {
		resp.MembershipList = append(resp.MembershipList, AdminPlatformUserMembership(m))
	}
	for _, i := range d.Identities {
		resp.Identities = append(resp.Identities, AdminPlatformUserIdentity(i))
	}
	for _, s := range d.Sessions {
		resp.Sessions = append(resp.Sessions, AdminPlatformUserSession(s))
	}
	writeJSON(w, http.StatusOK, resp)
}

// action runs one support action after checking the reason.
func (h *AdminPlatformUserHandler) action(w http.ResponseWriter, r *http.Request, run func(context.Context, shared.ID) error, done string) {
	id, ok := platformUserID(w, r)
	if !ok {
		return
	}
	var req AdminPlatformUserActionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if n := len([]rune(strings.TrimSpace(req.Reason))); n < platformUserReasonMin || n > platformUserReasonMax {
		apierror.BadRequest("Give a reason (10 to 500 characters); it is kept in the audit log.").WriteJSON(w)
		return
	}
	if h.actions == nil {
		apierror.ServiceUnavailable("Account actions are not available").WriteJSON(w)
		return
	}
	if err := run(r.Context(), id); err != nil {
		switch {
		case errors.Is(err, shared.ErrNotFound):
			apierror.NotFound("user").WriteJSON(w)
		case errors.Is(err, platformuser.ErrEmailUnavailable):
			apierror.New(http.StatusConflict, "EMAIL_UNAVAILABLE", "No email can be sent from this installation; configure SMTP first.").WriteJSON(w)
		case errors.Is(err, shared.ErrConflict):
			msg := err.Error()
			if i := strings.Index(msg, ": "); i != -1 {
				msg = msg[i+2:]
			}
			apierror.Conflict(strings.ToUpper(msg[:1]) + msg[1:] + ".").WriteJSON(w)
		default:
			h.logger.Error("platform user action", "action", done, "error", err)
			apierror.InternalServerError("the action failed").WriteJSON(w)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": done})
}

// RevokeSessions handles POST /api/v1/admin/platform-users/{userId}/revoke-sessions.
//
// @Summary      Sign an account out everywhere (platform admin)
// @Description  Ends every session of the account, in every organization. ops_admin+, reason required, audited. Refused for platform administrator and erased accounts.
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Param        userId   path  string                          true  "User ID"
// @Param        request  body  AdminPlatformUserActionRequest  true  "Reason"
// @Success      200  {object}  map[string]string
// @Router       /admin/platform-users/{userId}/revoke-sessions [post]
func (h *AdminPlatformUserHandler) RevokeSessions(w http.ResponseWriter, r *http.Request) {
	h.action(w, r, h.actions.RevokeSessions, "sessions_revoked")
}

// Unlock handles POST /api/v1/admin/platform-users/{userId}/unlock.
//
// @Summary      Unlock an account (platform admin)
// @Description  Clears a lockout from failed sign-ins. ops_admin+, reason required, audited.
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Param        userId   path  string                          true  "User ID"
// @Param        request  body  AdminPlatformUserActionRequest  true  "Reason"
// @Success      200  {object}  map[string]string
// @Router       /admin/platform-users/{userId}/unlock [post]
func (h *AdminPlatformUserHandler) Unlock(w http.ResponseWriter, r *http.Request) {
	h.action(w, r, h.actions.Unlock, "unlocked")
}

// SendPasswordReset handles POST /api/v1/admin/platform-users/{userId}/password-reset.
//
// @Summary      Email an account a password reset link (platform admin)
// @Description  The forgot-password link, sent to the account's own mailbox; never returned. Accounts with a password only. ops_admin+, reason required, audited.
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Param        userId   path  string                          true  "User ID"
// @Param        request  body  AdminPlatformUserActionRequest  true  "Reason"
// @Success      200  {object}  map[string]string
// @Router       /admin/platform-users/{userId}/password-reset [post]
func (h *AdminPlatformUserHandler) SendPasswordReset(w http.ResponseWriter, r *http.Request) {
	h.action(w, r, h.actions.SendPasswordReset, "password_reset_sent")
}

// ResendVerification handles POST /api/v1/admin/platform-users/{userId}/resend-verification.
//
// @Summary      Resend email verification (platform admin)
// @Description  A fresh verification link to an unverified account's own mailbox; the previous one stops working. ops_admin+, reason required, audited.
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Param        userId   path  string                          true  "User ID"
// @Param        request  body  AdminPlatformUserActionRequest  true  "Reason"
// @Success      200  {object}  map[string]string
// @Router       /admin/platform-users/{userId}/resend-verification [post]
func (h *AdminPlatformUserHandler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	h.action(w, r, h.actions.ResendVerification, "verification_sent")
}
