package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const stepUpPurposeEndAdminSession = "end administrator session"

// AdminSessionStore lists and ends console sessions.
type AdminSessionStore interface {
	ListOpen(ctx context.Context) ([]postgres.AdminSessionRow, error)
	End(ctx context.Context, id shared.ID) (adminID string, err error)
}

// AdminSessionHandler serves Security > Sessions (RFC-022): the open console
// sessions of every administrator, and ending one. Super admin only, like the
// roster: it shows other administrators' addresses and sign-in methods.
type AdminSessionHandler struct {
	store  AdminSessionStore
	stepUp StepUpVerifier
	logger *logger.Logger
}

// NewAdminSessionHandler creates the handler.
func NewAdminSessionHandler(store AdminSessionStore, stepUp StepUpVerifier, log *logger.Logger) *AdminSessionHandler {
	return &AdminSessionHandler{store: store, stepUp: stepUp, logger: log.With("handler", "admin_session")}
}

// AdminSessionResponse is one open console session.
type AdminSessionResponse struct {
	ID          string    `json:"id"`
	AdminID     string    `json:"admin_id"`
	AdminEmail  string    `json:"admin_email"`
	AdminName   string    `json:"admin_name"`
	AdminRole   string    `json:"admin_role"`
	BreakGlass  bool      `json:"break_glass"`
	AuthMethod  string    `json:"auth_method"`
	MFAVerified bool      `json:"mfa_verified"`
	IPAddress   string    `json:"ip_address,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	// Current is the session making this request.
	Current bool `json:"current"`
}

// AdminSessionListResponse is GET /api/v1/admin/sessions.
type AdminSessionListResponse struct {
	Data []AdminSessionResponse `json:"data"`
}

// EndAdminSessionRequest ends another administrator's session.
type EndAdminSessionRequest struct {
	// Reason (10 to 500 characters) is kept in the admin audit row.
	Reason string `json:"reason"`
	// TOTPCode is a fresh console authenticator code (step-up).
	TOTPCode string `json:"totp_code"`
}

// List handles GET /api/v1/admin/sessions.
//
// @Summary      Open console sessions (platform admin)
// @Description  Every administrator's open console session: who, how they signed in, from where, last seen. Super admin only.
// @Tags         Admin
// @Produce      json
// @Success      200  {object}  AdminSessionListResponse
// @Router       /admin/sessions [get]
func (h *AdminSessionHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.store.ListOpen(r.Context())
	if err != nil {
		h.logger.Error("list admin sessions", "error", err)
		apierror.InternalServerError("could not list sessions").WriteJSON(w)
		return
	}
	current := ""
	if s := middleware.GetAdminSession(r.Context()); s != nil {
		current = s.ID.String()
	}
	out := AdminSessionListResponse{Data: make([]AdminSessionResponse, 0, len(rows))}
	for _, s := range rows {
		out.Data = append(out.Data, AdminSessionResponse{
			ID: s.ID, AdminID: s.AdminID, AdminEmail: s.AdminEmail, AdminName: s.AdminName,
			AdminRole: s.AdminRole, BreakGlass: s.BreakGlass, AuthMethod: s.AuthMethod,
			MFAVerified: s.MFAVerified, IPAddress: s.IP, UserAgent: s.UserAgent,
			CreatedAt: s.CreatedAt, LastSeenAt: s.LastSeenAt, ExpiresAt: s.ExpiresAt,
			Current: s.ID == current,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// End handles DELETE /api/v1/admin/sessions/{session_id}.
//
// @Summary      End an administrator's console session (platform admin)
// @Description  Signs that console session out at once. Super admin, a reason and a fresh authenticator code; audited at high severity. Your own current session is ended with sign-out instead.
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Param        session_id path  string                   true  "Session ID"
// @Param        request    body  EndAdminSessionRequest   true  "Reason and code"
// @Success      204
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /admin/sessions/{session_id} [delete]
func (h *AdminSessionHandler) End(w http.ResponseWriter, r *http.Request) {
	middleware.SetAuditAction(r.Context(), "console.session_ended", true)
	id, err := shared.IDFromString(chi.URLParam(r, "session_id"))
	if err != nil {
		apierror.BadRequest("invalid session id").WriteJSON(w)
		return
	}
	if s := middleware.GetAdminSession(r.Context()); s != nil && s.ID == id {
		apierror.BadRequest("This is your current session; sign out instead.").WriteJSON(w)
		return
	}
	var req EndAdminSessionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if n := len([]rune(strings.TrimSpace(req.Reason))); n < platformUserReasonMin || n > platformUserReasonMax {
		apierror.BadRequest("Give a reason (10 to 500 characters); it is kept in the audit log.").WriteJSON(w)
		return
	}
	if !confirmAdminStepUp(w, r, h.stepUp, req.TOTPCode, stepUpPurposeEndAdminSession, h.logger) {
		return
	}
	if _, err := h.store.End(r.Context(), id); err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			apierror.NotFound("session").WriteJSON(w)
			return
		}
		h.logger.Error("end admin session", "error", err)
		apierror.InternalServerError("could not end the session").WriteJSON(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
