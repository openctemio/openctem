package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Announcement bounds.
const (
	announcementMessageMax  = 500
	announcementMaxDuration = 31 * 24 * time.Hour
	announcementActiveLimit = 5
	announcementListLimit   = 100
)

var announcementSeverities = map[string]bool{"info": true, "warning": true, "maintenance": true}

// AnnouncementStore stores platform announcements.
type AnnouncementStore interface {
	List(ctx context.Context, limit int) ([]postgres.PlatformAnnouncement, error)
	Active(ctx context.Context, now time.Time, limit int) ([]postgres.PlatformAnnouncement, error)
	Create(ctx context.Context, a postgres.PlatformAnnouncement) (string, error)
	End(ctx context.Context, id shared.ID, now time.Time) error
}

// AnnouncementHandler serves platform announcements (RFC-022): the operator
// writes a short plain-text notice in the console (System > Announcements),
// and every signed-in user sees it as a banner while it is active.
type AnnouncementHandler struct {
	store  AnnouncementStore
	now    func() time.Time
	logger *logger.Logger
}

// NewAnnouncementHandler creates the handler.
func NewAnnouncementHandler(store AnnouncementStore, log *logger.Logger) *AnnouncementHandler {
	return &AnnouncementHandler{store: store, now: time.Now, logger: log.With("handler", "announcement")}
}

// AnnouncementResponse is one announcement as a signed-in user sees it.
type AnnouncementResponse struct {
	ID       string     `json:"id"`
	Message  string     `json:"message"`
	Severity string     `json:"severity"`
	StartsAt time.Time  `json:"starts_at"`
	EndsAt   *time.Time `json:"ends_at,omitempty"`
}

// AdminAnnouncementResponse adds the console's view of the window.
type AdminAnnouncementResponse struct {
	AnnouncementResponse
	// State is scheduled, active or ended.
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
}

// AnnouncementListResponse wraps a list.
type AnnouncementListResponse struct {
	Data []AnnouncementResponse `json:"data"`
}

// AdminAnnouncementListResponse wraps the console list.
type AdminAnnouncementListResponse struct {
	Data []AdminAnnouncementResponse `json:"data"`
}

// CreateAnnouncementRequest creates an announcement.
type CreateAnnouncementRequest struct {
	// Message is plain text, 1 to 500 characters, shown as is (never HTML).
	Message  string     `json:"message"`
	Severity string     `json:"severity"`
	StartsAt *time.Time `json:"starts_at,omitempty"`
	// EndsAt is required: at most 31 days after the start, so a notice
	// cannot be left up forever by mistake.
	EndsAt time.Time `json:"ends_at"`
	// Reason (10 to 500 characters) is kept in the admin audit row.
	Reason string `json:"reason"`
}

// EndAnnouncementRequest ends an announcement early.
type EndAnnouncementRequest struct {
	Reason string `json:"reason"`
}

func toAnnouncementResponse(a postgres.PlatformAnnouncement) AnnouncementResponse {
	return AnnouncementResponse{ID: a.ID, Message: a.Message, Severity: a.Severity, StartsAt: a.StartsAt, EndsAt: a.EndsAt}
}

func announcementState(a postgres.PlatformAnnouncement, now time.Time) string {
	switch {
	case a.StartsAt.After(now):
		return "scheduled"
	case a.EndsAt != nil && !a.EndsAt.After(now):
		return "ended"
	default:
		return "active"
	}
}

// Active handles GET /api/v1/announcements.
//
// @Summary      Active platform announcements
// @Description  The platform operator's notices shown now (at most 5, maintenance first). Any signed-in user; plain text.
// @Tags         System
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  AnnouncementListResponse
// @Router       /announcements [get]
func (h *AnnouncementHandler) Active(w http.ResponseWriter, r *http.Request) {
	rows, err := h.store.Active(r.Context(), h.now(), announcementActiveLimit)
	if err != nil {
		h.logger.Error("active announcements", "error", err)
		apierror.InternalServerError("could not read announcements").WriteJSON(w)
		return
	}
	out := AnnouncementListResponse{Data: make([]AnnouncementResponse, 0, len(rows))}
	for _, a := range rows {
		out.Data = append(out.Data, toAnnouncementResponse(a))
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

// AdminList handles GET /api/v1/admin/announcements.
//
// @Summary      Platform announcements (platform admin)
// @Description  The newest 100 announcements with their state (scheduled, active, ended). Any admin role.
// @Tags         Admin
// @Produce      json
// @Success      200  {object}  AdminAnnouncementListResponse
// @Router       /admin/announcements [get]
func (h *AnnouncementHandler) AdminList(w http.ResponseWriter, r *http.Request) {
	rows, err := h.store.List(r.Context(), announcementListLimit)
	if err != nil {
		h.logger.Error("list announcements", "error", err)
		apierror.InternalServerError("could not list announcements").WriteJSON(w)
		return
	}
	now := h.now()
	out := AdminAnnouncementListResponse{Data: make([]AdminAnnouncementResponse, 0, len(rows))}
	for _, a := range rows {
		out.Data = append(out.Data, AdminAnnouncementResponse{
			AnnouncementResponse: toAnnouncementResponse(a), State: announcementState(a, now), CreatedAt: a.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// validAnnouncementMessage refuses control characters other than spaces:
// the banner is one plain line.
func validAnnouncementMessage(m string) bool {
	n := len([]rune(m))
	if n < 1 || n > announcementMessageMax {
		return false
	}
	for _, r := range m {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validReason(reason string) bool {
	n := len([]rune(strings.TrimSpace(reason)))
	return n >= platformUserReasonMin && n <= platformUserReasonMax
}

// AdminCreate handles POST /api/v1/admin/announcements.
//
// @Summary      Publish a platform announcement (platform admin)
// @Description  A plain-text notice (1-500 characters, one line) shown to every signed-in user between starts_at (default now) and ends_at (required, at most 31 days later). ops_admin+, reason required, audited.
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Param        request  body  CreateAnnouncementRequest  true  "Announcement"
// @Success      201  {object}  AdminAnnouncementResponse
// @Failure      400  {object}  apierror.Error
// @Router       /admin/announcements [post]
func (h *AnnouncementHandler) AdminCreate(w http.ResponseWriter, r *http.Request) {
	var req CreateAnnouncementRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	msg := strings.TrimSpace(req.Message)
	if !validAnnouncementMessage(msg) {
		apierror.BadRequest("The message must be one line of 1 to 500 characters.").WriteJSON(w)
		return
	}
	if !announcementSeverities[req.Severity] {
		apierror.BadRequest("severity must be info, warning or maintenance").WriteJSON(w)
		return
	}
	if !validReason(req.Reason) {
		apierror.BadRequest("Give a reason (10 to 500 characters); it is kept in the audit log.").WriteJSON(w)
		return
	}
	now := h.now()
	starts := now
	if req.StartsAt != nil {
		starts = *req.StartsAt
	}
	if starts.Before(now.Add(-time.Minute)) {
		apierror.BadRequest("starts_at cannot be in the past").WriteJSON(w)
		return
	}
	if !req.EndsAt.After(starts) || req.EndsAt.Sub(starts) > announcementMaxDuration {
		apierror.BadRequest("ends_at must be after starts_at and at most 31 days later").WriteJSON(w)
		return
	}
	a := postgres.PlatformAnnouncement{Message: msg, Severity: req.Severity, StartsAt: starts, EndsAt: &req.EndsAt}
	if actor := middleware.GetAdminUser(r.Context()); actor != nil {
		a.CreatedBy = actor.ID().String()
	}
	id, err := h.store.Create(r.Context(), a)
	if err != nil {
		h.logger.Error("create announcement", "error", err)
		apierror.InternalServerError("could not publish the announcement").WriteJSON(w)
		return
	}
	a.ID, a.CreatedAt = id, now
	writeJSON(w, http.StatusCreated, AdminAnnouncementResponse{
		AnnouncementResponse: toAnnouncementResponse(a), State: announcementState(a, now), CreatedAt: now,
	})
}

// AdminEnd handles POST /api/v1/admin/announcements/{announcement_id}/cancel.
//
// @Summary      End a platform announcement now (platform admin)
// @Description  Takes the notice down at once (a scheduled one never shows); it stays in the history. ops_admin+, reason required, audited.
// @Tags         Admin
// @Accept       json
// @Param        announcement_id  path  string                  true  "Announcement ID"
// @Param        request          body  EndAnnouncementRequest  true  "Reason"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /admin/announcements/{announcement_id}/cancel [post]
func (h *AnnouncementHandler) AdminEnd(w http.ResponseWriter, r *http.Request) {
	id, err := shared.IDFromString(chi.URLParam(r, "announcement_id"))
	if err != nil {
		apierror.BadRequest("invalid announcement id").WriteJSON(w)
		return
	}
	var req EndAnnouncementRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if !validReason(req.Reason) {
		apierror.BadRequest("Give a reason (10 to 500 characters); it is kept in the audit log.").WriteJSON(w)
		return
	}
	if err := h.store.End(r.Context(), id, h.now()); err != nil {
		switch {
		case errors.Is(err, shared.ErrNotFound):
			apierror.NotFound("announcement").WriteJSON(w)
		case errors.Is(err, shared.ErrConflict):
			apierror.Conflict("The announcement already ended.").WriteJSON(w)
		default:
			h.logger.Error("end announcement", "error", err)
			apierror.InternalServerError("could not end the announcement").WriteJSON(w)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
